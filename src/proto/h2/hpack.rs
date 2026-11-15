//! HPACK (RFC 7541): the decoder for request field blocks and the encoder for response ones.
//!
//! Neither side allocates per block once its buffers have grown: a dynamic table is one byte
//! buffer with an index of spans, the decoder hands each field to a callback as borrowed
//! slices, and the encoder appends to the connection's output.
//!
//! The decoder bounds its own work by the size of the block: a string is at most 8/5 of its
//! coded bytes, a table entry at most the table's size. What a block may expand to in total
//! is the caller's limit, enforced where the fields are stored.
//!
//! The encoder indexes a field the second time a connection sends it, so a field that never
//! repeats (a length, a validator of one resource) costs its literal once and never evicts a
//! field that does repeat.

use super::huffman;
use rustc_hash::FxHasher;
use std::collections::VecDeque;
use std::hash::Hasher;

/// RFC 7541 Appendix A.
const STATIC: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// The static index of a field name a response may carry; 0 when it has none.
fn static_name(name: &[u8]) -> usize {
    match name {
        b":status" => 8,
        b"accept-ranges" => 18,
        b"access-control-allow-origin" => 20,
        b"age" => 21,
        b"allow" => 22,
        b"cache-control" => 24,
        b"content-disposition" => 25,
        b"content-encoding" => 26,
        b"content-language" => 27,
        b"content-length" => 28,
        b"content-location" => 29,
        b"content-range" => 30,
        b"content-type" => 31,
        b"date" => 33,
        b"etag" => 34,
        b"expires" => 36,
        b"last-modified" => 44,
        b"link" => 45,
        b"location" => 46,
        b"proxy-authenticate" => 48,
        b"refresh" => 52,
        b"retry-after" => 53,
        b"server" => 54,
        b"set-cookie" => 55,
        b"strict-transport-security" => 56,
        b"vary" => 59,
        b"via" => 60,
        b"www-authenticate" => 61,
        _ => 0,
    }
}

/// What an entry adds to a table's size beyond its name and value (RFC 7541 4.1).
const ENTRY_OVERHEAD: usize = 32;

/// SETTINGS_HEADER_TABLE_SIZE before any SETTINGS frame, which is also what this server
/// keeps for both of its tables.
pub(super) const TABLE_SIZE: usize = 4096;

#[derive(Clone, Copy)]
struct Entry {
    name: (u32, u16),
    value: (u32, u16),
    /// The encoder's hash of the pair; unused by the decoder.
    hash: u32,
}

/// The name of an entry to add.
#[derive(Clone, Copy)]
enum Name<'a> {
    Bytes(&'a [u8]),
    /// That of the entry this many insertions back, as it is now.
    Entry(usize),
}

/// A dynamic table. Names and values sit in one buffer, appended as entries are added; an
/// entry named after another shares that entry's bytes, so adding it costs its value alone.
/// Evicted entries leave their bytes behind until the buffer has outgrown the table twice
/// over, when the live entries are copied out to the other buffer. Each buffer stays under
/// three times the table's size.
struct Table {
    bytes: Vec<u8>,
    /// The other buffer of the pair the entries move between.
    spare: Vec<u8>,
    /// Oldest first.
    entries: VecDeque<Entry>,
    /// The sum of the entries' sizes as RFC 7541 4.1 counts them.
    size: usize,
    max: usize,
}

fn span((start, len): (u32, u16), bytes: &[u8]) -> &[u8] {
    &bytes[start as usize..start as usize + usize::from(len)]
}

impl Table {
    fn new() -> Table {
        Table {
            bytes: Vec::new(),
            spare: Vec::new(),
            entries: VecDeque::new(),
            size: 0,
            max: TABLE_SIZE,
        }
    }

    /// The entry `index` insertions back; 0 is the newest.
    fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        let at = self.entries.len().checked_sub(index + 1)?;
        let entry = self.entries[at];
        Some((
            span(entry.name, &self.bytes),
            span(entry.value, &self.bytes),
        ))
    }

    fn evict_to(&mut self, size: usize) {
        while self.size > size {
            let Some(entry) = self.entries.pop_front() else {
                break;
            };
            self.size -= usize::from(entry.name.1) + usize::from(entry.value.1) + ENTRY_OVERHEAD;
        }
    }

    fn set_max(&mut self, max: usize) {
        self.max = max;
        self.evict_to(max);
        if self.entries.is_empty() {
            self.bytes.clear();
        }
    }

    /// Adds an entry, evicting the oldest ones to make room. An entry larger than the table
    /// empties it and is not added (RFC 7541 4.4). `value`, and a name given as bytes, must
    /// not borrow from this table.
    fn insert(&mut self, name: Name<'_>, value: &[u8], hash: u32) {
        // Resolved before eviction: the bytes of an evicted entry stay where they are.
        let name = match name {
            Name::Bytes(name) => Ok(name),
            Name::Entry(index) => match self.entries.len().checked_sub(index + 1) {
                Some(at) => Err(self.entries[at].name),
                None => return,
            },
        };
        let name_len = match name {
            Ok(name) => name.len(),
            Err((_, len)) => usize::from(len),
        };
        let size = name_len + value.len() + ENTRY_OVERHEAD;
        if size > self.max {
            self.evict_to(0);
            self.bytes.clear();
            return;
        }
        self.evict_to(self.max - size);
        let emptied = self.entries.is_empty();
        let name = match name {
            Ok(name) => {
                if emptied {
                    self.bytes.clear();
                }
                let start = self.bytes.len() as u32;
                self.bytes.extend_from_slice(name);
                (start, name.len() as u16)
            }
            // Making room took every entry, the one with the name too: its bytes are all
            // the buffer keeps.
            Err((start, len)) if emptied => {
                let start = start as usize;
                self.bytes.copy_within(start..start + usize::from(len), 0);
                self.bytes.truncate(len.into());
                (0, len)
            }
            Err(shared) => shared,
        };
        let start = self.bytes.len() as u32;
        self.bytes.extend_from_slice(value);
        self.entries.push_back(Entry {
            name,
            value: (start, value.len() as u16),
            hash,
        });
        self.size += size;
        if self.bytes.len() > 2 * self.max {
            self.compact();
        }
    }

    /// Copies the live entries to the spare buffer and swaps the two. At most the table's
    /// size is copied, after at least as much was appended.
    fn compact(&mut self) {
        self.spare.clear();
        for entry in &mut self.entries {
            for part in [&mut entry.name, &mut entry.value] {
                let start = self.spare.len() as u32;
                self.spare.extend_from_slice(span(*part, &self.bytes));
                part.0 = start;
            }
        }
        std::mem::swap(&mut self.bytes, &mut self.spare);
    }

    /// How many insertions back the pair is, if it is in the table.
    fn find(&self, hash: u32, name: &[u8], value: &[u8]) -> Option<usize> {
        self.entries.iter().rev().position(|entry| {
            entry.hash == hash
                && usize::from(entry.name.1) == name.len()
                && span(entry.name, &self.bytes) == name
                && span(entry.value, &self.bytes) == value
        })
    }
}

/// A field block that does not decode: a connection error of type COMPRESSION_ERROR.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Malformed;

impl From<huffman::BadCode> for Malformed {
    fn from(_: huffman::BadCode) -> Malformed {
        Malformed
    }
}

/// An integer with an `n`-bit prefix (RFC 7541 5.1), from `block[*pos..]`.
fn integer(block: &[u8], pos: &mut usize, prefix: u32) -> Result<usize, Malformed> {
    let mask = (1u32 << prefix) - 1;
    let first = u32::from(*block.get(*pos).ok_or(Malformed)?) & mask;
    *pos += 1;
    if first < mask {
        return Ok(first as usize);
    }
    let mut value = u64::from(first);
    let mut shift = 0;
    loop {
        let byte = *block.get(*pos).ok_or(Malformed)?;
        *pos += 1;
        value += u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err(Malformed);
        }
    }
    u32::try_from(value)
        .map(|v| v as usize)
        .map_err(|_| Malformed)
}

/// Where a decoded string's bytes are.
#[derive(Clone, Copy)]
enum Text {
    Static(&'static [u8]),
    /// The name of the dynamic table entry this many insertions back.
    Table(usize),
    /// A raw string, in the block.
    Block(usize, usize),
    /// A decoded Huffman string, in the decoder's scratch.
    Scratch(usize, usize),
}

pub(super) struct Decoder {
    table: Table,
    scratch: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Decoder {
        Decoder {
            table: Table::new(),
            scratch: Vec::new(),
        }
    }

    /// Decodes one whole field block, handing each field's name and value to `emit` in
    /// order. After an error the table no longer matches the peer's and the connection has
    /// to end.
    pub fn decode(
        &mut self,
        block: &[u8],
        mut emit: impl FnMut(&[u8], &[u8]),
    ) -> Result<(), Malformed> {
        let mut pos = 0;
        let mut fields = false;
        while let Some(&first) = block.get(pos) {
            if first & 0x80 != 0 {
                let index = integer(block, &mut pos, 7)?;
                let (name, value) = self.indexed(index)?;
                emit(name, value);
                fields = true;
            } else if first & 0xc0 == 0x40 {
                let (name, value) = self.literal(block, &mut pos, 6)?;
                // Only a name can be a table entry's.
                let value = text(value, block, &self.scratch);
                emit(self.text(name, block), value);
                let name = match name {
                    Text::Table(index) => Name::Entry(index),
                    name => Name::Bytes(text(name, block, &self.scratch)),
                };
                self.table.insert(name, value, 0);
                fields = true;
            } else if first & 0xe0 == 0x20 {
                // A size update belongs before the block's first field (RFC 7541 4.2) and
                // within the limit this side set (6.3).
                let max = integer(block, &mut pos, 5)?;
                if fields || max > TABLE_SIZE {
                    return Err(Malformed);
                }
                self.table.set_max(max);
            } else {
                let (name, value) = self.literal(block, &mut pos, 4)?;
                emit(self.text(name, block), self.text(value, block));
                fields = true;
            }
        }
        Ok(())
    }

    /// Lets go of a scratch buffer that a long string grew past `keep` bytes.
    pub fn trim(&mut self, keep: usize) {
        if self.scratch.capacity() > keep {
            self.scratch = Vec::new();
        }
    }

    fn indexed(&self, index: usize) -> Result<(&[u8], &[u8]), Malformed> {
        match index {
            0 => Err(Malformed),
            1..=61 => Ok(STATIC[index - 1]),
            _ => self.table.get(index - 62).ok_or(Malformed),
        }
    }

    /// A literal field: its name by index or as a string, then its value. The scratch
    /// holds the strings of one field at a time.
    fn literal(
        &mut self,
        block: &[u8],
        pos: &mut usize,
        prefix: u32,
    ) -> Result<(Text, Text), Malformed> {
        self.scratch.clear();
        let name = match integer(block, pos, prefix)? {
            0 => self.string(block, pos)?,
            index @ 1..=61 => Text::Static(STATIC[index - 1].0),
            index if index - 62 < self.table.entries.len() => Text::Table(index - 62),
            _ => return Err(Malformed),
        };
        let value = self.string(block, pos)?;
        Ok((name, value))
    }

    fn text<'a>(&'a self, text: Text, block: &'a [u8]) -> &'a [u8] {
        match text {
            Text::Table(index) => self.table.get(index).map_or(&[], |(name, _)| name),
            other => self::text(other, block, &self.scratch),
        }
    }

    fn string(&mut self, block: &[u8], pos: &mut usize) -> Result<Text, Malformed> {
        let coded = block.get(*pos).ok_or(Malformed)? & 0x80 != 0;
        let len = integer(block, pos, 7)?;
        let start = *pos;
        let end = start
            .checked_add(len)
            .filter(|&end| end <= block.len())
            .ok_or(Malformed)?;
        *pos = end;
        if !coded {
            return Ok(Text::Block(start, end));
        }
        let from = self.scratch.len();
        huffman::decode(&block[start..end], &mut self.scratch)?;
        Ok(Text::Scratch(from, self.scratch.len()))
    }
}

/// The bytes of a string that is not a table entry's.
fn text<'a>(text: Text, block: &'a [u8], scratch: &'a [u8]) -> &'a [u8] {
    match text {
        Text::Static(bytes) => bytes,
        Text::Block(start, end) => &block[start..end],
        Text::Scratch(start, end) => &scratch[start..end],
        Text::Table(_) => &[],
    }
}

/// Pairs remembered from their first sending, by hash.
const SEEN: usize = 32;

pub(super) struct Encoder {
    table: Table,
    /// The smallest table size in use since the last block, when it changed: announced at
    /// the start of the next block (RFC 7541 4.2).
    shrunk_to: Option<usize>,
    seen: [u32; SEEN],
    seen_next: usize,
}

impl Encoder {
    pub fn new() -> Encoder {
        Encoder {
            table: Table::new(),
            shrunk_to: None,
            seen: [0; SEEN],
            seen_next: 0,
        }
    }

    /// Applies the peer's SETTINGS_HEADER_TABLE_SIZE: the table never grows past
    /// [`TABLE_SIZE`], and shrinks to a smaller limit.
    pub fn set_limit(&mut self, limit: u32) {
        let max = (limit as usize).min(TABLE_SIZE);
        if max != self.table.max {
            self.shrunk_to = Some(self.shrunk_to.map_or(max, |low| low.min(max)));
            self.table.set_max(max);
        }
    }

    /// Starts a field block: announces a changed table size.
    pub fn begin(&mut self, out: &mut Vec<u8>) {
        if let Some(low) = self.shrunk_to.take() {
            if low < self.table.max {
                put_integer(out, 5, 0x20, low);
            }
            put_integer(out, 5, 0x20, self.table.max);
        }
    }

    /// Appends `:status`.
    pub fn status(&mut self, out: &mut Vec<u8>, code: u16) {
        let index = match code {
            200 => 8,
            204 => 9,
            206 => 10,
            304 => 11,
            400 => 12,
            404 => 13,
            500 => 14,
            _ => {
                let digits = [
                    b'0' + (code / 100 % 10) as u8,
                    b'0' + (code / 10 % 10) as u8,
                    b'0' + (code % 10) as u8,
                ];
                return self.field(out, b":status", &digits);
            }
        };
        out.push(0x80 | index);
    }

    /// Appends a field: as an index when the table has the pair, else as a literal, which
    /// enters the table when the connection has sent the pair before. Whitespace around
    /// the value is cut, and a value a field may not hold is left out (RFC 9113 8.2.1).
    pub fn field(&mut self, out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        let value = value.trim_ascii();
        let hash = pair_hash(name, value);
        if let Some(back) = self.table.find(hash, name, value) {
            return put_integer(out, 7, 0x80, 62 + back);
        }
        if !sendable(value) {
            return;
        }
        let fits = name.len() + value.len() + ENTRY_OVERHEAD <= self.table.max / 2;
        if fits && self.seen_before(hash) {
            put_integer(out, 6, 0x40, static_name(name));
            self.table.insert(Name::Bytes(name), value, hash);
        } else {
            put_integer(out, 4, 0x00, static_name(name));
        }
        put_literal(out, name, value);
    }

    /// Appends a field no table should hold (RFC 7541 7.1.3): a literal never indexed.
    pub fn sensitive(&mut self, out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
        let value = value.trim_ascii();
        if !sendable(value) {
            return;
        }
        put_integer(out, 4, 0x10, static_name(name));
        put_literal(out, name, value);
    }

    fn seen_before(&mut self, hash: u32) -> bool {
        if self.seen.contains(&hash) {
            return true;
        }
        self.seen[self.seen_next] = hash;
        self.seen_next = (self.seen_next + 1) % SEEN;
        false
    }
}

/// The name (unless the representation before it carried its static index) and the value,
/// as raw strings.
fn put_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    if static_name(name) == 0 {
        put_integer(out, 7, 0, name.len());
        out.extend_from_slice(name);
    }
    put_integer(out, 7, 0, value.len());
    out.extend_from_slice(value);
}

fn put_integer(out: &mut Vec<u8>, prefix: u32, flags: u8, value: usize) {
    let mask = (1usize << prefix) - 1;
    if value < mask {
        return out.push(flags | value as u8);
    }
    out.push(flags | mask as u8);
    let mut rest = value - mask;
    while rest >= 0x80 {
        out.push(rest as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

fn pair_hash(name: &[u8], value: &[u8]) -> u32 {
    let mut hasher = FxHasher::default();
    hasher.write(name);
    hasher.write_u8(0xff);
    hasher.write(value);
    let hash = hasher.finish();
    (hash ^ hash >> 32) as u32
}

/// Whether a field value may be sent: no control byte but a tab. NUL, CR and LF would let a
/// value built from request bytes end the field for a peer that forwards it as HTTP/1.1.
fn sendable(value: &[u8]) -> bool {
    !value.iter().fold(false, |bad, &b| {
        bad | ((b < 0x20 && b != b'\t') | (b == 0x7f))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    type Fields = Vec<(String, String)>;

    fn decode(decoder: &mut Decoder, block: &[u8]) -> Result<Fields, Malformed> {
        let mut fields = Vec::new();
        decoder.decode(block, |name, value| {
            fields.push((
                String::from_utf8(name.to_vec()).unwrap(),
                String::from_utf8(value.to_vec()).unwrap(),
            ));
        })?;
        Ok(fields)
    }

    fn fields(pairs: &[(&str, &str)]) -> Fields {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn table(table: &Table) -> Fields {
        (0..table.entries.len())
            .map(|i| {
                let (n, v) = table.get(i).unwrap();
                (
                    String::from_utf8(n.to_vec()).unwrap(),
                    String::from_utf8(v.to_vec()).unwrap(),
                )
            })
            .collect()
    }

    const DATE_21: (&str, &str) = ("date", "Mon, 21 Oct 2013 20:13:21 GMT");
    const DATE_22: (&str, &str) = ("date", "Mon, 21 Oct 2013 20:13:22 GMT");
    const LOCATION: (&str, &str) = ("location", "https://www.example.com");
    const COOKIE: (&str, &str) = (
        "set-cookie",
        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
    );

    /// RFC 7541 C.3 and C.4: three requests on one connection, raw and Huffman-coded.
    #[test]
    fn rfc_request_examples() {
        let raw = [
            "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            "8286 84be 5808 6e6f 2d63 6163 6865",
            "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
        ];
        let coded = [
            "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
            "8286 84be 5886 a8eb 1064 9cbf",
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ];
        let authority = (":authority", "www.example.com");
        let expected = [
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                authority,
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                authority,
                ("cache-control", "no-cache"),
            ]),
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                authority,
                ("custom-key", "custom-value"),
            ]),
        ];
        for blocks in [raw, coded] {
            let mut decoder = Decoder::new();
            for (block, expected) in blocks.iter().zip(&expected) {
                assert_eq!(&decode(&mut decoder, &hex(block)).unwrap(), expected);
            }
            assert_eq!(
                table(&decoder.table),
                fields(&[
                    ("custom-key", "custom-value"),
                    ("cache-control", "no-cache"),
                    authority,
                ])
            );
            assert_eq!(decoder.table.size, 164);
        }
    }

    /// RFC 7541 C.5 and C.6: three responses with a 256-byte table, so entries are evicted.
    #[test]
    fn rfc_response_examples_evict() {
        let raw = [
            "4803 3330 3258 0770 7269 7661 7465 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 \
             2032 303a 3133 3a32 3120 474d 546e 1768 7474 7073 3a2f 2f77 7777 2e65 7861 6d70 \
             6c65 2e63 6f6d",
            "4803 3330 37c1 c0bf",
            "88c1 611d 4d6f 6e2c 2032 3120 4f63 7420 3230 3133 2032 303a 3133 3a32 3220 474d \
             54c0 5a04 677a 6970 7738 666f 6f3d 4153 444a 4b48 514b 425a 584f 5157 454f 5049 \
             5541 5851 5745 4f49 553b 206d 6178 2d61 6765 3d33 3630 303b 2076 6572 7369 6f6e \
             3d31",
        ];
        let coded = [
            "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
             2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            "4883 640e ffc1 c0bf",
            "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
             77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
             9587 3160 65c0 03ed 4ee5 b106 3d50 07",
        ];
        let private = ("cache-control", "private");
        let expected = [
            fields(&[(":status", "302"), private, DATE_21, LOCATION]),
            fields(&[(":status", "307"), private, DATE_21, LOCATION]),
            fields(&[
                (":status", "200"),
                private,
                DATE_22,
                LOCATION,
                ("content-encoding", "gzip"),
                COOKIE,
            ]),
        ];
        for blocks in [raw, coded] {
            let mut decoder = Decoder::new();
            decoder.table.set_max(256);
            for (block, expected) in blocks.iter().zip(&expected) {
                assert_eq!(&decode(&mut decoder, &hex(block)).unwrap(), expected);
            }
            assert_eq!(
                table(&decoder.table),
                fields(&[COOKIE, ("content-encoding", "gzip"), DATE_22])
            );
            assert_eq!(decoder.table.size, 215);
        }
    }

    /// RFC 7541 C.1: 10 in 5 bits, 1337 in 5 bits, 42 in 8 bits.
    #[test]
    fn rfc_integer_examples() {
        for (bytes, prefix, value) in [
            (&[0b0000_1010][..], 5, 10),
            (&[0b0001_1111, 0b1001_1010, 0b0000_1010][..], 5, 1337),
            (&[42][..], 8, 42),
        ] {
            let mut pos = 0;
            assert_eq!(integer(bytes, &mut pos, prefix), Ok(value));
            assert_eq!(pos, bytes.len());
            let mut out = Vec::new();
            put_integer(&mut out, prefix, 0, value);
            assert_eq!(out, bytes);
        }
    }

    #[test]
    fn integers_past_32_bits_and_truncated_ones_are_errors() {
        let mut pos = 0;
        assert_eq!(
            integer(&[0x7f, 0xff, 0xff, 0xff, 0xff, 0x7f], &mut pos, 7),
            Err(Malformed)
        );
        let mut pos = 0;
        assert_eq!(
            integer(&[0x7f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01], &mut pos, 7),
            Err(Malformed),
            "more continuation bytes than 32 bits need"
        );
        let mut pos = 0;
        assert_eq!(integer(&[0x7f, 0x80], &mut pos, 7), Err(Malformed));
    }

    #[test]
    fn blocks_that_break_the_format_are_errors() {
        let cases: &[(&[u8], &str)] = &[
            (&[0x80], "index 0"),
            (&[0xbe], "a dynamic index into an empty table"),
            (&[0x7e, 0x00], "a literal named by a missing entry"),
            (&[0x00, 0x05, b'a'], "a name longer than the block"),
            (&[0x00, 0x01, b'a', 0x7f], "a truncated value length"),
            (&[0x82, 0x20], "a size update after a field"),
            (&[0x3f, 0xe2, 0x1f], "a size update above the limit (4097)"),
            (&[0x00, 0x81, 0xff, 0x00], "a name with bad Huffman padding"),
        ];
        for (block, why) in cases {
            assert_eq!(decode(&mut Decoder::new(), block), Err(Malformed), "{why}");
        }
    }

    #[test]
    fn a_size_update_shrinks_and_regrows_the_table() {
        let mut decoder = Decoder::new();
        decode(&mut decoder, &[0x40, 0x01, b'a', 0x01, b'b']).unwrap();
        assert_eq!(decoder.table.entries.len(), 1);
        // 0x20 sets size 0, then 0x3f 0xe1 0x1f sets it back to 4096.
        assert_eq!(
            decode(&mut decoder, &[0x20, 0x3f, 0xe1, 0x1f, 0x82]),
            Ok(fields(&[(":method", "GET")]))
        );
        assert_eq!(decoder.table.entries.len(), 0);
        assert_eq!(decoder.table.max, 4096);
    }

    #[test]
    fn an_entry_larger_than_the_table_empties_it() {
        let mut decoder = Decoder::new();
        decoder.table.set_max(64);
        decode(&mut decoder, &[0x40, 0x01, b'a', 0x01, b'b']).unwrap();
        let mut block = vec![0x40, 0x01, b'n', 40];
        block.extend_from_slice(&[b'v'; 40]);
        let got = decode(&mut decoder, &block).unwrap();
        assert_eq!(got[0].1.len(), 40, "the field itself is delivered");
        assert_eq!(decoder.table.entries.len(), 0);
        assert_eq!(decoder.table.size, 0);
    }

    #[test]
    fn the_table_keeps_its_buffer_bounded_under_churn() {
        let mut decoder = Decoder::new();
        let mut last = Vec::new();
        for i in 0..10_000u32 {
            let value = format!("value-{i:0>60}");
            let mut block = vec![0x40, 0x03, b'k', b'e', b'y', value.len() as u8];
            block.extend_from_slice(value.as_bytes());
            last = decode(&mut decoder, &block).unwrap();
            assert!(decoder.table.size <= TABLE_SIZE);
            assert!(decoder.table.bytes.len() <= 2 * TABLE_SIZE);
            assert!(decoder.table.spare.len() <= 3 * TABLE_SIZE);
        }
        assert_eq!(decode(&mut decoder, &[0xbe]).unwrap(), last);
        let (name, value) = decoder.table.get(decoder.table.entries.len() - 1).unwrap();
        assert_eq!(name, b"key");
        assert!(value.starts_with(b"value-"), "old entries stay readable");
    }

    #[test]
    fn a_literal_named_by_a_table_entry_can_evict_that_entry() {
        let mut decoder = Decoder::new();
        decoder.table.set_max(80);
        decode(
            &mut decoder,
            &[0x40, 0x04, b'n', b'a', b'm', b'e', 0x01, b'1'],
        )
        .unwrap();
        // Named by the entry just added (index 62), with a value that evicts it.
        let mut block = vec![0x7e, 30];
        block.extend_from_slice(&[b'x'; 30]);
        assert_eq!(
            decode(&mut decoder, &block).unwrap(),
            fields(&[("name", &"x".repeat(30))])
        );
        assert_eq!(table(&decoder.table), fields(&[("name", &"x".repeat(30))]));
    }

    /// A literal with incremental indexing named by a table entry costs its value: the
    /// name's bytes are shared, however often the entry is repeated or evicted.
    #[test]
    fn entries_named_after_an_entry_share_its_name() {
        let mut decoder = Decoder::new();
        let name = "n".repeat(1300);
        let mut first = vec![0x40];
        put_integer(&mut first, 7, 0, name.len());
        first.extend_from_slice(name.as_bytes());
        first.push(0x00);
        assert_eq!(
            decode(&mut decoder, &first).unwrap(),
            fields(&[(&name, "")])
        );
        // 0x7e names the newest entry (index 62); each of these evicts the oldest once
        // three are in the table (3 x 1332 fits 4096, a fourth does not).
        for round in 0..2000u32 {
            let value = (round % 10).to_string();
            let block = [0x7e, 0x01, value.as_bytes()[0]];
            assert_eq!(
                decode(&mut decoder, &block).unwrap(),
                fields(&[(&name, &value)])
            );
            assert_eq!(decoder.table.entries.len(), 3.min(round as usize + 2));
            assert!(decoder.table.bytes.len() <= 2 * TABLE_SIZE);
        }
        // A literal without indexing reads the name where it is.
        assert_eq!(
            decode(&mut decoder, &[0x0f, 0x2f, 0x01, b'z']).unwrap(),
            fields(&[(&name, "z")])
        );
        // An entry that evicts every other, the one it is named after too.
        decoder.table.set_max(1400);
        assert_eq!(
            decode(&mut decoder, &[0x7e, 0x02, b'o', b'k']).unwrap(),
            fields(&[(&name, "ok")])
        );
        assert_eq!(table(&decoder.table), fields(&[(&name, "ok")]));
    }

    fn encode(encoder: &mut Encoder, status: u16, pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        encoder.begin(&mut out);
        encoder.status(&mut out, status);
        for (name, value) in pairs {
            if *name == "set-cookie" {
                encoder.sensitive(&mut out, name.as_bytes(), value.as_bytes());
            } else {
                encoder.field(&mut out, name.as_bytes(), value.as_bytes());
            }
        }
        out
    }

    #[test]
    fn a_repeated_field_becomes_one_byte_and_a_peer_decodes_every_block() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        let head = [
            ("content-type", "text/html; charset=utf-8"),
            ("etag", "\"abc123\""),
            ("x-frame-options", "DENY"),
            ("content-length", "1024"),
            DATE_21,
        ];
        let mut expected = fields(&[(":status", "200")]);
        expected.extend(fields(&head));
        let sizes: Vec<usize> = (0..4)
            .map(|_| {
                let block = encode(&mut encoder, 200, &head);
                assert_eq!(decode(&mut decoder, &block).unwrap(), expected);
                block.len()
            })
            .collect();
        assert!(sizes[0] > 80, "literals first: {sizes:?}");
        assert!(
            sizes[1] > 80,
            "literals again, entering the table: {sizes:?}"
        );
        assert_eq!(sizes[2], 1 + head.len(), "then one byte per field");
        assert_eq!(sizes[3], sizes[2]);
        assert_eq!(table(&encoder.table), table(&decoder.table));
    }

    #[test]
    fn fields_that_never_repeat_stay_out_of_the_table() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        for i in 0..200 {
            let length = i.to_string();
            let block = encode(
                &mut encoder,
                404,
                &[("content-length", &length), COOKIE, COOKIE],
            );
            let got = decode(&mut decoder, &block).unwrap();
            assert_eq!(got[1], ("content-length".to_owned(), length));
            assert_eq!(got.len(), 4);
        }
        assert!(encoder.table.entries.is_empty());
        assert!(decoder.table.entries.is_empty());
    }

    #[test]
    fn statuses_use_the_static_table_or_a_literal() {
        let mut encoder = Encoder::new();
        assert_eq!(encode(&mut encoder, 200, &[]), [0x88]);
        assert_eq!(encode(&mut encoder, 404, &[]), [0x8d]);
        assert_eq!(
            encode(&mut encoder, 503, &[]),
            [0x08, 0x03, b'5', b'0', b'3']
        );
        let mut decoder = Decoder::new();
        for status in [100, 301, 418, 999] {
            let block = encode(&mut encoder, status, &[]);
            assert_eq!(
                decode(&mut decoder, &block).unwrap(),
                fields(&[(":status", &status.to_string())])
            );
        }
    }

    #[test]
    fn a_value_with_a_line_break_or_nul_is_not_sent() {
        let mut encoder = Encoder::new();
        for bad in ["a\r\nx: y", "a\nb", "a\0b", "a\x7fb"] {
            assert_eq!(
                encode(&mut encoder, 200, &[("x-a", bad)]),
                [0x88],
                "{bad:?}"
            );
            let mut out = Vec::new();
            encoder.sensitive(&mut out, b"set-cookie", bad.as_bytes());
            assert!(out.is_empty(), "{bad:?}");
        }
        let block = encode(&mut encoder, 200, &[("x-a", " tab\there, caf\u{e9}\t ")]);
        assert_eq!(
            decode(&mut Decoder::new(), &block).unwrap()[1].1,
            "tab\there, caf\u{e9}",
            "whitespace around a value is cut"
        );
    }

    #[test]
    fn a_smaller_peer_limit_is_announced_and_respected() {
        let mut encoder = Encoder::new();
        let mut decoder = Decoder::new();
        let head = [("content-type", "text/css"), ("server", "x")];
        for _ in 0..3 {
            let block = encode(&mut encoder, 200, &head);
            decode(&mut decoder, &block).unwrap();
        }
        assert_eq!(encoder.table.entries.len(), 2);

        encoder.set_limit(0);
        encoder.set_limit(100);
        let block = encode(&mut encoder, 200, &head);
        assert_eq!(&block[..2], [0x20, 0x3f], "size 0, then size 100");
        assert_eq!(
            decode(&mut decoder, &block).unwrap(),
            fields(&[(":status", "200"), head[0], head[1]])
        );
        assert_eq!(decoder.table.max, 100);
        for _ in 0..3 {
            let block = encode(&mut encoder, 200, &head);
            decode(&mut decoder, &block).unwrap();
            assert!(encoder.table.size <= 100);
        }
        assert_eq!(table(&encoder.table), table(&decoder.table));

        encoder.set_limit(1 << 20);
        assert_eq!(encoder.table.max, TABLE_SIZE, "never past this side's cap");
    }
}
