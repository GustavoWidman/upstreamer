//! HTTP/2 frame layout (RFC 9113 sections 4 and 6): the 9-byte header, the payload pieces a
//! server reads, and the frames it writes.

/// Octets of a frame header.
pub(super) const HEADER_LEN: usize = 9;
/// The largest payload accepted and sent: the protocol's initial SETTINGS_MAX_FRAME_SIZE,
/// which this server never raises and every peer accepts.
pub(super) const MAX_FRAME: usize = 16_384;
/// What a client sends first (RFC 9113 3.4).
pub(super) const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The largest stream identifier.
pub(super) const MAX_STREAM_ID: u32 = (1 << 31) - 1;

pub(super) const DATA: u8 = 0;
pub(super) const HEADERS: u8 = 1;
pub(super) const PRIORITY: u8 = 2;
pub(super) const RST_STREAM: u8 = 3;
pub(super) const SETTINGS: u8 = 4;
pub(super) const PUSH_PROMISE: u8 = 5;
pub(super) const PING: u8 = 6;
pub(super) const GOAWAY: u8 = 7;
pub(super) const WINDOW_UPDATE: u8 = 8;
pub(super) const CONTINUATION: u8 = 9;

pub(super) const END_STREAM: u8 = 0x1;
pub(super) const ACK: u8 = 0x1;
pub(super) const END_HEADERS: u8 = 0x4;
pub(super) const PADDED: u8 = 0x8;
pub(super) const PRIORITY_FLAG: u8 = 0x20;

pub(super) const SETTINGS_HEADER_TABLE_SIZE: u16 = 1;
pub(super) const SETTINGS_ENABLE_PUSH: u16 = 2;
pub(super) const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 3;
pub(super) const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 4;
pub(super) const SETTINGS_MAX_FRAME_SIZE: u16 = 5;
pub(super) const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 6;
/// RFC 9218 2.1: this endpoint ignores RFC 7540 stream priorities.
pub(super) const SETTINGS_NO_RFC7540_PRIORITIES: u16 = 9;

/// Error codes (RFC 9113 section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub(super) enum Reason {
    NoError = 0,
    Protocol = 1,
    Internal = 2,
    FlowControl = 3,
    StreamClosed = 5,
    FrameSize = 6,
    RefusedStream = 7,
    Cancel = 8,
    Compression = 9,
    EnhanceYourCalm = 11,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Head {
    /// Octets of payload after the header.
    pub len: usize,
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
}

impl Head {
    /// The header at the front of `bytes`, once all 9 octets are there.
    pub fn parse(bytes: &[u8]) -> Option<Head> {
        let b: &[u8; HEADER_LEN] = bytes.first_chunk()?;
        Some(Head {
            len: usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2]),
            kind: b[3],
            flags: b[4],
            stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]) & MAX_STREAM_ID,
        })
    }

    pub fn has(self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

fn head_bytes(len: usize, kind: u8, flags: u8, stream: u32) -> [u8; HEADER_LEN] {
    debug_assert!(len <= MAX_FRAME);
    let id = stream.to_be_bytes();
    [
        (len >> 16) as u8,
        (len >> 8) as u8,
        len as u8,
        kind,
        flags,
        id[0],
        id[1],
        id[2],
        id[3],
    ]
}

pub(super) fn put_head(out: &mut Vec<u8>, len: usize, kind: u8, flags: u8, stream: u32) {
    out.extend_from_slice(&head_bytes(len, kind, flags, stream));
}

/// The range of a DATA or HEADERS payload left once its padding is taken off (RFC 9113 6.1):
/// with PADDED, the first octet counts the padding at the end. Padding that does not fit the
/// payload is a connection error.
pub(super) fn unpad(head: Head, payload: &[u8]) -> Result<(usize, usize), Reason> {
    if !head.has(PADDED) {
        return Ok((0, payload.len()));
    }
    let padding = usize::from(*payload.first().ok_or(Reason::Protocol)?);
    if padding >= payload.len() {
        return Err(Reason::Protocol);
    }
    Ok((1, payload.len() - padding))
}

pub(super) fn u32_at(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

pub(super) fn put_settings(out: &mut Vec<u8>, settings: &[(u16, u32)]) {
    put_head(out, settings.len() * 6, SETTINGS, 0, 0);
    for &(id, value) in settings {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(super) fn put_settings_ack(out: &mut Vec<u8>) {
    put_head(out, 0, SETTINGS, ACK, 0);
}

pub(super) fn put_ping(out: &mut Vec<u8>, flags: u8, opaque: &[u8; 8]) {
    put_head(out, 8, PING, flags, 0);
    out.extend_from_slice(opaque);
}

pub(super) fn put_rst_stream(out: &mut Vec<u8>, stream: u32, reason: Reason) {
    put_head(out, 4, RST_STREAM, 0, stream);
    out.extend_from_slice(&(reason as u32).to_be_bytes());
}

pub(super) fn put_window_update(out: &mut Vec<u8>, stream: u32, increment: u32) {
    put_head(out, 4, WINDOW_UPDATE, 0, stream);
    out.extend_from_slice(&increment.to_be_bytes());
}

pub(super) fn put_goaway(out: &mut Vec<u8>, last_stream: u32, reason: Reason) {
    put_head(out, 8, GOAWAY, 0, 0);
    out.extend_from_slice(&last_stream.to_be_bytes());
    out.extend_from_slice(&(reason as u32).to_be_bytes());
}

/// Turns the field block at `out[start + HEADER_LEN..]`, written after 9 reserved octets,
/// into a HEADERS frame, followed by CONTINUATION frames when the block exceeds one frame.
pub(super) fn finish_headers(out: &mut Vec<u8>, start: usize, stream: u32, end_stream: bool) {
    let block = out.len() - start - HEADER_LEN;
    let flags = if end_stream { END_STREAM } else { 0 };
    if block <= MAX_FRAME {
        let head = head_bytes(block, HEADERS, flags | END_HEADERS, stream);
        out[start..start + HEADER_LEN].copy_from_slice(&head);
        return;
    }
    let rest = out.split_off(start + HEADER_LEN);
    out.truncate(start);
    let mut pieces = rest.chunks(MAX_FRAME).peekable();
    let mut kind = HEADERS;
    let mut flags = flags;
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_none() {
            flags |= END_HEADERS;
        }
        put_head(out, piece.len(), kind, flags, stream);
        out.extend_from_slice(piece);
        kind = CONTINUATION;
        flags = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_round_trips_and_drops_the_reserved_bit() {
        let mut out = Vec::new();
        put_head(
            &mut out,
            0x01_02_03 & 0x3fff,
            HEADERS,
            END_HEADERS | END_STREAM,
            0x7fff_fff1,
        );
        let head = Head::parse(&out).unwrap();
        assert_eq!(
            head,
            Head {
                len: 0x0203,
                kind: HEADERS,
                flags: 0x5,
                stream: 0x7fff_fff1
            }
        );
        out[5] |= 0x80;
        assert_eq!(Head::parse(&out).unwrap().stream, 0x7fff_fff1);
        assert_eq!(Head::parse(&out[..8]), None);
    }

    #[test]
    fn padding_is_cut_and_must_fit() {
        let padded = Head {
            len: 4,
            kind: DATA,
            flags: PADDED,
            stream: 1,
        };
        assert_eq!(unpad(padded, &[2, b'a', 0, 0]), Ok((1, 2)));
        assert_eq!(unpad(padded, &[3, 0, 0, 0]), Ok((1, 1)), "all padding");
        assert_eq!(unpad(padded, &[4, 0, 0, 0]), Err(Reason::Protocol));
        assert_eq!(unpad(padded, &[]), Err(Reason::Protocol));
        let plain = Head { flags: 0, ..padded };
        assert_eq!(unpad(plain, &[9, 9]), Ok((0, 2)));
    }

    /// RFC 9113 6.5, 6.7, 6.4, 6.9, 6.8: the wire bytes of the frames a server writes.
    #[test]
    fn control_frames_match_their_layouts() {
        let mut out = Vec::new();
        put_settings(&mut out, &[(3, 128), (4, 1 << 20)]);
        assert_eq!(
            out,
            [
                0, 0, 12, 4, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 128, 0, 4, 0, 16, 0, 0
            ]
        );
        out.clear();
        put_settings_ack(&mut out);
        assert_eq!(out, [0, 0, 0, 4, 1, 0, 0, 0, 0]);
        out.clear();
        put_ping(&mut out, ACK, b"12345678");
        assert_eq!(out, b"\0\0\x08\x06\x01\0\0\0\x0012345678");
        out.clear();
        put_rst_stream(&mut out, 5, Reason::Cancel);
        assert_eq!(out, [0, 0, 4, 3, 0, 0, 0, 0, 5, 0, 0, 0, 8]);
        out.clear();
        put_window_update(&mut out, 0, 65_536);
        assert_eq!(out, [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 1, 0, 0]);
        out.clear();
        put_goaway(&mut out, 7, Reason::EnhanceYourCalm);
        assert_eq!(out, [0, 0, 8, 7, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 11]);
    }

    fn frames(mut bytes: &[u8]) -> Vec<(Head, Vec<u8>)> {
        let mut frames = Vec::new();
        while let Some(head) = Head::parse(bytes) {
            frames.push((head, bytes[HEADER_LEN..HEADER_LEN + head.len].to_vec()));
            bytes = &bytes[HEADER_LEN + head.len..];
        }
        assert!(bytes.is_empty());
        frames
    }

    #[test]
    fn a_block_fills_one_headers_frame_or_continues() {
        let mut out = b"before".to_vec();
        let start = out.len();
        out.extend_from_slice(&[0; HEADER_LEN]);
        out.extend_from_slice(b"block");
        finish_headers(&mut out, start, 3, true);
        assert_eq!(&out[..6], b"before");
        let got = frames(&out[6..]);
        assert_eq!(got.len(), 1);
        assert_eq!(
            (got[0].0.kind, got[0].0.flags),
            (HEADERS, END_HEADERS | END_STREAM)
        );
        assert_eq!((got[0].0.stream, &got[0].1[..]), (3, &b"block"[..]));

        let block: Vec<u8> = (0..2 * MAX_FRAME + 10).map(|i| i as u8).collect();
        let mut out = vec![0; HEADER_LEN];
        out.extend_from_slice(&block);
        finish_headers(&mut out, 0, 9, false);
        let got = frames(&out);
        let kinds: Vec<_> = got.iter().map(|(h, _)| (h.kind, h.flags, h.len)).collect();
        assert_eq!(
            kinds,
            [
                (HEADERS, 0, MAX_FRAME),
                (CONTINUATION, 0, MAX_FRAME),
                (CONTINUATION, END_HEADERS, 10)
            ]
        );
        let joined: Vec<u8> = got.iter().flat_map(|(_, p)| p.clone()).collect();
        assert_eq!(joined, block);
        assert!(got.iter().all(|(h, _)| h.stream == 9));
    }
}
