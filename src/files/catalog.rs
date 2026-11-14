//! The per-core file catalog: what the file server and the `file`/`tryFiles` matchers know
//! about paths. One per core (no sharing, no locks). A new plan drops the mutable entries and
//! keeps the immutable ones: a store path's facts do not depend on the config.
//!
//! Immutability is the lever: a path under /nix/store never changes while it exists, and a
//! NixOS host serves its sites from store paths. Entries for such paths never expire, missing
//! ones included, so a warm store request does no file syscall. Entries for other roots are
//! revalidated after 1s (stat), like nginx's open_file_cache.
//!
//! Bounded: at most `MAX_ENTRIES` entries and `MAX_SMALL_BYTES` of cached file contents per
//! core, evicted CLOCK-style (an entry used since the last sweep survives it). Small files
//! (<= 64 KiB) and their sidecar variants are held as `Bytes`, so a warm small-file response is
//! a refcount bump (core-local, uncontended); larger ones keep an open descriptor.

use super::negotiate::{content_type, entity_tag, http_date};
use crate::encode::Encoding;
use bytes::Bytes;
use rustc_hash::FxHashMap;
use std::cell::Cell;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::rc::Rc;
use std::time::{Duration, Instant};

pub(crate) const MAX_ENTRIES: usize = 16 * 1024;
pub(crate) const MAX_SMALL_BYTES: usize = 32 * 1024 * 1024;
/// Files up to this size are read into memory; larger ones are sent from their descriptor.
pub(crate) const SMALL_FILE: u64 = 64 * 1024;
/// An ETag sidecar longer than this is not an ETag.
const MAX_ETAG: u64 = 256;

/// What a path is, as the file server sees it.
#[derive(Clone, Debug)]
pub(crate) enum Node {
    /// Absent, unreadable, or not a regular file or directory.
    Missing,
    Dir,
    File(Rc<FileEntry>),
}

/// A regular file with everything a response needs, computed once.
#[derive(Debug)]
pub(crate) struct FileEntry {
    pub identity: Content,
    /// Indexed by `Encoding as usize`: the sidecars found on disk, among those looked for.
    pub variants: [Option<Content>; 3],
    /// A valid entity-tag: the ETag sidecar's content when there is one, else derived from the
    /// store path and size (store files) or the mtime and size.
    pub etag: Box<[u8]>,
    /// `None` when the mtime is <= 1 (every store path), where a date would lie.
    pub last_modified: Option<[u8; 29]>,
    pub mtime: i64,
    pub content_type: &'static str,
    looked_for: LookedFor,
}

/// The bytes of one representation of a file.
#[derive(Debug)]
pub(crate) struct Content {
    pub len: u64,
    pub data: Data,
}

#[derive(Debug)]
pub(crate) enum Data {
    Small(Bytes),
    /// Shared with in-flight responses, so eviction never closes a descriptor being sent.
    Open(Rc<File>),
}

/// What the file server asks of a file beyond its existence: which precompressed sidecars and
/// which ETag sidecar to look for.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Want<'a> {
    /// Bit `Encoding as usize` set for each sidecar encoding.
    encodings: u8,
    etag_ext: Option<&'a [u8]>,
}

impl<'a> Want<'a> {
    pub fn new(encodings: &[Encoding], etag_ext: Option<&'a [u8]>) -> Want<'a> {
        Want {
            encodings: encodings.iter().fold(0, |m, &e| m | 1 << e as u8),
            etag_ext,
        }
    }
}

/// The [`Want`] an entry was built for.
#[derive(Debug)]
struct LookedFor {
    encodings: u8,
    etag_ext: Option<Box<[u8]>>,
}

impl LookedFor {
    fn covers(&self, want: &Want<'_>) -> bool {
        want.encodings & !self.encodings == 0 && self.etag_ext.as_deref() == want.etag_ext
    }
}

/// Size and lifetime limits; [`Catalog::default`] uses the module constants.
#[derive(Debug)]
pub(crate) struct Limits {
    pub entries: usize,
    pub small_bytes: usize,
    pub small_file: u64,
    pub revalidate: Duration,
    /// Paths under this prefix are immutable.
    pub store: Box<[u8]>,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            entries: MAX_ENTRIES,
            small_bytes: MAX_SMALL_BYTES,
            small_file: SMALL_FILE,
            revalidate: Duration::from_secs(1),
            store: Box::from(&b"/nix/store/"[..]),
        }
    }
}

#[derive(Debug)]
struct Slot {
    node: Node,
    /// `None` for immutable paths: never revalidated.
    checked: Option<Instant>,
    referenced: Cell<bool>,
}

impl Slot {
    fn small_bytes(&self) -> usize {
        match &self.node {
            Node::File(file) => file.small_bytes(),
            _ => 0,
        }
    }
}

impl FileEntry {
    fn small_bytes(&self) -> usize {
        std::iter::once(&self.identity)
            .chain(self.variants.iter().flatten())
            .map(|c| match c.data {
                Data::Small(ref b) => b.len(),
                Data::Open(_) => 0,
            })
            .sum()
    }
    /// The representation for `encoding` (`None`: identity), if it exists.
    pub fn content(&self, encoding: Option<Encoding>) -> Option<&Content> {
        match encoding {
            None => Some(&self.identity),
            Some(e) => self.variants[e as usize].as_ref(),
        }
    }
}

#[derive(Default)]
pub(crate) struct Catalog {
    map: FxHashMap<Box<[u8]>, Slot>,
    small_bytes: usize,
    /// Scratch for the full path of the current lookup, so a warm lookup allocates nothing.
    key: Vec<u8>,
    limits: Limits,
}

impl Catalog {
    #[cfg(test)]
    pub fn with_limits(limits: Limits) -> Catalog {
        Catalog {
            limits,
            ..Catalog::default()
        }
    }

    /// Existence check for `file` matchers and `tryFiles`: `root` + `rel` names a regular file,
    /// or a directory when `rel` ends in `/`. A `rel` with a `..` segment never exists, so a
    /// candidate built from config literals cannot leave the root either.
    pub fn probe(&mut self, root: &[u8], rel: &[u8]) -> bool {
        match self.node(root, &[rel], None) {
            Node::Dir => rel.ends_with(b"/"),
            Node::File(_) => !rel.ends_with(b"/"),
            Node::Missing => false,
        }
    }

    /// Full entry for the file server (opens and fills on a miss). `rel` is joined with `/`
    /// (a directory and an index name). The entry has every sidecar `want` asks for.
    pub fn lookup(&mut self, root: &[u8], rel: &[&[u8]], want: &Want<'_>) -> Node {
        self.node(root, rel, Some(want))
    }

    /// On a new plan: keep immutable (store) entries, drop the rest.
    pub fn retain_immutable(&mut self) {
        let mut freed = 0;
        self.map.retain(|_, slot| {
            let keep = slot.checked.is_none();
            if !keep {
                freed += slot.small_bytes();
            }
            keep
        });
        self.small_bytes -= freed;
    }

    fn node(&mut self, root: &[u8], rel: &[&[u8]], want: Option<&Want<'_>>) -> Node {
        if !self.set_key(root, rel) {
            return Node::Missing;
        }
        let immutable = self.key.starts_with(&self.limits.store);
        if let Some(slot) = self.map.get(self.key.as_slice()) {
            let fresh = slot
                .checked
                .is_none_or(|at| at.elapsed() < self.limits.revalidate);
            let complete = match (&slot.node, want) {
                (Node::File(file), Some(want)) => file.looked_for.covers(want),
                _ => true,
            };
            if fresh && complete {
                slot.referenced.set(true);
                return slot.node.clone();
            }
        }
        let want = match (self.map.get(self.key.as_slice()), want) {
            (
                Some(Slot {
                    node: Node::File(old),
                    ..
                }),
                Some(want),
            ) => Want {
                encodings: old.looked_for.encodings | want.encodings,
                etag_ext: want.etag_ext,
            },
            (_, want) => want.copied().unwrap_or_default(),
        };
        let node = load(&self.key, immutable, &want, self.limits.small_file);
        let slot = Slot {
            node: node.clone(),
            checked: (!immutable).then(Instant::now),
            referenced: Cell::new(true),
        };
        self.insert(slot);
        node
    }

    /// Builds `root/rel[0]/rel[1]..` in `self.key`, with repeated and trailing slashes removed.
    /// `false` when a part has a `..` segment.
    fn set_key(&mut self, root: &[u8], rel: &[&[u8]]) -> bool {
        self.key.clear();
        self.key.extend_from_slice(root);
        while self.key.len() > 1 && self.key.ends_with(b"/") {
            self.key.pop();
        }
        for part in rel {
            for segment in part.split(|&b| b == b'/').filter(|s| !s.is_empty()) {
                if segment == b".." {
                    return false;
                }
                if !self.key.ends_with(b"/") {
                    self.key.push(b'/');
                }
                self.key.extend_from_slice(segment);
            }
        }
        true
    }

    fn insert(&mut self, slot: Slot) {
        let added = slot.small_bytes();
        if let Some(old) = self.map.remove(self.key.as_slice()) {
            self.small_bytes -= old.small_bytes();
        }
        if self.map.len() >= self.limits.entries
            || self.small_bytes + added > self.limits.small_bytes
        {
            self.evict(added);
        }
        self.small_bytes += added;
        self.map.insert(Box::from(self.key.as_slice()), slot);
    }

    /// Frees room for one entry holding `incoming` cached bytes, and an eighth of the entry
    /// limit beyond it so sweeps stay rare: first entries unused since the last sweep (clearing
    /// the mark of the others), then any until the limits hold.
    fn evict(&mut self, incoming: usize) {
        let max_entries = self.limits.entries - (self.limits.entries / 8).max(1);
        let max_bytes = self.limits.small_bytes.saturating_sub(incoming);
        let mut entries = self.map.len();
        let mut bytes = self.small_bytes;
        for second_chance in [true, false] {
            self.map.retain(|_, slot| {
                if entries <= max_entries && bytes <= max_bytes {
                    return true;
                }
                if second_chance && slot.referenced.replace(false) {
                    return true;
                }
                entries -= 1;
                bytes -= slot.small_bytes();
                false
            });
        }
        self.small_bytes = bytes;
    }
}

fn load(path: &[u8], immutable: bool, want: &Want<'_>, small_file: u64) -> Node {
    let Some((content, meta)) = open(path, small_file) else {
        return match std::fs::metadata(OsStr::from_bytes(path)) {
            Ok(meta) if meta.is_dir() => Node::Dir,
            _ => Node::Missing,
        };
    };
    let mut sidecar = Vec::with_capacity(path.len() + 8);
    let mut sidecar_path = |ext: &[u8]| {
        sidecar.clear();
        sidecar.extend_from_slice(path);
        sidecar.extend_from_slice(ext);
        OsStr::from_bytes(&sidecar).to_owned()
    };
    let variants = [Encoding::Br, Encoding::Zstd, Encoding::Gzip].map(|e| {
        (want.encodings & 1 << e as u8 != 0)
            .then(|| open(sidecar_path(e.sidecar()).as_bytes(), small_file))
            .flatten()
            .map(|(content, _)| content)
    });
    let etag = want
        .etag_ext
        .and_then(|ext| etag_sidecar(sidecar_path(ext).as_bytes()))
        .unwrap_or_else(|| derived_etag(path, &meta, immutable));
    let mtime = meta.mtime();
    Node::File(Rc::new(FileEntry {
        identity: content,
        variants,
        etag,
        last_modified: (mtime > 1).then(|| http_date(mtime)),
        mtime,
        content_type: content_type(path),
        looked_for: LookedFor {
            encodings: want.encodings,
            etag_ext: want.etag_ext.map(Box::from),
        },
    }))
}

/// Opens a regular file: its bytes when small, its descriptor otherwise. `None` for anything
/// that is not a readable regular file.
fn open(path: &[u8], small_file: u64) -> Option<(Content, Metadata)> {
    let mut file = File::open(OsStr::from_bytes(path)).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() {
        return None;
    }
    let content = if meta.len() <= small_file {
        let mut bytes = Vec::with_capacity(meta.len() as usize);
        file.read_to_end(&mut bytes).ok()?;
        Content {
            len: bytes.len() as u64,
            data: Data::Small(Bytes::from(bytes)),
        }
    } else {
        Content {
            len: meta.len(),
            data: Data::Open(Rc::new(file)),
        }
    };
    Some((content, meta))
}

/// The content of an ETag sidecar, trimmed, when it is one valid entity-tag.
fn etag_sidecar(path: &[u8]) -> Option<Box<[u8]>> {
    let mut bytes = Vec::new();
    File::open(OsStr::from_bytes(path))
        .ok()?
        .take(MAX_ETAG + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    let tag = bytes.trim_ascii();
    (bytes.len() as u64 <= MAX_ETAG && entity_tag(tag).is_some()).then(|| Box::from(tag))
}

/// A store path names its content, so the path and size identify the bytes (store mtimes are
/// all 1). Elsewhere the mtime and size do. FNV-1a keeps the tag identical on every core and
/// across restarts.
fn derived_etag(path: &[u8], meta: &Metadata, immutable: bool) -> Box<[u8]> {
    let tag = if immutable {
        let hash = path.iter().fold(0xcbf2_9ce4_8422_2325_u64, |h, &b| {
            (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
        });
        format!("\"{hash:016x}-{:x}\"", meta.len())
    } else {
        format!(
            "\"{:x}.{:x}-{:x}\"",
            meta.mtime(),
            meta.mtime_nsec(),
            meta.len()
        )
    };
    tag.into_bytes().into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("blog")).unwrap();
        std::fs::write(dir.path().join("blog/index.html"), "x").unwrap();
        let root = dir.path().as_os_str().as_encoded_bytes();
        let mut catalog = Catalog::default();
        assert!(catalog.probe(root, b"/blog/index.html"));
        assert!(catalog.probe(root, b"blog/index.html"));
        assert!(!catalog.probe(root, b"/blog"), "a directory is not a file");
        assert!(catalog.probe(root, b"/blog/"));
        assert!(!catalog.probe(root, b"/blog/index.html/"));
        assert!(!catalog.probe(root, b"/missing"));
        assert!(!catalog.probe(root, b"/blog/../blog/index.html"));
    }
}
