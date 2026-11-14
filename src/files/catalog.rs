//! The per-core file catalog: what the file server and the `file`/`tryFiles` matchers know
//! about paths. One per core (no sharing, no locks). A new plan drops the mutable entries and
//! keeps the immutable ones: a store path's facts do not depend on the config.
//!
//! Immutability is the lever: a path under /nix/store never changes while it exists, and a
//! NixOS host serves its sites from store paths. Entries for such paths never expire.
//! Entries for other roots are revalidated after 1s (stat), like nginx's open_file_cache.
//!
//! Bounded: at most `MAX_ENTRIES` entries and `MAX_SMALL_BYTES` of cached file contents per
//! core, evicted CLOCK-style. Small files (<= 64 KiB) and their sidecar variants are held as
//! `Bytes`, so a warm small-file response is a refcount bump (core-local, uncontended).

use crate::encode::Encoding;
use bytes::Bytes;
use std::collections::HashMap;
use std::fs::File;
use std::rc::Rc;
use std::time::Instant;

pub(crate) const MAX_ENTRIES: usize = 16 * 1024;
pub(crate) const MAX_SMALL_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug)]
pub(crate) enum Kind {
    File,
    Dir,
    Missing,
}

#[derive(Debug)]
pub(crate) struct Variant {
    pub encoding: Encoding,
    pub len: u64,
    pub fd: Option<File>,
    pub small: Option<Bytes>,
}

#[derive(Debug)]
pub(crate) struct Entry {
    pub kind: Kind,
    pub len: u64,
    pub mtime: i64,
    pub immutable: bool,
    pub checked: Instant,
    pub etag: Option<Box<[u8]>>,
    pub content_type: &'static str,
    pub fd: Option<File>,
    pub small: Option<Bytes>,
    /// Indexed by `Encoding as usize`; sidecars found on disk.
    pub variants: [Option<Variant>; 3],
    /// Dynamically compressed copies made for `encode`, cached for immutable entries.
    pub encoded: [Option<Bytes>; 3],
}

#[derive(Default)]
pub(crate) struct Catalog {
    map: HashMap<Box<[u8]>, Rc<Entry>>,
    small_bytes: usize,
}

impl Catalog {
    /// Existence check for `file` matchers and `tryFiles`: `root` + `rel` names a regular file,
    /// or a directory when `rel` ends in `/`. A `rel` with a `..` segment never exists, so a
    /// candidate built from config literals cannot leave the root either.
    pub fn probe(&mut self, root: &[u8], rel: &[u8]) -> bool {
        use std::os::unix::ffi::OsStrExt;
        if rel.split(|&b| b == b'/').any(|segment| segment == b"..") {
            return false;
        }
        let mut full = Vec::with_capacity(root.len() + rel.len() + 1);
        full.extend_from_slice(root);
        if !root.ends_with(b"/") && !rel.starts_with(b"/") {
            full.push(b'/');
        }
        full.extend_from_slice(rel);
        match std::fs::metadata(std::ffi::OsStr::from_bytes(&full)) {
            Ok(meta) if rel.ends_with(b"/") => meta.is_dir(),
            Ok(meta) => meta.is_file(),
            Err(_) => false,
        }
    }
    /// Full entry for the file server (opens and fills on a miss).
    pub fn lookup(
        &mut self,
        root: &[u8],
        rel: &[u8],
        sidecars: &[Encoding],
        etag_ext: Option<&[u8]>,
    ) -> Rc<Entry> {
        todo!()
    }
    /// On a new plan: keep immutable (store) entries, drop the rest.
    pub fn retain_immutable(&mut self) {
        todo!()
    }
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
