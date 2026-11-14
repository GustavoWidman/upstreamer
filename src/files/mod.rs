//! Static files. Synchronous: everything it needs comes from the per-core [`Catalog`], which
//! for immutable roots (under /nix/store) holds metadata, ETags, sidecar variants, open file
//! descriptors and the bytes of small files, so a warm request does no file syscall at all
//! except sendfile/pread for large bodies.
//!
//! Behaviour:
//! - path = root + clean path; a directory serves its first `index` file; no directory
//!   listings, no canonical-URI redirects.
//! - The file server never serves its own sidecars (`<f>.br`, `.zst`, `.gz` for the listed
//!   encodings, `<f><etagSidecar>`): they 404 when requested directly.
//! - Encoding: the client's Accept-Encoding (q-values honoured) intersected with
//!   `precompressed` in config order, if the sidecar exists; else, if the request has an
//!   `encode` set and the type is compressible, dynamic compression (cached per core for
//!   immutable files). `Vary: Accept-Encoding` whenever a variant could differ.
//! - ETag: the sidecar's content if `etagSidecar` is set and the sidecar exists (identical for
//!   every encoding, as Caddy does), else for /nix/store files a hash of the store path and
//!   size (store mtimes are all 1), else mtime+size. Variant-specific suffixes are not added.
//! - No Last-Modified for files whose mtime is <= 1 (every store path).
//! - If-None-Match (weak comparison) -> 304; If-Modified-Since only without If-None-Match.
//! - Range: one `bytes=` range -> 206 on the identity representation (a ranged request never
//!   gets a compressed variant), If-Range honoured; multi-range -> 200 full.
//! - In an error route: served with the error's status, conditionals and ranges ignored.

pub(crate) mod catalog;
pub(crate) mod negotiate;

use crate::exchange::{ASpan, Exchange};
use crate::msg::Status;
use crate::pipeline::Response;
use crate::plan::FilesPlan;
use catalog::{Catalog, Entry};
use std::ops::Range;
use std::rc::Rc;

/// A file body to send: an open descriptor shared with the catalog, and the byte range.
pub(crate) struct FileBody {
    pub entry: Rc<Entry>,
    pub range: Range<u64>,
}

/// Answers from the file system. `Err(404)` (or 416, 400) goes through the error routes.
/// `root` is the expanded root template, in the exchange's arena.
pub(crate) fn serve(
    plan: &FilesPlan,
    root: ASpan,
    ex: &mut Exchange,
    catalog: &mut Catalog,
) -> Result<Response, Status> {
    todo!()
}
