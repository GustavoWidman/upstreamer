//! Dynamic compression (`encode` steps). Decided once per response, in `pipeline::finalize`'s
//! caller, from the request's `encode` set and the response head:
//! skip when the client accepts none of the set, the response already has Content-Encoding,
//! has `Cache-Control: no-transform`, is not compressible, is shorter than 512 bytes (when the
//! length is known), is a 204/304/HEAD/206, or is `text/event-stream`.
//!
//! Streaming: each input chunk is compressed and flushed as it comes (zstd `flush`, gzip sync
//! flush), so a slow stream is never held back. Immutable files are compressed once per core
//! and cached in the catalog instead.

use crate::body::Body;
use crate::config::EncodingName;
use crate::msg::{RequestHead, ResponseHead};
use bytes::Bytes;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    Br = 0,
    Zstd = 1,
    Gzip = 2,
}

impl From<EncodingName> for Encoding {
    fn from(name: EncodingName) -> Encoding {
        match name {
            EncodingName::Br => Encoding::Br,
            EncodingName::Zstd => Encoding::Zstd,
            EncodingName::Gzip => Encoding::Gzip,
        }
    }
}

impl Encoding {
    pub fn token(self) -> &'static [u8] {
        match self {
            Encoding::Br => b"br",
            Encoding::Zstd => b"zstd",
            Encoding::Gzip => b"gzip",
        }
    }
    /// Sidecar file extension for precompressed files.
    pub fn sidecar(self) -> &'static [u8] {
        match self {
            Encoding::Br => b".br",
            Encoding::Zstd => b".zst",
            Encoding::Gzip => b".gz",
        }
    }
}

/// Encodings allowed for dynamic compression, in preference order (at most 3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct EncodingSet {
    order: [Option<Encoding>; 3],
}

impl EncodingSet {
    /// The set in the given preference order; a repeated encoding keeps its first position.
    pub fn new(list: impl IntoIterator<Item = Encoding>) -> EncodingSet {
        let mut set = EncodingSet::default();
        let mut n = 0;
        for e in list {
            if n < set.order.len() && !set.order[..n].contains(&Some(e)) {
                set.order[n] = Some(e);
                n += 1;
            }
        }
        set
    }
    pub fn is_empty(&self) -> bool {
        self.order[0].is_none()
    }
    /// In preference order.
    pub fn iter(&self) -> impl Iterator<Item = Encoding> + '_ {
        self.order.iter().map_while(|e| *e)
    }
}

/// Whether and how to compress a response dynamically. `None` when the client accepts none of
/// `set`, or the response must not be compressed (see the module docs). Pure; called once per
/// response by the pipeline, after `finalize`.
pub(crate) fn decide(
    set: EncodingSet,
    req: &RequestHead,
    head: &ResponseHead,
    len: Option<u64>,
) -> Option<Encoding> {
    todo!()
}

/// Wraps `body` in a compressor for `encoding`, and edits `head` to match: sets
/// Content-Encoding, drops Content-Length, keeps a strong ETag from validating the encoded
/// bytes as if they were the identity ones, and sets `vary_accept_encoding`.
pub(crate) fn wrap(encoding: Encoding, body: Body, head: &mut ResponseHead) -> Body {
    todo!()
}

/// Streaming compressor state. zstd level 3 (window 8 MiB cap), gzip level 5; br only from
/// sidecars.
pub(crate) enum Encoder {
    Zstd(zstd::stream::raw::Encoder<'static>),
    Gzip(flate2::Compress),
}

pub(crate) struct EncodedBody {
    pub inner: Body,
    pub encoder: Encoder,
}

impl EncodedBody {
    /// The next compressed chunk: reads one chunk of `inner`, compresses it and flushes, so
    /// every input chunk produces output before the next read. `None` after the final frame.
    pub async fn next_chunk(&mut self, core: &crate::runtime::Core) -> io::Result<Option<Bytes>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_set_keeps_order_and_drops_repeats() {
        let set = EncodingSet::new([Encoding::Zstd, Encoding::Gzip, Encoding::Zstd]);
        assert_eq!(
            set.iter().collect::<Vec<_>>(),
            [Encoding::Zstd, Encoding::Gzip]
        );
        assert!(EncodingSet::new([]).is_empty());
    }
}
