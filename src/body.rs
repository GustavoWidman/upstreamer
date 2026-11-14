//! Bodies. Closed enums rather than a `dyn Body` stream, because each downstream protocol has a
//! different cheapest way to move each kind of body, and the driver picks it by matching:
//!
//! | body \ downstream | h1 cleartext / kTLS            | h1 userspace TLS | h2 / h3          |
//! |-------------------|--------------------------------|------------------|------------------|
//! | `Bytes`           | one writev with the head       | encrypt + write  | DATA frames      |
//! | `File`            | sendfile(2)                    | pread + write    | pread -> DATA    |
//! | `Upstream`        | relay in place, raw framing    | relay            | dechunk -> DATA  |
//! |                   | (or splice(2))                 |                  |                  |
//! | `Encoded`         | compress chunks, flush each    | same             | same             |
//!
//! Nothing is ever buffered whole: a chunk read is a chunk written (event streams included).

use crate::encode::EncodedBody;
use crate::files::FileBody;
use crate::proto::h1::server::H1Body;
use crate::proxy::UpstreamBody;
use crate::runtime::Core;
use bytes::Bytes;
use std::io;

pub(crate) enum Body {
    Empty,
    Bytes(Bytes),
    File(FileBody),
    Upstream(UpstreamBody),
    Encoded(Box<EncodedBody>),
}

impl Body {
    /// Exact length when known up front (Content-Length on h1, content-length on h2/h3).
    pub fn len(&self) -> Option<u64> {
        todo!()
    }
    /// Generic path (h2, h3, userspace TLS, compression input): the next chunk, or `None` at
    /// the end. For `Upstream`, the pooled connection goes back to the core's pool when the
    /// end is reached cleanly.
    pub async fn next_chunk(&mut self, core: &Core) -> io::Result<Option<Bytes>> {
        todo!()
    }
}

/// The request body as the downstream protocol delivers it. Borrowed from the h1 connection
/// for the duration of `pipeline::handle` (h1 has one request in flight, so the connection's
/// reader is lent, not shared); owned streams for h2/h3.
pub(crate) enum RequestBody<'a> {
    Empty,
    H1(H1Body<'a>),
    H2(::h2::RecvStream),
    H3(crate::proto::h3::H3Body),
}

impl RequestBody<'_> {
    pub fn len(&self) -> Option<u64> {
        todo!()
    }
    /// Whether the body can be replayed after a failed upstream attempt: only when it is
    /// empty, or fully buffered before the first byte was sent.
    pub fn replayable(&self) -> bool {
        todo!()
    }
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        todo!()
    }
}
