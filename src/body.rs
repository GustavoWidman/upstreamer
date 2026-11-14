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
use crate::net::buf::LARGE;
use crate::proto::h1::server::H1Body;
use crate::proxy::UpstreamBody;
use crate::runtime::Core;
use bytes::{Bytes, BytesMut};
use std::io;
use std::os::unix::fs::FileExt;

pub(crate) enum Body {
    Empty,
    Bytes(Bytes),
    File(FileBody),
    Upstream(UpstreamBody),
    Encoded(Box<EncodedBody>),
}

impl Body {
    /// Exact length when known up front (Content-Length on h1, content-length on h2/h3).
    /// `None` for a body whose end only its own framing shows: a chunked or close-delimited
    /// upstream body, and every compressed stream.
    pub fn len(&self) -> Option<u64> {
        match self {
            Body::Empty => Some(0),
            Body::Bytes(bytes) => Some(bytes.len() as u64),
            Body::File(file) => Some(file.range.end - file.range.start),
            Body::Upstream(upstream) => upstream.len(),
            Body::Encoded(_) => None,
        }
    }

    /// Generic path (h2, h3, userspace TLS, compression input): the next chunk, or `None` at
    /// the end. For `Upstream`, the pooled connection goes back to the core's pool when the
    /// end is reached cleanly, and is closed when the read fails.
    pub async fn next_chunk(&mut self, core: &Core) -> io::Result<Option<Bytes>> {
        match self {
            Body::Empty => Ok(None),
            Body::Bytes(bytes) => {
                let bytes = std::mem::take(bytes);
                *self = Body::Empty;
                Ok((!bytes.is_empty()).then_some(bytes))
            }
            Body::File(file) => {
                let chunk = read_file(file)?;
                if chunk.is_none() {
                    *self = Body::Empty;
                }
                Ok(chunk)
            }
            Body::Upstream(upstream) => match upstream.next_chunk().await {
                Ok(Some(chunk)) => Ok(Some(chunk)),
                end => {
                    if let Body::Upstream(upstream) = std::mem::replace(self, Body::Empty) {
                        upstream.finish(core);
                    }
                    end
                }
            },
            // The compressor reads its input through this function again; the box breaks the
            // cycle in the future's type.
            Body::Encoded(encoded) => Box::pin(encoded.next_chunk(core)).await,
        }
    }
}

/// The next piece of a file body, read on the core thread: file roots are local disks, and
/// most reads come from the page cache.
fn read_file(file: &mut FileBody) -> io::Result<Option<Bytes>> {
    let left = file.range.end - file.range.start;
    if left == 0 {
        return Ok(None);
    }
    let mut chunk = BytesMut::zeroed(left.min(LARGE as u64) as usize);
    let n = file.file.read_at(&mut chunk, file.range.start)?;
    if n == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    chunk.truncate(n);
    file.range.start += n as u64;
    Ok(Some(chunk.freeze()))
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
    /// The body's length, when the request declared one.
    pub fn len(&self) -> Option<u64> {
        match self {
            RequestBody::Empty => Some(0),
            RequestBody::H1(body) => body.state.track.remaining(),
            RequestBody::H2(_) => None,
            RequestBody::H3(body) => body.declared,
        }
    }

    /// Whether the request can be sent again after a failed upstream attempt: only while
    /// none of its body was consumed, which holds for a request without a body.
    pub fn replayable(&self) -> bool {
        match self {
            RequestBody::Empty => true,
            RequestBody::H1(body) => body.state.is_empty(),
            RequestBody::H2(_) | RequestBody::H3(_) => false,
        }
    }

    /// The next piece of body data, without framing; `None` at the end.
    pub async fn next_chunk(&mut self) -> io::Result<Option<Bytes>> {
        match self {
            RequestBody::Empty => Ok(None),
            RequestBody::H1(body) => body.next_chunk().await,
            RequestBody::H2(_) => todo!("request bodies of the h2 driver"),
            RequestBody::H3(body) => body.next_chunk().await,
        }
    }
}
