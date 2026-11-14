//! Moving bodies between two transports without buffering them whole.
//!
//! h1 <-> h1 bodies are relayed as raw framed bytes: a Content-Length body is copied as is, a
//! chunked body is forwarded chunk syntax and all while [`Chunked::scan`] tracks where it ends.
//! Every read is written before the next read (so SSE events and DERP frames go out as they
//! arrive; there is no flush interval because there is no buffering).
//!
//! When both transports expose a kernel-plaintext fd (cleartext or kTLS) and the body is long,
//! the copy loop can become splice(2) through a per-core pipe without changing these
//! signatures.

use super::{UpstreamBody, UpstreamConn};
use crate::net::Transport;
use crate::proto::h1::server::H1Body;
use bytes::BytesMut;
use std::io;
use std::time::Duration;

pub(crate) enum RelayEnd {
    /// The message ended cleanly; both sides may be reused.
    Complete,
    /// The source closed early or the sink failed; neither side is reusable.
    Broken,
}

/// Request body, client -> upstream. `head` (already serialised) is sent in the same writev as
/// the first body bytes.
pub(crate) async fn copy_request(
    head: &[u8],
    body: &mut H1Body<'_>,
    up: &mut UpstreamConn,
) -> io::Result<RelayEnd> {
    todo!()
}

/// Response body, upstream -> h1 client. `head` goes out with the first body bytes.
pub(crate) async fn copy_response(
    head: &[u8],
    body: &mut UpstreamBody,
    client: &mut Transport,
) -> io::Result<RelayEnd> {
    todo!()
}

/// After a 101: bytes both ways until either side closes, or nothing moved for `idle`.
/// Bytes the client sent after its upgrade request (already in `client_buf`) go first.
pub(crate) async fn tunnel(
    client: &mut Transport,
    client_buf: &mut BytesMut,
    up: &mut UpstreamConn,
    idle: Option<Duration>,
) -> io::Result<()> {
    todo!()
}
