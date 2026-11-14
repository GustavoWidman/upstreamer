//! HTTP/2 downstream via the `h2` crate (TLS with ALPN h2 only; no h2c). One local task drives
//! the connection; each stream runs `pipeline::handle` in its own local task (`spawn_local`,
//! `!Send` is fine). Responses stream as DATA frames, honouring flow control; nothing is
//! buffered whole.
//!
//! SETTINGS: initial stream window 1 MiB, connection window 4 MiB (1 MiB bodies in one RTT),
//! max concurrent streams from the config, max header list 64 KiB. Extended CONNECT is not
//! advertised, so browsers open WebSockets over HTTP/1.1, the only upgrade path.
//!
//! Graceful shutdown and reload of removed listeners: GOAWAY, then let open streams finish
//! within the shutdown timeout.

use crate::exchange::ConnInfo;
use crate::net::Transport;
use crate::pipeline::Response;
use crate::runtime::Core;
use bytes::Bytes;
use std::rc::Rc;

pub(crate) async fn serve(core: Rc<Core>, io: Transport, info: ConnInfo) {
    // let mut conn = ::h2::server::Builder::new()...handshake::<_, Bytes>(io).await?;
    // while let Some((req, respond)) = conn.accept().await { spawn_local(stream(core.clone(), info, req, respond)) }
    todo!()
}

/// One stream: head conversion (one copy of the header block into the exchange), the
/// pipeline, then DATA frames from `Body::next_chunk`.
async fn stream(
    core: Rc<Core>,
    info: ConnInfo,
    req: http::Request<::h2::RecvStream>,
    respond: ::h2::server::SendResponse<Bytes>,
) {
    todo!()
}

/// Sends a response body as DATA frames, waiting for window capacity per chunk.
async fn send_body(
    core: &Core,
    resp: Response,
    send: ::h2::SendStream<Bytes>,
) -> Result<(), ::h2::Error> {
    todo!()
}
