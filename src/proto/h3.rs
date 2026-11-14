//! HTTP/3 downstream via `quinn` + `h3`. One quinn endpoint per core on its own SO_REUSEPORT
//! UDP socket (GSO/GRO through quinn-udp). Server connection IDs carry the core index, so the
//! reuseport eBPF steering program (planned) can deliver a migrated connection's packets
//! to the core that owns it; until then the kernel's 4-tuple hash does, which holds for every
//! connection that does not migrate.
//!
//! Same pipeline as h1/h2: request head converted into the exchange, body streamed as DATA.
//! Alt-Svc on h1/h2 responses advertises it for sites with http3.

use crate::exchange::ConnInfo;
use crate::runtime::Core;
use bytes::Bytes;
use std::rc::Rc;

pub(crate) async fn serve_endpoint(core: Rc<Core>, endpoint: quinn::Endpoint) {
    // while let Some(incoming) = endpoint.accept().await { spawn_local(conn(core.clone(), incoming)) }
    todo!()
}

async fn conn(core: Rc<Core>, incoming: quinn::Incoming) {
    // let quic = incoming.await?; let mut h3 = h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
    // while let Some(resolver) = h3.accept().await? { spawn_local(stream(core.clone(), info, resolver)) }
    todo!()
}

async fn stream(
    core: Rc<Core>,
    info: ConnInfo,
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) {
    todo!()
}

/// The receive half of an h3 request stream, as a request body.
pub(crate) struct H3Body {
    pub recv: h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
}
