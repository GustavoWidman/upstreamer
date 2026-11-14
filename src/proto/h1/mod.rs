//! HTTP/1.1, our own codec. `codec` is the sans-IO part (parse heads, track body framing,
//! serialise heads) shared by the server driver and the upstream client; httparse tokenises
//! heads, everything about framing and smuggling defence is here.

pub(crate) mod client;
pub(crate) mod codec;
pub(crate) mod server;
