//! Downstream protocol drivers. Each turns its wire protocol into `Exchange` + `RequestBody`,
//! calls `pipeline::handle`, and writes the `Response` back. Routing, proxying and files are
//! protocol-blind.
//!
//! h1 is ours end to end (the dominant path behind a CDN: Cloudflare connects to origins over
//! HTTP/1.1, and upstreams are HTTP/1.1). h2 uses the `h2` crate and h3 uses `quinn` +
//! `h3`, adapted at the head boundary (one copy of the header block per request).

pub(crate) mod h1;
pub(crate) mod h2;
pub(crate) mod h3;
