//! Trusted proxies: the client address a trusted peer (a CDN, a load balancer) forwards.
//!
//! When the plan has `trustedProxies` and the connection's peer is one of them, the
//! exchange's client address becomes the address the configured header names, before the
//! access log, routing, rate-limit and hash keys read it. `{peer_host}` still names the peer.
//! An untrusted peer's header is ignored. A plan without `trustedProxies` has no `trust`, and
//! the pipeline never calls in here.

use crate::exchange::{ConnInfo, Exchange};
use crate::msg::RequestHead;
use std::io::Write;
use std::net::IpAddr;

/// Whose header is believed, and which header. Built by `plan::compile::trust`.
#[derive(Debug)]
pub(crate) struct TrustPlan {}

/// Sets `ex.client` from the forwarded address when the peer is trusted. Called once per
/// request of a plan with `trustedProxies`, before anything reads the client address.
pub(crate) fn resolve(plan: &TrustPlan, ex: &mut Exchange) {
    let _ = (plan, ex);
}

/// The `X-Forwarded-For` a plan with trusted proxies sends upstream, in place of
/// `{remote_host}`: the chain a trusted peer sent, then the peer; the peer alone otherwise.
pub(crate) fn forwarded_for(req: &RequestHead, conn: &ConnInfo, client: IpAddr, out: &mut Vec<u8>) {
    let _ = (req, client);
    let _ = write!(out, "{}", conn.remote.ip());
}
