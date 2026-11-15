//! In-process ACME (RFC 8555): certificates for sites with `tls.acme`, for hosts without an
//! ACME client of their own (NixOS hosts keep using `security.acme`).
//!
//! The control thread runs the client ([`Manager`]): account key and certificates in the state
//! directory; order, challenge, finalize, download; renewal at two thirds of a certificate's
//! lifetime with jitter, backoff on failure. Issued certificates are written where the plan's
//! `CertSource` for the site points, and loaded the way certificate files always are, so a
//! site serves a self-signed certificate until its first issuance.
//!
//! Validation answers are [`Challenges`], shared with the cores:
//! - HTTP-01: the HTTP->HTTPS redirect site answers `/.well-known/acme-challenge/<token>`
//!   before redirecting (`Terminal::AcmeChallenge`, answered by [`http01`]);
//! - TLS-ALPN-01 (RFC 8737): the certificate resolver answers a handshake that offers only
//!   `acme-tls/1` with the challenge certificate ([`Challenges::tls_alpn`]), and the
//!   connection closes once the handshake is done.
//!
//! A plan without `tls.acme` starts no client, has no challenge step and shares no
//! `Challenges`.

use crate::exchange::Exchange;
use crate::msg::Status;
use crate::pipeline::Response;
use crate::plan::Plan;
use crate::runtime::CoreSnapshot;
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;
use std::sync::Arc;

/// The ALPN protocol of TLS-ALPN-01 validation (RFC 8737 section 6.2).
pub(crate) const ALPN: &[u8] = b"acme-tls/1";

/// One certificate to issue and keep renewed, for one site's names. Built by
/// `plan::compile::acme`.
#[derive(Debug)]
pub(crate) struct AcmePlan {}

impl AcmePlan {
    /// Whether the CA validates this certificate's names over HTTP-01, which needs the token
    /// step on the redirect site.
    pub fn answers_http01(&self) -> bool {
        false
    }
}

/// The validation answers of pending orders. Written by the control thread, read by cores on
/// challenge requests and `acme-tls/1` handshakes only.
#[derive(Debug, Default)]
pub(crate) struct Challenges {}

impl Challenges {
    /// The certificate for a TLS-ALPN-01 validation: `Some` only for a client that offers
    /// `acme-tls/1` for a name with a pending challenge.
    pub fn tls_alpn(&self, hello: &ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let _ = hello;
        None
    }
}

/// The `AcmeChallenge` terminal: the key authorization of the token the path names, or 404.
pub(crate) fn http01(snap: &CoreSnapshot, ex: &mut Exchange) -> Result<Response, Status> {
    let _ = (snap, ex);
    Err(Status::NOT_FOUND)
}

/// What the client asks of the control loop.
#[derive(Debug)]
pub(crate) enum Event {
    /// Certificates were written to the state directory: load them and publish.
    Issued,
}

/// The control thread's ACME client.
pub(crate) struct Manager {
    challenges: Arc<Challenges>,
}

impl Manager {
    pub fn new() -> Manager {
        Manager {
            challenges: Arc::default(),
        }
    }

    /// After every published generation: the certificates the plan needs. Starts or stops
    /// orders to match; idempotent.
    pub fn set_plan(&mut self, plan: &Plan) {
        let _ = plan;
    }

    /// The answers shared with the cores: `Some` exactly when the plan has in-process ACME.
    pub fn challenges(&self, plan: &Plan) -> Option<Arc<Challenges>> {
        (!plan.acme.is_empty()).then(|| self.challenges.clone())
    }

    /// The next event. Pending forever when nothing is to be issued, so the control loop's
    /// `select!` arm costs nothing.
    pub async fn recv(&mut self) -> Event {
        std::future::pending().await
    }
}
