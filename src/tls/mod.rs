//! TLS: certificates by SNI, the per-core server configs, stateless resumption, kTLS offload,
//! and the upstream client config.
//!
//! Certificates come from files (NixOS ACME: `/var/lib/acme/<cert>/{fullchain,key}.pem`).
//! [`load`] never fails as a whole. A missing, unreadable, unparsable or mismatched pair is a
//! [`CertProblem`], and each of its names keeps the previous generation's certificate from
//! files if it had one, else is answered with an in-memory self-signed certificate for that
//! name. Every other site is unaffected. A later reload that finds the files picks them up.
//! So the proxy starts before `acme-<cert>.service` has run, and the first issuance window
//! keeps serving: Cloudflare's "Full" (not strict) mode accepts the self-signed answer.
//!
//! Rotation is reload: the NixOS ACME module calls `systemctl reload upstreamer` (via
//! `reloadServices`) after lego writes new files; reload re-reads every pair. No inotify: one
//! trigger, idempotent.

pub(crate) mod ktls;

use crate::exchange::Proto;
use crate::net::{Socket, Transport};
use crate::plan::CertSource;
use rustls::server::{ClientHello, ProducesTickets, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::sync::Arc;

/// SNI name -> certificate. Immutable once built; replaced whole at reload. Every name of
/// every source has a slot: from files, or self-signed while no usable pair was ever loaded.
#[derive(Debug, Default)]
pub(crate) struct CertStore {
    exact: HashMap<Box<str>, Slot>,
    /// `*.example.com` stored as `example.com`; matched one label deep.
    wildcard: HashMap<Box<str>, Slot>,
}

/// One name's certificate.
#[derive(Debug, Clone)]
pub(crate) struct Slot {
    pub key: Arc<CertifiedKey>,
    pub origin: Origin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// Read from the source's PEM files, in this generation or an earlier one.
    Files,
    /// Generated in memory for this one name (SAN = the name) because no usable pair for it
    /// was ever loaded. Reused across reloads until the files appear.
    SelfSigned,
}

impl CertStore {
    /// Exact name first, then the one-label wildcard (`a.example.com` -> `*.example.com`).
    /// `name` is the SNI value, which rustls has already lowercased.
    pub fn get(&self, name: &str) -> Option<&Slot> {
        todo!()
    }
}

/// A source whose pair could not be used at this load.
#[derive(Debug)]
pub(crate) struct CertProblem {
    /// Index into the plan's `certs`.
    pub source: usize,
    pub message: String,
    /// Names still served the previous generation's certificate from files.
    pub kept_previous: Vec<Box<str>>,
    /// Names served a self-signed certificate until a reload loads the pair.
    pub self_signed: Vec<Box<str>>,
}

/// Loads every pair. Blocking file IO; runs on the control thread. For each source:
/// - the pair parses, its key matches the leaf, the chain is non-empty: every name gets it;
/// - otherwise, a [`CertProblem`], and per name: the previous slot if its origin is
///   [`Origin::Files`]; else the previous self-signed slot; else a new [`self_signed`] one.
pub(crate) fn load(
    sources: &[CertSource],
    previous: Option<&CertStore>,
) -> (CertStore, Vec<CertProblem>) {
    todo!()
}

/// An ECDSA P-256 certificate for exactly `name` (a DNS name or `*.suffix`), valid from now for
/// a year, signed by its own key. Never written to disk.
pub(crate) fn self_signed(name: &str) -> Result<Arc<CertifiedKey>, rcgen::Error> {
    todo!()
}

/// SNI resolution against the store captured in this core's server config.
#[derive(Debug)]
pub(crate) struct Resolver {
    pub store: Arc<CertStore>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        todo!("store.get(sni); no SNI -> None")
    }
}

/// Session ticket keys: generated in memory at start, rotated every 12h by the control thread
/// (current + previous kept for decryption), published inside the snapshot. Every core holds
/// the same keys, so a ticket issued on one core resumes on another, and no lock is taken per
/// handshake (unlike rustls' rotating ticketer).
#[derive(Debug)]
pub(crate) struct TicketKeys {
    pub current: [u8; 32],
    pub previous: Option<[u8; 32]>,
    pub lifetime_secs: u32,
}

impl TicketKeys {
    /// Fresh random keys (aws-lc-rs RNG), no previous key.
    pub fn generate(lifetime_secs: u32) -> TicketKeys {
        todo!()
    }
    /// The next rotation: a fresh current key, this one's current kept as previous.
    pub fn rotated(&self) -> TicketKeys {
        todo!()
    }
}

impl ProducesTickets for TicketKeys {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        self.lifetime_secs
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        todo!("AES-256-GCM via aws-lc-rs, key id prefix")
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        todo!()
    }
}

/// Builds one core's server config: TLS 1.3 + 1.2, aws-lc-rs provider, ALPN [h2, http/1.1],
/// our resolver and tickets, one TLS 1.3 ticket per handshake, `max_early_data_size` 0.
/// Built per core so no handshake bumps a refcount another core also bumps.
pub(crate) fn server_config(
    store: Arc<CertStore>,
    tickets: Arc<TicketKeys>,
) -> Arc<rustls::ServerConfig> {
    todo!()
}

/// The QUIC side of the same: ALPN [h3], TLS 1.3 only, same resolver and tickets.
pub(crate) fn quic_server_config(
    store: Arc<CertStore>,
    tickets: Arc<TicketKeys>,
) -> Arc<rustls::ServerConfig> {
    todo!()
}

/// Upstream client config: TLS 1.3/1.2, webpki roots, session cache; `verify = false` installs
/// a verifier that accepts any certificate (`tlsSkipVerify`, for an origin with a self-signed certificate).
pub(crate) fn client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    todo!()
}

#[derive(Debug)]
pub(crate) enum TlsError {
    Handshake(rustls::Error),
    Io(std::io::Error),
    Timeout,
}

/// Server handshake on an accepted socket (handshake timeout = header timeout). Returns a
/// userspace `Transport::Tls` and the ALPN protocol; offload happens later, see
/// [`ktls::offload_point`].
pub(crate) async fn accept(
    sock: Socket,
    config: Arc<rustls::ServerConfig>,
) -> Result<(Transport, Proto), TlsError> {
    todo!()
}
