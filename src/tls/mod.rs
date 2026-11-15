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
pub(crate) mod record;

use crate::exchange::Proto;
use crate::net::{self, Socket, TlsStream, Transport};
use crate::plan::CertSource;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use bytes::{Buf, BytesMut};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::{ClientHello, NoServerSessionStorage, ProducesTickets, ResolvesServerCert};
use rustls::server::{ServerConnectionData, UnbufferedServerConnection};
use rustls::sign::CertifiedKey;
use rustls::unbuffered::{ConnectionState, EncodeError, EncodeTlsData, InsufficientSizeError};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::collections::HashMap;
use std::fmt;
use std::io::{self, IoSlice};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
        let name = name.strip_suffix('.').unwrap_or(name);
        if let Some(slot) = self.exact.get(name) {
            return Some(slot);
        }
        let (_, parent) = name.split_once('.')?;
        self.wildcard.get(parent)
    }

    /// The slot configured for `name` exactly as written in a source (`*.x` is the wildcard
    /// slot for `x`), without SNI matching.
    fn configured(&self, name: &ConfiguredName) -> Option<&Slot> {
        match name {
            ConfiguredName::Exact(n) => self.exact.get(n),
            ConfiguredName::Wildcard(parent) => self.wildcard.get(parent),
        }
    }

    fn contains(&self, name: &ConfiguredName) -> bool {
        self.configured(name).is_some()
    }

    fn insert(&mut self, name: ConfiguredName, slot: Slot) {
        match name {
            ConfiguredName::Exact(n) => self.exact.insert(n, slot),
            ConfiguredName::Wildcard(parent) => self.wildcard.insert(parent, slot),
        };
    }
}

/// A source name normalised for the store: lowercase, no trailing dot, wildcard split off.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ConfiguredName {
    Exact(Box<str>),
    /// `*.example.com`, holding `example.com`.
    Wildcard(Box<str>),
}

impl ConfiguredName {
    fn parse(raw: &str) -> ConfiguredName {
        let lower = raw.to_ascii_lowercase();
        let name = lower.strip_suffix('.').unwrap_or(&lower);
        match name.strip_prefix("*.") {
            Some(parent) => ConfiguredName::Wildcard(parent.into()),
            None => ConfiguredName::Exact(name.into()),
        }
    }
}

impl fmt::Display for ConfiguredName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfiguredName::Exact(n) => f.write_str(n),
            ConfiguredName::Wildcard(parent) => write!(f, "*.{parent}"),
        }
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
///
/// A name listed by more than one source is served by the first source that lists it.
pub(crate) fn load(
    sources: &[CertSource],
    previous: Option<&CertStore>,
) -> (CertStore, Vec<CertProblem>) {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let mut store = CertStore::default();
    let mut problems = Vec::new();
    for (index, source) in sources.iter().enumerate() {
        let names = source.names.iter().map(|n| ConfiguredName::parse(n));
        match read_pair(&source.cert, &source.key, &provider) {
            Ok(key) => {
                let key = Arc::new(key);
                for name in names {
                    if !store.contains(&name) {
                        let slot = Slot {
                            key: key.clone(),
                            origin: Origin::Files,
                        };
                        store.insert(name, slot);
                    }
                }
            }
            Err(message) => {
                let mut problem = CertProblem {
                    source: index,
                    message,
                    kept_previous: Vec::new(),
                    self_signed: Vec::new(),
                };
                for name in names {
                    if store.contains(&name) {
                        continue;
                    }
                    let kept = previous.and_then(|p| p.configured(&name)).cloned();
                    let slot = match kept {
                        Some(slot) if slot.origin == Origin::Files => {
                            problem.kept_previous.push(name.to_string().into());
                            slot
                        }
                        Some(slot) => {
                            problem.self_signed.push(name.to_string().into());
                            slot
                        }
                        None => match self_signed(&name.to_string()) {
                            Ok(key) => {
                                problem.self_signed.push(name.to_string().into());
                                Slot {
                                    key,
                                    origin: Origin::SelfSigned,
                                }
                            }
                            Err(e) => {
                                problem.message.push_str(&format!(
                                    "; no self-signed certificate for {name}: {e}"
                                ));
                                continue;
                            }
                        },
                    };
                    store.insert(name, slot);
                }
                problems.push(problem);
            }
        }
    }
    (store, problems)
}

fn read_pair(cert: &Path, key: &Path, provider: &CryptoProvider) -> Result<CertifiedKey, String> {
    let cert_pem = std::fs::read(cert).map_err(|e| format!("{}: {e}", cert.display()))?;
    let key_pem = std::fs::read(key).map_err(|e| format!("{}: {e}", key.display()))?;
    let chain = CertificateDer::pem_slice_iter(&cert_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!("{}: no certificate in PEM", cert.display()));
    }
    let private =
        PrivateKeyDer::from_pem_slice(&key_pem).map_err(|e| format!("{}: {e}", key.display()))?;
    CertifiedKey::from_der(chain, private, provider)
        .map_err(|e| format!("{} with {}: {e}", cert.display(), key.display()))
}

#[derive(Debug)]
pub(crate) enum SelfSignedError {
    Generate(rcgen::Error),
    Key(rustls::Error),
}

impl fmt::Display for SelfSignedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SelfSignedError::Generate(e) => write!(f, "generating: {e}"),
            SelfSignedError::Key(e) => write!(f, "loading key: {e}"),
        }
    }
}

/// An ECDSA P-256 certificate for exactly `name` (a DNS name or `*.suffix`), valid from now for
/// a year, signed by its own key. Never written to disk.
pub(crate) fn self_signed(name: &str) -> Result<Arc<CertifiedKey>, SelfSignedError> {
    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(SelfSignedError::Generate)?;
    let mut params =
        rcgen::CertificateParams::new(vec![name.to_owned()]).map_err(SelfSignedError::Generate)?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, name);
    let (year, month, day) = civil_today();
    params.not_before = rcgen::date_time_ymd(year, month, day);
    params.not_after = rcgen::date_time_ymd(year + 1, month, day.min(28));
    let cert = params
        .self_signed(&key_pair)
        .map_err(SelfSignedError::Generate)?;
    let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    let signing = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(SelfSignedError::Key)?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

/// Today's UTC date as (year, month, day), from the days-to-civil algorithm.
fn civil_today() -> (i32, u8, u8) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year as i32, month as u8, day as u8)
}

/// SNI resolution against the store captured in this core's server config.
#[derive(Debug)]
pub(crate) struct Resolver {
    pub store: Arc<CertStore>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = hello.server_name()?;
        self.store.get(name).map(|slot| slot.key.clone())
    }
}

const TICKET_KEY_ID_LEN: usize = 4;
const TICKET_TAG_LEN: usize = 16;

/// One AES-256-GCM ticket key with its id; tickets carry the id so the right key decrypts.
pub(crate) struct TicketKey {
    pub id: [u8; TICKET_KEY_ID_LEN],
    secret: [u8; 32],
    aead: LessSafeKey,
}

impl TicketKey {
    fn generate(rng: &SystemRandom) -> TicketKey {
        let mut secret = [0u8; 32];
        let mut id = [0u8; TICKET_KEY_ID_LEN];
        rng.fill(&mut secret).expect("system RNG");
        rng.fill(&mut id).expect("system RNG");
        TicketKey::new(id, secret)
    }

    fn new(id: [u8; TICKET_KEY_ID_LEN], secret: [u8; 32]) -> TicketKey {
        let key = UnboundKey::new(&AES_256_GCM, &secret).expect("32-byte AES-256-GCM key");
        TicketKey {
            id,
            secret,
            aead: LessSafeKey::new(key),
        }
    }
}

impl fmt::Debug for TicketKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TicketKey")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Session ticket keys: generated in memory at start, rotated every 12h by the control thread
/// (current + previous kept for decryption), published inside the snapshot. Every core holds
/// the same keys, so a ticket issued on one core resumes on another, and no lock is taken per
/// handshake (unlike rustls' rotating ticketer).
///
/// Ticket layout: key id (4) | nonce (12) | AES-256-GCM ciphertext | tag (16), the key id as
/// additional data.
#[derive(Debug)]
pub(crate) struct TicketKeys {
    pub current: TicketKey,
    pub previous: Option<TicketKey>,
    pub lifetime_secs: u32,
}

impl TicketKeys {
    /// Fresh random keys (aws-lc-rs RNG), no previous key.
    pub fn generate(lifetime_secs: u32) -> TicketKeys {
        TicketKeys {
            current: TicketKey::generate(&SystemRandom::new()),
            previous: None,
            lifetime_secs,
        }
    }

    /// The next rotation: a fresh current key, this one's current kept as previous.
    pub fn rotated(&self) -> TicketKeys {
        let current = TicketKey::generate(&SystemRandom::new());
        let previous = TicketKey::new(self.current.id, self.current.secret);
        TicketKeys {
            current,
            previous: Some(previous),
            lifetime_secs: self.lifetime_secs,
        }
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
        let mut nonce = [0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce).ok()?;
        let key = &self.current;
        let mut out =
            Vec::with_capacity(TICKET_KEY_ID_LEN + NONCE_LEN + plain.len() + TICKET_TAG_LEN);
        out.extend_from_slice(&key.id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(plain);
        let (_, body) = out.split_at_mut(TICKET_KEY_ID_LEN + NONCE_LEN);
        let tag = key
            .aead
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&key.id),
                body,
            )
            .ok()?;
        out.extend_from_slice(tag.as_ref());
        Some(out)
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < TICKET_KEY_ID_LEN + NONCE_LEN + TICKET_TAG_LEN {
            return None;
        }
        let (id, rest) = cipher.split_at(TICKET_KEY_ID_LEN);
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let key = [Some(&self.current), self.previous.as_ref()]
            .into_iter()
            .flatten()
            .find(|k| k.id == id)?;
        let nonce = Nonce::try_assume_unique_for_key(nonce).ok()?;
        let mut buf = sealed.to_vec();
        let plain_len = key
            .aead
            .open_in_place(nonce, Aad::from(&key.id), &mut buf)
            .ok()?
            .len();
        buf.truncate(plain_len);
        Some(buf)
    }
}

/// Builds one core's server config: TLS 1.3 + 1.2, aws-lc-rs provider, ALPN [h2, http/1.1],
/// our resolver and tickets, one TLS 1.3 ticket per handshake, `max_early_data_size` 0.
/// Built per core so no handshake bumps a refcount another core also bumps.
pub(crate) fn server_config(
    store: Arc<CertStore>,
    tickets: Arc<TicketKeys>,
) -> Arc<rustls::ServerConfig> {
    let versions: &[&rustls::SupportedProtocolVersion] =
        &[&rustls::version::TLS13, &rustls::version::TLS12];
    let mut config = base_server_config(store, tickets, versions, &[b"h2", b"http/1.1"]);
    // The record layer (and kTLS) take the traffic keys over from rustls after the handshake.
    config.enable_secret_extraction = true;
    Arc::new(config)
}

/// The QUIC side of the same: ALPN [h3], TLS 1.3 only, same resolver and tickets.
pub(crate) fn quic_server_config(
    store: Arc<CertStore>,
    tickets: Arc<TicketKeys>,
) -> Arc<rustls::ServerConfig> {
    Arc::new(base_server_config(
        store,
        tickets,
        &[&rustls::version::TLS13],
        &[b"h3"],
    ))
}

fn base_server_config(
    store: Arc<CertStore>,
    tickets: Arc<TicketKeys>,
    versions: &[&'static rustls::SupportedProtocolVersion],
    alpn: &[&[u8]],
) -> rustls::ServerConfig {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .expect("aws-lc-rs supports TLS 1.2 and 1.3")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Resolver { store }));
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    // Stateless tickets only: a server-side session cache would be per core (so it would not
    // resume across cores) and takes a lock per handshake.
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.ticketer = tickets;
    config.send_tls13_tickets = 1;
    config.max_early_data_size = 0;
    config
}

/// Upstream client config: TLS 1.3/1.2, the system trust store, session cache; `verify = false`
/// installs a verifier that accepts any certificate (`tlsSkipVerify`, for an origin with a
/// self-signed certificate).
pub(crate) fn client_config(verify: bool) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .expect("aws-lc-rs supports TLS 1.2 and 1.3");
    let config = if verify {
        builder
            .with_root_certificates(system_roots())
            .with_no_client_auth()
    } else {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert { provider }))
            .with_no_client_auth()
    };
    Arc::new(config)
}

/// The system CA bundle: `SSL_CERT_FILE`, `NIX_SSL_CERT_FILE`, then the usual Linux and macOS
/// paths. Missing or unparsable bundles leave the store empty, so verification fails closed.
fn system_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    let env = ["SSL_CERT_FILE", "NIX_SSL_CERT_FILE"]
        .into_iter()
        .filter_map(std::env::var_os);
    let fixed = ["/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem"].map(Into::into);
    for path in env.chain(fixed) {
        let Ok(pem) = std::fs::read(&path) else {
            continue;
        };
        let certs = CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok);
        let (added, _) = roots.add_parsable_certificates(certs);
        if added > 0 {
            break;
        }
    }
    roots
}

/// Accepts any server certificate, but still checks that the handshake was signed by the key in
/// the presented certificate.
#[derive(Debug)]
struct AcceptAnyCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug)]
pub(crate) enum TlsError {
    Handshake(rustls::Error),
    Io(std::io::Error),
    Timeout,
}

impl From<rustls::Error> for TlsError {
    fn from(e: rustls::Error) -> TlsError {
        TlsError::Handshake(e)
    }
}

impl From<std::io::Error> for TlsError {
    fn from(e: std::io::Error) -> TlsError {
        TlsError::Io(e)
    }
}

/// Server handshake on an accepted socket. Returns a userspace `Transport::Tls` and the
/// protocol ALPN chose (h2, else HTTP/1.1); offload happens later, see
/// [`ktls::offload_point`]. A client that has not finished within `timeout` is dropped, which
/// closes its socket.
pub(crate) async fn accept_within(
    mut sock: Socket,
    config: Arc<rustls::ServerConfig>,
    timeout: Duration,
) -> Result<(Transport, Proto), TlsError> {
    let conn = UnbufferedServerConnection::new(config)?;
    let handshake = async {
        // A client that connects and sends nothing holds no buffer.
        sock.readable().await?;
        let mut rx = net::take_ciphertext();
        let mut tx = net::take_ciphertext();
        let done = handshake(&mut sock, conn, &mut rx, &mut tx).await;
        net::put_ciphertext(tx);
        match done {
            Ok(done) => Ok((done, rx)),
            Err(e) => {
                net::put_ciphertext(rx);
                Err(e)
            }
        }
    };
    let ((conn, proto), rx) = tokio::time::timeout(timeout, handshake)
        .await
        .map_err(|_| TlsError::Timeout)??;
    let (secrets, kernel) = conn.dangerous_into_kernel_connection()?;
    let session = record::Session::new(secrets, kernel)?;
    Ok((
        Transport::Tls(Box::new(TlsStream::new(sock, session, rx))),
        proto,
    ))
}

/// Drives rustls's unbuffered server through the handshake. On a handshake error the alert
/// rustls produced is sent before returning.
async fn handshake(
    sock: &mut Socket,
    mut conn: UnbufferedServerConnection,
    rx: &mut BytesMut,
    tx: &mut BytesMut,
) -> Result<(UnbufferedServerConnection, Proto), TlsError> {
    // The front of `rx` given to rustls. It grows one whole record at a time, only when rustls
    // is blocked mid-handshake, so rustls never opens the application data that may follow the
    // client's last flight: those records stay in `rx` for the record layer. A handshake
    // message split across records stays in this region, joined in place by rustls, until the
    // record that completes it is given.
    let mut fed = 0;
    loop {
        let status = conn.process_tls_records(&mut rx[..fed]);
        let discard = status.discard;
        let next = match status.state {
            Ok(ConnectionState::EncodeTlsData(mut data)) => {
                encode(&mut data, tx)?;
                Next::Process
            }
            Ok(ConnectionState::TransmitTlsData(data)) => {
                data.done();
                Next::Transmit
            }
            Ok(ConnectionState::BlockedHandshake) => Next::Receive,
            Ok(ConnectionState::WriteTraffic(_)) => Next::Traffic,
            Ok(ConnectionState::PeerClosed | ConnectionState::Closed) => {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
            }
            Ok(_) => {
                return Err(rustls::Error::General("unexpected handshake state".into()).into());
            }
            Err(e) => {
                rx.advance(discard);
                send_alert(sock, &mut conn, tx);
                return Err(e.into());
            }
        };
        rx.advance(discard);
        fed -= discard;
        match next {
            Next::Process => {}
            Next::Transmit => {
                sock.write_all_vectored(&mut [IoSlice::new(tx)]).await?;
                tx.clear();
            }
            Next::Traffic if !conn.is_handshaking() => {
                let proto = match conn.alpn_protocol() {
                    Some(b"h2") => Proto::H2,
                    _ => Proto::H1,
                };
                return Ok((conn, proto));
            }
            Next::Receive | Next::Traffic => match record::record_len(&rx[fed..])? {
                Some(len) => fed += len,
                None => {
                    if sock.read(rx).await? == 0 {
                        return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                    }
                }
            },
        }
    }
}

enum Next {
    Process,
    Transmit,
    Receive,
    Traffic,
}

fn encode(
    data: &mut EncodeTlsData<'_, ServerConnectionData>,
    tx: &mut BytesMut,
) -> Result<(), rustls::Error> {
    let start = tx.len();
    let mut room = 4096;
    loop {
        tx.resize(start + room, 0);
        match data.encode(&mut tx[start..]) {
            Ok(n) => {
                tx.truncate(start + n);
                return Ok(());
            }
            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                room = required_size;
            }
            Err(EncodeError::AlreadyEncoded) => {
                tx.truncate(start);
                return Err(rustls::Error::General(
                    "handshake record encoded twice".into(),
                ));
            }
        }
    }
}

/// Encodes what rustls queued after a failed handshake (its alert) and writes it once, without
/// waiting for the socket.
fn send_alert(sock: &Socket, conn: &mut UnbufferedServerConnection, tx: &mut BytesMut) {
    while let Ok(ConnectionState::EncodeTlsData(mut data)) = conn.process_tls_records(&mut []).state
    {
        if encode(&mut data, tx).is_err() {
            break;
        }
    }
    let _ = sock.try_write(tx);
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::{ClientConnection, HandshakeKind, ServerConnection};
    use std::path::PathBuf;

    struct Pair {
        cert_pem: String,
        key_pem: String,
        der: CertificateDer<'static>,
    }

    fn fixture_text(file: &str) -> String {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
        std::fs::read_to_string(dir.join(file)).unwrap()
    }

    /// A PEM pair from `tests/fixtures/tls`: EC keys in SEC1 form, `kept.crt` a leaf plus its
    /// issuer, like the `fullchain.pem` and `key.pem` that NixOS ACME writes.
    fn fixture(stem: &str) -> Pair {
        let cert_pem = fixture_text(&format!("{stem}.crt"));
        let der = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        Pair {
            key_pem: fixture_text(&format!("{stem}.key")),
            cert_pem,
            der,
        }
    }

    struct Files {
        dir: tempfile::TempDir,
    }

    impl Files {
        fn new() -> Files {
            Files {
                dir: tempfile::tempdir().unwrap(),
            }
        }
        fn path(&self, file: &str) -> PathBuf {
            self.dir.path().join(file)
        }
        fn write(&self, file: &str, contents: &str) {
            std::fs::write(self.path(file), contents).unwrap();
        }
        fn write_pair(&self, stem: &str, pair: &Pair) {
            self.write(&format!("{stem}.crt"), &pair.cert_pem);
            self.write(&format!("{stem}.key"), &pair.key_pem);
        }
        fn source(&self, stem: &str, names: &[&str]) -> CertSource {
            CertSource {
                cert: self.path(&format!("{stem}.crt")),
                key: self.path(&format!("{stem}.key")),
                names: names.iter().map(|n| Box::from(*n)).collect(),
            }
        }
    }

    fn client(alpn: &[&[u8]]) -> Arc<rustls::ClientConfig> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCert { provider }))
            .with_no_client_auth();
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }

    /// Moves records between the two ends until neither has anything to send. Returns each
    /// side's first error.
    fn pump(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> (Result<(), rustls::Error>, Result<(), rustls::Error>) {
        let (mut client_result, mut server_result) = (Ok(()), Ok(()));
        loop {
            let mut moved = false;
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() && server_result.is_ok() {
                moved = true;
                let mut rd = &buf[..];
                while !rd.is_empty() {
                    server.read_tls(&mut rd).unwrap();
                }
                server_result = server.process_new_packets().map(|_| ());
            }
            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() && client_result.is_ok() {
                moved = true;
                let mut rd = &buf[..];
                while !rd.is_empty() {
                    client.read_tls(&mut rd).unwrap();
                }
                client_result = client.process_new_packets().map(|_| ());
            }
            if !moved {
                return (client_result, server_result);
            }
        }
    }

    struct Handshake {
        client: ClientConnection,
        server: ServerConnection,
    }

    fn connect(
        client_config: Arc<rustls::ClientConfig>,
        server_config: Arc<rustls::ServerConfig>,
        sni: &str,
    ) -> Result<Handshake, rustls::Error> {
        let name = ServerName::try_from(sni.to_owned()).unwrap();
        let mut client = ClientConnection::new(client_config, name).unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        match pump(&mut client, &mut server) {
            (Ok(()), Ok(())) => Ok(Handshake { client, server }),
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => panic!("server failed without alerting the client: {e}"),
        }
    }

    fn served(store: &Arc<CertStore>, sni: &str) -> CertificateDer<'static> {
        let config = server_config(store.clone(), Arc::new(TicketKeys::generate(3600)));
        let hs = connect(client(&[]), config, sni).expect("handshake");
        hs.client.peer_certificates().unwrap()[0].clone()
    }

    #[test]
    fn sni_selects_exact_then_one_label_wildcard() {
        let files = Files::new();
        let apex = fixture("apex");
        let wild = fixture("wild");
        let api = fixture("api");
        files.write_pair("apex", &apex);
        files.write_pair("wild", &wild);
        files.write_pair("api", &api);
        let sources = [
            files.source("apex", &["example.test"]),
            files.source("wild", &["*.example.test"]),
            files.source("api", &["api.example.test"]),
        ];
        let (store, problems) = load(&sources, None);
        assert!(problems.is_empty(), "{problems:?}");
        let store = Arc::new(store);
        assert_eq!(
            served(&store, "example.test"),
            apex.der,
            "apex is an exact name"
        );
        assert_eq!(
            served(&store, "api.example.test"),
            api.der,
            "exact beats wildcard"
        );
        assert_eq!(
            served(&store, "www.example.test"),
            wild.der,
            "one label under the wildcard"
        );
        assert!(
            store.get("a.b.example.test").is_none(),
            "wildcard covers one label only"
        );
        assert!(
            store.get("EXAMPLE.test").is_none(),
            "SNI arrives lowercased from rustls"
        );
    }

    #[test]
    fn source_names_are_normalised() {
        let files = Files::new();
        let pair = fixture("a");
        files.write_pair("mixed", &pair);
        let (store, _) = load(
            &[files.source("mixed", &["Mixed.TEST.", "*.Wild.test"])],
            None,
        );
        assert_eq!(store.get("mixed.test").unwrap().key.cert[0], pair.der);
        assert_eq!(store.get("x.wild.test").unwrap().key.cert[0], pair.der);
    }

    #[test]
    fn unconfigured_name_or_no_sni_gets_an_alert() {
        let files = Files::new();
        files.write_pair("a", &fixture("a"));
        let (store, _) = load(&[files.source("a", &["a.test"])], None);
        let config = server_config(Arc::new(store), Arc::new(TicketKeys::generate(3600)));
        // An IP address as the server name makes the client send no SNI.
        for sni in ["other.test", "192.0.2.1"] {
            let Err(client_err) = connect(client(&[]), config.clone(), sni) else {
                panic!("handshake for {sni} succeeded");
            };
            assert_eq!(
                client_err,
                rustls::Error::AlertReceived(rustls::AlertDescription::AccessDenied),
                "{sni}"
            );
        }
    }

    #[test]
    fn missing_pair_serves_self_signed_for_its_name_only() {
        let files = Files::new();
        let real = fixture("real");
        files.write_pair("real", &real);
        let sources = [
            files.source("real", &["real.test"]),
            files.source("acme", &["new.test"]),
        ];
        let (store, problems) = load(&sources, None);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].source, 1);
        assert_eq!(problems[0].self_signed, vec![Box::from("new.test")]);
        assert!(problems[0].kept_previous.is_empty());
        let store = Arc::new(store);
        assert_eq!(
            served(&store, "real.test"),
            real.der,
            "other sites keep their certificate"
        );

        let stand_in = served(&store, "new.test");
        assert_eq!(store.get("new.test").unwrap().origin, Origin::SelfSigned);
        let mut roots = rustls::RootCertStore::empty();
        roots.add(stand_in).unwrap();
        let verifying = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let config = server_config(store.clone(), Arc::new(TicketKeys::generate(3600)));
        connect(verifying, config, "new.test")
            .expect("the self-signed certificate is valid for exactly its name");
    }

    #[test]
    fn pair_that_appears_is_served_after_reload() {
        let files = Files::new();
        let sources = [files.source("acme", &["late.test"])];
        let (first, _) = load(&sources, None);
        let (second, problems) = load(&sources, Some(&first));
        assert_eq!(problems[0].self_signed, vec![Box::from("late.test")]);
        assert!(
            Arc::ptr_eq(
                &first.get("late.test").unwrap().key,
                &second.get("late.test").unwrap().key
            ),
            "the self-signed stand-in is reused while the pair is missing"
        );

        let issued = fixture("late");
        files.write_pair("acme", &issued);
        let (third, problems) = load(&sources, Some(&second));
        assert!(problems.is_empty(), "{problems:?}");
        assert_eq!(third.get("late.test").unwrap().origin, Origin::Files);
        assert_eq!(served(&Arc::new(third), "late.test"), issued.der);
    }

    fn reload_keeps_previous(break_pair: impl FnOnce(&Files)) {
        let files = Files::new();
        let good = fixture("kept");
        files.write_pair("site", &good);
        let sources = [files.source("site", &["kept.test", "*.kept.test"])];
        let (before, _) = load(&sources, None);
        break_pair(&files);
        let (after, problems) = load(&sources, Some(&before));
        assert_eq!(problems.len(), 1);
        assert_eq!(
            problems[0].kept_previous,
            vec![Box::from("kept.test"), Box::from("*.kept.test")]
        );
        assert!(problems[0].self_signed.is_empty());
        let after = Arc::new(after);
        assert_eq!(after.get("kept.test").unwrap().origin, Origin::Files);
        assert_eq!(served(&after, "kept.test"), good.der);
        assert_eq!(served(&after, "a.kept.test"), good.der);
    }

    #[test]
    fn corrupt_cert_at_reload_keeps_previous_pair() {
        reload_keeps_previous(|files| {
            files.write(
                "site.crt",
                "-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n",
            )
        });
    }

    #[test]
    fn truncated_cert_at_reload_keeps_previous_pair() {
        reload_keeps_previous(|files| files.write("site.crt", ""));
    }

    #[test]
    fn mismatched_key_at_reload_keeps_previous_pair() {
        reload_keeps_previous(|files| {
            files.write("site.key", &fixture_text("other.key"));
        });
    }

    #[test]
    fn mismatched_key_without_previous_is_self_signed() {
        let files = Files::new();
        files.write("site.crt", &fixture("a").cert_pem);
        files.write("site.key", &fixture_text("other.key"));
        let (store, problems) = load(&[files.source("site", &["fresh.test"])], None);
        assert_eq!(problems[0].self_signed, vec![Box::from("fresh.test")]);
        assert_eq!(store.get("fresh.test").unwrap().origin, Origin::SelfSigned);
    }

    #[test]
    fn alpn_picks_h2_or_http11() {
        let files = Files::new();
        files.write_pair("a", &fixture("a"));
        let (store, _) = load(&[files.source("a", &["a.test"])], None);
        let config = server_config(Arc::new(store), Arc::new(TicketKeys::generate(3600)));
        type Offer<'a> = &'a [&'a [u8]];
        let cases: [(Offer, Option<&[u8]>); 4] = [
            (&[b"h2", b"http/1.1"], Some(b"h2")),
            (&[b"http/1.1", b"h2"], Some(b"h2")),
            (&[b"http/1.1"], Some(b"http/1.1")),
            (&[], None),
        ];
        for (offered, chosen) in cases {
            let hs = connect(client(offered), config.clone(), "a.test").unwrap();
            assert_eq!(
                hs.server.alpn_protocol(),
                chosen,
                "client offered {offered:?}"
            );
        }
        let Err(client_err) = connect(client(&[b"h3"]), config, "a.test") else {
            panic!("h3 accepted over TCP");
        };
        assert_eq!(
            client_err,
            rustls::Error::AlertReceived(rustls::AlertDescription::NoApplicationProtocol)
        );
    }

    #[test]
    fn quic_config_is_tls13_h3_and_accepted_by_quinn() {
        let config = quic_server_config(Arc::default(), Arc::new(TicketKeys::generate(3600)));
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
        assert!(
            quinn::crypto::rustls::QuicServerConfig::try_from(config).is_ok(),
            "quinn accepts the QUIC server config"
        );
    }

    fn store_a() -> Arc<CertStore> {
        let files = Files::new();
        files.write_pair("a", &fixture("a"));
        Arc::new(load(&[files.source("a", &["a.test"])], None).0)
    }

    fn resumes(
        issuer: Arc<rustls::ServerConfig>,
        resumer: Arc<rustls::ServerConfig>,
        versions: &[&'static rustls::SupportedProtocolVersion],
    ) -> Option<HandshakeKind> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = Arc::new(
            rustls::ClientConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(versions)
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCert { provider }))
                .with_no_client_auth(),
        );
        let first = connect(client_config.clone(), issuer, "a.test").unwrap();
        assert_eq!(first.server.handshake_kind(), Some(HandshakeKind::Full));
        let second = connect(client_config, resumer, "a.test").unwrap();
        second.server.handshake_kind()
    }

    #[test]
    fn ticket_from_one_core_resumes_on_another() {
        let store = store_a();
        let keys = Arc::new(TicketKeys::generate(3600));
        for versions in [
            &[&rustls::version::TLS13][..],
            &[&rustls::version::TLS12][..],
        ] {
            let core0 = server_config(store.clone(), keys.clone());
            let core1 = server_config(store.clone(), keys.clone());
            assert_eq!(
                resumes(core0, core1, versions),
                Some(HandshakeKind::Resumed),
                "{versions:?}"
            );
        }
    }

    #[test]
    fn ticket_from_another_generation_does_full_handshake() {
        let store = store_a();
        let core0 = server_config(store.clone(), Arc::new(TicketKeys::generate(3600)));
        let other = server_config(store, Arc::new(TicketKeys::generate(3600)));
        let versions = &[&rustls::version::TLS13];
        assert_eq!(resumes(core0, other, versions), Some(HandshakeKind::Full));
    }

    #[test]
    fn ticket_survives_one_rotation_but_not_two() {
        let store = store_a();
        let keys = TicketKeys::generate(3600);
        let once = keys.rotated();
        let twice = once.rotated();
        let versions = &[&rustls::version::TLS13];
        let keys = Arc::new(keys);
        let after_one = server_config(store.clone(), Arc::new(once));
        let issued = server_config(store.clone(), keys.clone());
        assert_eq!(
            resumes(issued, after_one, versions),
            Some(HandshakeKind::Resumed)
        );
        let issued = server_config(store.clone(), keys);
        let after_two = server_config(store, Arc::new(twice));
        assert_eq!(
            resumes(issued, after_two, versions),
            Some(HandshakeKind::Full)
        );
    }

    #[test]
    fn tickets_round_trip_and_reject_tampering() {
        let keys = TicketKeys::generate(3600);
        let plain = b"session state";
        let ticket = keys.encrypt(plain).unwrap();
        assert_eq!(ticket.len(), 4 + 12 + plain.len() + 16);
        assert_eq!(keys.decrypt(&ticket).as_deref(), Some(&plain[..]));
        assert_ne!(
            keys.encrypt(plain).unwrap(),
            ticket,
            "every ticket has a fresh nonce"
        );
        for i in [0, 5, ticket.len() - 1] {
            let mut bad = ticket.clone();
            bad[i] ^= 1;
            assert_eq!(keys.decrypt(&bad), None, "flipped byte {i}");
        }
        assert_eq!(keys.decrypt(&ticket[..20]), None);
    }

    fn self_signed_upstream() -> Arc<rustls::ServerConfig> {
        let key = self_signed("adguard.lan").unwrap();
        let mut store = CertStore::default();
        store.insert(
            ConfiguredName::parse("adguard.lan"),
            Slot {
                key,
                origin: Origin::SelfSigned,
            },
        );
        server_config(Arc::new(store), Arc::new(TicketKeys::generate(3600)))
    }

    #[test]
    fn skip_verify_accepts_self_signed_upstream() {
        connect(client_config(false), self_signed_upstream(), "adguard.lan")
            .expect("tlsSkipVerify accepts a self-signed origin");
    }

    #[test]
    fn default_verifier_rejects_self_signed_upstream() {
        let Err(client_err) = connect(client_config(true), self_signed_upstream(), "adguard.lan")
        else {
            panic!("a self-signed origin passed verification");
        };
        assert_eq!(
            client_err,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        );
    }

    #[test]
    fn civil_date_is_a_real_date() {
        let (year, month, day) = civil_today();
        assert!(year >= 2024 && (1..=12).contains(&month) && (1..=31).contains(&day));
    }
}
