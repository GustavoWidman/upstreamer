//! In-process ACME (RFC 8555): certificates for sites with `tls.acme`, for hosts without an
//! ACME client of their own (NixOS hosts keep using `security.acme`).
//!
//! The control thread runs one task per certificate ([`Manager`]). Each task converges on one
//! state: a certificate in the state directory that covers the site's names and is not yet
//! due for renewal. It reads what is on disk, and orders a certificate (account, order,
//! challenge, finalize, download) only when there is none, when it names other hosts, or when
//! two thirds of its lifetime are over (less a random part of a thirtieth, so certificates
//! issued together do not renew together). A failed order is retried with exponential backoff
//! from a minute up to six hours, or later when the CA says so. Issued pairs are written where
//! the plan's `CertSource` for the site points and loaded the way certificate files always
//! are, so a site serves a self-signed certificate until its first issuance, and keeps the
//! last issued one when a renewal fails.
//!
//! Validation answers are [`Challenges`], shared with the cores, holding only the answers of
//! validations in progress:
//! - HTTP-01: the HTTP->HTTPS redirect site answers `/.well-known/acme-challenge/<token>`
//!   before redirecting (`Terminal::AcmeChallenge`, answered by [`http01`]);
//! - TLS-ALPN-01 (RFC 8737): the certificate resolver answers a handshake that offers only
//!   `acme-tls/1` with the challenge certificate ([`Challenges::tls_alpn`]), and the
//!   connection closes once the handshake is done.
//!
//! A plan without `tls.acme` starts no client, has no challenge step and shares no
//! `Challenges`.

mod der;
pub(crate) mod http;
mod jws;
mod order;
mod store;

use crate::body::Body;
use crate::config::acme::Challenge;
use crate::exchange::Exchange;
use crate::log::{info, warning};
use crate::msg::{Known, Status};
use crate::pipeline::Response;
use crate::plan::Plan;
use crate::runtime::CoreSnapshot;
use bytes::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ClientHello;
use rustls::sign::CertifiedKey;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;

/// The ALPN protocol of TLS-ALPN-01 validation (RFC 8737 section 6.2).
pub(crate) const ALPN: &[u8] = b"acme-tls/1";

/// Where HTTP-01 tokens are fetched (RFC 8555 section 8.3).
const HTTP01_PREFIX: &[u8] = b"/.well-known/acme-challenge/";

/// One certificate to issue and keep renewed, for one site's names. Built by
/// `plan::compile::acme`; two equal plans are the same certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AcmePlan {
    /// DNS names, lowercase, without duplicates or wildcards.
    pub names: Box<[Box<str>]>,
    /// The account's contact address.
    pub email: Box<str>,
    /// The CA's directory.
    pub directory: http::Url,
    pub challenge: Challenge,
    /// The account key (PKCS#8 PEM), shared by every certificate of one CA and address.
    pub account_key: PathBuf,
    /// The issued chain and its key, the site's `CertSource`.
    pub cert: PathBuf,
    pub key: PathBuf,
}

impl AcmePlan {
    /// Whether the CA validates this certificate's names over HTTP-01, which needs the token
    /// step on the redirect site.
    pub fn answers_http01(&self) -> bool {
        self.challenge == Challenge::Http01
    }
}

/// The validation answers of pending orders. Written by the control thread, read by cores on
/// challenge requests and `acme-tls/1` handshakes only. An answer exists only while its
/// validation is in progress ([`Answer`] removes it).
#[derive(Debug, Default)]
pub(crate) struct Challenges {
    /// HTTP-01: token -> key authorization.
    http01: Mutex<HashMap<Box<str>, Bytes>>,
    /// TLS-ALPN-01: name -> the validation certificate for it.
    tls_alpn01: Mutex<HashMap<Box<str>, Arc<CertifiedKey>>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Challenges {
    /// The certificate for a TLS-ALPN-01 validation: `Some` only for a client that offers
    /// `acme-tls/1` and nothing else (RFC 8737 section 3) for a name with a pending
    /// challenge. Every other handshake returns before taking the lock.
    pub fn tls_alpn(&self, hello: &ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let mut offered = hello.alpn()?;
        if offered.next()? != ALPN || offered.next().is_some() {
            return None;
        }
        let name = hello.server_name()?;
        locked(&self.tls_alpn01).get(name).cloned()
    }

    fn key_authorization(&self, token: &[u8]) -> Option<Bytes> {
        let token = std::str::from_utf8(token).ok()?;
        locked(&self.http01).get(token).cloned()
    }

    /// Publishes the answer to one challenge until the returned guard drops.
    fn answer(
        &self,
        kind: Challenge,
        name: &str,
        token: &str,
        key_authorization: &str,
    ) -> Result<Answer<'_>, String> {
        let key = match kind {
            Challenge::Http01 => {
                locked(&self.http01).insert(
                    token.into(),
                    Bytes::copy_from_slice(key_authorization.as_bytes()),
                );
                AnswerKey::Token(token.into())
            }
            Challenge::TlsAlpn01 => {
                let cert = alpn_certificate(name, key_authorization)?;
                locked(&self.tls_alpn01).insert(name.into(), cert);
                AnswerKey::Name(name.into())
            }
        };
        Ok(Answer {
            challenges: self,
            key,
        })
    }
}

/// A published answer; dropping it (the validation ended, failed, or its task was stopped)
/// withdraws it.
struct Answer<'a> {
    challenges: &'a Challenges,
    key: AnswerKey,
}

enum AnswerKey {
    Token(Box<str>),
    Name(Box<str>),
}

impl Drop for Answer<'_> {
    fn drop(&mut self) {
        match &self.key {
            AnswerKey::Token(token) => {
                locked(&self.challenges.http01).remove(token);
            }
            AnswerKey::Name(name) => {
                locked(&self.challenges.tls_alpn01).remove(name);
            }
        }
    }
}

/// The self-signed certificate of a TLS-ALPN-01 validation (RFC 8737 section 3): the name as
/// its only subjectAltName and the critical acmeIdentifier extension holding the SHA-256 of
/// the key authorization. Its key is made for it and never stored.
fn alpn_certificate(name: &str, key_authorization: &str) -> Result<Arc<CertifiedKey>, String> {
    let fail = |e: &dyn std::fmt::Display| format!("the TLS-ALPN-01 certificate for {name}: {e}");
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| fail(&e))?;
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).map_err(|e| fail(&e))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let digest =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, key_authorization.as_bytes());
    params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(digest.as_ref())];
    let cert = params.self_signed(&key_pair).map_err(|e| fail(&e))?;
    let key = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
    let signing = rustls::crypto::aws_lc_rs::default_provider()
        .key_provider
        .load_private_key(key)
        .map_err(|e| fail(&e))?;
    Ok(Arc::new(CertifiedKey::new(
        vec![cert.der().clone()],
        signing,
    )))
}

/// The `AcmeChallenge` terminal: the key authorization of the token the path names, or 404.
pub(crate) fn http01(snap: &CoreSnapshot, ex: &mut Exchange) -> Result<Response, Status> {
    let challenges = snap.acme.as_deref().ok_or(Status::NOT_FOUND)?;
    let token = ex
        .req
        .path()
        .as_bytes()
        .strip_prefix(HTTP01_PREFIX)
        .ok_or(Status::NOT_FOUND)?;
    let body = challenges
        .key_authorization(token)
        .ok_or(Status::NOT_FOUND)?;
    let mut head = ex.response_head(Status::OK);
    head.fields
        .append_known(Known::ContentType, b"application/octet-stream");
    Ok(Response {
        head,
        body: Body::Bytes(body),
        upgrade: None,
        local: true,
    })
}

/// What the client asks of the control loop.
#[derive(Debug)]
pub(crate) enum Event {
    /// Certificates were written to the state directory: load them and publish.
    Issued,
}

/// The control thread's ACME client: one task per certificate the plan names.
pub(crate) struct Manager {
    challenges: Arc<Challenges>,
    tasks: Vec<Task>,
    issued: mpsc::UnboundedSender<()>,
    events: mpsc::UnboundedReceiver<()>,
}

/// A running certificate task, stopped when dropped.
struct Task {
    plan: AcmePlan,
    handle: tokio::task::AbortHandle,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl Manager {
    pub fn new() -> Manager {
        let (issued, events) = mpsc::unbounded_channel();
        Manager {
            challenges: Arc::default(),
            tasks: Vec::new(),
            issued,
            events,
        }
    }

    /// After every published generation: the certificates the plan needs. Starts or stops
    /// tasks to match; a certificate whose plan is unchanged keeps its task. Idempotent.
    pub fn set_plan(&mut self, plan: &Plan) {
        self.tasks.retain(|t| plan.acme.contains(&t.plan));
        for wanted in plan.acme.iter() {
            if self.tasks.iter().any(|t| t.plan == *wanted) {
                continue;
            }
            let task = tokio::spawn(keep(
                wanted.clone(),
                self.challenges.clone(),
                self.issued.clone(),
            ));
            self.tasks.push(Task {
                plan: wanted.clone(),
                handle: task.abort_handle(),
            });
        }
    }

    /// The answers shared with the cores: `Some` exactly when the plan has in-process ACME.
    pub fn challenges(&self, plan: &Plan) -> Option<Arc<Challenges>> {
        (!plan.acme.is_empty()).then(|| self.challenges.clone())
    }

    /// The next event. Pending forever when nothing is to be issued, so the control loop's
    /// `select!` arm costs nothing.
    pub async fn recv(&mut self) -> Event {
        match self.events.recv().await {
            Some(()) => Event::Issued,
            // The manager holds a sender, so the channel never closes.
            None => std::future::pending().await,
        }
    }
}

/// The longest a task sleeps before reading its certificate again, so a clock step or a
/// suspended host does not postpone a renewal by more than this.
const RECHECK: Duration = Duration::from_secs(3600);
const FIRST_RETRY: Duration = Duration::from_secs(60);
const LAST_RETRY: Duration = Duration::from_secs(6 * 3600);
/// The longest a CA's `Retry-After` is followed.
const LONGEST_RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);

/// Keeps one certificate issued and renewed, forever.
async fn keep(plan: AcmePlan, challenges: Arc<Challenges>, issued: mpsc::UnboundedSender<()>) {
    let http = http::Client::new();
    let jitter = random_unit();
    let name = &plan.names[0];
    let mut failures = 0;
    let mut just_issued = false;
    loop {
        let why = match due(&plan, jitter, SystemTime::now()) {
            Due::At(when) => {
                just_issued = false;
                let wait = when
                    .duration_since(SystemTime::now())
                    .unwrap_or_default()
                    .min(RECHECK);
                tokio::time::sleep(wait).await;
                continue;
            }
            Due::Now(why) => why,
        };
        let result = match just_issued {
            // A certificate due as soon as it is issued would be ordered again and again.
            true => Err(order::Failure::from(
                "the certificate the CA issued is already due for renewal".to_owned(),
            )),
            false => {
                info!(
                    "acme: ordering a certificate for {} ({why})",
                    plan.names.join(", ")
                );
                obtain(&http, &plan, &challenges).await
            }
        };
        match result {
            Ok(()) => {
                info!("acme: issued the certificate for {}", plan.names.join(", "));
                failures = 0;
                just_issued = true;
                let _ = issued.send(());
            }
            Err(failure) => {
                just_issued = false;
                failures += 1;
                let delay = backoff(failures, failure.retry_after);
                warning!(
                    "acme: {name}: {}; retrying in {}s",
                    failure.message,
                    delay.as_secs()
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// Orders a certificate and writes it to the plan's files, key first.
async fn obtain(
    http: &http::Client,
    plan: &AcmePlan,
    challenges: &Challenges,
) -> Result<(), order::Failure> {
    let key = account_key(&plan.account_key)?;
    let issued = order::issue(http, &key, plan, challenges).await?;
    let write = |path: &std::path::Path, bytes: &[u8]| {
        store::write_private(path, bytes).map_err(|e| format!("writing {}: {e}", path.display()))
    };
    write(&plan.key, issued.key_pem.as_bytes())?;
    write(&plan.cert, &issued.chain_pem)?;
    Ok(())
}

/// The account key at `path`, made and stored there when there is none. Runs without an
/// await, so tasks sharing an account never both make one.
fn account_key(path: &std::path::Path) -> Result<jws::AccountKey, String> {
    let at = |e: &dyn std::fmt::Display| format!("account key {}: {e}", path.display());
    match store::read(path).map_err(|e| at(&e))? {
        Some(pem) => {
            let der = PrivateKeyDer::from_pem_slice(&pem).map_err(|e| at(&e))?;
            jws::AccountKey::from_pkcs8(der.secret_der()).map_err(|e| at(&e))
        }
        None => {
            let (key, der) = jws::AccountKey::generate()?;
            store::write_private(path, store::pem("PRIVATE KEY", &der).as_bytes())
                .map_err(|e| at(&e))?;
            Ok(key)
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Due {
    Now(&'static str),
    At(SystemTime),
}

/// When the certificate on disk needs replacing.
fn due(plan: &AcmePlan, jitter: f64, now: SystemTime) -> Due {
    let Some(leaf) = on_disk(plan) else {
        return Due::Now("no usable certificate in the state directory");
    };
    let mut names: Vec<&str> = leaf.names.iter().map(|n| &**n).collect();
    let mut wanted: Vec<&str> = plan.names.iter().map(|n| &**n).collect();
    names.sort_unstable();
    names.dedup();
    wanted.sort_unstable();
    if names != wanted {
        return Due::Now("the certificate names other hosts than the site");
    }
    match renew_at(&leaf, jitter) {
        at if at <= now => Due::Now("renewal"),
        at => Due::At(at),
    }
}

/// The leaf of the plan's pair, when the pair loads the way `tls::load` loads it.
fn on_disk(plan: &AcmePlan) -> Option<der::Leaf> {
    let chain_pem = store::read(&plan.cert).ok()??;
    let key_pem = store::read(&plan.key).ok()??;
    let chain = CertificateDer::pem_slice_iter(&chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    let leaf = der::leaf(chain.first()?)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).ok()?;
    CertifiedKey::from_der(chain, key, &rustls::crypto::aws_lc_rs::default_provider()).ok()?;
    Some(leaf)
}

/// Two thirds into the certificate's lifetime, less `jitter` (in [0, 1)) of a thirtieth of it.
fn renew_at(leaf: &der::Leaf, jitter: f64) -> SystemTime {
    let lifetime = leaf
        .not_after
        .duration_since(leaf.not_before)
        .unwrap_or_default();
    leaf.not_before + lifetime * 2 / 3 - (lifetime / 30).mul_f64(jitter)
}

/// The wait after the `failures`th failure in a row: a minute, doubling up to six hours, or
/// the CA's `Retry-After` when that is longer (up to a day).
fn backoff(failures: u32, retry_after: Option<Duration>) -> Duration {
    let doubled = FIRST_RETRY.saturating_mul(1 << failures.saturating_sub(1).min(16));
    let ours = doubled.min(LAST_RETRY);
    retry_after.map_or(ours, |theirs| theirs.min(LONGEST_RETRY_AFTER).max(ours))
}

/// A random number in [0, 1).
fn random_unit() -> f64 {
    use aws_lc_rs::rand::SecureRandom;
    let mut bytes = [0u8; 8];
    let _ = aws_lc_rs::rand::SystemRandom::new().fill(&mut bytes);
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1u64 << 53) as f64
}

#[cfg(test)]
mod tests;
