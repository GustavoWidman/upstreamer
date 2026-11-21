//! One issuance (RFC 8555 section 7): the directory, the account, a new order, one
//! authorization per name, finalization with a fresh key's CSR, and the download of the chain.

use super::der;
use super::http::{Client, Method, Response, Url};
use super::jws::{AccountKey, Signer, base64url, is_token};
use super::store;
use super::{AcmePlan, Challenge, Challenges};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::time::{Duration, Instant};

/// How long one order may wait for the CA to validate a name or to issue.
const PATIENCE: Duration = Duration::from_secs(120);
/// Bounds on the wait between two polls, whatever `Retry-After` says.
const POLL_MIN: Duration = Duration::from_secs(1);
const POLL_MAX: Duration = Duration::from_secs(10);
/// How often a request rejected for its nonce is sent again with a fresh one.
const NONCE_RETRIES: usize = 5;

/// Why an issuance failed, and how long the CA asked to wait before the next.
#[derive(Debug)]
pub(super) struct Failure {
    pub message: String,
    pub retry_after: Option<Duration>,
}

impl From<String> for Failure {
    fn from(message: String) -> Failure {
        Failure {
            message,
            retry_after: None,
        }
    }
}

/// A chain the CA issued for the plan's names, checked to match the key made for it.
pub(super) struct Issued {
    pub chain_pem: Vec<u8>,
    pub key_pem: String,
}

pub(super) async fn issue(
    http: &Client,
    key: &AccountKey,
    plan: &AcmePlan,
    challenges: &Challenges,
) -> Result<Issued, Failure> {
    let mut ca = Session::open(http, key, &plan.directory).await?;
    ca.register(&plan.email).await?;
    let (order_url, order) = ca.new_order(&plan.names).await?;
    for authorization in &order.authorizations {
        let url = parse_url(authorization)?;
        ca.authorize(&url, plan, challenges).await?;
    }
    let order: Order = ca
        .poll(&order_url, |o: &Order| o.status != Status::Pending)
        .await?;
    order.expect(Status::Ready, "ready to finalize")?;

    let (csr, key_pem) = request(&plan.names)?;
    let finalize = parse_url(&order.finalize)?;
    ca.post(&finalize, &json!({ "csr": base64url(&csr) }).to_string())
        .await?;
    let order: Order = ca
        .poll(&order_url, |o: &Order| {
            !matches!(o.status, Status::Ready | Status::Processing)
        })
        .await?;
    order.expect(Status::Valid, "issued")?;
    let certificate = order
        .certificate
        .as_deref()
        .ok_or_else(|| "the valid order names no certificate".to_owned())?;
    let chain_pem = ca.post(&parse_url(certificate)?, "").await?.body;
    check_chain(&chain_pem, &key_pem, &plan.names)?;
    Ok(Issued { chain_pem, key_pem })
}

/// A new P-256 key for the certificate, and the DER CSR naming every name as a
/// subjectAltName with an empty subject (RFC 8555 section 7.4).
fn request(names: &[Box<str>]) -> Result<(Vec<u8>, String), String> {
    let fail = |e: rcgen::Error| format!("making the certificate request: {e}");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(fail)?;
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .map_err(fail)?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key).map_err(fail)?;
    let key_pem = store::pem("PRIVATE KEY", &key.serialize_der());
    Ok((csr.der().to_vec(), key_pem))
}

/// The downloaded chain parses, its leaf is for `key_pem`'s key, and it names every name.
fn check_chain(chain_pem: &[u8], key_pem: &str, names: &[Box<str>]) -> Result<(), String> {
    let chain = CertificateDer::pem_slice_iter(chain_pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("the issued chain: {e}"))?;
    let leaf = chain
        .first()
        .and_then(|c| der::leaf(c))
        .ok_or_else(|| "the issued chain has no readable certificate".to_owned())?;
    if let Some(missing) = names.iter().find(|n| !leaf.names.contains(n)) {
        return Err(format!("the issued certificate does not name {missing}"));
    }
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).map_err(|e| e.to_string())?;
    rustls::sign::CertifiedKey::from_der(
        chain,
        key,
        &rustls::crypto::aws_lc_rs::default_provider(),
    )
    .map_err(|e| format!("the issued certificate: {e}"))?;
    Ok(())
}

/// A conversation with the CA under one account key.
struct Session<'a> {
    http: &'a Client,
    key: &'a AccountKey,
    directory: Directory,
    nonce: Option<String>,
    /// The account URL, once registered.
    account: Option<String>,
}

struct Directory {
    new_nonce: Url,
    new_account: Url,
    new_order: Url,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DirectoryDoc {
    new_nonce: String,
    new_account: String,
    new_order: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Status {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
    #[serde(other)]
    Other,
}

#[derive(Deserialize)]
struct Order {
    status: Status,
    #[serde(default)]
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
    error: Option<Problem>,
}

impl Order {
    fn expect(&self, status: Status, what: &str) -> Result<(), String> {
        if self.status == status {
            return Ok(());
        }
        let mut message = format!("the order is {:?}, not {what}", self.status);
        if let Some(problem) = &self.error {
            message.push_str(&format!(": {problem}"));
        }
        Err(message)
    }
}

#[derive(Deserialize)]
struct Authorization {
    status: Status,
    identifier: Identifier,
    #[serde(default)]
    challenges: Vec<ChallengeDoc>,
}

#[derive(Deserialize)]
struct Identifier {
    value: String,
}

#[derive(Deserialize)]
struct ChallengeDoc {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    status: Status,
    token: Option<String>,
    error: Option<Problem>,
}

/// An RFC 7807 problem document, as ACME errors are (RFC 8555 section 6.7).
#[derive(Debug, Default, Deserialize)]
struct Problem {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    detail: String,
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.detail, self.kind)
    }
}

const BAD_NONCE: &str = "urn:ietf:params:acme:error:badNonce";

fn parse_url(text: &str) -> Result<Url, String> {
    Url::parse(text).map_err(|e| format!("the CA named a bad URL: {e}"))
}

fn json<T: DeserializeOwned>(response: &Response, url: &Url) -> Result<T, String> {
    serde_json::from_slice(&response.body).map_err(|e| format!("{url}: unexpected answer: {e}"))
}

/// A `Replay-Nonce` the client may use: base64url characters only (RFC 8555 section 6.5.1).
fn valid_nonce(nonce: Option<String>) -> Option<String> {
    nonce.filter(|n| {
        !n.is_empty()
            && n.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

impl<'a> Session<'a> {
    async fn open(
        http: &'a Client,
        key: &'a AccountKey,
        url: &Url,
    ) -> Result<Session<'a>, Failure> {
        let response = http.request(Method::Get, url, b"").await?;
        if response.status != 200 {
            return Err(format!("{url}: status {} for the directory", response.status).into());
        }
        let doc: DirectoryDoc = json(&response, url)?;
        Ok(Session {
            http,
            key,
            directory: Directory {
                new_nonce: parse_url(&doc.new_nonce)?,
                new_account: parse_url(&doc.new_account)?,
                new_order: parse_url(&doc.new_order)?,
            },
            nonce: None,
            account: None,
        })
    }

    /// Creates the account, or finds the one this key already has (RFC 8555 section 7.3.1).
    /// The configured address is the account's only contact; asking for an account agrees to
    /// the CA's terms of service.
    async fn register(&mut self, email: &str) -> Result<(), Failure> {
        let payload = json!({
            "termsOfServiceAgreed": true,
            "contact": [format!("mailto:{email}")],
        });
        let url = self.directory.new_account.clone();
        let response = self.post(&url, &payload.to_string()).await?;
        let account = response
            .location
            .ok_or_else(|| "the CA returned no account URL".to_owned())?;
        self.account = Some(account);
        Ok(())
    }

    async fn new_order(&mut self, names: &[Box<str>]) -> Result<(Url, Order), Failure> {
        let identifiers: Vec<_> = names
            .iter()
            .map(|n| json!({ "type": "dns", "value": n }))
            .collect();
        let url = self.directory.new_order.clone();
        let response = self
            .post(&url, &json!({ "identifiers": identifiers }).to_string())
            .await?;
        let location = response
            .location
            .as_deref()
            .ok_or_else(|| "the CA returned no order URL".to_owned())?;
        let order_url = parse_url(location)?;
        Ok((order_url, json(&response, &url)?))
    }

    /// Proves control of one name with the plan's challenge type, unless the account already
    /// has (a valid authorization is reused).
    async fn authorize(
        &mut self,
        url: &Url,
        plan: &AcmePlan,
        challenges: &Challenges,
    ) -> Result<(), Failure> {
        let authorization: Authorization = self.get(url).await?.0;
        match authorization.status {
            Status::Valid => return Ok(()),
            Status::Pending => {}
            other => {
                return Err(format!(
                    "the authorization for {} is {other:?}",
                    authorization.identifier.value
                )
                .into());
            }
        }
        let name = authorization.identifier.value.to_ascii_lowercase();
        if !plan.names.iter().any(|n| **n == *name) {
            return Err(
                format!("the CA asked to validate {name}, which the order does not name").into(),
            );
        }
        let wanted = match plan.challenge {
            Challenge::Http01 => "http-01",
            Challenge::TlsAlpn01 => "tls-alpn-01",
        };
        let challenge = authorization
            .challenges
            .iter()
            .find(|c| c.kind == wanted)
            .ok_or_else(|| format!("the CA offers no {wanted} challenge for {name}"))?;
        let token = challenge
            .token
            .as_deref()
            .filter(|t| is_token(t))
            .ok_or_else(|| format!("the {wanted} challenge for {name} has no valid token"))?;
        let key_authorization = self.key.key_authorization(token);
        let _answer = challenges.answer(plan.challenge, &name, token, &key_authorization)?;
        if challenge.status == Status::Pending {
            self.post(&parse_url(&challenge.url)?, "{}").await?;
        }
        let done: Authorization = self
            .poll(url, |a: &Authorization| a.status != Status::Pending)
            .await?;
        if done.status == Status::Valid {
            return Ok(());
        }
        let reason = done
            .challenges
            .iter()
            .find(|c| c.kind == wanted)
            .and_then(|c| c.error.as_ref())
            .map_or_else(|| format!("{:?}", done.status), ToString::to_string);
        Err(format!("{wanted} validation of {name} failed: {reason}").into())
    }

    /// POST-as-GET (RFC 8555 section 6.3), with the response's `Retry-After`.
    async fn get<T: DeserializeOwned>(
        &mut self,
        url: &Url,
    ) -> Result<(T, Option<Duration>), Failure> {
        let response = self.post(url, "").await?;
        Ok((json(&response, url)?, response.retry_after))
    }

    /// Fetches `url` until `done` holds, waiting as the CA asks between fetches.
    async fn poll<T: DeserializeOwned>(
        &mut self,
        url: &Url,
        done: impl Fn(&T) -> bool,
    ) -> Result<T, Failure> {
        let deadline = Instant::now() + PATIENCE;
        loop {
            let (value, retry_after) = self.get(url).await?;
            if done(&value) {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                return Err(
                    format!("{url}: still in progress after {}s", PATIENCE.as_secs()).into(),
                );
            }
            let wait = retry_after.unwrap_or(POLL_MIN).clamp(POLL_MIN, POLL_MAX);
            tokio::time::sleep(wait).await;
        }
    }

    /// A signed request. A `badNonce` rejection is sent again with the nonce it carried; any
    /// other error status is the CA's problem document as a failure.
    async fn post(&mut self, url: &Url, payload: &str) -> Result<Response, Failure> {
        for attempt in 1.. {
            let nonce = match self.nonce.take() {
                Some(nonce) => nonce,
                None => self.fresh_nonce().await?,
            };
            let signer = match &self.account {
                Some(account) => Signer::Kid(account),
                None => Signer::Jwk,
            };
            let body = self.key.sign(signer, &nonce, &url.text, payload);
            let response = self.http.request(Method::Post, url, &body).await?;
            self.nonce = valid_nonce(response.nonce.clone());
            if response.status < 400 {
                return Ok(response);
            }
            let problem: Problem = serde_json::from_slice(&response.body).unwrap_or_default();
            if problem.kind == BAD_NONCE && attempt < NONCE_RETRIES {
                continue;
            }
            return Err(Failure {
                message: format!("{url}: status {}: {problem}", response.status),
                retry_after: response.retry_after,
            });
        }
        unreachable!("the loop returns")
    }

    async fn fresh_nonce(&mut self) -> Result<String, Failure> {
        let url = &self.directory.new_nonce;
        let response = self.http.request(Method::Head, url, b"").await?;
        valid_nonce(response.nonce).ok_or_else(|| format!("{url}: no Replay-Nonce").into())
    }
}

/// Fuzz entry points; not part of the API.
#[cfg(feature = "internals")]
pub mod harness {
    use super::super::http::{check_url, parse_response};
    use super::*;

    /// A response from an ACME server, read to the end of the connection. The first byte
    /// says whether it answers a HEAD (bit 0), which document its body should be (bits 4
    /// and 5), and the chunk size its body is framed again with (bits 1 to 3).
    ///
    /// A body is never more than the bytes it came in, and framed again by length or by
    /// chunks it reads back the same. Every URL the client would follow, from the documents
    /// or the `Location`, is checked as [`check_url`] says, and a nonce it would send is
    /// base64url.
    pub fn response_input(data: &[u8]) {
        let Some((&options, bytes)) = data.split_first() else {
            return;
        };
        let head_only = options & 1 != 0;
        let Ok(response) = parse_response(bytes, head_only) else {
            return;
        };
        assert!(response.body.len() <= bytes.len());
        let bodiless = head_only || matches!(response.status, 204 | 304);
        assert!(!bodiless || response.body.is_empty());
        if !bodiless {
            let status = format!("HTTP/1.1 {:03} X\r\n", response.status);
            let mut length =
                format!("{status}content-length: {}\r\n\r\n", response.body.len()).into_bytes();
            length.extend_from_slice(&response.body);
            let mut chunked = format!("{status}transfer-encoding: chunked\r\n\r\n").into_bytes();
            for chunk in response.body.chunks(1 + usize::from(options >> 1 & 7) * 9) {
                chunked.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
                chunked.extend_from_slice(chunk);
                chunked.extend_from_slice(b"\r\n");
            }
            chunked.extend_from_slice(b"0\r\n\r\n");
            for framed in [length, chunked] {
                let again = parse_response(&framed, false).expect("a framed body parses");
                assert_eq!(again.status, response.status);
                assert_eq!(again.body, response.body);
            }
        }
        if let Some(nonce) = valid_nonce(response.nonce.clone()) {
            assert!(
                nonce
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            );
        }
        let urls: Vec<String> = match options >> 4 & 3 {
            0 => serde_json::from_slice::<DirectoryDoc>(&response.body)
                .map(|d| vec![d.new_nonce, d.new_account, d.new_order])
                .unwrap_or_default(),
            1 => serde_json::from_slice::<Order>(&response.body)
                .map(|o| {
                    let _ = o.expect(Status::Ready, "ready");
                    let mut urls = o.authorizations;
                    urls.push(o.finalize);
                    urls.extend(o.certificate);
                    urls
                })
                .unwrap_or_default(),
            2 => serde_json::from_slice::<Authorization>(&response.body)
                .map(|a| {
                    let _ = a.identifier.value.to_ascii_lowercase();
                    for c in &a.challenges {
                        let _ = c.token.as_deref().filter(|t| is_token(t));
                        let _ = c.error.as_ref().map(ToString::to_string);
                    }
                    a.challenges.into_iter().map(|c| c.url).collect()
                })
                .unwrap_or_default(),
            _ => {
                let problem: Problem = serde_json::from_slice(&response.body).unwrap_or_default();
                let _ = problem.to_string();
                Vec::new()
            }
        };
        for url in urls.iter().chain(&response.location) {
            if let Ok(url) = parse_url(url) {
                check_url(&url);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(list: &[&str]) -> Vec<Box<str>> {
        list.iter().map(|n| Box::from(*n)).collect()
    }

    /// A chain for `names` signed by the key of `key_pem`.
    fn chain(key_pem: &str, names: &[&str]) -> Vec<u8> {
        let der = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
        let key = rcgen::KeyPair::try_from(&der).unwrap();
        let params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        store::pem("CERTIFICATE", params.self_signed(&key).unwrap().der()).into_bytes()
    }

    #[test]
    fn an_issued_chain_must_name_every_host_and_match_the_requested_key() {
        let wanted = names(&["a.test", "b.test"]);
        let (_, key_pem) = request(&wanted).unwrap();
        assert!(check_chain(&chain(&key_pem, &["b.test", "a.test"]), &key_pem, &wanted).is_ok());
        assert_eq!(
            check_chain(&chain(&key_pem, &["a.test"]), &key_pem, &wanted).unwrap_err(),
            "the issued certificate does not name b.test"
        );
        let (_, other_key) = request(&wanted).unwrap();
        assert!(
            check_chain(&chain(&other_key, &["a.test", "b.test"]), &key_pem, &wanted).is_err(),
            "a certificate for another key"
        );
        assert!(
            check_chain(b"", &key_pem, &wanted).is_err(),
            "no certificate"
        );
    }

    #[test]
    fn only_base64url_nonces_are_used() {
        assert_eq!(
            valid_nonce(Some("abc-_09".into())).as_deref(),
            Some("abc-_09")
        );
        for bad in ["", "a b", "a+b", "a/b", "a=b"] {
            assert_eq!(valid_nonce(Some(bad.into())), None, "{bad:?}");
        }
        assert_eq!(valid_nonce(None), None);
    }
}
