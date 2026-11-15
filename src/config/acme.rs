//! The schema of in-process ACME: a site's `tls.acme`, and the top-level `acme` settings every
//! such site shares.

use serde::Deserialize;
use std::path::PathBuf;

/// `tls.acme = { email = "ops@example.com", directory = "https://...", challenge = "http-01" }`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct SiteAcme {
    /// The account's contact address.
    pub email: String,
    /// The CA's directory URL. Default: Let's Encrypt's production directory.
    #[serde(default)]
    pub directory: Option<String>,
    /// How the CA validates the names. Default `http-01`.
    #[serde(default)]
    pub challenge: Option<Challenge>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum Challenge {
    /// A token under `/.well-known/acme-challenge/` on port 80 (RFC 8555 section 8.3).
    #[serde(rename = "http-01")]
    Http01,
    /// A certificate offered for the `acme-tls/1` protocol on port 443 (RFC 8737).
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

/// `acme = { stateDirectory = "/var/lib/upstreamer" }`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct AcmeSettings {
    /// Where account keys and issued certificates are kept. Default `/var/lib/upstreamer`.
    #[serde(default)]
    pub state_directory: Option<PathBuf>,
}
