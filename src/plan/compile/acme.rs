//! Lowering of a site's `tls.acme`.

use super::{Compiler, Where};
use crate::acme::AcmePlan;
use crate::acme::http::Url;
use crate::config::SiteTls;
use crate::config::acme::{AcmeSettings, Challenge, SiteAcme};
use crate::plan::CertSource;
use std::path::{Path, PathBuf};

/// Let's Encrypt's production directory.
const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";
const STATE_DIRECTORY: &str = "/var/lib/upstreamer";

impl Compiler<'_> {
    /// The certificate source of a TLS site whose names get certificates from an ACME CA,
    /// recording what the ACME client must issue in `self.acme`. `None` (with a diagnostic)
    /// when the site cannot be served that way.
    ///
    /// The pair lives at `<stateDirectory>/acme/<CA>/certificates/<first name>/` and the
    /// account key at `<stateDirectory>/acme/<CA>/accounts/<email>.pem`, so a second CA (the
    /// staging one, say) never overwrites the first one's files.
    pub(super) fn acme_certificate(
        &mut self,
        site: &str,
        names: Vec<Box<str>>,
        spec: &SiteAcme,
        settings: Option<&AcmeSettings>,
        tls: &SiteTls,
        at: &Where,
    ) -> Option<CertSource> {
        let errors = self.diags.len();
        let state = settings
            .and_then(|s| s.state_directory.as_deref())
            .unwrap_or(Path::new(STATE_DIRECTORY));
        if !state.is_absolute() {
            self.error(
                &Where {
                    file: None,
                    ptr: "/acme/stateDirectory".into(),
                },
                format!("`{}` is not an absolute path", state.display()),
            );
        }
        let mut hosts: Vec<Box<str>> = Vec::new();
        for name in names {
            if name.starts_with('*') {
                self.error(
                    at,
                    format!(
                        "`{name}` is a wildcard, which only DNS-01 validation can prove; \
                         in-process ACME validates over HTTP-01 or TLS-ALPN-01, so serve it \
                         with `cert` and `key` files"
                    ),
                );
            } else if name.parse::<std::net::IpAddr>().is_ok() {
                self.error(
                    at,
                    format!("`{name}` is an IP address; in-process ACME issues for host names"),
                );
            } else {
                hosts.push(name);
            }
        }
        let challenge = spec.challenge.unwrap_or(Challenge::Http01);
        if challenge == Challenge::Http01 && !tls.redirect_http {
            self.error(
                at,
                "http-01 tokens are answered on the http addresses by the HTTP->HTTPS redirect, \
                 which `redirectHttp: false` turns off; use `\"challenge\": \"tls-alpn-01\"` \
                 or keep the redirect",
            );
        }
        let directory = match Url::parse(spec.directory.as_deref().unwrap_or(LETS_ENCRYPT)) {
            Ok(url) => Some(url),
            Err(e) => {
                self.error(&at.at("directory"), e);
                None
            }
        };
        if !is_email(&spec.email) {
            self.error(
                &at.at("email"),
                format!("`{}` is not an email address", spec.email),
            );
        }
        let (Some(directory), Some(first)) = (directory, hosts.first().cloned()) else {
            return None;
        };
        if self.diags.len() > errors {
            return None;
        }

        let base = state.join("acme").join(directory.file_name());
        let pair = base.join("certificates").join(&*first);
        let plan = AcmePlan {
            account_key: base.join("accounts").join(account_file(&spec.email)),
            cert: pair.join("fullchain.pem"),
            key: pair.join("key.pem"),
            names: hosts.into(),
            email: spec.email.as_str().into(),
            directory,
            challenge,
        };
        let source = CertSource {
            cert: plan.cert.clone(),
            key: plan.key.clone(),
            names: plan.names.clone(),
        };
        match self.acme.iter().find(|p| p.cert == plan.cert) {
            Some(same) if *same == plan => {}
            Some(_) => {
                self.error(
                    at,
                    format!(
                        "site `{site}` and an earlier site both get a certificate for `{first}` \
                         from the same CA, with different names or settings; give them the \
                         same `hosts` and `tls.acme`, or one site"
                    ),
                );
                return None;
            }
            None => self.acme.push(plan),
        }
        Some(source)
    }
}

/// `local@domain`, with no whitespace, commas or angle brackets (a `mailto:` URI holds it).
fn is_email(text: &str) -> bool {
    let Some((local, domain)) = text.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && text
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b',' | b'<' | b'>' | b'?' | b'/'))
        && !domain.contains('@')
}

/// The account key's file name: the address, with every byte a file name should not hold
/// replaced by `_`.
fn account_file(email: &str) -> PathBuf {
    let name: String = email
        .to_ascii_lowercase()
        .chars()
        .map(|c| match c {
            'a'..='z' | '0'..='9' | '.' | '-' | '+' | '@' => c,
            _ => '_',
        })
        .collect();
    format!("{name}.pem").into()
}
