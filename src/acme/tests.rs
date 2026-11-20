use super::*;
use crate::plan::CertSource;
use crate::runtime::testing::plan_from;
use crate::tls::{CertStore, TicketKeys};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, ServerConnection, SignatureScheme};
use serde_json::json;
use std::path::Path;
use std::time::UNIX_EPOCH;

fn acme_site(hosts: &[&str], acme: serde_json::Value) -> serde_json::Value {
    json!({ "name": "s", "hosts": hosts, "tls": { "acme": acme } })
}

fn config(sites: serde_json::Value, top: serde_json::Value) -> serde_json::Value {
    let mut doc = json!({ "version": 1, "sites": sites });
    for (key, value) in top.as_object().into_iter().flatten() {
        doc[key] = value.clone();
    }
    doc
}

fn errors(doc: &serde_json::Value) -> Vec<String> {
    let config =
        crate::config::parse_config(crate::config::Format::Json, doc.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message))
            .value;
    match crate::plan::compile::compile(&config, &crate::plan::compile::FileSystem, 1) {
        Ok(_) => Vec::new(),
        Err(diagnostics) => diagnostics.iter().map(ToString::to_string).collect(),
    }
}

#[test]
fn a_site_with_acme_gets_its_certificate_from_the_state_directory() {
    let plan = plan_from(
        1,
        &config(
            json!([acme_site(
                &["A.example.com", "b.example.com"],
                json!({ "email": "Ops+Certs@example.com" })
            )]),
            json!({ "acme": { "stateDirectory": "/srv/state" } }),
        ),
    );
    let base = Path::new("/srv/state/acme/acme-v02.api.letsencrypt.org_directory");
    let pair = base.join("certificates/a.example.com");
    assert_eq!(
        *plan.acme,
        [AcmePlan {
            names: ["a.example.com".into(), "b.example.com".into()].into(),
            email: "Ops+Certs@example.com".into(),
            directory: http::Url::parse("https://acme-v02.api.letsencrypt.org/directory").unwrap(),
            challenge: Challenge::Http01,
            account_key: base.join("accounts/ops+certs@example.com.pem"),
            cert: pair.join("fullchain.pem"),
            key: pair.join("key.pem"),
        }]
    );
    assert_eq!(plan.certs.len(), 1);
    let CertSource { cert, key, names } = &plan.certs[0];
    assert_eq!((cert, key), (&plan.acme[0].cert, &plan.acme[0].key));
    assert_eq!(names, &plan.acme[0].names);
    assert!(plan.acme[0].answers_http01());
}

#[test]
fn the_default_state_directory_and_another_ca_keep_files_apart() {
    let plan = plan_from(
        1,
        &config(
            json!([
                acme_site(&["a.test"], json!({ "email": "ops@example.com" })),
                {
                    "name": "staging", "hosts": ["b.test"],
                    "tls": { "acme": {
                        "email": "ops@example.com",
                        "directory": "https://acme-staging-v02.api.letsencrypt.org/directory",
                        "challenge": "tls-alpn-01",
                    } },
                },
            ]),
            json!({}),
        ),
    );
    let paths: Vec<_> = plan
        .acme
        .iter()
        .map(|p| (&p.cert, &p.account_key))
        .collect();
    assert_eq!(
        paths,
        [
            (
                &"/var/lib/upstreamer/acme/acme-v02.api.letsencrypt.org_directory/certificates/a.test/fullchain.pem".into(),
                &"/var/lib/upstreamer/acme/acme-v02.api.letsencrypt.org_directory/accounts/ops@example.com.pem".into(),
            ),
            (
                &"/var/lib/upstreamer/acme/acme-staging-v02.api.letsencrypt.org_directory/certificates/b.test/fullchain.pem".into(),
                &"/var/lib/upstreamer/acme/acme-staging-v02.api.letsencrypt.org_directory/accounts/ops@example.com.pem".into(),
            ),
        ] as [(&PathBuf, &PathBuf); 2]
    );
    assert_eq!(plan.acme[1].challenge, Challenge::TlsAlpn01);
}

#[test]
fn sites_naming_the_same_certificate_share_it_and_conflicting_ones_are_errors() {
    let same = acme_site(&["a.test"], json!({ "email": "ops@example.com" }));
    let mut other_listener = same.clone();
    other_listener["listen"] = json!(["127.0.0.1:8443"]);
    let plan = plan_from(1, &config(json!([same.clone(), other_listener]), json!({})));
    assert_eq!(plan.acme.len(), 1, "one certificate, one order");
    assert_eq!(plan.certs.len(), 1);

    let mut more_names = acme_site(&["a.test", "b.test"], json!({ "email": "ops@example.com" }));
    more_names["listen"] = json!(["127.0.0.1:8443"]);
    more_names["name"] = json!("t");
    assert_eq!(
        errors(&config(json!([same, more_names]), json!({}))),
        [
            "/sites/1/tls/acme: site `t` and an earlier site both get a certificate for `a.test` \
          from the same CA, with different names or settings; give them the same `hosts` and \
          `tls.acme`, or one site"
        ]
    );
}

#[test]
fn what_in_process_acme_cannot_issue_is_an_error() {
    let email = json!({ "email": "ops@example.com" });
    let site_errors = |hosts: &[&str], acme: serde_json::Value| {
        errors(&config(json!([acme_site(hosts, acme)]), json!({})))
    };
    assert_eq!(
        site_errors(&["*.example.com"], email.clone()),
        [
            "/sites/0/tls/acme: `*.example.com` is a wildcard, which only DNS-01 validation can \
          prove; in-process ACME validates over HTTP-01 or TLS-ALPN-01, so serve it with \
          `cert` and `key` files"
        ]
    );
    assert_eq!(
        site_errors(&["192.0.2.1"], email.clone()),
        ["/sites/0/tls/acme: `192.0.2.1` is an IP address; in-process ACME issues for host names"]
    );
    assert_eq!(
        site_errors(
            &["a.test"],
            json!({ "email": "ops@example.com", "directory": "http://ca.test/dir" })
        ),
        ["/sites/0/tls/acme/directory: \"http://ca.test/dir\" is not an https URL"]
    );
    for bad in [
        "ops",
        "ops@localhost",
        "a@b@c.test",
        "ops@example.com, evil@example.com",
        "<ops@example.com>",
    ] {
        assert_eq!(
            site_errors(&["a.test"], json!({ "email": bad })),
            [format!(
                "/sites/0/tls/acme/email: `{bad}` is not an email address"
            )],
        );
    }
    assert_eq!(
        errors(&config(
            json!([acme_site(&["a.test"], email)]),
            json!({ "acme": { "stateDirectory": "state" } })
        )),
        ["/acme/stateDirectory: `state` is not an absolute path"]
    );
}

#[test]
fn http01_puts_the_token_step_on_the_redirect_site_and_tls_alpn01_does_not() {
    let redirect_steps = |challenge: &str| {
        let plan = plan_from(
            1,
            &config(
                json!([acme_site(
                    &["a.test"],
                    json!({ "email": "ops@example.com", "challenge": challenge })
                )]),
                json!({}),
            ),
        );
        let redirect = &plan.sites[usize::from(plan.user_sites)];
        redirect
            .routes
            .steps
            .iter()
            .map(|s| s.name.as_deref().unwrap_or_default().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        redirect_steps("http-01"),
        ["acme_challenge", "redirect_http"]
    );
    assert_eq!(redirect_steps("tls-alpn-01"), ["redirect_http"]);
}

#[test]
fn http01_tokens_reach_a_site_without_the_redirect_on_the_http_addresses() {
    let http = "127.0.0.1:8080";
    for (name, site) in [
        (
            "its own listen",
            json!({ "name": "s", "hosts": ["a.test"], "listen": ["127.0.0.1:8443"],
                "tls": { "acme": { "email": "ops@example.com" } } }),
        ),
        (
            "redirectHttp: false",
            json!({ "name": "s", "hosts": ["a.test"],
                "tls": { "acme": { "email": "ops@example.com" }, "redirectHttp": false } }),
        ),
    ] {
        let plan = plan_from(
            1,
            &config(
                json!([site]),
                json!({ "listen": { "http": [http], "https": ["127.0.0.1:8444"] } }),
            ),
        );
        let listener = plan
            .listeners
            .iter()
            .find(|l| l.key.addr.to_string() == http)
            .unwrap_or_else(|| panic!("{name}: a listener on the http address"));
        assert_eq!(listener.key.kind, crate::plan::ListenerKind::Http, "{name}");
        let site = &plan.sites[usize::from(listener.hosts.lookup(b"a.test").unwrap().0)];
        assert_eq!(&*site.name, "ACME HTTP-01 tokens", "{name}");
        let steps: Vec<_> = site
            .routes
            .steps
            .iter()
            .map(|s| s.name.as_deref())
            .collect();
        assert_eq!(
            steps,
            [Some("acme_challenge"), Some("not_found")],
            "{name}: tokens, and nothing else, on the http address"
        );
        assert!(
            listener.hosts.lookup(b"b.test").is_none(),
            "{name}: other names get nothing there"
        );
    }
}

#[test]
fn answers_exist_only_while_their_validation_runs() {
    let challenges = Challenges::default();
    let token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA";
    {
        let _answer = challenges
            .answer(Challenge::Http01, "a.test", token, "key-authorization")
            .unwrap();
        assert_eq!(
            challenges.key_authorization(token.as_bytes()).as_deref(),
            Some(&b"key-authorization"[..])
        );
        assert_eq!(challenges.key_authorization(b"other"), None);
    }
    assert_eq!(challenges.key_authorization(token.as_bytes()), None);
}

/// Accepts any server certificate; the tests read it from the connection afterwards.
#[derive(Debug)]
struct AnyCert;

impl ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The leaf certificate and ALPN protocol a client offering `alpn` for `name` is given.
fn handshake(
    store: &Arc<CertStore>,
    name: &str,
    alpn: &[&[u8]],
) -> (CertificateDer<'static>, Option<Vec<u8>>) {
    let server_config =
        crate::tls::server_config(store.clone(), Arc::new(TicketKeys::generate(3600)));
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(AnyCert))
    .with_no_client_auth();
    client_config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from(name.to_owned()).unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(server_config).unwrap();
    while client.is_handshaking() || server.is_handshaking() {
        let mut wire = Vec::new();
        client.write_tls(&mut wire).unwrap();
        server.read_tls(&mut &wire[..]).unwrap();
        server.process_new_packets().unwrap();
        let mut wire = Vec::new();
        server.write_tls(&mut wire).unwrap();
        client.read_tls(&mut &wire[..]).unwrap();
        client.process_new_packets().unwrap();
    }
    let leaf = client.peer_certificates().unwrap()[0].clone().into_owned();
    (leaf, client.alpn_protocol().map(<[u8]>::to_vec))
}

/// RFC 8737 section 3: the critical id-pe-acmeIdentifier extension (1.3.6.1.5.5.7.1.31)
/// whose value is the DER OCTET STRING of SHA-256(key authorization).
fn acme_identifier(digest: &[u8]) -> Vec<u8> {
    let mut extension = vec![0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x1f];
    extension.extend([0x01, 0x01, 0xff, 0x04, 0x22, 0x04, 0x20]);
    extension.extend_from_slice(digest);
    extension
}

#[test]
fn only_an_acme_tls_1_handshake_for_a_pending_name_gets_the_validation_certificate() {
    let missing = Path::new("/nonexistent/upstreamer-acme-test");
    let source = CertSource {
        cert: missing.join("fullchain.pem"),
        key: missing.join("key.pem"),
        names: ["a.test".into(), "b.test".into()].into(),
    };
    let challenges = Arc::new(Challenges::default());
    let (mut store, _) = crate::tls::load(&[source], None);
    store.acme = Some(challenges.clone());
    let store = Arc::new(store);
    let site_cert = |name: &str| store.get(name).unwrap().key.cert[0].clone();

    let answer = challenges
        .answer(
            Challenge::TlsAlpn01,
            "a.test",
            "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
            "the key authorization",
        )
        .unwrap();
    let (leaf, alpn) = handshake(&store, "a.test", &[ALPN]);
    assert_eq!(alpn.as_deref(), Some(ALPN));
    assert_ne!(leaf, site_cert("a.test"));
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, b"the key authorization");
    let needle = acme_identifier(digest.as_ref());
    assert!(
        leaf.windows(needle.len()).any(|w| w == needle),
        "the critical acmeIdentifier extension holds SHA-256 of the key authorization"
    );
    assert_eq!(
        der::leaf(&leaf).unwrap().names,
        ["a.test".into()] as [Box<str>; 1]
    );

    let (leaf, alpn) = handshake(&store, "a.test", &[b"h2", ALPN]);
    assert_eq!(
        alpn.as_deref(),
        Some(&b"h2"[..]),
        "a client offering more is not a validation"
    );
    assert_eq!(leaf, site_cert("a.test"));
    let (leaf, _) = handshake(&store, "b.test", &[ALPN]);
    assert_eq!(
        leaf,
        site_cert("b.test"),
        "no validation is pending for b.test"
    );

    drop(answer);
    let (leaf, _) = handshake(&store, "a.test", &[ALPN]);
    assert_eq!(
        leaf,
        site_cert("a.test"),
        "the answer is gone once the validation ends"
    );
}

fn pair_plan(dir: &Path, names: &[&str]) -> AcmePlan {
    AcmePlan {
        names: names.iter().map(|n| Box::from(*n)).collect(),
        email: "ops@example.com".into(),
        directory: http::Url::parse("https://ca.test/dir").unwrap(),
        challenge: Challenge::Http01,
        account_key: dir.join("account.pem"),
        cert: dir.join("fullchain.pem"),
        key: dir.join("key.pem"),
    }
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Writes a pair for `names` valid over `[from, until]` (whole days since the epoch).
fn write_pair(plan: &AcmePlan, names: &[&str], from_day: u64, until_day: u64) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params =
        rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
            .unwrap();
    params.not_before = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(from_day * 86_400);
    params.not_after = rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(until_day * 86_400);
    let cert = params.self_signed(&key).unwrap();
    std::fs::write(&plan.cert, store::pem("CERTIFICATE", cert.der())).unwrap();
    std::fs::write(&plan.key, store::pem("PRIVATE KEY", &key.serialize_der())).unwrap();
}

#[test]
fn a_certificate_is_due_when_missing_for_other_names_or_two_thirds_through_its_life() {
    let dir = tempfile::tempdir().unwrap();
    let plan = pair_plan(dir.path(), &["a.test", "b.test"]);
    let day = |d: u64| at(d * 86_400);
    let now = day(20_030);
    assert_eq!(
        due(&plan, 0.0, now),
        Due::Now("no usable certificate in the state directory")
    );

    write_pair(&plan, &["b.test", "a.test"], 20_000, 20_090);
    assert_eq!(due(&plan, 0.0, now), Due::At(day(20_060)), "day 60 of 90");
    assert_eq!(
        due(&plan, 0.5, now),
        Due::At(day(20_060) - Duration::from_secs(36 * 3600)),
        "half of a thirtieth (three days) earlier"
    );
    assert_eq!(due(&plan, 0.0, day(20_060)), Due::Now("renewal"));
    assert_eq!(due(&plan, 0.0, day(20_100)), Due::Now("renewal"), "expired");

    write_pair(&plan, &["a.test"], 20_000, 20_090);
    assert_eq!(
        due(&plan, 0.0, now),
        Due::Now("the certificate names other hosts than the site")
    );

    write_pair(&plan, &["a.test", "b.test"], 20_000, 20_090);
    let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    std::fs::write(&plan.key, store::pem("PRIVATE KEY", &other.serialize_der())).unwrap();
    assert_eq!(
        due(&plan, 0.0, now),
        Due::Now("no usable certificate in the state directory"),
        "a key that does not match the certificate"
    );
}

#[test]
fn retries_back_off_from_a_minute_to_six_hours_or_as_the_ca_asks() {
    let minutes = |m: u64| Duration::from_secs(m * 60);
    let waits: Vec<_> = (1..=12).map(|n| backoff(n, None)).collect();
    assert_eq!(
        waits,
        [1, 2, 4, 8, 16, 32, 64, 128, 256, 360, 360, 360].map(minutes)
    );
    assert_eq!(backoff(40, None), minutes(360));
    assert_eq!(backoff(1, Some(minutes(30))), minutes(30));
    assert_eq!(
        backoff(9, Some(minutes(30))),
        minutes(256),
        "never sooner than our own wait"
    );
    assert_eq!(
        backoff(1, Some(minutes(10_000))),
        minutes(24 * 60),
        "at most a day"
    );
}

#[test]
fn the_account_key_is_made_once_and_kept_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acme/ca/accounts/ops@example.com.pem");
    let first = account_key(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let again = account_key(&path).unwrap();
    assert_eq!(
        again.key_authorization("t"),
        first.key_authorization("t"),
        "the stored key is used, not a new one"
    );
    std::fs::write(&path, b"not a key").unwrap();
    assert!(
        account_key(&path).is_err(),
        "an unreadable key is an error, not replaced"
    );
    assert_eq!(std::fs::read(&path).unwrap(), b"not a key");
}

#[test]
fn renewal_jitter_is_uniform_in_the_unit_interval() {
    let samples: Vec<f64> = (0..1000).map(|_| random_unit()).collect();
    assert!(samples.iter().all(|x| (0.0..1.0).contains(x)));
    let below_half = samples.iter().filter(|&&x| x < 0.5).count();
    assert!(
        (350..650).contains(&below_half),
        "{below_half} of 1000 below one half"
    );
}
