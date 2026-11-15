//! In-process ACME through the real binary.
//!
//! Without a CA: what a site with `tls.acme` serves before any issuance (a self-signed
//! certificate, the HTTP->HTTPS redirect, 404 for unknown tokens).
//!
//! Against pebble, the ACME test server, with its DNS server (pebble-challtestsrv) resolving
//! every name to 127.0.0.1: HTTP-01 and TLS-ALPN-01 issuance, the issued chain served without
//! a restart, a name whose validation fails beside them, the state directory kept across a
//! restart, and renewal two thirds into a certificate's life. Pebble rejects a tenth of the
//! nonces, so the client's `badNonce` retry runs too. These tests look for `pebble` and
//! `pebble-challtestsrv` in `$PEBBLE` (a directory) or on `PATH`, and say they skipped when
//! neither has them: `PEBBLE=$(nix build --print-out-paths nixpkgs#pebble)/bin cargo test
//! --test e2e_acme`.

mod support;

use rustls::RootCertStore;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::clients::{h1_tls_get, served_chain};
use support::{PATIENCE, Reserved};

/// How long issuance may take: pebble validates at once, and a failed order is retried a minute later.
const ISSUANCE: Duration = Duration::from_secs(90);

/// A running `upstreamer run` with its own http and https addresses, stopped when dropped.
struct Upstreamer {
    child: Child,
    /// Kept open so the proxy's notifications have a receiver.
    _notify: UnixDatagram,
    http: SocketAddr,
    https: SocketAddr,
    ports: Option<(Reserved, Reserved)>,
}

impl Upstreamer {
    /// `sites` on fresh loopback ports, with the state directory `state`; `trust` is the CA
    /// bundle the ACME client verifies the CA's server with.
    fn start(
        sites: Value,
        state: &Path,
        trust: Option<&Path>,
        ports: Option<(Reserved, Reserved)>,
    ) -> Upstreamer {
        let (http_port, https_port) = ports.unwrap_or_else(|| (Reserved::new(), Reserved::new()));
        let config = state.join("config.json");
        let doc = json!({
            "version": 1,
            "workers": 2,
            "http3": false,
            "listen": { "http": [http_port.addr], "https": [https_port.addr] },
            "timeouts": { "shutdown": "1s" },
            "acme": { "stateDirectory": state },
            "sites": sites,
        });
        std::fs::write(&config, doc.to_string()).unwrap();
        let notify_path = state.join("notify");
        let _ = std::fs::remove_file(&notify_path);
        let notify = UnixDatagram::bind(&notify_path).unwrap();
        notify.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_upstreamer"));
        command
            .arg("run")
            .arg(&config)
            .env("NOTIFY_SOCKET", &notify_path)
            .stdin(Stdio::null());
        if let Some(trust) = trust {
            command.env("SSL_CERT_FILE", trust);
        }
        let child = command.spawn().expect("the upstreamer binary starts");
        let mut buf = [0u8; 4096];
        let n = notify.recv(&mut buf).expect("upstreamer becomes ready");
        assert!(
            buf[..n].starts_with(b"READY=1"),
            "{}",
            String::from_utf8_lossy(&buf[..n])
        );
        Upstreamer {
            child,
            _notify: notify,
            http: http_port.addr,
            https: https_port.addr,
            ports: Some((http_port, https_port)),
        }
    }

    /// Stops the process and hands back its ports, for a restart on the same addresses.
    fn stop(mut self) -> (Reserved, Reserved) {
        self.terminate();
        self.ports.take().unwrap()
    }

    fn terminate(&mut self) {
        // SAFETY: signals the child this test started and has not waited for.
        unsafe { libc::kill(self.child.id() as i32, libc::SIGTERM) };
        let _ = self.child.wait();
    }

    /// The leaf certificate served for `name`.
    fn leaf(&self, name: &str) -> CertificateDer<'static> {
        served_chain(self.https, name).remove(0)
    }
}

impl Drop for Upstreamer {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            self.terminate();
        }
    }
}

fn site(name: &str, hosts: &[&str], acme: Value) -> Value {
    json!({
        "name": name,
        "hosts": hosts,
        "tls": { "acme": acme },
        "routes": [{ "respond": { "body": format!("site {name}") } }],
    })
}

/// A raw HTTP/1.1 request on the http address; the status line and the whole response.
fn http_get(addr: SocketAddr, host: &str, path: &str) -> String {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(PATIENCE)).unwrap();
    write!(
        sock,
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut response = String::new();
    sock.read_to_string(&mut response).unwrap();
    response
}

fn is_self_signed(leaf: &CertificateDer<'_>) -> bool {
    let (issuer, subject) = issuer_and_subject(leaf);
    issuer == subject
}

/// The issuer and subject Names of a DER certificate (RFC 5280 section 4.1).
fn issuer_and_subject(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    fn next<'a>(input: &mut &'a [u8]) -> (u8, &'a [u8], &'a [u8]) {
        let tag = input[0];
        let (len, header) = match input[1] {
            n if n < 0x80 => (usize::from(n), 2),
            n => {
                let count = usize::from(n & 0x7f);
                let len = input[2..2 + count]
                    .iter()
                    .fold(0, |l, &b| l << 8 | usize::from(b));
                (len, 2 + count)
            }
        };
        let whole = &input[..header + len];
        let body = &input[header..header + len];
        *input = &input[header + len..];
        (tag, body, whole)
    }
    let mut input = der;
    let (_, mut cert, _) = next(&mut input);
    let (_, mut tbs, _) = next(&mut cert);
    if tbs[0] == 0xa0 {
        next(&mut tbs);
    }
    next(&mut tbs); // serial
    next(&mut tbs); // signature algorithm
    let (_, _, issuer) = next(&mut tbs);
    next(&mut tbs); // validity
    let (_, _, subject) = next(&mut tbs);
    (issuer.to_vec(), subject.to_vec())
}

/// A PEM block (RFC 7468).
fn pem(label: &str, der: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut body = String::new();
    for chunk in der.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            body.push(match i <= chunk.len() {
                true => ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char,
                false => '=',
            });
        }
    }
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|l| std::str::from_utf8(l).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

fn roots(certs: &[CertificateDer<'static>]) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(certs.iter().cloned());
    roots
}

#[test]
fn before_issuance_a_site_serves_a_self_signed_certificate_and_the_redirect() {
    let state = tempfile::tempdir().unwrap();
    // A CA that never answers: issuance fails and is retried a minute later.
    let unreachable = support::closed_addr();
    let acme =
        json!({ "email": "ops@example.com", "directory": format!("https://{unreachable}/dir") });
    let proxy = Upstreamer::start(
        json!([site("a", &["a.test"], acme)]),
        state.path(),
        None,
        None,
    );

    let leaf = proxy.leaf("a.test");
    assert!(
        is_self_signed(&leaf),
        "self-signed until the first issuance"
    );
    let reply = h1_tls_get(proxy.https, "a.test", "/").unwrap();
    assert_eq!((reply.status, reply.text()), (200, "site a".to_owned()));

    let token = http_get(
        proxy.http,
        "a.test",
        "/.well-known/acme-challenge/evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA",
    );
    assert!(
        token.starts_with("HTTP/1.1 404 "),
        "no validation is pending: {token}"
    );
    let other = http_get(proxy.http, "a.test", "/page?q=1");
    assert!(other.starts_with("HTTP/1.1 308 "), "{other}");
    assert!(
        other.contains(&format!(
            "location: https://a.test:{}/page?q=1",
            proxy.https.port()
        )),
        "{other}"
    );
}

/// pebble and pebble-challtestsrv, killed when dropped.
struct Pebble {
    children: Vec<Child>,
    /// The ACME directory URL.
    directory: String,
    /// The root that signs pebble's own HTTPS certificate, which the proxy must trust.
    wfe_root: PathBuf,
    /// The root that signs the certificates pebble issues.
    issuer_root: CertificateDer<'static>,
    dns_management: SocketAddr,
    _dir: tempfile::TempDir,
}

/// The directory holding `pebble` and `pebble-challtestsrv`, if any.
fn pebble_bin() -> Option<PathBuf> {
    let dirs = std::env::var_os("PEBBLE")
        .into_iter()
        .chain(std::env::var_os("PATH"))
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>());
    dirs.into_iter()
        .find(|d| d.join("pebble").is_file() && d.join("pebble-challtestsrv").is_file())
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

impl Pebble {
    /// Validates on the proxy's `http` and `https` ports and issues certificates valid for
    /// `validity` seconds. `None` when pebble is not installed.
    fn start(http: SocketAddr, https: SocketAddr, validity: u64) -> Option<Pebble> {
        let Some(bin) = pebble_bin() else {
            eprintln!("skipped: no pebble and pebble-challtestsrv in $PEBBLE or on PATH");
            return None;
        };
        let dir = tempfile::tempdir().unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(rcgen::DnType::CommonName, "test WFE root");
        let ca_cert = ca.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca, ca_key);
        let wfe_key = rcgen::KeyPair::generate().unwrap();
        let wfe =
            rcgen::CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
                .unwrap()
                .signed_by(&wfe_key, &issuer)
                .unwrap();
        let wfe_root = dir.path().join("wfe-root.pem");
        std::fs::write(&wfe_root, pem("CERTIFICATE", ca_cert.der())).unwrap();
        std::fs::write(dir.path().join("wfe.pem"), pem("CERTIFICATE", wfe.der())).unwrap();
        std::fs::write(
            dir.path().join("wfe.key"),
            pem("PRIVATE KEY", &wfe_key.serialize_der()),
        )
        .unwrap();

        let (listen, management) = (free_port(), free_port());
        let (dns, dns_management) = (free_port(), free_port());
        let config = json!({ "pebble": {
            "listenAddress": listen,
            "managementListenAddress": management,
            "certificate": dir.path().join("wfe.pem"),
            "privateKey": dir.path().join("wfe.key"),
            "httpPort": http.port(),
            "tlsPort": https.port(),
            "ocspResponderURL": "",
            "externalAccountBindingRequired": false,
            "strict": true,
            "retryAfter": { "authz": 1, "order": 1 },
            "profiles": { "default": { "description": "test", "validityPeriod": validity } },
        }});
        let config_path = dir.path().join("pebble.json");
        std::fs::write(&config_path, config.to_string()).unwrap();

        let quiet = || Stdio::from(std::fs::File::create("/dev/null").unwrap());
        let dns_server = Command::new(bin.join("pebble-challtestsrv"))
            .args([
                "-dnsserver",
                &dns.to_string(),
                "-management",
                &dns_management.to_string(),
            ])
            .args(["-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""])
            .args(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
            .stdout(quiet())
            .stderr(quiet())
            .spawn()
            .unwrap();
        let pebble = Command::new(bin.join("pebble"))
            .arg("-config")
            .arg(&config_path)
            .args(["-dnsserver", &dns.to_string()])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "10")
            .env("PEBBLE_AUTHZREUSE", "0")
            .stdout(quiet())
            .stderr(quiet())
            .spawn()
            .unwrap();
        let mut pebble = Pebble {
            children: vec![dns_server, pebble],
            directory: format!("https://localhost:{}/dir", listen.port()),
            wfe_root,
            issuer_root: CertificateDer::from(Vec::new()),
            dns_management,
            _dir: dir,
        };
        let root_pem = pebble.management_get(management, "/roots/0");
        pebble.issuer_root = CertificateDer::from_pem_slice(root_pem.as_bytes()).unwrap();
        Some(pebble)
    }

    /// A GET on pebble's management interface, retried until pebble listens.
    fn management_get(&self, addr: SocketAddr, path: &str) -> String {
        let pem = std::fs::read(&self.wfe_root).unwrap();
        let root = CertificateDer::from_pem_slice(&pem).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots(&[root]))
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let deadline = Instant::now() + PATIENCE;
        loop {
            if let Ok(mut sock) = TcpStream::connect(addr) {
                let name = ServerName::try_from("localhost").unwrap();
                let mut tls = rustls::ClientConnection::new(config.clone(), name).unwrap();
                let mut stream = rustls::Stream::new(&mut tls, &mut sock);
                write!(
                    stream,
                    "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                let mut response = Vec::new();
                let _ = stream.read_to_end(&mut response);
                let response = String::from_utf8_lossy(&response).into_owned();
                let (head, body) = response.split_once("\r\n\r\n").unwrap();
                assert!(head.starts_with("HTTP/1.1 200"), "{head}");
                return body.to_owned();
            }
            assert!(Instant::now() < deadline, "pebble never listened");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Makes the DNS server answer `name` with an address nothing listens on.
    fn misdirect(&self, name: &str) {
        let body = json!({ "host": format!("{name}."), "addresses": ["127.0.0.2"] }).to_string();
        let mut sock = TcpStream::connect(self.dns_management).unwrap();
        write!(
            sock,
            "POST /add-a HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
        let mut response = String::new();
        sock.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    }

    fn acme(&self, challenge: &str) -> Value {
        json!({ "email": "ops@example.com", "directory": self.directory, "challenge": challenge })
    }

    /// Whether `leaf` (served for `name`) chains to the root pebble issues under.
    fn issued(&self, name: &str, chain: &[CertificateDer<'static>]) -> bool {
        let verifier =
            WebPkiServerVerifier::builder(Arc::new(roots(std::slice::from_ref(&self.issuer_root))))
                .build()
                .unwrap();
        verifier
            .verify_server_cert(
                &chain[0],
                &chain[1..],
                &ServerName::try_from(name.to_owned()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    /// Waits until `proxy` serves `name` a chain pebble issued, other than `not`.
    fn wait_issued(
        &self,
        proxy: &Upstreamer,
        name: &str,
        not: Option<&CertificateDer<'_>>,
    ) -> CertificateDer<'static> {
        let deadline = Instant::now() + ISSUANCE;
        loop {
            let chain = served_chain(proxy.https, name);
            if self.issued(name, &chain) && Some(&chain[0]) != not {
                return chain[0].clone();
            }
            assert!(
                Instant::now() < deadline,
                "{name}: no certificate from pebble in {ISSUANCE:?}"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        for child in &mut self.children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn http01_and_tls_alpn01_issue_and_the_state_directory_survives_a_restart() {
    let ports = (Reserved::new(), Reserved::new());
    let Some(pebble) = Pebble::start(ports.0.addr, ports.1.addr, 90 * 86_400) else {
        return;
    };
    pebble.misdirect("unreachable.test");
    let state = tempfile::tempdir().unwrap();
    let sites = json!([
        site("web", &["web.test", "www.web.test"], pebble.acme("http-01")),
        site("alpn", &["alpn.test"], pebble.acme("tls-alpn-01")),
        site("down", &["unreachable.test"], pebble.acme("http-01")),
    ]);
    let proxy = Upstreamer::start(
        sites.clone(),
        state.path(),
        Some(&pebble.wfe_root),
        Some(ports),
    );

    let web = pebble.wait_issued(&proxy, "web.test", None);
    assert_eq!(
        proxy.leaf("www.web.test"),
        web,
        "one certificate for the site's names"
    );
    let alpn = pebble.wait_issued(&proxy, "alpn.test", None);
    let reply = h1_tls_get(proxy.https, "alpn.test", "/").unwrap();
    assert_eq!((reply.status, reply.text()), (200, "site alpn".to_owned()));
    assert!(
        is_self_signed(&proxy.leaf("unreachable.test")),
        "a name pebble cannot validate keeps its self-signed certificate"
    );
    let reply = h1_tls_get(proxy.https, "unreachable.test", "/").unwrap();
    assert_eq!(reply.text(), "site down");

    let ca_dir = state.path().join(format!(
        "acme/localhost_{}_dir",
        pebble
            .directory
            .trim_end_matches("/dir")
            .rsplit(':')
            .next()
            .unwrap()
    ));
    let pair = ca_dir.join("certificates/web.test");
    for private in [
        pair.join("key.pem"),
        ca_dir.join("accounts/ops@example.com.pem"),
    ] {
        assert_eq!(mode(&private), 0o600, "{}", private.display());
    }
    for dir in [state.path().join("acme"), ca_dir.clone(), pair.clone()] {
        assert_eq!(mode(&dir), 0o700, "{}", dir.display());
    }

    let ports = proxy.stop();
    let proxy = Upstreamer::start(sites, state.path(), Some(&pebble.wfe_root), Some(ports));
    assert_eq!(
        proxy.leaf("web.test"),
        web,
        "served from the state directory at startup"
    );
    assert_eq!(proxy.leaf("alpn.test"), alpn);
}

#[test]
fn a_certificate_is_renewed_two_thirds_into_its_life() {
    let ports = (Reserved::new(), Reserved::new());
    let Some(pebble) = Pebble::start(ports.0.addr, ports.1.addr, 12) else {
        return;
    };
    let state = tempfile::tempdir().unwrap();
    let sites = json!([site("short", &["short.test"], pebble.acme("tls-alpn-01"))]);
    let proxy = Upstreamer::start(sites, state.path(), Some(&pebble.wfe_root), Some(ports));
    let first = pebble.wait_issued(&proxy, "short.test", None);
    let issued_at = Instant::now();
    let second = pebble.wait_issued(&proxy, "short.test", Some(&first));
    let after = issued_at.elapsed();
    assert!(
        after >= Duration::from_secs(5) && after < Duration::from_secs(12),
        "renewed {after:?} after the first issuance, about 8s into a 12s life"
    );
    assert_ne!(first, second);
}
