//! Where the API server is and how to authenticate to it: the in-cluster service account or a
//! kubeconfig file with a bearer token or a client certificate.
//!
//! Not supported, and reported as such instead of ignored: `exec` and `auth-provider` plugins
//! (OIDC and cloud CLIs), basic auth, and `proxy-url`.

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// An API server and the credentials for it. One is loaded per list cycle, so a kubeconfig or
/// service account that changed on disk is picked up when the watch next relists.
pub(super) struct Cluster {
    pub endpoint: Endpoint,
    /// `None` for a plain `http://` server.
    pub tls: Option<Tls>,
    bearer: Bearer,
}

pub(super) struct Endpoint {
    pub host: String,
    pub port: u16,
    /// A path the server is mounted under (an API gateway), without a trailing slash.
    pub prefix: String,
}

pub(super) struct Tls {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
}

enum Bearer {
    None,
    Fixed(String),
    /// A projected service account token: the kubelet rewrites the file before the token
    /// expires, so it is read again whenever its modification time or size changed.
    File {
        path: PathBuf,
        seen: Option<(SystemTime, u64)>,
        token: String,
    },
}

impl Cluster {
    /// A plain HTTP server with a fixed token (or none): for tests and local API proxies.
    #[cfg(test)]
    pub fn plain(host: &str, port: u16, token: Option<&str>) -> Cluster {
        Cluster {
            endpoint: Endpoint {
                host: host.into(),
                port,
                prefix: String::new(),
            },
            tls: None,
            bearer: token.map_or(Bearer::None, |t| Bearer::Fixed(t.into())),
        }
    }

    #[cfg(test)]
    pub fn with_token_file(mut self, path: &Path) -> Cluster {
        self.bearer = Bearer::File {
            path: path.into(),
            seen: None,
            token: String::new(),
        };
        self
    }

    /// The bearer token to send now, re-reading its file when that changed.
    pub fn token(&mut self) -> Result<Option<&str>, String> {
        match &mut self.bearer {
            Bearer::None => Ok(None),
            Bearer::Fixed(token) => Ok(Some(token)),
            Bearer::File { path, seen, token } => {
                let stat = std::fs::metadata(&*path)
                    .map_err(|e| format!("token file {}: {e}", path.display()))?;
                let now = (
                    stat.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                    stat.len(),
                );
                if *seen != Some(now) {
                    let text = std::fs::read_to_string(&*path)
                        .map_err(|e| format!("token file {}: {e}", path.display()))?;
                    *token = header_safe(text.trim(), "token file")?;
                    *seen = Some(now);
                }
                Ok(Some(token))
            }
        }
    }
}

fn header_safe(token: &str, what: &str) -> Result<String, String> {
    if token.is_empty() {
        return Err(format!("{what} is empty"));
    }
    if token.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return Err(format!("{what} holds a character a header cannot carry"));
    }
    Ok(token.to_owned())
}

/// The cluster to talk to: `$KUBECONFIG` (its first file), else the in-cluster service
/// account, else `~/.kube/config`.
pub(super) fn infer() -> Result<Cluster, String> {
    if let Some(list) = std::env::var_os("KUBECONFIG").filter(|v| !v.is_empty())
        && let Some(path) = std::env::split_paths(&list).find(|p| !p.as_os_str().is_empty())
    {
        return from_kubeconfig(&path);
    }
    if let Ok(host) = std::env::var("KUBERNETES_SERVICE_HOST")
        && !host.is_empty()
    {
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
        return in_cluster(&host, &port, Path::new(SERVICE_ACCOUNT));
    }
    let home = std::env::var_os("HOME").ok_or("no KUBECONFIG, no service account and no $HOME")?;
    from_kubeconfig(&Path::new(&home).join(".kube/config"))
}

/// The pod's own service account: `token` and `ca.crt` in `dir`.
pub(super) fn in_cluster(host: &str, port: &str, dir: &Path) -> Result<Cluster, String> {
    let port: u16 = port
        .parse()
        .map_err(|_| format!("KUBERNETES_SERVICE_PORT {port:?} is not a port"))?;
    let ca = read(&dir.join("ca.crt"))?;
    let roots = roots_from_pem(&ca, "service account ca.crt")?;
    Ok(Cluster {
        endpoint: Endpoint {
            host: host.to_owned(),
            port,
            prefix: String::new(),
        },
        tls: Some(Tls {
            config: client_config(roots, None, false)?,
            name: server_name(host)?,
        }),
        bearer: Bearer::File {
            path: dir.join("token"),
            seen: None,
            token: String::new(),
        },
    })
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "kebab-case")]
struct Kubeconfig {
    current_context: Option<String>,
    clusters: Vec<Named<ClusterEntry>>,
    users: Vec<Named<UserEntry>>,
    contexts: Vec<Named<ContextEntry>>,
}

#[derive(Deserialize)]
struct Named<T> {
    name: String,
    #[serde(alias = "cluster", alias = "user", alias = "context")]
    value: Option<T>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "kebab-case")]
struct ClusterEntry {
    server: String,
    certificate_authority: Option<PathBuf>,
    certificate_authority_data: Option<String>,
    insecure_skip_tls_verify: bool,
    tls_server_name: Option<String>,
    proxy_url: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "kebab-case")]
struct UserEntry {
    token: Option<String>,
    token_file: Option<PathBuf>,
    client_certificate: Option<PathBuf>,
    client_certificate_data: Option<String>,
    client_key: Option<PathBuf>,
    client_key_data: Option<String>,
    username: Option<String>,
    exec: Option<serde_json::Value>,
    auth_provider: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ContextEntry {
    cluster: String,
    user: String,
}

/// The first file of a kubeconfig, its current context.
pub(super) fn from_kubeconfig(path: &Path) -> Result<Cluster, String> {
    let text =
        String::from_utf8(read(path)?).map_err(|_| format!("{}: not UTF-8", path.display()))?;
    let dir = path.parent().unwrap_or(Path::new("."));
    from_kubeconfig_text(&text, dir).map_err(|e| format!("{}: {e}", path.display()))
}

/// `dir` resolves the relative file paths a kubeconfig may hold.
fn from_kubeconfig_text(text: &str, dir: &Path) -> Result<Cluster, String> {
    let config: Kubeconfig = serde_json::from_value(yaml_to_json(text)?)
        .map_err(|e| format!("not a kubeconfig: {e}"))?;
    let context_name = config
        .current_context
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or("no current-context")?;
    let context = config
        .contexts
        .iter()
        .find(|c| c.name == context_name)
        .and_then(|c| c.value.as_ref())
        .ok_or_else(|| format!("current-context {context_name:?} is not in contexts"))?;
    let cluster = config
        .clusters
        .iter()
        .find(|c| c.name == context.cluster)
        .and_then(|c| c.value.as_ref())
        .ok_or_else(|| format!("cluster {:?} is not in clusters", context.cluster))?;
    let user = config
        .users
        .iter()
        .find(|u| u.name == context.user)
        .and_then(|u| u.value.as_ref());

    if cluster.proxy_url.is_some() {
        return Err("cluster proxy-url is not supported".into());
    }
    let (https, endpoint) = parse_server(&cluster.server)?;

    let mut bearer = Bearer::None;
    let mut identity = None;
    if let Some(user) = user {
        if user.exec.is_some() {
            return Err(format!(
                "user {:?} authenticates through an exec plugin, which is not supported; \
                 use a service account token or a client certificate",
                context.user
            ));
        }
        if user.auth_provider.is_some() {
            return Err(format!(
                "user {:?} authenticates through an auth-provider plugin, which is not \
                 supported; use a service account token or a client certificate",
                context.user
            ));
        }
        if user.username.is_some() {
            return Err("basic authentication is not supported".into());
        }
        if let Some(token) = &user.token {
            bearer = Bearer::Fixed(header_safe(token.trim(), "token")?);
        } else if let Some(file) = &user.token_file {
            bearer = Bearer::File {
                path: dir.join(file),
                seen: None,
                token: String::new(),
            };
        }
        let cert = pem_source(dir, &user.client_certificate, &user.client_certificate_data)?;
        let key = pem_source(dir, &user.client_key, &user.client_key_data)?;
        identity = match (cert, key) {
            (Some(cert), Some(key)) => Some((cert, key)),
            (None, None) => None,
            _ => return Err("client certificate and client key must both be set".into()),
        };
    }

    let tls = if https {
        let roots = match pem_source(
            dir,
            &cluster.certificate_authority,
            &cluster.certificate_authority_data,
        )? {
            Some(pem) => roots_from_pem(&pem, "certificate authority")?,
            None => RootCertStore::empty(),
        };
        let name = cluster.tls_server_name.as_deref().unwrap_or(&endpoint.host);
        Some(Tls {
            config: client_config(roots, identity, cluster.insecure_skip_tls_verify)?,
            name: server_name(name)?,
        })
    } else {
        None
    };
    if !https && matches!(bearer, Bearer::Fixed(_) | Bearer::File { .. }) {
        return Err("a bearer token would travel over plain http; use an https server".into());
    }
    Ok(Cluster {
        endpoint,
        tls,
        bearer,
    })
}

/// `https://host:port/prefix`, as a kubeconfig's `server` writes it.
fn parse_server(server: &str) -> Result<(bool, Endpoint), String> {
    let (https, rest) = if let Some(rest) = server.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = server.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(format!("server {server:?} is not an http(s) URL"));
    };
    let (authority, prefix) = rest.split_once('/').map_or((rest, ""), |(a, p)| (a, p));
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, tail) = v6
            .split_once(']')
            .ok_or_else(|| format!("server {server:?}: unclosed ["))?;
        (host, tail.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err(format!("server {server:?} has no host"));
    }
    let port = match port {
        Some(p) => p
            .parse()
            .map_err(|_| format!("server {server:?}: bad port {p:?}"))?,
        None if https => 443,
        None => 80,
    };
    Ok((
        https,
        Endpoint {
            host: host.to_owned(),
            port,
            prefix: match prefix.trim_end_matches('/') {
                "" => String::new(),
                p => format!("/{p}"),
            },
        },
    ))
}

fn server_name(host: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(host.to_owned()).map_err(|_| format!("{host:?} is not a valid TLS name"))
}

/// A file or its inline base64 twin (`-data`), as bytes.
fn pem_source(
    dir: &Path,
    file: &Option<PathBuf>,
    data: &Option<String>,
) -> Result<Option<Vec<u8>>, String> {
    match (data, file) {
        (Some(data), _) => base64(data).map(Some),
        (None, Some(file)) => read(&dir.join(file)).map(Some),
        (None, None) => Ok(None),
    }
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn roots_from_pem(pem: &[u8], what: &str) -> Result<RootCertStore, String> {
    let mut roots = RootCertStore::empty();
    let certs = CertificateDer::pem_slice_iter(pem).filter_map(Result::ok);
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(format!("{what} holds no certificate"));
    }
    Ok(roots)
}

fn client_config(
    roots: RootCertStore,
    identity: Option<(Vec<u8>, Vec<u8>)>,
    skip_verify: bool,
) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| e.to_string())?;
    let builder = if skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny { provider }))
    } else {
        builder.with_root_certificates(roots)
    };
    let config = match identity {
        None => builder.with_no_client_auth(),
        Some((cert, key)) => {
            let chain = CertificateDer::pem_slice_iter(&cert)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| format!("client certificate: {e}"))?;
            if chain.is_empty() {
                return Err("client certificate holds no certificate".into());
            }
            let key =
                PrivateKeyDer::from_pem_slice(&key).map_err(|e| format!("client key: {e}"))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|e| format!("client certificate does not match its key: {e}"))?
        }
    };
    Ok(Arc::new(config))
}

/// `insecure-skip-tls-verify: true`: accepts any certificate, but still checks that the
/// handshake was signed by the key the certificate presents.
#[derive(Debug)]
struct AcceptAny {
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
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
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A kubeconfig as the JSON value the typed structs read. YAML is the only reason this module
/// needs a parser; JSON documents are a subset of it.
fn yaml_to_json(text: &str) -> Result<serde_json::Value, String> {
    use saphyr::{LoadableYamlNode, Scalar, Yaml};
    use serde_json::Value;

    fn convert(node: &Yaml<'_>) -> Result<Value, String> {
        Ok(match node {
            Yaml::Value(Scalar::Null) => Value::Null,
            Yaml::Value(Scalar::Boolean(b)) => Value::Bool(*b),
            Yaml::Value(Scalar::Integer(i)) => Value::from(*i),
            Yaml::Value(Scalar::FloatingPoint(f)) => {
                serde_json::Number::from_f64(f.0).map_or(Value::Null, Value::Number)
            }
            Yaml::Value(Scalar::String(s)) | Yaml::Representation(s, _, _) => {
                Value::String(s.to_string())
            }
            Yaml::Sequence(items) => {
                Value::Array(items.iter().map(convert).collect::<Result<_, _>>()?)
            }
            Yaml::Mapping(map) => {
                let mut out = serde_json::Map::new();
                for (key, value) in map {
                    let key = match convert(key)? {
                        Value::String(s) => s,
                        other => other.to_string(),
                    };
                    out.insert(key, convert(value)?);
                }
                Value::Object(out)
            }
            Yaml::Tagged(_, inner) => convert(inner)?,
            Yaml::Alias(_) | Yaml::BadValue => return Err("unsupported YAML node".into()),
        })
    }

    let docs = Yaml::load_from_str(text).map_err(|e| format!("invalid YAML: {e}"))?;
    let doc = docs.first().ok_or("empty file")?;
    convert(doc)
}

/// Standard base64, with or without padding and line breaks.
pub(super) fn base64(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => return Err(format!("invalid base64 byte {byte:#04x}")),
        };
        acc = acc << 6 | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_decodes_what_rfc4648_lists() {
        for (encoded, plain) in [
            ("", ""),
            ("Zg==", "f"),
            ("Zm8=", "fo"),
            ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"),
            ("Zm9vYmE=", "fooba"),
            ("Zm9vYmFy", "foobar"),
            ("Zm9v\nYmFy", "foobar"),
            ("Zm9vYmFy", "foobar"),
        ] {
            assert_eq!(base64(encoded).unwrap(), plain.as_bytes(), "{encoded:?}");
        }
        assert!(base64("Zm9v!").is_err());
    }

    #[test]
    fn servers_parse_with_port_prefix_and_ipv6() {
        let (https, e) = parse_server("https://10.0.0.1:6443").unwrap();
        assert!(https && e.host == "10.0.0.1" && e.port == 6443 && e.prefix.is_empty());
        let (https, e) = parse_server("https://k8s.example.com/k8s/clusters/c-1/").unwrap();
        assert!(https && e.host == "k8s.example.com" && e.port == 443);
        assert_eq!(e.prefix, "/k8s/clusters/c-1");
        let (https, e) = parse_server("http://[::1]:8080").unwrap();
        assert!(!https && e.host == "::1" && e.port == 8080);
        assert!(parse_server("ftp://x").is_err());
        assert!(parse_server("https://:443").is_err());
    }

    const TOKEN_CONFIG: &str = r#"
apiVersion: v1
kind: Config
current-context: prod
contexts:
- name: dev
  context: {cluster: dev, user: nobody}
- name: prod
  context:
    cluster: prod
    user: robot
clusters:
- name: prod
  cluster:
    server: https://203.0.113.7:6443
    certificate-authority-data: CA_DATA
users:
- name: robot
  user:
    token: "abc.def"
"#;

    use super::super::tests::{b64, pem};

    pub(crate) fn ca_pem() -> String {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "test ca");
        pem(params.self_signed(&key).unwrap().der(), "CERTIFICATE")
    }

    fn encode(bytes: &[u8]) -> String {
        b64(bytes)
    }

    #[test]
    fn kubeconfig_with_a_token_selects_the_current_context() {
        let ca = encode(ca_pem().as_bytes());
        let text = TOKEN_CONFIG.replace("CA_DATA", &ca);
        let mut cluster = from_kubeconfig_text(&text, Path::new(".")).unwrap();
        assert_eq!(cluster.endpoint.host, "203.0.113.7");
        assert_eq!(cluster.endpoint.port, 6443);
        assert!(cluster.tls.is_some());
        assert_eq!(cluster.token().unwrap(), Some("abc.def"));
    }

    #[test]
    fn kubeconfig_errors_name_the_unsupported_mechanism() {
        let ca = encode(ca_pem().as_bytes());
        let base = TOKEN_CONFIG.replace("CA_DATA", &ca);
        let exec = base.replace(
            "token: \"abc.def\"",
            "exec: {command: aws, apiVersion: client.authentication.k8s.io/v1}",
        );
        let err = from_kubeconfig_text(&exec, Path::new(".")).err().unwrap();
        assert!(err.contains("exec plugin"), "{err}");
        let provider = base.replace("token: \"abc.def\"", "auth-provider: {name: oidc}");
        let err = from_kubeconfig_text(&provider, Path::new("."))
            .err()
            .unwrap();
        assert!(err.contains("auth-provider"), "{err}");
        let missing = base.replace("current-context: prod", "current-context: gone");
        let err = from_kubeconfig_text(&missing, Path::new("."))
            .err()
            .unwrap();
        assert!(err.contains("gone"), "{err}");
        let half = base.replace("token: \"abc.def\"", "client-certificate-data: AAAA");
        let err = from_kubeconfig_text(&half, Path::new(".")).err().unwrap();
        assert!(err.contains("both"), "{err}");
    }

    #[test]
    fn a_token_over_plain_http_is_refused() {
        let text = TOKEN_CONFIG.replace("https://", "http://").replace(
            "certificate-authority-data: CA_DATA",
            "insecure-skip-tls-verify: true",
        );
        let err = from_kubeconfig_text(&text, Path::new(".")).err().unwrap();
        assert!(err.contains("plain http"), "{err}");
    }

    #[test]
    fn a_json_kubeconfig_reads_like_its_yaml() {
        let ca = encode(ca_pem().as_bytes());
        let text = format!(
            r#"{{"current-context":"c","contexts":[{{"name":"c","context":{{"cluster":"k","user":"u"}}}}],
"clusters":[{{"name":"k","cluster":{{"server":"https://[::1]:6443","certificate-authority-data":"{ca}"}}}}],
"users":[{{"name":"u","user":{{"token":"t"}}}}]}}"#
        );
        let cluster = from_kubeconfig_text(&text, Path::new(".")).unwrap();
        assert_eq!(cluster.endpoint.host, "::1");
    }

    #[test]
    fn a_token_file_is_read_again_when_it_changes() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.crt");
        std::fs::write(&ca, ca_pem()).unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "first\n").unwrap();
        let mut cluster = in_cluster("10.96.0.1", "443", dir.path()).unwrap();
        assert_eq!(cluster.token().unwrap(), Some("first"));
        std::fs::write(&token, "second-and-longer\n").unwrap();
        assert_eq!(cluster.token().unwrap(), Some("second-and-longer"));
        std::fs::remove_file(&token).unwrap();
        assert!(
            cluster.token().is_err(),
            "a missing token is an error, not the stale one"
        );
    }
}
