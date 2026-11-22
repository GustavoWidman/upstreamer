//! HTTPS requests to an ACME CA: one connection per request (`Connection: close`), the server
//! certificate verified against the system trust store, bodies bounded in size and every
//! request bounded in time. Issuance makes a handful of requests per certificate, so this
//! favours being small over reusing connections.

use crate::net::Socket;
use crate::proxy::tls::ClientStream;
use rustls::pki_types::ServerName;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The largest response accepted. A certificate chain is a few KiB.
const MAX_RESPONSE: usize = 1 << 20;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// An `https` URL. ACME servers serve every resource over HTTPS (RFC 8555 section 6.1), so
/// nothing else parses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Url {
    /// As given; the `url` of a JWS names the resource exactly this way.
    pub text: Box<str>,
    /// Without the brackets of an IPv6 literal.
    host: Box<str>,
    port: u16,
    /// Path and query, starting with `/`.
    target: Box<str>,
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, String> {
        let rest = text
            .strip_prefix("https://")
            .ok_or_else(|| format!("{text:?} is not an https URL"))?;
        let (authority, target) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let target = target.split('#').next().unwrap_or_default();
        let target = match target.starts_with('/') {
            true => target.to_owned(),
            false => format!("/{target}"),
        };
        let bad = || format!("{text:?} has no valid host");
        if authority.contains('@') {
            return Err(format!("{text:?} carries user information"));
        }
        let (host, port) = match authority.strip_prefix('[') {
            Some(v6) => {
                let (host, after) = v6.split_once(']').ok_or_else(bad)?;
                host.parse::<std::net::Ipv6Addr>().map_err(|_| bad())?;
                (host, after.strip_prefix(':'))
            }
            None => match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            },
        };
        let port = match port {
            Some(port) => port
                .parse()
                .map_err(|_| format!("{text:?} has a bad port"))?,
            None => 443,
        };
        let valid = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':');
        if host.is_empty() || !host.bytes().all(valid) || target.bytes().any(|b| b <= b' ') {
            return Err(bad());
        }
        Ok(Url {
            text: text.into(),
            host: host.to_ascii_lowercase().into(),
            port,
            target: target.into(),
        })
    }

    /// A short, file-name-safe name for the server: host, port when not 443, and path, with
    /// every other byte replaced by `_` (`acme-v02.api.letsencrypt.org_directory`).
    pub fn file_name(&self) -> String {
        let mut name = self.host.to_string();
        if self.port != 443 {
            name.push_str(&format!("_{}", self.port));
        }
        name.push_str(&self.target);
        let name: String = name
            .chars()
            .map(|c| match c {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' => c,
                _ => '_',
            })
            .collect();
        name.trim_end_matches('_').to_owned()
    }

    fn authority(&self) -> String {
        let host = match self.host.contains(':') {
            true => format!("[{}]", self.host),
            false => self.host.to_string(),
        };
        match self.port {
            443 => host,
            port => format!("{host}:{port}"),
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// What the ACME client reads from a response.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub location: Option<String>,
    pub nonce: Option<String>,
    pub retry_after: Option<Duration>,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Head,
    /// A JWS body (`application/jose+json`).
    Post,
}

/// Makes requests with one TLS client config, built once.
pub(crate) struct Client {
    tls: Arc<rustls::ClientConfig>,
}

impl Client {
    pub fn new() -> Client {
        let mut config = (*crate::tls::client_config(true)).clone();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Client {
            tls: Arc::new(config),
        }
    }

    pub async fn request(
        &self,
        method: Method,
        url: &Url,
        body: &[u8],
    ) -> Result<Response, String> {
        tokio::time::timeout(REQUEST_TIMEOUT, self.exchange(method, url, body))
            .await
            .map_err(|_| format!("{url}: no response within {REQUEST_TIMEOUT:?}"))?
            .map_err(|e| format!("{url}: {e}"))
    }

    async fn exchange(&self, method: Method, url: &Url, body: &[u8]) -> Result<Response, String> {
        let name = ServerName::try_from(url.host.to_string()).map_err(|e| e.to_string())?;
        let sock = connect(url).await?;
        let mut stream = ClientStream::connect(sock, self.tls.clone(), name)
            .await
            .map_err(|e| format!("TLS: {e}"))?;
        let head = request_head(method, url, body.len());
        stream
            .write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        stream.write_all(body).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        let mut received = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if received.len() + n > MAX_RESPONSE {
                return Err(format!("response larger than {MAX_RESPONSE} bytes"));
            }
            received.extend_from_slice(&chunk[..n]);
        }
        parse_response(&received, method == Method::Head)
    }
}

async fn connect(url: &Url) -> Result<Socket, String> {
    let addrs = tokio::net::lookup_host((&*url.host, url.port))
        .await
        .map_err(|e| format!("resolving {}: {e}", url.host))?;
    let mut last = format!("{} resolves to no address", url.host);
    for addr in addrs {
        match tokio::time::timeout(CONNECT_TIMEOUT, Socket::connect(addr)).await {
            Ok(Ok(sock)) => return Ok(sock),
            Ok(Err(e)) => last = format!("connecting to {addr}: {e}"),
            Err(_) => last = format!("connecting to {addr}: timed out"),
        }
    }
    Err(last)
}

fn request_head(method: Method, url: &Url, body_len: usize) -> String {
    let (verb, framing) = match method {
        Method::Get => ("GET", String::new()),
        Method::Head => ("HEAD", String::new()),
        Method::Post => (
            "POST",
            format!("content-type: application/jose+json\r\ncontent-length: {body_len}\r\n"),
        ),
    };
    format!(
        "{verb} {} HTTP/1.1\r\nhost: {}\r\nuser-agent: upstreamer/{}\r\naccept: */*\r\n\
         connection: close\r\n{framing}\r\n",
        url.target,
        url.authority(),
        env!("CARGO_PKG_VERSION"),
    )
}

/// Parses a whole response read to the end of the connection. The body must be complete per
/// its framing: a short `Content-Length` body or a chunked body without its last chunk is a
/// truncated response, not a smaller one.
pub(crate) fn parse_response(bytes: &[u8], head_only: bool) -> Result<Response, String> {
    let mut fields = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut fields);
    let head_len = match parsed.parse(bytes) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => return Err("the response ended inside its head".into()),
        Err(e) => return Err(format!("bad response head: {e}")),
    };
    let mut response = Response {
        status: parsed.code.unwrap_or_default(),
        ..Response::default()
    };
    let mut length = None;
    let mut chunked = false;
    for field in parsed.headers.iter() {
        let value = || String::from_utf8_lossy(field.value).trim().to_owned();
        match field.name.to_ascii_lowercase().as_str() {
            "location" => response.location = Some(value()),
            "replay-nonce" => response.nonce = Some(value()),
            "content-type" => response.content_type = Some(value()),
            "retry-after" => {
                response.retry_after = value().parse().ok().map(Duration::from_secs);
            }
            "content-length" => {
                length = Some(
                    value()
                        .parse::<usize>()
                        .map_err(|_| "bad content-length".to_owned())?,
                );
            }
            "transfer-encoding" => chunked = value().eq_ignore_ascii_case("chunked"),
            _ => {}
        }
    }
    let rest = &bytes[head_len..];
    if head_only || response.status == 204 || response.status == 304 {
        return Ok(response);
    }
    response.body = match (chunked, length) {
        (true, _) => dechunk(rest)?,
        (false, Some(len)) if rest.len() >= len => rest[..len].to_vec(),
        (false, Some(len)) => {
            return Err(format!("body truncated at {} of {len} bytes", rest.len()));
        }
        (false, None) => rest.to_vec(),
    };
    Ok(response)
}

fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, String> {
    let truncated = || "chunked body truncated".to_owned();
    let mut body = Vec::new();
    loop {
        let line_end = memchr::memmem::find(rest, b"\r\n").ok_or_else(truncated)?;
        let size = std::str::from_utf8(&rest[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next()?.trim(), 16).ok())
            .ok_or_else(|| "bad chunk size".to_owned())?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        // The size is the server's: compared without adding to it, so no size overflows.
        if rest.len().saturating_sub(2) < size {
            return Err(truncated());
        }
        body.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
}

/// Checks what [`Url::parse`] made of a URL a CA named: the text is kept, the target is a
/// path without spaces or a fragment, the host is a lowercase name or address, the URL its
/// parts make parses back to the same parts, and the file name holds only safe bytes.
#[cfg(feature = "internals")]
pub(super) fn check_url(url: &Url) {
    assert!(url.target.starts_with('/'), "{url:?}");
    assert!(
        !url.target.bytes().any(|b| b <= b' ' || b == b'#'),
        "{url:?}"
    );
    assert!(!url.host.is_empty() && url.host.bytes().all(|b| !b.is_ascii_uppercase()));
    let again = Url::parse(&format!("https://{}{}", url.authority(), url.target))
        .unwrap_or_else(|e| panic!("{url:?} does not parse back: {e}"));
    assert_eq!(
        (&again.host, again.port, &again.target),
        (&url.host, url.port, &url.target)
    );
    let name = url.file_name();
    assert!(
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_'),
        "{name:?}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_https_with_a_host() {
        let url = Url::parse("https://acme-v02.api.letsencrypt.org/directory").unwrap();
        assert_eq!(
            (&*url.host, url.port, &*url.target),
            ("acme-v02.api.letsencrypt.org", 443, "/directory")
        );
        assert_eq!(url.authority(), "acme-v02.api.letsencrypt.org");
        assert_eq!(url.file_name(), "acme-v02.api.letsencrypt.org_directory");

        let url = Url::parse("https://[::1]:14000/dir?x=1").unwrap();
        assert_eq!(
            (&*url.host, url.port, &*url.target),
            ("::1", 14000, "/dir?x=1")
        );
        assert_eq!(url.authority(), "[::1]:14000");
        assert_eq!(url.file_name(), "__1_14000_dir_x_1");

        let url = Url::parse("https://LOCALHOST:14000").unwrap();
        assert_eq!((&*url.host, &*url.target), ("localhost", "/"));

        for bad in [
            "http://ca.example/dir",
            "https:///dir",
            "https://user@ca.example/dir",
            "https://ca.example:99999/dir",
            "https://ca example/dir",
            "https://ca.example/a b",
            "ftp://ca.example",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_request_names_its_host_and_closes_the_connection() {
        let url = Url::parse("https://ca.example:14000/acme/new-order").unwrap();
        assert_eq!(
            request_head(Method::Post, &url, 12),
            format!(
                "POST /acme/new-order HTTP/1.1\r\nhost: ca.example:14000\r\n\
                 user-agent: upstreamer/{}\r\naccept: */*\r\nconnection: close\r\n\
                 content-type: application/jose+json\r\ncontent-length: 12\r\n\r\n",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    #[test]
    fn responses_are_read_by_their_framing() {
        let response = parse_response(
            b"HTTP/1.1 201 Created\r\nReplay-Nonce: abc\r\nLocation: https://ca/o/1\r\n\
              Retry-After: 3\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
            false,
        )
        .unwrap();
        assert_eq!(
            response,
            Response {
                status: 201,
                location: Some("https://ca/o/1".into()),
                nonce: Some("abc".into()),
                retry_after: Some(Duration::from_secs(3)),
                content_type: Some("application/json".into()),
                body: b"{}".to_vec(),
            }
        );

        let chunked = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n",
            false,
        )
        .unwrap();
        assert_eq!(chunked.body, b"abcde");

        let head = parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n", true).unwrap();
        assert!(head.body.is_empty(), "a HEAD response has no body");

        let close = parse_response(b"HTTP/1.1 200 OK\r\n\r\nto the end", false).unwrap();
        assert_eq!(close.body, b"to the end");
    }

    #[test]
    fn a_chunk_larger_than_any_body_is_a_truncated_one() {
        for size in ["ffffffffffffffff", "fffffffffffffffe", "10000000000000000"] {
            let bytes =
                format!("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n{size}\r\nab");
            let parsed = parse_response(bytes.as_bytes(), false);
            assert!(parsed.is_err(), "{size}: {parsed:?}");
        }
    }

    #[test]
    fn a_truncated_response_is_an_error() {
        for bytes in [
            &b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabc",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n",
            b"HTTP/1.1 200 OK\r\nContent-",
        ] {
            assert!(
                parse_response(bytes, false).is_err(),
                "{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }
}
