//! The fleet's sites through the real binary: the routing tables of
//! `tests/fixtures/routing` replayed as requests, and the full chains (static files,
//! sidecars, compression, error pages, a proxied API) of the two sites that have them.
//!
//! The fixture configs describe TLS sites. They are served here over cleartext, by dropping
//! each site's `tls`: routing, files and proxying are the same behind either listener.

mod support;

use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use support::{Client, Origin, Proxy, ok};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A fixture site, started: its config with `@out@` standing for `out`, included fragments
/// copied next to it with the same substitution, `tls` dropped, and the API origin's address
/// in place of the one the config names.
struct Site {
    proxy: Proxy,
    out: PathBuf,
    _fragments: tempfile::TempDir,
}

impl Site {
    fn start(config: &str, out: &Path, api: Option<&Origin>) -> Site {
        let routing = fixtures().join("routing");
        let fragments = tempfile::tempdir().unwrap();
        let subst = |text: String| {
            let text = text
                .replace("@out@", &out.display().to_string())
                .replace("@fixtures@", &fragments.path().display().to_string());
            match api {
                Some(api) => text.replace("http://127.0.0.1:7979", &api.url()),
                None => text,
            }
        };
        let config = routing.join(config);
        let siblings = config.parent().unwrap();
        let copies = fragments.path().join(siblings.file_name().unwrap());
        std::fs::create_dir(&copies).unwrap();
        for entry in std::fs::read_dir(siblings).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let text = subst(std::fs::read_to_string(&path).unwrap());
                std::fs::write(copies.join(path.file_name().unwrap()), text).unwrap();
            }
        }
        let mut doc: Value =
            serde_json::from_str(&subst(std::fs::read_to_string(&config).unwrap())).unwrap();
        let mut sites = doc["sites"].take();
        for site in sites.as_array_mut().unwrap() {
            site.as_object_mut().unwrap().remove("tls");
        }
        Site {
            proxy: Proxy::start(sites),
            out: out.to_path_buf(),
            _fragments: fragments,
        }
    }

    fn file(&self, rel: &str) -> Vec<u8> {
        std::fs::read(self.out.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }
}

#[derive(Deserialize)]
struct Table {
    config: String,
    out: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    /// `METHOD scheme://host/target`.
    request: String,
    #[serde(default)]
    headers: Vec<(String, String)>,
    /// What routing decides: `proxy <origin>`, `files <root>`, `respond <status> <body>`,
    /// `redirect <status> <location>`, `error <status>`, or `none` (no site).
    outcome: String,
    /// The path after routing.
    path: Option<String>,
    /// The request-target that goes upstream.
    target: Option<String>,
    /// Every response header op routing left, in order; `null` removes.
    ops: Option<Vec<(String, Option<String>)>>,
    /// A status the handler is assumed to fail with.
    fail: Option<u16>,
    /// What the error routes answer: an outcome, or `bare`.
    then: Option<String>,
}

/// What the file server sends for `path` under `root`: the file, or a directory's
/// `index.html`. `None` for what it answers 404: nothing there, or one of its own sidecars.
fn served_file(root: &str, path: &str) -> Option<Vec<u8>> {
    let full = PathBuf::from(format!("{root}{path}"));
    for ext in [".br", ".zst", ".gz", ".etag"] {
        if path
            .strip_suffix(ext)
            .is_some_and(|base| Path::new(&format!("{root}{base}")).is_file())
        {
            return None;
        }
    }
    if full.is_dir() {
        return std::fs::read(full.join("index.html")).ok();
    }
    std::fs::read(full).ok()
}

/// The response a case's routing decision produces.
struct Expected {
    status: u16,
    /// `None` when the case does not determine the body.
    body: Option<Vec<u8>>,
    /// Whether the case's `ops` are all the response header ops. Not so when the file
    /// server misses a file the case assumed: the error routes then add theirs.
    ops: bool,
}

fn expected(case: &Case, out: &str, target: &str, method: &str) -> Expected {
    let subst = |s: &str| s.replace("@out@", out);
    let outcome = subst(&case.outcome);
    let mut words = outcome.splitn(3, ' ');
    let (kind, first, second) = (
        words.next().unwrap(),
        words.next().unwrap_or_default(),
        words.next().unwrap_or_default(),
    );
    let request_path = target.split('?').next().unwrap();
    let routed_path = case.path.as_deref().unwrap_or(request_path);
    let known = |status: u16, body: Option<Vec<u8>>| Expected {
        status,
        body,
        ops: true,
    };
    let failed = |status: u16| match case.then.as_deref().map(subst).as_deref() {
        None => known(status, None),
        Some("bare") => known(status, Some(Vec::new())),
        Some(then) => {
            let root = then
                .strip_prefix("files ")
                .expect("an error page from files");
            let page = served_file(root, case.path.as_deref().unwrap_or("/404.html"));
            known(status, Some(page.expect("the error page exists")))
        }
    };
    match kind {
        "none" => known(404, Some(Vec::new())),
        "redirect" => known(first.parse().unwrap(), Some(Vec::new())),
        "respond" => known(first.parse().unwrap(), Some(second.as_bytes().to_vec())),
        "error" => failed(first.parse().unwrap()),
        "proxy" => {
            let target = case.target.as_deref().unwrap_or(target);
            let echoed = format!("{method} {target} HTTP/1.1");
            known(200, Some(echoed.into_bytes()))
        }
        "files" => match case.fail {
            Some(status) => failed(status),
            None => match served_file(first, routed_path) {
                Some(body) => known(200, Some(body)),
                None => Expected {
                    status: 404,
                    body: None,
                    ops: false,
                },
            },
        },
        other => panic!("{}: outcome {other:?}", case.name),
    }
}

/// Sends every case of a routing table to the running site and compares the response with
/// what the case's routing decision implies. Returns how many cases were sent.
fn replay(table: &str) -> usize {
    let routing = fixtures().join("routing");
    let table: Table =
        serde_json::from_str(&std::fs::read_to_string(routing.join(table)).unwrap()).unwrap();
    let out = routing.join(&table.out);
    let api = Origin::answering(|request| ok(request.line()));
    let site = Site::start(&table.config, &out, Some(&api));
    let out = out.display().to_string();

    let mut sent = 0;
    let mut problems = Vec::new();
    for case in &table.cases {
        let (method, url) = case.request.split_once(' ').unwrap();
        // The cleartext listener of a TLS site only redirects, and a failure other than a
        // missing file cannot be provoked from outside.
        let Some(rest) = url.strip_prefix("https://") else {
            continue;
        };
        if case.fail.is_some_and(|status| status != 404) {
            continue;
        }
        let (host, target) = rest.split_at(rest.find('/').unwrap());
        let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
        for (name, value) in &case.headers {
            request.push_str(&format!("{name}: {value}\r\n"));
        }
        if method == "POST" {
            request.push_str("Content-Length: 0\r\n");
        }
        request.push_str("\r\n");
        let response = site.proxy.client().roundtrip(&request);
        sent += 1;

        let mut problem = |what: String| problems.push(format!("{}: {what}", case.name));
        let expected = expected(case, &out, target, method);
        if response.status != expected.status {
            problem(format!(
                "status {} instead of {}",
                response.status, expected.status
            ));
            continue;
        }
        if let Some(body) = expected.body.filter(|_| method != "HEAD")
            && response.body != body
        {
            problem(format!(
                "body {:?} instead of {:?}",
                response.text(),
                String::from_utf8_lossy(&body)
            ));
        }
        if let Some(location) = case.outcome.strip_prefix("redirect ")
            && response.header("location") != location.split_once(' ').map(|(_, to)| to)
        {
            problem(format!("location {:?}", response.header("location")));
        }
        // The ops apply in order, so the last one for a name decides the header.
        let ops = case
            .ops
            .as_deref()
            .filter(|_| expected.ops)
            .unwrap_or_default();
        for (i, (name, want)) in ops.iter().enumerate() {
            let last = ops.iter().rposition(|(n, _)| n.eq_ignore_ascii_case(name));
            if last != Some(i) {
                continue;
            }
            let (want, got) = (want.as_deref(), response.header(name));
            // Negotiation adds Accept-Encoding to the Vary the ops set.
            let matches = match (name.eq_ignore_ascii_case("vary"), want, got) {
                (true, Some(want), Some(got)) => got.starts_with(want),
                _ => want == got,
            };
            if !matches {
                problem(format!("{name}: {got:?} instead of {want:?}"));
            }
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
    sent
}

#[test]
fn the_portfolio_routing_table_holds_through_the_binary() {
    let sent = replay("portfolio.json");
    assert!(sent >= 90, "{sent} cases");
}

#[test]
fn the_heimdall_routing_table_holds_through_the_binary() {
    let sent = replay("heimdall.json");
    assert!(sent >= 20, "{sent} cases");
}

/// heimdall's site (a SvelteKit app and its API) over the file fixture tree, whose sidecars
/// hold real encodings and a real entity-tag.
fn heimdall(api: &Origin) -> Site {
    Site::start(
        "heimdall/config.json",
        &fixtures().join("files/heimdall"),
        Some(api),
    )
}

fn get(client: &mut Client, path: &str, fields: &str) -> support::Response {
    client.roundtrip(&format!(
        "GET {path} HTTP/1.1\r\nHost: app.example.com\r\n{fields}\r\n"
    ))
}

#[test]
fn heimdall_serves_its_app_shell_assets_and_api() {
    let api = Origin::answering(|request| ok(&request.head));
    let site = heimdall(&api);
    let mut client = site.proxy.client();
    let index = site.file("index.html");

    // A client-side route is not a file: the app shell answers it.
    for path in ["/", "/settings", "/feeds/42/items?unread=1"] {
        let shell = get(&mut client, path, "");
        assert_eq!(shell.status, 200, "{path}");
        assert_eq!(shell.body, index, "{path}");
        assert_eq!(
            shell.header("content-type"),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(shell.header("cache-control"), Some("no-cache"));
        assert_eq!(shell.header("etag"), Some("\"Vh2c1Qx0aZ3kLm9PqR7sT4uW\""));
        assert_eq!(shell.header("last-modified"), None);
        assert_eq!(shell.header("server"), None);
        assert_eq!(shell.header("x-content-type-options"), Some("nosniff"));
        assert_eq!(shell.header("x-frame-options"), Some("DENY"));
        assert_eq!(shell.header("vary"), Some("Accept-Encoding"));
        assert!(shell.header("date").is_some());
    }

    // The ETag is the sidecar's content, the same for every encoding, and revalidates.
    let etag = String::from_utf8(site.file("index.html.etag")).unwrap();
    let etag = etag.trim();
    assert_eq!(etag.len(), 26);
    let fresh = get(&mut client, "/", &format!("If-None-Match: {etag}\r\n"));
    assert_eq!((fresh.status, fresh.body.len()), (304, 0));
    assert_eq!(fresh.header("etag"), Some(etag));
    assert_eq!(fresh.header("cache-control"), Some("no-cache"));
    let stale = get(&mut client, "/", "If-None-Match: \"another\"\r\n");
    assert_eq!(stale.status, 200);
    let dated = get(
        &mut client,
        "/",
        "If-Modified-Since: Thu, 01 Jan 2099 00:00:00 GMT\r\n",
    );
    assert_eq!(
        dated.status, 200,
        "If-Modified-Since never reaches the file server"
    );

    // Precompressed sidecars, by the client's preference among br and gzip.
    let br = get(&mut client, "/", "Accept-Encoding: gzip, br\r\n");
    assert_eq!(br.header("content-encoding"), Some("br"));
    assert_eq!(br.body, site.file("index.html.br"));
    assert_eq!(br.header("etag"), Some(etag));
    let gzip = get(&mut client, "/settings", "Accept-Encoding: gzip\r\n");
    assert_eq!(gzip.header("content-encoding"), Some("gzip"));
    assert_eq!(gzip.body, site.file("index.html.gz"));

    // Hashed assets are immutable; a missing one is a 404, not the app shell.
    let asset = "/_app/immutable/entry/app.Bk3d9f.js";
    let js = get(&mut client, asset, "Accept-Encoding: br\r\n");
    assert_eq!(js.status, 200);
    assert_eq!(
        js.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(js.header("content-encoding"), Some("br"));
    assert_eq!(js.body, site.file("_app/immutable/entry/app.Bk3d9f.js.br"));
    let missing = get(&mut client, "/_app/immutable/entry/gone.js", "");
    assert_eq!((missing.status, missing.body.len()), (404, 0));
    assert_eq!(
        missing.header("x-frame-options"),
        Some("DENY"),
        "site headers on errors"
    );

    // Sidecars are never served under their own names.
    for sidecar in [
        "/index.html.etag",
        "/index.html.br",
        "/sw.js.etag",
        &format!("{asset}.br"),
    ] {
        assert_eq!(get(&mut client, sidecar, "").status, 404, "{sidecar}");
    }

    // The file server answers GET and HEAD only, and says so.
    let post = client
        .roundtrip("POST /sw.js HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 2\r\n\r\nhi");
    assert_eq!(post.status, 405);
    assert_eq!(post.header("allow"), Some("GET, HEAD"));

    // HEAD gets the head of the GET.
    let head = client.roundtrip("HEAD /sw.js HTTP/1.1\r\nHost: app.example.com\r\n\r\n");
    assert_eq!(head.status, 200);
    assert_eq!(
        head.header("content-length"),
        Some(site.file("sw.js").len().to_string().as_str())
    );

    // The API is proxied, with the request as the client sent it.
    let api_call = get(
        &mut client,
        "/api/sync?since=5",
        "If-Modified-Since: Thu, 01 Jan 2099 00:00:00 GMT\r\n",
    );
    assert_eq!(api_call.status, 200);
    let seen = api_call.text();
    assert_eq!(seen.lines().next(), Some("GET /api/sync?since=5 HTTP/1.1"));
    assert_eq!(support::header(&seen, "host"), Some("app.example.com"));
    assert_eq!(support::header(&seen, "x-forwarded-proto"), Some("http"));
    assert!(support::header(&seen, "if-modified-since").is_some());
    assert_eq!(
        api_call.header("cache-control"),
        None,
        "the API sets its own caching"
    );
    assert_eq!(api_call.header("x-frame-options"), Some("DENY"));
    assert_eq!(api.connections(), 1);
}

#[test]
fn heimdall_event_stream_is_not_buffered_or_compressed() {
    const EVENT: &str = "event: ping\ndata: 1\n\n";
    let api = Origin::start(|stream, _| {
        let mut conn = Client::over(stream);
        conn.request().unwrap();
        conn.send(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nTransfer-Encoding: chunked\r\n\r\n")
            .unwrap();
        conn.send(format!("{:x}\r\n{EVENT}\r\n", EVENT.len()).as_bytes())
            .unwrap();
        // The stream stays open: the event must arrive without waiting for more.
        conn.closed();
    });
    let site = heimdall(&api);
    let mut client = site.proxy.client();
    client
        .send(b"GET /api/live HTTP/1.1\r\nHost: app.example.com\r\nAccept: text/event-stream\r\nAccept-Encoding: gzip, br, zstd\r\n\r\n")
        .unwrap();
    let head = client.head().unwrap();
    assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
    assert_eq!(support::header(&head, "content-encoding"), None);
    assert_eq!(support::header(&head, "cache-control"), Some("no-store"));
    let size = client.head_line();
    assert_eq!(usize::from_str_radix(size.trim(), 16), Ok(EVENT.len()));
    assert_eq!(client.bytes(EVENT.len()), EVENT.as_bytes());
}

#[test]
fn portfolio_pages_are_negotiated_compressed_and_varied() {
    let routing = fixtures().join("routing");
    let out = routing.join("portfolio/out");
    let site = Site::start("portfolio/config.json", &out, None);
    let mut client = site.proxy.client();
    let home = |fields: &str| format!("GET / HTTP/1.1\r\nHost: example.org\r\n{fields}\r\n");

    let plain = client.roundtrip(&home(""));
    assert_eq!(plain.status, 200);
    assert_eq!(plain.body, site.file("site/e0/main/en/index.html"));
    assert_eq!(
        plain.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(plain.header("cache-control"), Some("private, no-cache"));
    assert_eq!(
        plain.header("vary"),
        Some("Cookie, Accept-Language, User-Agent, Accept, Accept-Encoding"),
        "the sidecar's Accept-Encoding joins the Vary the route set"
    );
    assert_eq!(plain.header("server"), None);
    assert_eq!(plain.header("last-modified"), None);

    // A precompressed sidecar is preferred to compressing.
    let br = client.roundtrip(&home("Accept-Encoding: br, zstd, gzip\r\n"));
    assert_eq!(br.header("content-encoding"), Some("br"));
    assert_eq!(br.body, site.file("site/e0/main/en/index.html.br"));

    // The language comes from the cookie, then the page from that tree.
    let pt = client.roundtrip(&home("Cookie: portfolio_lang=pt\r\n"));
    assert_eq!(pt.body, site.file("site/e0/main/pt/index.html"));

    // curl gets the text card for the home page.
    let card = client.roundtrip(&home("User-Agent: curl/8.5.0\r\n"));
    assert_eq!(card.body, site.file("site/e0/main/en/_curl.txt"));
    assert_eq!(
        card.header("content-type"),
        Some("text/plain; charset=utf-8")
    );

    // A missing page is the tree's 404 page, with the error route's headers.
    let missing = client.roundtrip("GET /nowhere HTTP/1.1\r\nHost: example.org\r\n\r\n");
    assert_eq!(missing.status, 404);
    assert_eq!(missing.body, site.file("site/e0/main/en/404.html"));
    assert_eq!(
        missing.header("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(
        missing.header("etag"),
        None,
        "an error page has no validator"
    );

    // Redirects keep the query and need no body.
    let slash = client.roundtrip("GET /blog/hello/?a=1&b=2 HTTP/1.1\r\nHost: example.org\r\n\r\n");
    assert_eq!(
        (slash.status, slash.header("location")),
        (301, Some("/blog/hello?a=1&b=2"))
    );
    assert_eq!(slash.header("content-length"), Some("0"));

    // The blog host shares the tree layout under its own root.
    let blog = client.roundtrip("GET /hello HTTP/1.1\r\nHost: blog.example.org\r\n\r\n");
    assert_eq!(blog.body, site.file("site/e0/blog/en/hello/index.html"));
}

#[test]
fn a_large_page_is_compressed_on_the_fly_and_a_large_file_is_sent_whole() {
    let dir = tempfile::tempdir().unwrap();
    let page: String = (0..4000)
        .map(|i| format!("<p>paragraph {i}</p>\n"))
        .collect();
    std::fs::write(dir.path().join("page.html"), &page).unwrap();
    let blob = support::payload(3 << 20);
    std::fs::write(dir.path().join("blob.bin"), &blob).unwrap();
    let proxy = Proxy::start(support::site(serde_json::json!([
        { "encode": ["zstd", "gzip"] },
        { "files": { "root": dir.path() } },
    ])));
    let mut client = proxy.client();

    let gzip =
        client.roundtrip("GET /page.html HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip\r\n\r\n");
    assert_eq!(gzip.header("content-encoding"), Some("gzip"));
    assert_eq!(gzip.header("vary"), Some("Accept-Encoding"));
    assert!(
        gzip.body.len() < page.len() / 4,
        "{} bytes",
        gzip.body.len()
    );
    let mut decoded = String::new();
    std::io::Read::read_to_string(
        &mut flate2::read::GzDecoder::new(&gzip.body[..]),
        &mut decoded,
    )
    .unwrap();
    assert_eq!(decoded, page);

    let zstd = client
        .roundtrip("GET /page.html HTTP/1.1\r\nHost: test\r\nAccept-Encoding: gzip, zstd\r\n\r\n");
    assert_eq!(
        zstd.header("content-encoding"),
        Some("zstd"),
        "the route's order decides"
    );
    assert_eq!(zstd::decode_all(&zstd.body[..]).unwrap(), page.as_bytes());

    // A file above the in-memory limit goes out from its descriptor.
    let whole = client.get("/blob.bin");
    assert_eq!(
        whole.header("content-length"),
        Some(blob.len().to_string().as_str())
    );
    assert_eq!(support::sha256(&whole.body), support::sha256(&blob));
    let range = client
        .roundtrip("GET /blob.bin HTTP/1.1\r\nHost: test\r\nRange: bytes=1048570-2097160\r\n\r\n");
    assert_eq!(range.status, 206);
    assert_eq!(
        range.header("content-range"),
        Some(format!("bytes 1048570-2097160/{}", blob.len()).as_str())
    );
    assert_eq!(range.body, &blob[1048570..=2097160]);
    assert_eq!(
        client.get("/page.html").text(),
        page,
        "the connection outlives a sendfile"
    );
}
