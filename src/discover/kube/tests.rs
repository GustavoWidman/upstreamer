//! The watch against a fake API server: real sockets, real HTTP/1.1 (chunked watches
//! included), the server a thread whose answers each test scripts.

use super::*;
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;

/// What the fake server answers to one request.
enum Reply {
    Json(u16, Value),
    /// A watch: lines the test sends while the request is open.
    Stream(mpsc::Receiver<Item>),
    /// Raw bytes of the whole response, written a piece at a time.
    Pieces(Vec<Vec<u8>>),
}

enum Item {
    Line(String),
    /// The terminating chunk: the server ends the watch as `timeoutSeconds` would.
    End,
    /// The connection drops without a terminating chunk.
    Cut,
}

#[derive(Clone, Debug)]
struct Request {
    path: String,
    query: HashMap<String, String>,
    authorization: Option<String>,
    at: Instant,
}

impl Request {
    fn is_watch(&self) -> bool {
        self.query.get("watch").is_some_and(|v| v == "true")
    }
}

type Handler = Box<dyn FnMut(&Request) -> Reply + Send>;

struct Fake {
    addr: SocketAddr,
    requests: Arc<Mutex<Vec<Request>>>,
    handler: Arc<Mutex<Handler>>,
}

impl Fake {
    fn new(handler: impl FnMut(&Request) -> Reply + Send + 'static) -> Fake {
        Fake::start(None, Box::new(handler))
    }

    fn tls(
        config: Arc<rustls::ServerConfig>,
        handler: impl FnMut(&Request) -> Reply + Send + 'static,
    ) -> Fake {
        Fake::start(Some(config), Box::new(handler))
    }

    fn start(tls: Option<Arc<rustls::ServerConfig>>, handler: Handler) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let handler = Arc::new(Mutex::new(handler));
        let (seen, answer) = (requests.clone(), handler.clone());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let (seen, answer, tls) = (seen.clone(), answer.clone(), tls.clone());
                std::thread::spawn(move || {
                    stream.set_nodelay(true).unwrap();
                    match tls {
                        None => serve(stream, &seen, &answer),
                        Some(config) => {
                            let conn = rustls::ServerConnection::new(config).unwrap();
                            serve(rustls::StreamOwned::new(conn, stream), &seen, &answer)
                        }
                    }
                });
            }
        });
        Fake {
            addr,
            requests,
            handler,
        }
    }

    fn cluster(&self, token: Option<&str>) -> config::Cluster {
        config::Cluster::plain("127.0.0.1", self.addr.port(), token)
    }

    fn loader(&self, token: Option<&'static str>) -> Loader {
        let port = self.addr.port();
        Arc::new(move || Ok(config::Cluster::plain("127.0.0.1", port, token)))
    }

    fn requests(&self) -> Vec<Request> {
        self.requests.lock().unwrap().clone()
    }

    fn lists(&self) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(|r| !r.is_watch())
            .collect()
    }

    fn watches(&self) -> Vec<Request> {
        self.requests()
            .into_iter()
            .filter(Request::is_watch)
            .collect()
    }

    fn answer(&self, handler: impl FnMut(&Request) -> Reply + Send + 'static) {
        *self.handler.lock().unwrap() = Box::new(handler);
    }
}

fn serve<S: Read + Write>(mut stream: S, seen: &Mutex<Vec<Request>>, handler: &Mutex<Handler>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let text = String::from_utf8(head).unwrap();
    let mut lines = text.lines();
    let target = lines.next().unwrap().split(' ').nth(1).unwrap().to_owned();
    let authorization = lines
        .filter_map(|l| l.split_once(": "))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, v)| v.to_owned());
    let (path, query) = target.split_once('?').unwrap_or((&target, ""));
    let query = query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.to_owned(), decode(v)))
        .collect();
    let request = Request {
        path: path.to_owned(),
        query,
        authorization,
        at: Instant::now(),
    };
    seen.lock().unwrap().push(request.clone());
    let reply = (handler.lock().unwrap())(&request);
    let _ = write_reply(&mut stream, reply);
}

fn write_reply<S: Write>(stream: &mut S, reply: Reply) -> std::io::Result<()> {
    match reply {
        Reply::Json(status, body) => {
            let body = body.to_string();
            write!(
                stream,
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )?;
            stream.flush()
        }
        Reply::Stream(items) => {
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            )?;
            stream.flush()?;
            loop {
                match items.recv() {
                    Ok(Item::Line(line)) => {
                        let line = format!("{line}\n");
                        write!(stream, "{:x}\r\n{line}\r\n", line.len())?;
                        stream.flush()?;
                    }
                    Ok(Item::End) | Err(_) => {
                        stream.write_all(b"0\r\n\r\n")?;
                        return stream.flush();
                    }
                    Ok(Item::Cut) => return Ok(()),
                }
            }
        }
        Reply::Pieces(pieces) => {
            for piece in pieces {
                stream.write_all(&piece)?;
                stream.flush()?;
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }
    }
}

fn decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(&text[i + 1..i + 3], 16).unwrap());
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

type Ready<'a> = (&'a str, Option<bool>, Option<bool>);

/// An EndpointSlice: endpoints as (address, ready, terminating), ports as (name, number).
fn slice(name: &str, version: &str, endpoints: &[Ready<'_>], ports: &[(&str, u16)]) -> Value {
    json!({
        "metadata": {"name": name, "resourceVersion": version},
        "addressType": "IPv4",
        "endpoints": endpoints.iter().map(|(addr, ready, terminating)| {
            let mut conditions = serde_json::Map::new();
            if let Some(r) = ready { conditions.insert("ready".into(), json!(r)); }
            if let Some(t) = terminating { conditions.insert("terminating".into(), json!(t)); }
            json!({"addresses": [addr], "conditions": conditions})
        }).collect::<Vec<_>>(),
        "ports": ports.iter().map(|(n, p)| json!({"name": n, "port": p, "protocol": "TCP"})).collect::<Vec<_>>(),
    })
}

fn up(addr: &str) -> Ready<'_> {
    (addr, Some(true), None)
}

fn list(version: &str, items: Vec<Value>) -> Reply {
    Reply::Json(
        200,
        json!({"kind": "EndpointSliceList", "metadata": {"resourceVersion": version}, "items": items}),
    )
}

fn event(kind: &str, object: Value) -> Item {
    Item::Line(json!({"type": kind, "object": object}).to_string())
}

fn sa(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

fn web() -> Arc<KubeWatch> {
    Arc::new(KubeWatch {
        namespace: "shop".into(),
        select: KubeSelect::Service("web".into()),
        port: KubePort::Name("http".into()),
    })
}

/// Fast timings: only the coalescing window keeps its real 250 ms.
fn quick() -> Timing {
    Timing {
        coalesce: Duration::from_millis(250),
        backoff_start: Duration::from_millis(40),
        backoff_max: Duration::from_millis(320),
        head: Duration::from_secs(5),
        watch: Duration::from_secs(30),
        grace: Duration::from_secs(5),
        min_watch: Duration::ZERO,
    }
}

struct Source {
    found: UnboundedReceiver<Found>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Source {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Source {
    fn start(fake: &Fake, watch: Arc<KubeWatch>, timing: Timing) -> Source {
        Source::with_loader(fake.loader(Some("secret")), watch, timing)
    }

    fn with_loader(load: Loader, watch: Arc<KubeWatch>, timing: Timing) -> Source {
        let (out, found) = unbounded_channel();
        let task = tokio::spawn(super::watch(watch, load, timing, out));
        Source { found, task }
    }

    async fn next(&mut self) -> Found {
        tokio::time::timeout(Duration::from_secs(10), self.found.recv())
            .await
            .expect("a report within 10 s")
            .expect("the watch runs")
    }

    /// The first report that is not the "waiting for the first list" placeholder.
    async fn first(&mut self) -> Found {
        let waiting = self.next().await;
        assert!(
            matches!(&waiting.state, SourceState::Unreachable { error, .. } if error.contains("first list")),
            "a source that has not listed yet says so: {waiting:?}"
        );
        assert!(waiting.endpoints.is_empty());
        self.next().await
    }

    async fn silent_for(&mut self, window: Duration) {
        if let Ok(found) = tokio::time::timeout(window, self.found.recv()).await {
            panic!("unexpected report: {found:?}");
        }
    }
}

fn synced(found: &Found) -> &[SocketAddr] {
    assert!(matches!(found.state, SourceState::Synced), "{found:?}");
    &found.endpoints
}

async fn until(what: &str, mut ready: impl FnMut() -> bool) {
    for _ in 0..400 {
        if ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test]
async fn list_then_watch_from_the_list_version() {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            Reply::Stream(rx.lock().unwrap().take().unwrap())
        } else {
            list(
                "100",
                vec![
                    slice(
                        "web-b",
                        "90",
                        &[up("10.0.0.3"), up("10.0.0.2")],
                        &[("http", 8080)],
                    ),
                    slice("web-a", "95", &[up("10.0.0.1")], &[("http", 8080)]),
                ],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    let found = source.first().await;
    assert_eq!(
        synced(&found),
        [
            sa("10.0.0.1:8080"),
            sa("10.0.0.2:8080"),
            sa("10.0.0.3:8080")
        ],
        "the union of the slices, sorted"
    );
    until("the watch", || !fake.watches().is_empty()).await;
    let list = &fake.lists()[0];
    let watch = &fake.watches()[0];
    for request in [list, watch] {
        assert_eq!(
            request.path,
            "/apis/discovery.k8s.io/v1/namespaces/shop/endpointslices"
        );
        assert_eq!(
            request.query["labelSelector"],
            "kubernetes.io/service-name=web"
        );
        assert_eq!(request.authorization.as_deref(), Some("Bearer secret"));
    }
    assert_eq!(watch.query["resourceVersion"], "100");
    assert_eq!(watch.query["allowWatchBookmarks"], "true");
    assert_eq!(watch.query["timeoutSeconds"], "30");
    drop(tx);
}

#[tokio::test]
async fn a_selector_source_watches_by_label_selector() {
    let fake = Fake::new(|req| {
        if req.is_watch() {
            Reply::Stream(mpsc::channel().1)
        } else {
            list("1", vec![])
        }
    });
    let selector = Arc::new(KubeWatch {
        namespace: "team a".into(),
        select: KubeSelect::Labels("app=shop,tier in (web,api)".into()),
        port: KubePort::Number(8080),
    });
    let mut source = Source::start(&fake, selector, quick());
    source.next().await;
    until("the list", || !fake.lists().is_empty()).await;
    let list = &fake.lists()[0];
    assert_eq!(list.query["labelSelector"], "app=shop,tier in (web,api)");
    assert_eq!(
        list.path,
        "/apis/discovery.k8s.io/v1/namespaces/team%20a/endpointslices"
    );
}

#[tokio::test]
async fn only_ready_endpoints_at_the_source_port_are_members() {
    let mut mixed = slice(
        "mixed",
        "5",
        &[
            up("10.0.0.1"),
            ("10.0.0.2", Some(false), None),
            ("10.0.0.3", None, None),
            ("10.0.0.4", Some(true), Some(true)),
            ("10.0.0.5", Some(false), Some(true)),
            ("not-an-ip", Some(true), None),
            up("10.0.0.1"),
        ],
        &[("http", 8080), ("metrics", 9090)],
    );
    mixed["endpoints"][2]["conditions"] = Value::Null;
    let mut fqdn = slice("names", "6", &[up("db.example.com")], &[("http", 8080)]);
    fqdn["addressType"] = json!("FQDN");
    let mut v6 = slice("v6", "7", &[up("fd00::7")], &[("http", 8080)]);
    v6["addressType"] = json!("IPv6");
    let mut udp = slice("udp", "8", &[up("10.0.0.9")], &[("http", 8080)]);
    udp["ports"][0]["protocol"] = json!("UDP");
    let other = slice("other", "9", &[up("10.0.0.8")], &[("grpc", 8080)]);
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            Reply::Stream(mpsc::channel().1)
        } else {
            list(
                "10",
                vec![
                    mixed.clone(),
                    fqdn.clone(),
                    v6.clone(),
                    udp.clone(),
                    other.clone(),
                ],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    let found = source.first().await;
    assert_eq!(
        synced(&found),
        [
            sa("10.0.0.1:8080"),
            sa("10.0.0.3:8080"),
            sa("[fd00::7]:8080")
        ],
        "ready (or unstated), not terminating, TCP, named http, an IP address, each once"
    );

    let by_number = Arc::new(KubeWatch {
        port: KubePort::Number(9090),
        ..KubeWatch {
            namespace: "shop".into(),
            select: KubeSelect::Service("web".into()),
            port: KubePort::Number(0),
        }
    });
    let mut source = Source::start(&fake, by_number, quick());
    let found = source.first().await;
    assert_eq!(synced(&found), [sa("10.0.0.1:9090"), sa("10.0.0.3:9090")]);
}

#[tokio::test]
async fn a_burst_of_events_is_one_report_after_the_window() {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            Reply::Stream(rx.lock().unwrap().take().unwrap())
        } else {
            list(
                "1",
                vec![slice("web", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    assert_eq!(synced(&source.first().await), [sa("10.0.0.1:80")]);
    until("the watch", || !fake.watches().is_empty()).await;

    let begun = Instant::now();
    for n in 2..=6 {
        let addrs: Vec<String> = (1..=n).map(|i| format!("10.0.0.{i}")).collect();
        let endpoints: Vec<Ready<'_>> = addrs.iter().map(|a| up(a)).collect();
        tx.send(event(
            "MODIFIED",
            slice("web", &n.to_string(), &endpoints, &[("http", 80)]),
        ))
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let found = source.next().await;
    assert!(
        begun.elapsed() >= Duration::from_millis(240),
        "reported after {:?}, before the 250 ms window closed",
        begun.elapsed()
    );
    assert_eq!(
        synced(&found).len(),
        6,
        "the set as it was when the window closed"
    );
    source.silent_for(Duration::from_millis(500)).await;

    let same: Vec<Ready<'_>> = [
        "10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.6",
    ]
    .into_iter()
    .map(up)
    .collect();
    tx.send(event("MODIFIED", slice("web", "7", &same, &[("http", 80)])))
        .unwrap();
    source.silent_for(Duration::from_millis(500)).await;
}

#[tokio::test]
async fn added_modified_and_deleted_slices_move_the_set() {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            Reply::Stream(rx.lock().unwrap().take().unwrap())
        } else {
            list(
                "1",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    source.first().await;
    until("the watch", || !fake.watches().is_empty()).await;

    tx.send(event(
        "ADDED",
        slice("b", "2", &[up("10.0.0.2")], &[("http", 80)]),
    ))
    .unwrap();
    assert_eq!(
        synced(&source.next().await),
        [sa("10.0.0.1:80"), sa("10.0.0.2:80")]
    );

    tx.send(event(
        "MODIFIED",
        slice(
            "a",
            "3",
            &[("10.0.0.1", Some(false), None)],
            &[("http", 80)],
        ),
    ))
    .unwrap();
    assert_eq!(
        synced(&source.next().await),
        [sa("10.0.0.2:80")],
        "an endpoint that stops being ready leaves"
    );

    tx.send(event(
        "DELETED",
        slice("b", "4", &[up("10.0.0.2")], &[("http", 80)]),
    ))
    .unwrap();
    assert!(
        synced(&source.next().await).is_empty(),
        "a deleted slice takes its endpoints"
    );
}

#[tokio::test]
async fn bookmarks_move_the_version_and_a_clean_end_watches_again_without_a_list() {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let (tx2, rx2) = mpsc::channel();
    let rx2 = Mutex::new(Some(rx2));
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            let mut first = rx.lock().unwrap();
            Reply::Stream(first.take().or_else(|| rx2.lock().unwrap().take()).unwrap())
        } else {
            list(
                "10",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    source.first().await;
    until("the first watch", || fake.watches().len() == 1).await;

    tx.send(event(
        "BOOKMARK",
        json!({"kind": "EndpointSlice", "metadata": {"resourceVersion": "57"}}),
    ))
    .unwrap();
    tx.send(Item::End).unwrap();
    until("the second watch", || fake.watches().len() == 2).await;
    assert_eq!(fake.watches()[1].query["resourceVersion"], "57");
    assert_eq!(
        fake.lists().len(),
        1,
        "a watch the server ended is resumed, not relisted"
    );
    source.silent_for(Duration::from_millis(400)).await;
    drop(tx2);
}

/// A server whose first list says `.1`, and whose later lists say `.2` at version 20.
fn moving_server(
    first_watch: mpsc::Receiver<Item>,
    watch_answer: impl Fn(usize) -> Option<Reply> + Send + 'static,
) -> Fake {
    let first_watch = Mutex::new(Some(first_watch));
    let (lists, watches) = (AtomicUsize::new(0), AtomicUsize::new(0));
    Fake::new(move |req| {
        if req.is_watch() {
            let n = watches.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                return Reply::Stream(first_watch.lock().unwrap().take().unwrap());
            }
            return watch_answer(n).unwrap_or_else(|| Reply::Stream(mpsc::channel().1));
        }
        if lists.fetch_add(1, Ordering::SeqCst) == 0 {
            list(
                "10",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        } else {
            list(
                "20",
                vec![slice("a", "1", &[up("10.0.0.2")], &[("http", 80)])],
            )
        }
    })
}

async fn relists_from(fake: &Fake, source: &mut Source) {
    assert_eq!(
        synced(&source.next().await),
        [sa("10.0.0.2:80")],
        "after 410 the source reports what the new list says"
    );
    until("a watch from the new list", || {
        fake.watches()
            .last()
            .is_some_and(|w| w.query["resourceVersion"] == "20")
    })
    .await;
    assert_eq!(fake.lists().len(), 2);
}

#[tokio::test]
async fn an_error_event_with_code_410_relists() {
    let (tx, rx) = mpsc::channel();
    let fake = moving_server(rx, |_| None);
    let mut source = Source::start(&fake, web(), quick());
    assert_eq!(synced(&source.first().await), [sa("10.0.0.1:80")]);
    until("the first watch", || !fake.watches().is_empty()).await;
    let status = json!({"kind": "Status", "code": 410, "reason": "Expired", "message": "too old resource version: 10 (15)"});
    tx.send(event("ERROR", status)).unwrap();
    relists_from(&fake, &mut source).await;
}

#[tokio::test]
async fn a_watch_answered_with_410_relists() {
    let (tx, rx) = mpsc::channel();
    let fake = moving_server(rx, |n| {
        (n == 1).then(|| {
            Reply::Json(
                410,
                json!({"kind": "Status", "code": 410, "reason": "Expired"}),
            )
        })
    });
    let mut source = Source::start(&fake, web(), quick());
    assert_eq!(synced(&source.first().await), [sa("10.0.0.1:80")]);
    until("the first watch", || !fake.watches().is_empty()).await;
    tx.send(Item::End).unwrap();
    relists_from(&fake, &mut source).await;
}

#[tokio::test]
async fn a_failing_server_is_unreachable_then_synced_with_growing_pauses() {
    let failures = Arc::new(AtomicUsize::new(0));
    let counted = failures.clone();
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            Reply::Stream(mpsc::channel().1)
        } else if counted.fetch_add(1, Ordering::SeqCst) < 4 {
            Reply::Json(
                503,
                json!({"kind": "Status", "code": 503, "message": "etcd is down"}),
            )
        } else {
            list(
                "1",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    let waiting = source.next().await;
    assert!(
        matches!(&waiting.state, SourceState::Unreachable { error, .. } if error.contains("first list"))
    );
    let failed = source.next().await;
    assert!(
        matches!(&failed.state, SourceState::Unreachable { error, .. } if error.contains("HTTP 503 etcd is down")),
        "the first failure replaces the placeholder with its cause: {failed:?}"
    );
    let found = source.next().await;
    assert_eq!(
        synced(&found),
        [sa("10.0.0.1:80")],
        "no report per repeated failure, one when it works"
    );

    let gaps: Vec<Duration> = fake.lists().windows(2).map(|w| w[1].at - w[0].at).collect();
    assert_eq!(gaps.len(), 4);
    for (gap, (low, _)) in gaps.iter().zip([(20, 40), (40, 80), (80, 160), (160, 320)]) {
        assert!(
            *gap >= Duration::from_millis(low),
            "a pause of {gap:?} is below the jittered backoff floor of {low} ms: {gaps:?}"
        );
    }
}

#[tokio::test]
async fn an_error_names_what_the_server_said() {
    let fake = Fake::new(|_| {
        Reply::Json(
            403,
            json!({"kind": "Status", "code": 403, "reason": "Forbidden", "message": "endpointslices.discovery.k8s.io is forbidden: User \"system:serviceaccount:shop:upstreamer\" cannot list resource"}),
        )
    });
    let mut cluster = fake.cluster(None);
    let failure = api::get(&mut cluster, "/x", Duration::from_secs(5))
        .await
        .err()
        .unwrap();
    let text = failure.to_string();
    assert!(
        text.contains("HTTP 403") && text.contains("is forbidden"),
        "{text}"
    );
    let gone = Fake::new(|_| Reply::Json(410, json!({"code": 410})));
    let mut cluster = gone.cluster(None);
    let failure = api::get(&mut cluster, "/x", Duration::from_secs(5))
        .await
        .err()
        .unwrap();
    assert!(matches!(failure, Failure::Gone));
}

#[tokio::test]
async fn a_dropped_watch_keeps_the_endpoints_and_recovers_on_the_relist() {
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let lists = Arc::new(AtomicUsize::new(0));
    let counted = lists.clone();
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            match rx.lock().unwrap().take() {
                Some(stream) => Reply::Stream(stream),
                None => Reply::Stream(mpsc::channel().1),
            }
        } else {
            counted.fetch_add(1, Ordering::SeqCst);
            list(
                "1",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let mut source = Source::start(&fake, web(), quick());
    source.first().await;
    until("the watch", || !fake.watches().is_empty()).await;
    tx.send(Item::Cut).unwrap();
    let found = source.next().await;
    let SourceState::Unreachable { error, since } = &found.state else {
        panic!("a cut watch makes the source unreachable: {found:?}");
    };
    assert!(since.elapsed().unwrap() < Duration::from_secs(5));
    assert!(!error.is_empty());
    assert_eq!(
        &*found.endpoints,
        [sa("10.0.0.1:80")],
        "the last endpoints stay in use"
    );
    let found = source.next().await;
    assert_eq!(
        synced(&found),
        [sa("10.0.0.1:80")],
        "the relist says the source is back"
    );
    assert_eq!(lists.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_token_is_read_again_for_each_request() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, "token-one").unwrap();
    let (tx, rx) = mpsc::channel();
    let rx = Mutex::new(Some(rx));
    let (_idle, idle_rx) = mpsc::channel();
    let idle_rx = Mutex::new(Some(idle_rx));
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            let first = rx.lock().unwrap().take();
            Reply::Stream(first.or_else(|| idle_rx.lock().unwrap().take()).unwrap())
        } else {
            list("1", vec![])
        }
    });
    let port = fake.addr.port();
    let path = file.clone();
    let load: Loader =
        Arc::new(
            move || Ok(config::Cluster::plain("127.0.0.1", port, None).with_token_file(&path)),
        );
    let mut source = Source::with_loader(load, web(), quick());
    source.next().await;
    until("the first watch", || !fake.watches().is_empty()).await;
    std::fs::write(&file, "the-rotated-token").unwrap();
    tx.send(Item::End).unwrap();
    until("the second watch", || fake.watches().len() == 2).await;
    let tokens: Vec<_> = fake
        .requests()
        .iter()
        .map(|r| r.authorization.clone().unwrap())
        .collect();
    assert_eq!(tokens.len(), 3);
    assert_eq!(
        tokens,
        [
            "Bearer token-one",
            "Bearer token-one",
            "Bearer the-rotated-token"
        ],
        "list, first watch, and the watch after the token file changed"
    );
}

#[tokio::test]
async fn responses_decode_whatever_the_framing_and_the_packet_boundaries() {
    let line1 = r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"1"}}}"#;
    let line2 = r#"{"type":"BOOKMARK","object":{"metadata":{"resourceVersion":"2"}}}"#;
    let joined = format!("{line1}\n{line2}\n");
    let split = joined.len() / 2 + 3;
    let (a, b) = joined.split_at(split);
    let chunked = format!(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x};ext=1\r\n{a}\r\n{:X}\r\n{b}\r\n0\r\nTrailer: x\r\n\r\n",
        a.len(),
        b.len()
    );
    let length = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{joined}",
        joined.len()
    );
    let close = format!("HTTP/1.1 200 OK\r\n\r\n{joined}");
    for (framing, wire) in [("chunked", chunked), ("length", length), ("close", close)] {
        let pieces: Vec<Vec<u8>> = wire.bytes().map(|b| vec![b]).collect();
        let fake = Fake::new(move |_| Reply::Pieces(pieces.clone()));
        let mut cluster = fake.cluster(None);
        let mut response = api::get(&mut cluster, "/watch", Duration::from_secs(5))
            .await
            .unwrap();
        let mut lines = Vec::new();
        while let Some(line) = response.next_line().await.unwrap() {
            lines.push(String::from_utf8(line).unwrap());
        }
        assert_eq!(lines, [line1, line2], "{framing} body, one byte per packet");
    }
}

#[tokio::test]
async fn a_truncated_chunked_body_is_an_error_not_an_end() {
    let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort".to_vec();
    let fake = Fake::new(move |_| Reply::Pieces(vec![wire.clone()]));
    let mut cluster = fake.cluster(None);
    let mut response = api::get(&mut cluster, "/watch", Duration::from_secs(5))
        .await
        .unwrap();
    assert!(response.next_line().await.is_err());
}

#[test]
fn backoff_doubles_to_the_cap_and_jitters_in_the_upper_half() {
    let mut backoff = Backoff::new(Timing::default());
    let ceilings = [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0];
    for ceiling in ceilings {
        let low = backoff.delay(0.0).as_secs_f64();
        let high = backoff.delay(0.999_999).as_secs_f64();
        assert!((low - ceiling / 2.0).abs() < 1e-9, "{low} for {ceiling}");
        assert!((high - ceiling).abs() < 1e-3, "{high} for {ceiling}");
        backoff.failures += 1;
    }
    backoff.reset();
    assert_eq!(backoff.delay(0.0), Duration::from_millis(500));
    backoff.failures = u32::MAX;
    assert_eq!(
        backoff.delay(1.0),
        Duration::from_secs(30),
        "no overflow at the extreme"
    );
}

#[test]
fn query_values_are_percent_encoded() {
    assert_eq!(
        encode("a=b,c!=d (x y)/é"),
        "a%3Db%2Cc%21%3Dd%20%28x%20y%29%2F%C3%A9"
    );
    assert_eq!(encode("AZaz09-._~"), "AZaz09-._~");
}

/// The open watches: the label selector each asked for, and the way to feed it.
type Streams = Arc<Mutex<Vec<(String, mpsc::Sender<Item>)>>>;

#[tokio::test]
async fn the_thread_follows_the_set_of_sources() {
    let streams: Streams = Arc::default();
    let held = streams.clone();
    let fake = Fake::new(move |req| {
        if req.is_watch() {
            let (tx, rx) = mpsc::channel();
            held.lock()
                .unwrap()
                .push((req.query["labelSelector"].clone(), tx));
            Reply::Stream(rx)
        } else {
            list(
                "1",
                vec![slice("a", "1", &[up("10.0.0.1")], &[("http", 80)])],
            )
        }
    });
    let thread = Thread::spawn_with(fake.loader(None), quick()).unwrap();
    let mut thread = thread;
    let a = web();
    let b = Arc::new(KubeWatch {
        namespace: "shop".into(),
        select: KubeSelect::Service("api".into()),
        port: KubePort::Name("http".into()),
    });
    let count = |name: &str| {
        fake.lists()
            .iter()
            .filter(|r| r.query["labelSelector"].ends_with(name))
            .count()
    };

    thread.set_sources(vec![a.clone()]);
    until("a's watch", || streams.lock().unwrap().len() == 1).await;
    thread.set_sources(vec![a.clone(), b.clone()]);
    until("b's watch", || streams.lock().unwrap().len() == 2).await;
    assert_eq!(count("=web"), 1, "a source that stays is not restarted");

    thread.set_sources(vec![b.clone()]);
    for (_, stream) in streams.lock().unwrap().iter() {
        let _ = stream.send(Item::End);
    }
    until("b's watch to resume", || fake.watches().len() == 3).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        fake.watches().len(),
        3,
        "a removed source does not watch again"
    );
    assert!(fake.watches()[2].query["labelSelector"].ends_with("=api"));

    let mut reports = 0;
    while let Ok(Some(_)) = tokio::time::timeout(Duration::from_millis(50), thread.recv()).await {
        reports += 1;
    }
    assert!(
        reports >= 4,
        "each source reported its placeholder and its list: {reports}"
    );
}

/// Standard base64 with padding.
pub(super) fn b64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().fold(0u32, |a, &b| a << 8 | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            out.push(TABLE[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
    }
    out
}

/// A PEM block around `der`.
pub(super) fn pem(der: &[u8], label: &str) -> String {
    let body = b64(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

mod tls {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, SanType,
    };

    struct Pki {
        ca_pem: String,
        server: Arc<rustls::ServerConfig>,
        client_cert_pem: String,
        client_key_pem: String,
    }

    fn leaf(issuer: &Issuer<'_, KeyPair>, usage: ExtendedKeyUsagePurpose) -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        params.extended_key_usages = vec![usage];
        let cert = params.signed_by(&key, issuer).unwrap();
        (
            pem(cert.der(), "CERTIFICATE"),
            pem(&key.serialize_der(), "PRIVATE KEY"),
        )
    }

    fn pki(require_client_auth: bool) -> Pki {
        let ca_key = KeyPair::generate().unwrap();
        let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name
            .push(DnType::CommonName, "fake cluster ca");
        let ca_pem = pem(
            ca.clone().self_signed(&ca_key).unwrap().der(),
            "CERTIFICATE",
        );
        let issuer = Issuer::new(ca, ca_key);
        let (server_pem, server_key) = leaf(&issuer, ExtendedKeyUsagePurpose::ServerAuth);
        let (client_cert_pem, client_key_pem) = leaf(&issuer, ExtendedKeyUsagePurpose::ClientAuth);

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = if require_client_auth {
            let mut roots = rustls::RootCertStore::empty();
            roots.add_parsable_certificates(
                rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes())
                    .filter_map(Result::ok),
            );
            builder.with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .unwrap(),
            )
        } else {
            builder.with_no_client_auth()
        };
        let chain = rustls::pki_types::CertificateDer::pem_slice_iter(server_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(server_key.as_bytes()).unwrap();
        Pki {
            ca_pem,
            server: Arc::new(builder.with_single_cert(chain, key).unwrap()),
            client_cert_pem,
            client_key_pem,
        }
    }

    use rustls::pki_types::pem::PemObject;

    fn kubeconfig(pki: &Pki, port: u16, user: &str) -> String {
        format!(
            "current-context: c\ncontexts:\n- name: c\n  context: {{cluster: k, user: u}}\nclusters:\n- name: k\n  cluster:\n    server: https://127.0.0.1:{port}\n    certificate-authority-data: {}\nusers:\n- name: u\n  user:\n{user}\n",
            b64(pki.ca_pem.as_bytes())
        )
    }

    fn serve_list() -> impl FnMut(&Request) -> Reply + Send + 'static {
        |req| {
            if req.is_watch() {
                Reply::Stream(mpsc::channel().1)
            } else {
                list(
                    "1",
                    vec![slice("a", "1", &[up("10.1.1.1")], &[("http", 80)])],
                )
            }
        }
    }

    #[tokio::test]
    async fn a_client_certificate_and_the_cluster_ca() {
        let pki = pki(true);
        let fake = Fake::tls(pki.server.clone(), serve_list());
        let user = format!(
            "    client-certificate-data: {}\n    client-key-data: {}",
            b64(pki.client_cert_pem.as_bytes()),
            b64(pki.client_key_pem.as_bytes())
        );
        let text = kubeconfig(&pki, fake.addr.port(), &user);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kubeconfig");
        std::fs::write(&path, text).unwrap();
        let load: Loader = Arc::new(move || config::from_kubeconfig(&path));
        let mut source = Source::with_loader(load, web(), quick());
        assert_eq!(synced(&source.first().await), [sa("10.1.1.1:80")]);
        until("the watch over TLS", || !fake.watches().is_empty()).await;
    }

    #[tokio::test]
    async fn a_bearer_token_over_tls_and_a_wrong_ca_is_refused() {
        let pki = pki(false);
        let fake = Fake::tls(pki.server.clone(), serve_list());
        let text = kubeconfig(&pki, fake.addr.port(), "    token: tls-token");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kubeconfig");
        std::fs::write(&path, &text).unwrap();
        let good = path.clone();
        let load: Loader = Arc::new(move || config::from_kubeconfig(&good));
        let mut source = Source::with_loader(load, web(), quick());
        assert_eq!(synced(&source.first().await), [sa("10.1.1.1:80")]);
        assert_eq!(
            fake.lists()[0].authorization.as_deref(),
            Some("Bearer tls-token")
        );
        drop(source);

        let other = self::pki(false);
        let wrong = kubeconfig(&other, fake.addr.port(), "    token: tls-token");
        std::fs::write(&path, wrong).unwrap();
        let load: Loader = Arc::new(move || config::from_kubeconfig(&path));
        let mut source = Source::with_loader(load, web(), quick());
        source.next().await;
        let refused = source.next().await;
        assert!(
            matches!(&refused.state, SourceState::Unreachable { error, .. } if error.contains("certificate")),
            "the handshake fails on the certificate: {refused:?}"
        );
        source.silent_for(Duration::from_millis(600)).await;
        assert_eq!(
            fake.lists().len(),
            1,
            "a server the CA did not sign is never queried"
        );
    }
}
