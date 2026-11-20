//! Prometheus metrics. Collection is on only while some site has a `metrics` step.
//!
//! # Collection: plain memory on the core, no atomic, no lock
//!
//! Counters a request touches belong to the `CoreSnapshot` it runs under ([`Counters`], cells
//! laid out by [`Layout`]). A reload never re-indexes anything and never misattributes a
//! request that started before it: the old snapshot keeps counting until its last request
//! ends, then its `Drop` folds its counts into the core's [`Retired`] totals, keyed by label.
//! Per-connection facts are [`ConnCounters`] on the `Core` itself.
//!
//! # Publication: once a second, off the request path
//!
//! The core's 1 s clock tick sums its retired totals and every live snapshot's counters by
//! label, and copies them with its connection counters into its slot of the [`Hub`], which
//! only that tick and a scrape lock. A count is visible to a scrape at most one second after
//! its request ended; a long tunnel's snapshot is live, and published, until it closes.
//!
//! # Exposition: the `metrics` step
//!
//! Whatever core takes the scrape publishes its own counts first, then sums the slots by
//! label, reads the shared health cells, the limit tables and the process's own figures, and
//! writes the text format (`render::SERIES` lists every family).
//!
//! # Cardinality, bounded by the config
//!
//! Request series: (site, nearest named step, status class). Upstream series: one per origin
//! label the config names, one per discovery source (its origins aggregate there). Limits:
//! one per `limit` step. Listeners: derived from sites. `upstreamer check` prints the count.

mod counters;
mod render;

pub(crate) use counters::{Cause, ConnCounters, Counters, Layout, Published, Retired};

use crate::body::Body;
use crate::exchange::Exchange;
use crate::msg::{Known, Status};
use crate::pipeline::{self, Response};
use crate::plan::{ListenerKind, Plan};
use crate::runtime::{Core, CoreSnapshot};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// One per process, made by the control thread. Every generation that collects metrics carries
/// the same `Arc`, so nothing about it depends on the plan.
pub(crate) struct Hub {
    cores: Box<[Mutex<Published>]>,
    /// Written by the control thread: generation, reload results, discovery state.
    control: Mutex<Control>,
    started: std::time::SystemTime,
}

#[derive(Clone, Default)]
pub(crate) struct Control {
    pub generation: u64,
    pub reloads_ok: u64,
    pub reloads_rejected: u64,
    /// Per discovery source: label, endpoints, synced.
    pub sources: Vec<(Arc<str>, usize, bool)>,
}

impl Hub {
    /// A hub with a slot for each of `cores` cores.
    pub fn new(cores: usize) -> Arc<Hub> {
        Arc::new(Hub {
            cores: (0..cores).map(|_| Mutex::default()).collect(),
            control: Mutex::default(),
            started: std::time::SystemTime::now(),
        })
    }

    /// The control thread's facts, updated after each reload and discovery change.
    pub fn control(&self) -> std::sync::MutexGuard<'_, Control> {
        self.control.lock().unwrap_or_else(|e| e.into_inner())
    }
}

thread_local! {
    /// The core's scrape buffer, kept between scrapes.
    static SCRAPE: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// The `metrics` terminal: the exposition of every core as a local `200`.
pub(crate) fn serve(core: &Core, snap: &CoreSnapshot, ex: &mut Exchange) -> Response {
    let Some(counters) = &snap.metrics else {
        return pipeline::bare(ex, Status::NOT_FOUND);
    };
    publish(core);
    let body = SCRAPE.with_borrow_mut(|out| {
        out.clear();
        render::render(
            &render::Inputs {
                hub: &counters.hub,
                layout: &counters.layout,
                upstreams: &snap.upstreams,
                limits: &snap.limits,
                now: core.clock.mono.get(),
            },
            out,
        );
        bytes::Bytes::copy_from_slice(out)
    });
    let mut head = ex.response_head(Status::OK);
    head.fields
        .append_known(Known::ContentType, render::CONTENT_TYPE.as_bytes());
    Response {
        head,
        body: Body::Bytes(body),
        upgrade: None,
        local: true,
    }
}

/// Called from the core's 1 s tick while its snapshot collects metrics.
pub(crate) fn publish(core: &Core) {
    counters::publish(core);
}

/// The most series a plan exposes, for `upstreamer check`: every label set the plan can
/// produce, each histogram counted with its buckets, sum and count.
pub(crate) fn series(plan: &Plan) -> usize {
    use counters::{BUCKETS, CLASSES};
    let histogram = BUCKETS + 2;
    let routes = plan.routes.len() * (CLASSES + histogram);
    let limits = plan.limits.len() * 2;
    let upstreams = crate::upstream::Registry::new(1).build(plan);
    let labels: HashSet<&str> = upstreams.origins().iter().map(|o| &*o.label).collect();
    let per_origin = CLASSES + Cause::ALL.len() + histogram + 3;
    let origins = (labels.len() + plan.sources.len()) * per_origin;
    let listeners: usize = plan
        .listeners
        .iter()
        .map(|l| {
            if l.key.kind == ListenerKind::Https {
                4
            } else {
                2
            }
        })
        .sum();
    let sources = plan.sources.len() * 2;
    routes + limits + origins + listeners + sources + render::FIXED_SERIES
}

/// Entry points for `benches/metrics.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {
    use super::counters::{Counters, Layout, Published, Retired};
    use crate::msg::Status;
    use crate::plan::{Plan, RouteSlot};
    use crate::upstream::{Registry, Upstreams};
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::Duration;

    fn compile(config: serde_json::Value) -> Plan {
        let config =
            crate::config::parse_config(crate::config::Format::Json, config.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message))
                .value;
        match crate::plan::compile::compile(&config, &crate::plan::compile::FileSystem, 1) {
            Ok((plan, _)) => plan,
            Err(diagnostics) => panic!("{diagnostics:?}"),
        }
    }

    /// A plan with `routes` named proxy routes, each to an origin of its own.
    fn plan(routes: usize) -> Plan {
        let mut steps: Vec<serde_json::Value> = vec![
            serde_json::json!({"name": "scrape", "when": {"path": "/metrics"}, "metrics": {}}),
        ];
        steps.extend((0..routes).map(|i| {
            serde_json::json!({
                "name": format!("route{i}"),
                "when": {"path": format!("/r{i}")},
                "proxy": format!("http://127.0.0.{}:{}", 1 + i / 60000, 1024 + i % 60000),
            })
        }));
        compile(serde_json::json!({
            "version": 1,
            "sites": [{"name": "bench", "hosts": ["*"], "listen": ["127.0.0.1:1"], "routes": steps}],
        }))
    }

    /// One snapshot's counters, as a request sees them.
    pub struct Requests {
        counters: Counters,
        slot: RouteSlot,
    }

    impl Requests {
        pub fn new() -> Requests {
            let plan = plan(4);
            let upstreams = Registry::new(1).build(&plan);
            Requests {
                counters: Counters::new(
                    Layout::build(&plan, &upstreams),
                    super::Hub::new(1),
                    Rc::new(RefCell::new(Retired::default())),
                ),
                slot: RouteSlot(2),
            }
        }

        /// What `observe::finish` counts for a proxied request.
        #[inline]
        pub fn count(&self, took: Duration) {
            self.counters.request(self.slot, Status::OK, took);
            self.counters
                .upstream(crate::plan::OriginId(1), Ok(Status::OK), took / 2);
        }
    }

    impl Default for Requests {
        fn default() -> Requests {
            Requests::new()
        }
    }

    /// A hub whose cores published counts for every series of a plan with `routes` routes.
    pub struct Scrape {
        layout: Arc<Layout>,
        hub: Arc<super::Hub>,
        upstreams: Arc<Upstreams>,
        limits: Arc<crate::limit::Limiters>,
        out: Vec<u8>,
        _counters: Vec<Counters>,
    }

    impl Scrape {
        pub fn new(routes: usize, cores: usize) -> Scrape {
            let plan = plan(routes);
            let upstreams = Registry::new(1).build(&plan);
            let layout = Layout::build(&plan, &upstreams);
            let hub = super::Hub::new(cores);
            let mut counters = Vec::new();
            for core in 0..cores {
                let retired = Rc::new(RefCell::new(Retired::default()));
                let c = Counters::new(layout.clone(), hub.clone(), retired.clone());
                for (i, _) in plan.routes.iter().enumerate() {
                    for status in [200, 301, 404, 503] {
                        c.request(
                            RouteSlot(i as u16),
                            Status::new(status).unwrap(),
                            Duration::from_micros((i as u64 * 7919) % 2_000_000),
                        );
                    }
                }
                for i in 0..upstreams.origins().len() {
                    let id = crate::plan::OriginId(i as u16);
                    c.upstream(id, Ok(Status::OK), Duration::from_micros(900));
                    c.upstream(id, Err(super::Cause::Connect), Duration::ZERO);
                }
                let mut published = hub.cores[core].lock().unwrap();
                retired
                    .borrow_mut()
                    .publish(&layout, 0, &mut published as &mut Published);
                counters.push(c);
            }
            Scrape {
                limits: crate::limit::Limiters::carry(&plan, None),
                layout,
                hub,
                upstreams,
                out: Vec::new(),
                _counters: counters,
            }
        }

        /// Renders one scrape; returns its length in bytes.
        pub fn render(&mut self) -> usize {
            self.out.clear();
            super::render::render(
                &super::render::Inputs {
                    hub: &self.hub,
                    layout: &self.layout,
                    upstreams: &self.upstreams,
                    limits: &self.limits,
                    now: 0,
                },
                &mut self.out,
            );
            self.out.len()
        }

        /// The sample lines of the last scrape.
        pub fn samples(&self) -> usize {
            self.out
                .split(|&b| b == b'\n')
                .filter(|l| !l.is_empty() && l[0] != b'#')
                .count()
        }

        pub fn text(&self) -> &[u8] {
            &self.out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::render::{Kind, SERIES};
    use crate::runtime::control::publish as install;
    use crate::runtime::testing::*;
    use crate::runtime::{Generation, allowed_cpus, spawn_workers, stop};
    use crate::upstream::Registry;
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    /// An origin that answers every request with `200` and a two-byte body.
    fn origin() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut pending = Vec::new();
                    loop {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                        while let Some(end) = memchr::memmem::find(&pending, b"\r\n\r\n") {
                            pending.drain(..end + 4);
                            let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                            if stream.write_all(answer).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    /// A site named `t` on `listen`: `/metrics` scrapes, `/api` proxies to `origin`, anything
    /// else answers `ok` under the step name `web`.
    fn config(listen: SocketAddr, origin: SocketAddr, web: &str) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "listen": { "http": [listen], "https": [] },
            "sites": [{
                "name": "t",
                "hosts": ["*"],
                "routes": [
                    { "name": "scrape", "when": { "path": "/metrics" }, "metrics": {} },
                    { "name": "api", "when": { "path": "/api" },
                      "proxy": format!("http://{origin}") },
                    { "name": web, "respond": { "body": "ok" } },
                ],
            }],
        })
    }

    fn generation(number: u64, config: &serde_json::Value) -> Arc<Generation> {
        Arc::new(Generation::standalone(
            plan_from(number, config),
            None,
            Arc::default(),
        ))
    }

    fn request(conn: &mut TcpStream, path: &str) -> (String, Vec<u8>) {
        // One write: a head sent in pieces waits on Nagle and the server's delayed ACK.
        let head = format!("GET {path} HTTP/1.1\r\nHost: t\r\n\r\n");
        conn.write_all(head.as_bytes()).unwrap();
        let (head, body) = read_response(conn).unwrap();
        assert!(head.starts_with("HTTP/1.1 200 OK\r\n"), "{head}");
        (head, body)
    }

    struct Sample {
        name: String,
        labels: Vec<(String, String)>,
        value: f64,
    }

    impl Sample {
        fn label(&self, key: &str) -> Option<&str> {
            self.labels
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.as_str())
        }
    }

    /// The families (name to type) and samples of a text exposition. Panics on a line the
    /// format does not allow, a sample of no declared family, or a series given twice.
    fn parse(text: &str) -> (HashMap<String, String>, Vec<Sample>) {
        let mut types = HashMap::new();
        let mut samples: Vec<Sample> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').expect("a type line");
                assert!(
                    types.insert(name.to_owned(), kind.to_owned()).is_none(),
                    "{name} typed twice"
                );
                continue;
            }
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let (series, value) = line.rsplit_once(' ').expect("a value");
            let value: f64 = match value {
                "+Inf" => f64::INFINITY,
                v => v.parse().unwrap_or_else(|_| panic!("value of {line}")),
            };
            let (name, labels) = match series.split_once('{') {
                None => (series, Vec::new()),
                Some((name, rest)) => {
                    let rest = rest.strip_suffix('}').expect("closed labels");
                    let mut labels = Vec::new();
                    let mut chars = rest.chars().peekable();
                    while chars.peek().is_some() {
                        let key: String = chars.by_ref().take_while(|&c| c != '=').collect();
                        assert_eq!(chars.next(), Some('"'), "{line}");
                        let mut value = String::new();
                        while let Some(c) = chars.next() {
                            match c {
                                '\\' => value.push(match chars.next() {
                                    Some('n') => '\n',
                                    Some(c) => c,
                                    None => panic!("{line}"),
                                }),
                                '"' => break,
                                c => value.push(c),
                            }
                        }
                        if chars.peek() == Some(&',') {
                            chars.next();
                        }
                        labels.push((key, value));
                    }
                    (name, labels)
                }
            };
            let family = ["_bucket", "_sum", "_count"]
                .iter()
                .find_map(|s| {
                    name.strip_suffix(s)
                        .filter(|f| types.get(*f).is_some_and(|t| t == "histogram"))
                })
                .unwrap_or(name);
            assert!(types.contains_key(family), "{name} has no TYPE before it");
            assert!(seen.insert(series.to_owned()), "{series} given twice");
            samples.push(Sample {
                name: name.to_owned(),
                labels,
                value,
            });
        }
        (types, samples)
    }

    fn total(samples: &[Sample], name: &str, filter: impl Fn(&Sample) -> bool) -> f64 {
        samples
            .iter()
            .filter(|s| s.name == name && filter(s))
            .map(|s| s.value)
            .sum()
    }

    /// The histogram of `name` for the labels `filter` selects: checks its buckets are
    /// cumulative and end in `+Inf` equal to `_count`, and returns the count.
    fn histogram_count(samples: &[Sample], name: &str, filter: impl Fn(&Sample) -> bool) -> f64 {
        let buckets: Vec<&Sample> = samples
            .iter()
            .filter(|s| s.name == format!("{name}_bucket") && filter(s))
            .collect();
        assert_eq!(buckets.len(), 14, "{name} has 13 buckets and +Inf");
        let mut last = 0.0;
        let mut bound = 0.0;
        for b in &buckets {
            let le: f64 = match b.label("le").unwrap() {
                "+Inf" => f64::INFINITY,
                le => le.parse().unwrap(),
            };
            assert!(le > bound, "{name}: buckets in increasing `le` order");
            assert!(b.value >= last, "{name}: buckets are cumulative");
            (bound, last) = (le, b.value);
        }
        assert_eq!(bound, f64::INFINITY, "{name}: the last bucket is +Inf");
        let count = total(samples, &format!("{name}_count"), &filter);
        assert_eq!(last, count, "{name}: +Inf equals _count");
        count
    }

    #[test]
    fn check_counts_each_named_route_and_origin_once() {
        let listen = "127.0.0.1:1".parse().unwrap();
        let origin = "127.0.0.1:2".parse().unwrap();
        let one = super::series(&plan_from(1, &config(listen, origin, "web")));
        let mut more = config(listen, origin, "web");
        more["sites"][0]["routes"].as_array_mut().unwrap().insert(
            2,
            serde_json::json!({ "name": "other", "when": { "path": "/o" },
                "proxy": "http://127.0.0.1:3" }),
        );
        let two = super::series(&plan_from(1, &more));
        // A route: five classes and a 14-bucket histogram with its sum and count. An origin:
        // five classes, five causes, a histogram, health, in-flight and retries.
        assert_eq!(two - one, (5 + 16) + (5 + 5 + 16 + 3));
    }

    #[test]
    fn a_scrape_has_every_family_with_its_type_and_counts_each_request_once() {
        let listen = free_addr();
        let origin = origin();
        let workers = spawn_workers(
            &[allowed_cpus()[0]],
            generation(1, &config(listen, origin, "web")),
        )
        .unwrap();
        let mut conn = connect(listen);
        for _ in 0..30 {
            request(&mut conn, "/api");
        }
        for _ in 0..20 {
            request(&mut conn, "/");
        }
        let (head, body) = request(&mut conn, "/metrics");
        stop(workers, Instant::now());
        assert!(
            head.contains("\r\ncontent-type: text/plain; version=0.0.4; charset=utf-8\r\n"),
            "{head}"
        );
        let text = String::from_utf8(body).unwrap();
        let (types, samples) = parse(&text);
        for family in SERIES {
            let kind = match family.kind {
                Kind::Counter => "counter",
                Kind::Gauge => "gauge",
                Kind::Histogram => "histogram",
            };
            assert_eq!(
                types.get(family.name).map(String::as_str),
                Some(kind),
                "{} is declared with its type",
                family.name
            );
        }
        assert_eq!(types.len(), SERIES.len(), "no family outside SERIES");

        let route = |r: &'static str| move |s: &Sample| s.label("route") == Some(r);
        assert_eq!(
            total(&samples, "upstreamer_requests_total", route("api")),
            30.0
        );
        assert_eq!(
            total(&samples, "upstreamer_requests_total", route("web")),
            20.0
        );
        assert_eq!(
            total(&samples, "upstreamer_requests_total", |s| s.label("code")
                == Some("2xx")),
            50.0,
            "every request answered 200"
        );
        assert_eq!(
            histogram_count(
                &samples,
                "upstreamer_request_duration_seconds",
                route("api")
            ),
            30.0
        );
        assert_eq!(
            histogram_count(
                &samples,
                "upstreamer_request_duration_seconds",
                route("web")
            ),
            20.0
        );
        let label = origin.to_string();
        let at_origin = |s: &Sample| s.label("origin") == Some(label.as_str());
        assert_eq!(
            total(&samples, "upstreamer_upstream_responses_total", at_origin),
            30.0
        );
        assert_eq!(
            histogram_count(&samples, "upstreamer_upstream_response_seconds", at_origin),
            30.0
        );
        assert_eq!(
            total(&samples, "upstreamer_upstream_failures_total", at_origin),
            0.0
        );
        assert_eq!(
            total(&samples, "upstreamer_upstream_healthy", at_origin),
            1.0
        );
        assert_eq!(
            total(&samples, "upstreamer_connections_total", |s| s
                .label("listener")
                == Some(&format!("{listen}/tcp"))),
            1.0
        );
        assert!(
            samples
                .iter()
                .any(|s| s.name == "process_cpu_seconds_total" && s.value > 0.0)
        );
    }

    #[test]
    fn a_closed_connection_leaves_the_open_gauge_and_stays_in_the_total() {
        let listen = free_addr();
        let workers = spawn_workers(
            &[allowed_cpus()[0]],
            generation(1, &config(listen, origin(), "web")),
        )
        .unwrap();
        let mut kept = connect(listen);
        let mut closed = connect(listen);
        request(&mut closed, "/");
        drop(closed);
        let name = format!("{listen}/tcp");
        let on_listener = |s: &Sample| s.label("listener") == Some(name.as_str());
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let (open, accepted) = loop {
            let (_, body) = request(&mut kept, "/metrics");
            let (_, samples) = parse(&String::from_utf8(body).unwrap());
            let open = total(&samples, "upstreamer_connections_open", on_listener);
            let all = total(&samples, "upstreamer_connections_total", on_listener);
            if open == 1.0 || Instant::now() > deadline {
                break (open, all);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        stop(workers, Instant::now());
        assert_eq!(open, 1.0, "only the scraping connection is open");
        assert_eq!(accepted, 2.0, "both connections were accepted");
    }

    #[test]
    fn counts_are_exact_across_reloads_and_discovery_epochs() {
        let listen = free_addr();
        let origin = origin();
        let cpus = allowed_cpus();
        let cores = [cpus[0], cpus[cpus.len() - 1]];
        let mut current = generation(1, &config(listen, origin, "web0"));
        let workers = spawn_workers(&cores, current.clone()).unwrap();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let running = Arc::new(AtomicBool::new(true));
        let completed = Arc::new(AtomicU64::new(0));
        let proxied = Arc::new(AtomicU64::new(0));
        let clients: Vec<_> = (0..4)
            .map(|i| {
                let (running, completed, proxied) =
                    (running.clone(), completed.clone(), proxied.clone());
                std::thread::spawn(move || {
                    let mut conn = connect(listen);
                    let mut n = 0u64;
                    while running.load(Ordering::Relaxed) {
                        let path = if (n + i).is_multiple_of(3) {
                            "/api"
                        } else {
                            "/"
                        };
                        request(&mut conn, path);
                        completed.fetch_add(1, Ordering::Relaxed);
                        if path == "/api" {
                            proxied.fetch_add(1, Ordering::Relaxed);
                        }
                        n += 1;
                        // A new connection now and then, so connections span generations.
                        if n.is_multiple_of(97) {
                            conn = connect(listen);
                        }
                    }
                })
            })
            .collect();

        let mut registry = Registry::new(2);
        for step in 0..70u64 {
            std::thread::sleep(Duration::from_millis(15));
            let next = if step % 7 == 3 {
                let upstreams = registry.build(&current.plan);
                let hub = current.metrics.as_ref().unwrap().1.clone();
                Arc::new(Generation {
                    metrics: Some((super::Layout::build(&current.plan, &upstreams), hub)),
                    upstreams,
                    ..(*current).clone()
                })
            } else {
                let web = format!("web{}", step % 3);
                generation(step + 2, &config(listen, origin, &web))
            };
            assert!(rt.block_on(install(&workers, next.clone())).is_empty());
            current = next;
        }
        running.store(false, Ordering::Relaxed);
        for client in clients {
            client.join().unwrap();
        }
        std::thread::sleep(Duration::from_millis(1_500));
        let mut conn = connect(listen);
        let (_, body) = request(&mut conn, "/metrics");
        stop(workers, Instant::now());

        let text = String::from_utf8(body).unwrap();
        let (_, samples) = parse(&text);
        let completed = completed.load(Ordering::Relaxed) as f64;
        assert!(completed > 1_000.0, "the clients ran: {completed}");
        assert_eq!(
            total(&samples, "upstreamer_requests_total", |_| true),
            completed,
            "every completed request counted once"
        );
        assert_eq!(
            total(
                &samples,
                "upstreamer_request_duration_seconds_count",
                |_| true
            ),
            completed
        );
        assert_eq!(
            total(&samples, "upstreamer_upstream_responses_total", |_| true),
            proxied.load(Ordering::Relaxed) as f64,
            "every proxied request counted once at its origin"
        );
        for web in ["web0", "web1", "web2"] {
            assert!(
                total(&samples, "upstreamer_requests_total", |s| s.label("route")
                    == Some(web))
                    > 0.0,
                "{web} keeps its counts after the plan moved on"
            );
        }
    }

    #[test]
    fn zero_allocations_per_request_with_metrics_on() {
        let listen = free_addr();
        let origin = origin();
        let workers = spawn_workers(
            &[allowed_cpus()[0]],
            generation(1, &config(listen, origin, "web")),
        )
        .unwrap();
        let mut conn = connect(listen);
        let warm = |conn: &mut TcpStream| {
            for _ in 0..1_000 {
                request(conn, "/api");
                request(conn, "/");
            }
        };
        warm(&mut conn);
        // The first ticks size what each tick reuses.
        std::thread::sleep(Duration::from_millis(2_200));
        warm(&mut conn);
        let signals = counting(|| {
            request(&mut conn, "/");
        });
        let before = served(listen.port(), 0).allocations;
        let requests = 10_000;
        for _ in 0..requests {
            request(&mut conn, "/api");
            request(&mut conn, "/");
        }
        // A tick runs, and the next request shows what it allocated.
        std::thread::sleep(Duration::from_millis(1_200));
        request(&mut conn, "/");
        let after = served(listen.port(), 0).allocations;
        drop(signals);
        stop(workers, Instant::now());
        println!(
            "core thread allocations over {} requests with metrics on: {}",
            2 * requests + 1,
            after - before
        );
        assert_eq!(after - before, 0, "allocations on the core thread");
    }
}
