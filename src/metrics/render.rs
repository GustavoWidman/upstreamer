//! The text exposition format (version 0.0.4). `SERIES` is the one list of metric names,
//! types and help texts: rendering iterates it, and a test checks a scrape against it.

use super::counters::{BUCKET_LABELS, BUCKETS, CLASSES, Cause, Key, Layout, conn, route, upstream};
use super::{Control, Hub};
use crate::limit::Limiters;
use crate::plan::{ListenerKey, ListenerKind};
use crate::upstream::Upstreams;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::Ordering;

pub(crate) const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub(super) struct Family {
    pub name: &'static str,
    pub kind: Kind,
    pub help: &'static str,
    /// Writes the family's samples.
    samples: fn(&Scrape, &'static str, &mut Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Counter,
    Gauge,
    Histogram,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Counter => "counter",
            Kind::Gauge => "gauge",
            Kind::Histogram => "histogram",
        }
    }
}

const fn family(
    name: &'static str,
    kind: Kind,
    help: &'static str,
    samples: fn(&Scrape, &'static str, &mut Vec<u8>),
) -> Family {
    Family {
        name,
        kind,
        help,
        samples,
    }
}

pub(super) const SERIES: &[Family] = &[
    family(
        "upstreamer_requests_total",
        Kind::Counter,
        "Requests answered, by site, nearest named step and status class.",
        |s, name, out| {
            for (labels, v) in s.routes() {
                classes(out, name, labels, &v[route::REQUESTS..]);
            }
        },
    ),
    family(
        "upstreamer_request_duration_seconds",
        Kind::Histogram,
        "From the site's choice to the end of the response or tunnel.",
        |s, name, out| {
            for (labels, v) in s.routes() {
                histogram(out, name, labels, &v[route::DURATION..=route::DURATION_SUM]);
            }
        },
    ),
    family(
        "upstreamer_upstream_responses_total",
        Kind::Counter,
        "Response heads received from an origin, by status class.",
        |s, name, out| {
            for (labels, v) in s.upstreams() {
                classes(out, name, labels, &v[upstream::RESPONSES..]);
            }
        },
    ),
    family(
        "upstreamer_upstream_failures_total",
        Kind::Counter,
        "Attempts that got no usable response head, by cause.",
        |s, name, out| {
            for (labels, v) in s.upstreams() {
                for cause in Cause::ALL {
                    sample(
                        out,
                        name,
                        "",
                        labels,
                        Some(("cause", cause.label())),
                        v[upstream::FAILURES + cause.index()],
                    );
                }
            }
        },
    ),
    family(
        "upstreamer_upstream_response_seconds",
        Kind::Histogram,
        "From the first attempt to the origin's response head.",
        |s, name, out| {
            for (labels, v) in s.upstreams() {
                histogram(
                    out,
                    name,
                    labels,
                    &v[upstream::RESPONSE..=upstream::RESPONSE_SUM],
                );
            }
        },
    ),
    family(
        "upstreamer_upstream_healthy",
        Kind::Gauge,
        "Origins behind the label that may be picked now (not failing a probe, not ejected): \
         0 or 1 for an origin from the config, a count for a discovery source.",
        |s, name, out| {
            for (labels, origin) in &s.origins {
                sample(out, name, "", labels, None, origin.healthy);
            }
        },
    ),
    family(
        "upstreamer_upstream_in_flight",
        Kind::Gauge,
        "Requests waiting on or reading from an origin behind the label.",
        |s, name, out| {
            for (labels, origin) in &s.origins {
                sample(out, name, "", labels, None, origin.in_flight);
            }
        },
    ),
    family(
        "upstreamer_upstream_retries_total",
        Kind::Counter,
        "Attempts made on another origin after a failure.",
        |s, name, out| {
            for (labels, v) in s.upstreams() {
                if v[upstream::RETRIES] > 0 {
                    sample(out, name, "", labels, None, v[upstream::RETRIES]);
                }
            }
        },
    ),
    family(
        "upstreamer_ratelimit_rejected_total",
        Kind::Counter,
        "Requests a limit step answered with 429.",
        |s, name, out| {
            for (labels, limit) in &s.limits {
                sample(out, name, "", labels, None, limit.rejected);
            }
        },
    ),
    family(
        "upstreamer_ratelimit_evictions_total",
        Kind::Counter,
        "Live buckets replaced because the table was full.",
        |s, name, out| {
            for (labels, limit) in &s.limits {
                if let Some(evictions) = limit.evictions {
                    sample(out, name, "", labels, None, evictions);
                }
            }
        },
    ),
    family(
        "upstreamer_connections_open",
        Kind::Gauge,
        "Downstream connections open now.",
        |s, name, out| {
            for (listener, cells) in &s.conns {
                let open = cells[conn::ACCEPTED].saturating_sub(cells[conn::CLOSED]);
                listener_sample(out, name, listener, None, open);
            }
        },
    ),
    family(
        "upstreamer_connections_total",
        Kind::Counter,
        "Downstream connections accepted.",
        |s, name, out| {
            for (listener, cells) in &s.conns {
                listener_sample(out, name, listener, None, cells[conn::ACCEPTED]);
            }
        },
    ),
    family(
        "upstreamer_tls_handshakes_total",
        Kind::Counter,
        "TLS handshakes over TCP, by result.",
        |s, name, out| {
            for (listener, cells) in &s.conns {
                if listener.kind == ListenerKind::Https {
                    for (result, cell) in [
                        ("completed", conn::HANDSHAKES_OK),
                        ("failed", conn::HANDSHAKES_FAILED),
                    ] {
                        listener_sample(out, name, listener, Some(result), cells[cell]);
                    }
                }
            }
        },
    ),
    family(
        "upstreamer_discovery_endpoints",
        Kind::Gauge,
        "Ready endpoints a discovery source last reported.",
        |s, name, out| {
            for (source, endpoints, _) in &s.control.sources {
                labelled(out, name, "source", source, *endpoints as u64);
            }
        },
    ),
    family(
        "upstreamer_discovery_synced",
        Kind::Gauge,
        "1 while the source's watch is connected and listed.",
        |s, name, out| {
            for (source, _, synced) in &s.control.sources {
                labelled(out, name, "source", source, u64::from(*synced));
            }
        },
    ),
    family(
        "upstreamer_config_generation",
        Kind::Gauge,
        "The generation being served.",
        |s, name, out| sample(out, name, "", "", None, s.control.generation),
    ),
    family(
        "upstreamer_config_reloads_total",
        Kind::Counter,
        "Reloads, by result.",
        |s, name, out| {
            labelled(out, name, "result", "ok", s.control.reloads_ok);
            labelled(out, name, "result", "rejected", s.control.reloads_rejected);
        },
    ),
    family(
        "upstreamer_build_info",
        Kind::Gauge,
        "The running build.",
        |_, name, out| {
            let features = if cfg!(feature = "kubernetes") {
                "kubernetes"
            } else {
                ""
            };
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b"{version=\"");
            out.extend_from_slice(env!("CARGO_PKG_VERSION").as_bytes());
            out.extend_from_slice(b"\",features=\"");
            out.extend_from_slice(features.as_bytes());
            out.extend_from_slice(b"\"} 1\n");
        },
    ),
    family(
        "process_cpu_seconds_total",
        Kind::Counter,
        "Total user and system CPU time spent in seconds.",
        |s, name, out| seconds(out, name, s.process.cpu_micros),
    ),
    family(
        "process_resident_memory_bytes",
        Kind::Gauge,
        "Resident memory size in bytes.",
        |s, name, out| optional(out, name, s.process.resident_bytes),
    ),
    family(
        "process_virtual_memory_bytes",
        Kind::Gauge,
        "Virtual memory size in bytes.",
        |s, name, out| optional(out, name, s.process.virtual_bytes),
    ),
    family(
        "process_open_fds",
        Kind::Gauge,
        "Number of open file descriptors.",
        |s, name, out| optional(out, name, s.process.open_fds),
    ),
    family(
        "process_max_fds",
        Kind::Gauge,
        "Maximum number of open file descriptors.",
        |s, name, out| optional(out, name, s.process.max_fds),
    ),
    family(
        "process_start_time_seconds",
        Kind::Gauge,
        "Start time of the process since unix epoch in seconds.",
        |s, name, out| seconds(out, name, s.process.start_micros),
    ),
    family(
        "process_threads",
        Kind::Gauge,
        "Number of OS threads in the process.",
        |s, name, out| optional(out, name, s.process.threads),
    ),
];

/// Series every plan has whatever its config: the generation, two reload results, the build
/// and seven process figures.
pub(super) const FIXED_SERIES: usize = 1 + 2 + 1 + 7;

/// What a scrape reads besides the hub.
pub(super) struct Inputs<'a> {
    pub hub: &'a Hub,
    pub layout: &'a Layout,
    pub upstreams: &'a Upstreams,
    pub limits: &'a Limiters,
    /// The health clock, whole seconds.
    pub now: u32,
}

#[derive(Default)]
struct OriginState {
    healthy: u64,
    in_flight: u64,
}

#[derive(Default)]
struct LimitState {
    rejected: u64,
    /// `None` for a route whose rejections come from a limit step no longer in the plan.
    evictions: Option<u64>,
}

/// Everything a scrape writes, summed across cores and sorted by labels.
struct Scrape {
    series: Vec<(Key, Vec<u64>)>,
    /// By escaped `origin=".."` labels.
    origins: BTreeMap<String, OriginState>,
    /// By escaped route labels.
    limits: BTreeMap<Arc<str>, LimitState>,
    conns: Vec<(ListenerKey, [u64; conn::LEN])>,
    control: Control,
    process: Process,
}

impl Scrape {
    fn routes(&self) -> impl Iterator<Item = (&str, &[u64])> {
        self.series
            .iter()
            .filter(|(k, _)| matches!(k, Key::Route(_)))
            .map(|(k, v)| (k.labels(), &v[..]))
    }

    fn upstreams(&self) -> impl Iterator<Item = (&str, &[u64])> {
        self.series
            .iter()
            .filter(|(k, _)| matches!(k, Key::Upstream(_)))
            .map(|(k, v)| (k.labels(), &v[..]))
    }

    fn gather(inputs: &Inputs) -> Scrape {
        let mut index: HashMap<Key, usize> = HashMap::new();
        let mut series: Vec<(Key, Vec<u64>)> = Vec::new();
        let mut in_flight: HashMap<Arc<str>, u64> = HashMap::new();
        let mut conns: Vec<(ListenerKey, [u64; conn::LEN])> = Vec::new();
        for slot in inputs.hub.cores.iter() {
            let published = slot.lock().unwrap_or_else(|e| e.into_inner());
            for (key, values) in &published.series {
                let i = *index.entry(key.clone()).or_insert_with(|| {
                    series.push((key.clone(), vec![0; values.len()]));
                    series.len() - 1
                });
                for (sum, v) in series[i].1.iter_mut().zip(values.iter()) {
                    *sum = sum.wrapping_add(*v);
                }
            }
            for (label, n) in &published.in_flight {
                *in_flight.entry(label.clone()).or_default() += u64::from(*n);
            }
            for (listener, cells) in &published.conns {
                match conns.iter_mut().find(|(l, _)| l == listener) {
                    Some((_, sum)) => {
                        for (s, c) in sum.iter_mut().zip(cells) {
                            *s = s.wrapping_add(*c);
                        }
                    }
                    None => conns.push((*listener, *cells)),
                }
            }
        }
        series.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        conns.sort_unstable_by_key(|(l, _)| (l.addr, l.kind as u8));

        let mut origins: BTreeMap<String, OriginState> = BTreeMap::new();
        let mut labels: HashMap<&str, String> = HashMap::new();
        for origin in inputs.upstreams.origins() {
            let label = labels
                .entry(&origin.label)
                .or_insert_with(|| super::counters::origin_labels(&origin.label).to_string());
            let state = origins.entry(label.clone()).or_default();
            state.healthy += u64::from(origin.health.eligible(inputs.now));
        }
        for (raw, n) in in_flight {
            if let Some(state) = labels.get(&*raw).and_then(|l| origins.get_mut(l)) {
                state.in_flight += n;
            }
        }

        let mut limits: BTreeMap<Arc<str>, LimitState> = BTreeMap::new();
        for (labels, table) in inputs.layout.limits.iter().zip(inputs.limits.tables()) {
            let state = limits.entry(labels.clone()).or_default();
            let evictions = table.evictions.load(Ordering::Relaxed);
            state.evictions = Some(state.evictions.unwrap_or(0) + evictions);
        }
        for (key, values) in &series {
            if let Key::Route(labels) = key {
                let rejected = values[route::REJECTED];
                if rejected > 0 || limits.contains_key(labels) {
                    limits.entry(labels.clone()).or_default().rejected = rejected;
                }
            }
        }

        Scrape {
            series,
            origins,
            limits,
            conns,
            control: inputs.hub.control().clone(),
            process: Process::read(inputs.hub.started),
        }
    }
}

/// Sums the published slots, then writes every family in `SERIES` order into `out`.
pub(super) fn render(inputs: &Inputs, out: &mut Vec<u8>) {
    let scrape = Scrape::gather(inputs);
    for family in SERIES {
        out.extend_from_slice(b"# HELP ");
        out.extend_from_slice(family.name.as_bytes());
        out.push(b' ');
        out.extend_from_slice(family.help.as_bytes());
        out.extend_from_slice(b"\n# TYPE ");
        out.extend_from_slice(family.name.as_bytes());
        out.push(b' ');
        out.extend_from_slice(family.kind.name().as_bytes());
        out.push(b'\n');
        (family.samples)(&scrape, family.name, out);
    }
}

/// One sample line: `name suffix {labels,extra} value`.
fn sample(
    out: &mut Vec<u8>,
    name: &str,
    suffix: &str,
    labels: &str,
    extra: Option<(&str, &str)>,
    value: u64,
) {
    open(out, name, suffix, labels, extra);
    integer(out, value);
    out.push(b'\n');
}

fn open(out: &mut Vec<u8>, name: &str, suffix: &str, labels: &str, extra: Option<(&str, &str)>) {
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(suffix.as_bytes());
    if !labels.is_empty() || extra.is_some() {
        out.push(b'{');
        out.extend_from_slice(labels.as_bytes());
        if let Some((key, value)) = extra {
            if !labels.is_empty() {
                out.push(b',');
            }
            out.extend_from_slice(key.as_bytes());
            out.extend_from_slice(b"=\"");
            out.extend_from_slice(value.as_bytes());
            out.push(b'"');
        }
        out.push(b'}');
    }
    out.push(b' ');
}

/// A sample with one label whose value needs escaping.
fn labelled(out: &mut Vec<u8>, name: &str, key: &str, value: &str, n: u64) {
    let mut labels = String::with_capacity(key.len() + value.len() + 3);
    labels.push_str(key);
    labels.push_str("=\"");
    super::counters::escape_into(value, &mut labels);
    labels.push('"');
    sample(out, name, "", &labels, None, n);
}

fn listener_sample(
    out: &mut Vec<u8>,
    name: &str,
    listener: &ListenerKey,
    result: Option<&str>,
    n: u64,
) {
    use std::io::Write;
    out.extend_from_slice(name.as_bytes());
    let transport = match listener.kind {
        ListenerKind::Http | ListenerKind::Https => "tcp",
        ListenerKind::Quic => "quic",
    };
    let _ = write!(out, "{{listener=\"{}/{transport}\"", listener.addr);
    if let Some(result) = result {
        let _ = write!(out, ",result=\"{result}\"");
    }
    out.extend_from_slice(b"} ");
    integer(out, n);
    out.push(b'\n');
}

const CLASS_LABELS: [&str; CLASSES] = ["1xx", "2xx", "3xx", "4xx", "5xx"];

/// The status classes with a count.
fn classes(out: &mut Vec<u8>, name: &str, labels: &str, cells: &[u64]) {
    for (class, &n) in CLASS_LABELS.iter().zip(cells) {
        if n > 0 {
            sample(out, name, "", labels, Some(("code", class)), n);
        }
    }
}

/// Cumulative buckets, sum and count, from per-bucket counts followed by the sum in
/// microseconds. Nothing for a series nothing was observed in.
fn histogram(out: &mut Vec<u8>, name: &str, labels: &str, cells: &[u64]) {
    let (buckets, sum) = cells.split_at(BUCKETS);
    let count: u64 = buckets.iter().sum();
    if count == 0 {
        return;
    }
    let mut cumulative = 0;
    for (i, &n) in buckets.iter().enumerate() {
        cumulative += n;
        let le = BUCKET_LABELS.get(i).copied().unwrap_or("+Inf");
        sample(out, name, "_bucket", labels, Some(("le", le)), cumulative);
    }
    open(out, name, "_sum", labels, None);
    micros_as_seconds(out, sum[0]);
    out.push(b'\n');
    sample(out, name, "_count", labels, None, count);
}

fn integer(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[at..]);
}

fn micros_as_seconds(out: &mut Vec<u8>, us: u64) {
    integer(out, us / 1_000_000);
    let fraction = us % 1_000_000;
    out.push(b'.');
    let mut digits = [b'0'; 6];
    let mut f = fraction;
    for d in digits.iter_mut().rev() {
        *d = b'0' + (f % 10) as u8;
        f /= 10;
    }
    out.extend_from_slice(&digits);
}

fn seconds(out: &mut Vec<u8>, name: &str, micros: u64) {
    open(out, name, "", "", None);
    micros_as_seconds(out, micros);
    out.push(b'\n');
}

fn optional(out: &mut Vec<u8>, name: &str, value: Option<u64>) {
    if let Some(value) = value {
        sample(out, name, "", "", None, value);
    }
}

/// The `process_*` figures. CPU time, the descriptor limit and the start time come from
/// portable calls; memory, descriptors and threads from `/proc/self`, so they are absent on
/// systems without it.
#[derive(Default)]
struct Process {
    cpu_micros: u64,
    resident_bytes: Option<u64>,
    virtual_bytes: Option<u64>,
    open_fds: Option<u64>,
    max_fds: Option<u64>,
    start_micros: u64,
    threads: Option<u64>,
}

impl Process {
    fn read(started: std::time::SystemTime) -> Process {
        let mut p = Process {
            start_micros: started
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_micros() as u64),
            ..Process::default()
        };
        // SAFETY: getrusage and getrlimit write only into the structs they are given.
        unsafe {
            let mut usage: libc::rusage = std::mem::zeroed();
            if libc::getrusage(libc::RUSAGE_SELF, &mut usage) == 0 {
                let micros = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
                p.cpu_micros = micros(usage.ru_utime) + micros(usage.ru_stime);
            }
            let mut limit: libc::rlimit = std::mem::zeroed();
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
                p.max_fds = Some(limit.rlim_cur as u64);
            }
        }
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            // SAFETY: sysconf reads a constant.
            let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
            let mut fields = statm
                .split_ascii_whitespace()
                .map(|f| f.parse::<u64>().ok());
            p.virtual_bytes = fields.next().flatten().map(|n| n * page);
            p.resident_bytes = fields.next().flatten().map(|n| n * page);
        }
        if let Ok(dir) = std::fs::read_dir("/proc/self/fd") {
            p.open_fds = Some(dir.count() as u64);
        }
        if let Ok(stat) = std::fs::read_to_string("/proc/self/stat") {
            // Fields after the parenthesised command name, which may hold spaces; the thread
            // count is field 20 of the whole line.
            p.threads = stat
                .rsplit_once(')')
                .and_then(|(_, rest)| rest.split_ascii_whitespace().nth(17))
                .and_then(|n| n.parse().ok());
        }
        p
    }
}
