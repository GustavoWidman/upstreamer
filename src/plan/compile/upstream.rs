//! Lowering of a proxy step's target: `to`, `balance`, `retries`, `failStatuses`, `health`.
//! `Compiler::proxy` keeps the header and timeout handling and calls [`Compiler::target`] for
//! the rest.
//!
//! A single origin with none of `retries`, `failStatuses` or `health` compiles to
//! `Target::Origin`, the path with no balancing state. Everything else is a `PoolPlan`, interned
//! by value, whose static members are interned origins. Every default is applied here, once:
//! `retries` 1 when the pool can hold two origins (a list of two or more, or a source), else 0;
//! passive checks on with `maxFails` 3 and `cooldown` 10s; a probe every 10s with a 2s
//! timeout, passing on 2xx and 3xx, healthy after 2 passes and unhealthy after 3 failures.

use super::{Compiler, MAX_IDLE_PER_CORE, Where, fmt_duration, parse_origin};
use crate::config::{ActiveSpec, BalanceSpec, HealthSpec, Member, Members, ProxyFull, ProxySpec};
use crate::plan::template::Scope;
use crate::plan::{
    BalancePlan, MembersPlan, OriginAddr, OriginId, OriginSpec, PassivePlan, PoolId, PoolPlan,
    ProbePlan, SourceSpec, StatusSet, Target, UpstreamTls,
};
use std::time::Duration;

/// The interned origins, pools and sources of a compile.
#[derive(Default)]
pub(super) struct Upstreams {
    /// By identity ([`OriginSpec::key`], the one definition of "the same origin"); the index
    /// is the `OriginId`.
    pub(super) origins: Vec<OriginSpec>,
    /// By value; the index is the `PoolId`.
    pub(super) pools: Vec<PoolPlan>,
    /// By value; the index is the `SourceId`.
    pub(super) sources: Vec<SourceSpec>,
}

/// The heaviest weight a member may have.
const MAX_WEIGHT: u16 = 1000;
const DEFAULT_MAX_FAILS: u8 = 3;
const DEFAULT_COOLDOWN: Duration = Duration::from_secs(10);
const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_HEALTHY_AFTER: u8 = 2;
const DEFAULT_UNHEALTHY_AFTER: u8 = 3;

/// A step's `health.active`, validated; the request bytes depend on each origin's host.
struct Probe {
    path: String,
    host: Option<String>,
    interval: Duration,
    timeout: Duration,
    expect: StatusSet,
    healthy_after: u8,
    unhealthy_after: u8,
}

impl Probe {
    fn plan(&self, default_host: &str) -> ProbePlan {
        let host = self.host.as_deref().unwrap_or(default_host);
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: upstreamer-health-check\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            self.path
        );
        ProbePlan {
            request: request.into_bytes().into(),
            interval: self.interval,
            timeout: self.timeout,
            expect: self.expect,
            healthy_after: self.healthy_after,
            unhealthy_after: self.unhealthy_after,
        }
    }
}

impl Compiler<'_> {
    /// The target of a proxy step; `at` is the step's `proxy` value.
    ///
    /// Errors: an origin URL that does not parse; two steps giving one origin different idle
    /// timeouts or health checks; a member listed twice; a weight above 1000; every member
    /// at weight 0; `failStatuses` or `expect` outside 100..=599; a hash key that reads
    /// `{re.N}` or `{err.*}`; for a Kubernetes source, `service` and `selector` both or
    /// neither, and `serverName` or `tlsSkipVerify` with `scheme = "http"`.
    pub(super) fn target(
        &mut self,
        spec: &ProxySpec,
        idle: Duration,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<Target> {
        let idle_at = at.at("timeouts").at("idle");
        let full = match spec {
            ProxySpec::To(url) => {
                return self
                    .origin(url, at, None, idle, &idle_at, None)
                    .map(Target::Origin);
            }
            ProxySpec::Full(full) => full,
        };
        let skip_verify = full.tls_skip_verify.then(|| at.at("tlsSkipVerify"));
        let checked =
            full.retries.is_some() || !full.fail_statuses.is_empty() || full.health.is_some();
        let single = match &full.to {
            Members::One(url) => Some((url, at.at("to"))),
            Members::List(list) if list.len() == 1 => match &list[0] {
                Member::Url(url) => Some((url, at.at("to").at(0))),
                Member::Weighted { url, weight } if *weight > 0 => {
                    Some((url, at.at("to").at(0).at("url")))
                }
                Member::Weighted { .. } => None,
            },
            _ => None,
        };
        if let Some((url, url_at)) = single.filter(|_| !checked) {
            if full.balance.is_some() {
                self.warn(
                    &at.at("balance"),
                    "`balance` has no effect on a single origin",
                );
            }
            return self
                .origin(url, &url_at, skip_verify.as_ref(), idle, &idle_at, None)
                .map(Target::Origin);
        }

        let balance = self.balance(full, at, scope);
        let fail_statuses = self.fail_statuses(full, at);
        let (passive, probe) = self.health(full.health.as_ref(), &at.at("health"));
        let members = match &full.to {
            Members::One(url) => {
                let id = self.origin(
                    url,
                    &at.at("to"),
                    skip_verify.as_ref(),
                    idle,
                    &idle_at,
                    probe.as_ref(),
                );
                MembersPlan::Static(Box::new([(id?, 1)]))
            }
            Members::List(list) => self.list(
                list,
                &at.at("to"),
                skip_verify.as_ref(),
                idle,
                &idle_at,
                probe.as_ref(),
            )?,
            Members::Kubernetes(source) => {
                MembersPlan::Discovered(self.source(source, full, idle, probe.as_ref(), at)?)
            }
        };
        let (balance, fail_statuses, passive) = (balance?, fail_statuses?, passive?);
        let several = match &members {
            MembersPlan::Static(m) => m.len() > 1,
            MembersPlan::Discovered(_) => true,
        };
        let pool = PoolPlan {
            members,
            balance,
            retries: full.retries.unwrap_or(u8::from(several)),
            fail_statuses,
            passive,
        };
        Some(Target::Pool(self.pool(pool)))
    }

    fn balance(
        &mut self,
        full: &ProxyFull,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<BalancePlan> {
        Some(match &full.balance {
            None | Some(BalanceSpec::RoundRobin) => BalancePlan::RoundRobin,
            Some(BalanceSpec::LeastRequests) => BalancePlan::LeastRequests,
            Some(BalanceSpec::P2c) => BalancePlan::P2c,
            Some(BalanceSpec::Hash(key)) => {
                BalancePlan::Hash(self.key(key, &at.at("balance").at("hash"), scope)?)
            }
        })
    }

    fn fail_statuses(&mut self, full: &ProxyFull, at: &Where) -> Option<StatusSet> {
        let mut set = StatusSet::default();
        let mut ok = true;
        for (i, &code) in full.fail_statuses.iter().enumerate() {
            if set.insert(code).is_none() {
                self.error(
                    &at.at("failStatuses").at(i),
                    format!("{code} is not an HTTP status (100 to 599)"),
                );
                ok = false;
            }
        }
        ok.then_some(set)
    }

    /// Passive checks (`None` inside: off) and the probe, each with its defaults. The outer
    /// `Option` of the passive half is `None` after an error.
    fn health(
        &mut self,
        spec: Option<&HealthSpec>,
        at: &Where,
    ) -> (Option<Option<PassivePlan>>, Option<Probe>) {
        let passive = spec.and_then(|h| h.passive.as_ref());
        let max_fails = passive
            .and_then(|p| p.max_fails)
            .unwrap_or(DEFAULT_MAX_FAILS);
        let cooldown = passive
            .and_then(|p| p.cooldown.as_ref())
            .map_or(DEFAULT_COOLDOWN, |d| d.0);
        let passive = if max_fails == 0 {
            Some(None)
        } else if cooldown < Duration::from_secs(1) {
            self.error(
                &at.at("passive").at("cooldown"),
                "an ejection lasts at least 1s",
            );
            None
        } else {
            let whole = cooldown.as_secs() + u64::from(cooldown.subsec_nanos() > 0);
            Some(Some(PassivePlan {
                max_fails,
                cooldown: whole.try_into().unwrap_or(u32::MAX),
            }))
        };
        let probe = match spec.and_then(|h| h.active.as_ref()) {
            Some(active) => self.active_check(active, &at.at("active")),
            None => None,
        };
        (passive, probe)
    }

    fn active_check(&mut self, spec: &ActiveSpec, at: &Where) -> Option<Probe> {
        let mut ok = true;
        let mut fail = |c: &mut Self, key: &str, message: String| {
            c.error(&at.at(key), message);
            ok = false;
        };
        let visible = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic());
        if !spec.path.starts_with('/') || !visible(&spec.path) {
            fail(
                self,
                "path",
                format!(
                    "{:?} is not a request path: start it with / and leave out spaces",
                    spec.path
                ),
            );
        }
        if let Some(host) = spec.host.as_deref().filter(|h| !visible(h)) {
            fail(self, "host", format!("{host:?} is not a Host value"));
        }
        let interval = spec
            .interval
            .as_ref()
            .map_or(DEFAULT_PROBE_INTERVAL, |d| d.0);
        let timeout = spec.timeout.as_ref().map_or(DEFAULT_PROBE_TIMEOUT, |d| d.0);
        for (key, d) in [("interval", interval), ("timeout", timeout)] {
            if d < Duration::from_millis(100) {
                fail(
                    self,
                    key,
                    format!("{} is shorter than 100ms", fmt_duration(d)),
                );
            }
        }
        let mut expect = StatusSet::default();
        match &spec.expect {
            None => {
                for code in 200..400 {
                    expect.insert(code);
                }
            }
            Some(codes) if codes.is_empty() => {
                fail(self, "expect", "list at least one status".to_owned())
            }
            Some(codes) => {
                for (i, &code) in codes.iter().enumerate() {
                    if expect.insert(code).is_none() {
                        self.error(
                            &at.at("expect").at(i),
                            format!("{code} is not an HTTP status (100 to 599)"),
                        );
                        ok = false;
                    }
                }
            }
        }
        let mut count = |c: &mut Self, key: &str, value: Option<u8>, default: u8| -> u8 {
            match value {
                Some(0) => {
                    c.error(&at.at(key), "count at least 1");
                    ok = false;
                    0
                }
                Some(n) => n,
                None => default,
            }
        };
        let healthy_after = count(
            self,
            "healthyAfter",
            spec.healthy_after,
            DEFAULT_HEALTHY_AFTER,
        );
        let unhealthy_after = count(
            self,
            "unhealthyAfter",
            spec.unhealthy_after,
            DEFAULT_UNHEALTHY_AFTER,
        );
        ok.then(|| Probe {
            path: spec.path.clone(),
            host: spec.host.clone(),
            interval,
            timeout,
            expect,
            healthy_after,
            unhealthy_after,
        })
    }

    fn list(
        &mut self,
        list: &[Member],
        at: &Where,
        skip_verify: Option<&Where>,
        idle: Duration,
        idle_at: &Where,
        probe: Option<&Probe>,
    ) -> Option<MembersPlan> {
        if list.is_empty() {
            self.error(at, "list at least one origin");
            return None;
        }
        let mut members: Vec<(OriginId, u16)> = Vec::with_capacity(list.len());
        let mut ok = true;
        for (i, member) in list.iter().enumerate() {
            let (url, weight, url_at) = match member {
                Member::Url(url) => (url, 1, at.at(i)),
                Member::Weighted { url, weight } => (url, *weight, at.at(i).at("url")),
            };
            if weight > MAX_WEIGHT {
                self.error(
                    &at.at(i).at("weight"),
                    format!("weight {weight} is above {MAX_WEIGHT}"),
                );
                ok = false;
            }
            let Some(id) = self.origin(url, &url_at, skip_verify, idle, idle_at, probe) else {
                ok = false;
                continue;
            };
            if members.iter().any(|&(other, _)| other == id) {
                self.error(
                    &url_at,
                    format!("origin {url} is listed twice; give it one entry with a weight"),
                );
                ok = false;
            }
            members.push((id, weight));
        }
        if ok && members.iter().all(|&(_, w)| w == 0) {
            self.error(
                at,
                "every origin has weight 0, so none would ever be picked",
            );
            ok = false;
        }
        ok.then(|| MembersPlan::Static(members.into()))
    }

    #[cfg(not(feature = "kubernetes"))]
    fn source(
        &mut self,
        _: &crate::config::KubernetesSource,
        _: &ProxyFull,
        _: Duration,
        _: Option<&Probe>,
        at: &Where,
    ) -> Option<crate::plan::SourceId> {
        self.error(
            &at.at("to").at("kubernetes"),
            "this upstreamer is built without Kubernetes support; use the `kubernetes` package",
        );
        None
    }

    /// A Kubernetes source, interned by value. Its origins are the ready endpoints the watch
    /// reports, labelled for metrics by the source.
    #[cfg(feature = "kubernetes")]
    fn source(
        &mut self,
        spec: &crate::config::KubernetesSource,
        full: &ProxyFull,
        idle: Duration,
        probe: Option<&Probe>,
        at: &Where,
    ) -> Option<crate::plan::SourceId> {
        use crate::config::PortRef;
        use crate::plan::{KubePort, KubeSelect, KubeSource, KubeWatch, SourceId};
        let at_source = at.at("to").at("kubernetes");
        let mut ok = true;
        if spec.namespace.is_empty() {
            self.error(&at_source.at("namespace"), "name the namespace");
            ok = false;
        }
        let select = match (&spec.service, &spec.selector) {
            (Some(service), None) if !service.is_empty() => {
                Some(KubeSelect::Service(service.as_str().into()))
            }
            (None, Some(selector)) if !selector.is_empty() => {
                Some(KubeSelect::Labels(selector.as_str().into()))
            }
            (Some(_), Some(_)) => {
                self.error(&at_source, "name a `service` or a `selector`, not both");
                None
            }
            _ => {
                self.error(&at_source, "name a `service` or a `selector`");
                None
            }
        };
        let port = match &spec.port {
            PortRef::Number(0) => {
                self.error(&at_source.at("port"), "0 is not a port");
                None
            }
            PortRef::Number(n) => Some(KubePort::Number(*n)),
            PortRef::Name(name) if name.is_empty() => {
                self.error(&at_source.at("port"), "name the port or give its number");
                None
            }
            PortRef::Name(name) => Some(KubePort::Name(name.as_str().into())),
        };
        let https = match spec.scheme.as_deref() {
            None | Some("http") => false,
            Some("https") => true,
            Some(other) => {
                self.error(
                    &at_source.at("scheme"),
                    format!("scheme {other:?} is neither \"http\" nor \"https\""),
                );
                ok = false;
                false
            }
        };
        if !https && spec.server_name.is_some() {
            self.error(
                &at_source.at("serverName"),
                "serverName applies to `scheme = \"https\"`",
            );
            ok = false;
        }
        if !https && full.tls_skip_verify {
            self.error(
                &at.at("tlsSkipVerify"),
                "tlsSkipVerify applies to an https upstream",
            );
            ok = false;
        }
        let (select, port) = (select?, port?);
        let shown_port = match &port {
            KubePort::Number(n) => n.to_string(),
            KubePort::Name(name) => name.to_string(),
        };
        let (shown, probe_host) = match &select {
            KubeSelect::Service(s) => (s.to_string(), Some(format!("{s}.{}.svc", spec.namespace))),
            KubeSelect::Labels(l) => (l.to_string(), None),
        };
        let probe = match probe {
            Some(probe) => {
                let host = probe
                    .host
                    .clone()
                    .or_else(|| spec.server_name.clone())
                    .or(probe_host);
                match host {
                    Some(host) => Some(probe.plan(&host)),
                    None => {
                        self.error(
                            &at.at("health").at("active").at("host"),
                            "a selector names no single host: set the probe's `host`",
                        );
                        ok = false;
                        None
                    }
                }
            }
            None => None,
        };
        if !ok {
            return None;
        }
        let source = SourceSpec::Kubernetes(KubeSource {
            label: format!("kubernetes:{}/{shown}:{shown_port}", spec.namespace).into(),
            watch: std::sync::Arc::new(KubeWatch {
                namespace: spec.namespace.as_str().into(),
                select,
                port,
            }),
            https,
            server_name: spec.server_name.as_deref().map(Into::into),
            verify: !full.tls_skip_verify,
            idle,
            probe,
        });
        let sources = &mut self.upstreams.sources;
        let index = sources
            .iter()
            .position(|s| *s == source)
            .unwrap_or_else(|| {
                sources.push(source);
                sources.len() - 1
            });
        Some(SourceId(index as u16))
    }

    /// Interns one origin, merging its settings (idle, probe) with an earlier mention: one
    /// origin has one idle timeout and one health check. `skip_verify` is where
    /// `tlsSkipVerify` was set, if it was.
    fn origin(
        &mut self,
        url: &str,
        url_at: &Where,
        skip_verify: Option<&Where>,
        idle: Duration,
        idle_at: &Where,
        probe: Option<&Probe>,
    ) -> Option<OriginId> {
        let origin = match parse_origin(url) {
            Ok(o) => o,
            Err(message) => {
                self.error(url_at, message);
                return None;
            }
        };
        if let Some(skip_at) = skip_verify.filter(|_| !origin.https) {
            self.error(skip_at, "tlsSkipVerify applies to an https upstream");
            return None;
        }
        let tls = origin.https.then(|| UpstreamTls {
            server_name: match origin.addr {
                OriginAddr::Ip(_) => None,
                OriginAddr::Name => Some(origin.host.clone()),
            },
            verify: skip_verify.is_none(),
        });
        let default_port = if origin.https { 443 } else { 80 };
        let host_header = match (origin.host.contains(':'), origin.port == default_port) {
            (true, true) => format!("[{}]", origin.host),
            (true, false) => format!("[{}]:{}", origin.host, origin.port),
            (false, true) => origin.host.to_string(),
            (false, false) => format!("{}:{}", origin.host, origin.port),
        };
        let spec = OriginSpec {
            host: origin.host,
            port: origin.port,
            addr: origin.addr,
            tls,
            idle,
            max_idle_per_core: MAX_IDLE_PER_CORE,
            probe: probe.map(|p| p.plan(&host_header)),
        };
        let key = spec.key();
        let Some(i) = self.upstreams.origins.iter().position(|o| o.key() == key) else {
            self.upstreams.origins.push(spec);
            return Some(OriginId(self.upstreams.origins.len() as u16 - 1));
        };
        let known = &mut self.upstreams.origins[i];
        if known.idle != idle {
            let theirs = fmt_duration(known.idle);
            let ours = fmt_duration(idle);
            self.error(
                idle_at,
                format!(
                    "origin {url} already has idle timeout {theirs} from another proxy step, not {ours}; one origin has one idle timeout"
                ),
            );
            return None;
        }
        match (&known.probe, spec.probe) {
            (Some(theirs), Some(ours)) if *theirs != ours => {
                self.error(
                    url_at,
                    format!(
                        "origin {url} already has another health check from another proxy step; one origin has one health check"
                    ),
                );
                return None;
            }
            (None, Some(ours)) => known.probe = Some(ours),
            _ => {}
        }
        Some(OriginId(i as u16))
    }

    /// Interns a pool by value.
    fn pool(&mut self, pool: PoolPlan) -> PoolId {
        let pools = &mut self.upstreams.pools;
        let index = pools.iter().position(|p| *p == pool).unwrap_or_else(|| {
            pools.push(pool);
            pools.len() - 1
        });
        PoolId(index as u16)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{self, Format};
    use crate::msg::Status;
    use crate::plan::compile::{FileSystem, compile};
    use crate::plan::{
        Action, BalancePlan, Diagnostic, KeyPlan, MembersPlan, OriginId, PassivePlan, Plan,
        PoolPlan, Target, Terminal,
    };
    use std::time::Duration;

    fn compiled(proxies: &[serde_json::Value]) -> Result<(Plan, Vec<String>), Vec<String>> {
        let routes: Vec<_> = proxies
            .iter()
            .enumerate()
            .map(|(i, p)| serde_json::json!({ "when": { "path": format!("/{i}") }, "proxy": p }))
            .collect();
        let json = serde_json::json!({
            "version": 1,
            "sites": [{ "name": "a", "hosts": ["a.example"], "routes": routes }],
        });
        let config = config::parse_config(Format::Json, json.to_string().as_bytes())
            .expect("schema")
            .value;
        let text = |d: Vec<Diagnostic>| d.iter().map(ToString::to_string).collect::<Vec<_>>();
        compile(&config, &FileSystem, 1)
            .map(|(plan, warnings)| (plan, text(warnings)))
            .map_err(text)
    }

    fn errors(proxy: serde_json::Value) -> Vec<String> {
        compiled(&[proxy]).expect_err("an invalid target")
    }

    fn targets(plan: &Plan) -> Vec<Target> {
        plan.sites[0]
            .routes
            .steps
            .iter()
            .map(|s| match &s.action {
                Action::Answer(Terminal::Proxy(p), _) => p.to,
                other => panic!("{other:?}"),
            })
            .collect()
    }

    fn pool(proxy: serde_json::Value) -> (Plan, usize) {
        let (plan, _) = compiled(&[proxy]).expect("a valid target");
        let Target::Pool(id) = targets(&plan)[0] else {
            panic!("{:?}", targets(&plan))
        };
        (plan, usize::from(id.0))
    }

    #[test]
    fn a_list_is_a_pool_with_every_default() {
        let (plan, id) =
            pool(serde_json::json!({ "to": ["http://10.0.0.1:80", "http://10.0.0.2:80"] }));
        assert_eq!(
            plan.pools[id],
            PoolPlan {
                members: MembersPlan::Static(Box::new([(OriginId(0), 1), (OriginId(1), 1)])),
                balance: BalancePlan::RoundRobin,
                retries: 1,
                fail_statuses: Default::default(),
                passive: Some(PassivePlan {
                    max_fails: 3,
                    cooldown: 10
                }),
            }
        );
        assert!(plan.origins.iter().all(|o| o.probe.is_none()));
    }

    #[test]
    fn a_single_origin_stays_target_origin_unless_a_health_or_retry_setting_names_it() {
        let (plan, warnings) = compiled(&[
            serde_json::json!({ "to": "http://10.0.0.1:80", "balance": "p2c" }),
            serde_json::json!({ "to": ["http://10.0.0.1:80"] }),
            serde_json::json!({ "to": "http://10.0.0.1:80", "retries": 2 }),
            serde_json::json!({ "to": "http://10.0.0.1:80", "health": {} }),
        ])
        .unwrap();
        let t = targets(&plan);
        assert_eq!(&t[..2], [Target::Origin(OriginId(0)); 2]);
        assert!(matches!(t[2], Target::Pool(_)) && matches!(t[3], Target::Pool(_)));
        assert_ne!(t[2], t[3], "pools differ by value");
        let Target::Pool(health) = t[3] else {
            unreachable!()
        };
        assert_eq!(
            plan.pools[usize::from(health.0)].retries,
            0,
            "one origin retries nothing"
        );
        assert_eq!(
            warnings,
            [
                "warning: /sites/0/routes/0/proxy/balance: `balance` has no effect on a single origin"
            ]
        );
    }

    #[test]
    fn weights_policies_fail_statuses_and_hash_keys_lower_to_the_pool() {
        let (plan, id) = pool(serde_json::json!({
            "to": [{ "url": "http://10.0.0.1:80", "weight": 5 }, { "url": "http://10.0.0.2:80", "weight": 0 }],
            "balance": { "hash": "{remote_host}" },
            "failStatuses": [502, 503],
            "retries": 3,
            "health": { "passive": { "maxFails": 0 } },
        }));
        let p = &plan.pools[id];
        assert_eq!(
            p.members,
            MembersPlan::Static(Box::new([(OriginId(0), 5), (OriginId(1), 0)]))
        );
        assert_eq!(p.balance, BalancePlan::Hash(KeyPlan::RemoteHost));
        assert!(p.fail_statuses.contains(Status::new(503).unwrap()));
        assert!(!p.fail_statuses.contains(Status::new(500).unwrap()));
        assert_eq!(
            (p.retries, p.passive),
            (3, None),
            "maxFails 0 turns passive checks off"
        );
        for (spec, want) in [
            ("leastRequests", BalancePlan::LeastRequests),
            ("p2c", BalancePlan::P2c),
            ("roundRobin", BalancePlan::RoundRobin),
        ] {
            let (plan, id) = pool(serde_json::json!({
                "to": ["http://10.0.0.1:80", "http://10.0.0.2:80"], "balance": spec,
            }));
            assert_eq!(plan.pools[id].balance, want);
        }
    }

    #[test]
    fn an_active_check_belongs_to_each_origin_with_its_own_host() {
        let (plan, _) = pool(serde_json::json!({
            "to": ["http://10.0.0.1:8080", "https://storage.lan", "http://[::1]:80"],
            "health": { "active": { "path": "/healthz?full=1", "expect": [200, 204] } },
        }));
        let request = |i: usize| {
            String::from_utf8(plan.origins[i].probe.as_ref().unwrap().request.to_vec()).unwrap()
        };
        assert_eq!(
            request(0),
            "GET /healthz?full=1 HTTP/1.1\r\nHost: 10.0.0.1:8080\r\nUser-Agent: upstreamer-health-check\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        assert!(
            request(1).contains("\r\nHost: storage.lan\r\n"),
            "the scheme's port is implied"
        );
        assert!(request(2).contains("\r\nHost: [::1]\r\n"));
        let probe = plan.origins[0].probe.as_ref().unwrap();
        assert_eq!(
            (
                probe.interval,
                probe.timeout,
                probe.healthy_after,
                probe.unhealthy_after
            ),
            (Duration::from_secs(10), Duration::from_secs(2), 2, 3)
        );
        assert!(probe.expect.contains(Status::new(204).unwrap()));
        assert!(!probe.expect.contains(Status::new(301).unwrap()));

        let (plan, _) = pool(serde_json::json!({
            "to": ["http://10.0.0.1:80", "http://10.0.0.2:80"],
            "health": { "active": { "path": "/", "host": "app.internal" } },
        }));
        let probe = plan.origins[0].probe.as_ref().unwrap();
        assert!(String::from_utf8_lossy(&probe.request).contains("\r\nHost: app.internal\r\n"));
        assert!(
            probe.expect.contains(Status::new(302).unwrap()),
            "2xx and 3xx by default"
        );
        assert!(!probe.expect.contains(Status::new(404).unwrap()));
    }

    #[test]
    fn one_origin_has_one_health_check() {
        let a = serde_json::json!({
            "to": ["http://10.0.0.1:80", "http://10.0.0.2:80"],
            "health": { "active": { "path": "/a" } },
        });
        let b = serde_json::json!({
            "to": ["http://10.0.0.1:80", "http://10.0.0.3:80"],
            "health": { "active": { "path": "/b" } },
        });
        let errors = compiled(&[a.clone(), b]).unwrap_err();
        assert_eq!(
            errors,
            [
                "/sites/0/routes/1/proxy/to/0: origin http://10.0.0.1:80 already has another health check from another proxy step; one origin has one health check"
            ]
        );
        let (plan, _) = compiled(&[serde_json::json!("http://10.0.0.1:80"), a.clone(), a]).unwrap();
        assert!(
            plan.origins[0].probe.is_some(),
            "a probe from one step applies wherever the origin is used"
        );
    }

    #[test]
    fn invalid_targets_fail_at_their_pointer() {
        let cases = [
            (
                serde_json::json!({ "to": [] }),
                "/sites/0/routes/0/proxy/to: list at least one origin",
            ),
            (
                serde_json::json!({ "to": [{ "url": "http://a:1", "weight": 1001 }, "http://b:1"] }),
                "/sites/0/routes/0/proxy/to/0/weight: weight 1001 is above 1000",
            ),
            (
                serde_json::json!({ "to": [{ "url": "http://a:1", "weight": 0 }, { "url": "http://b:1", "weight": 0 }] }),
                "/sites/0/routes/0/proxy/to: every origin has weight 0, so none would ever be picked",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://A:1/"] }),
                "/sites/0/routes/0/proxy/to/1: origin http://A:1/ is listed twice; give it one entry with a weight",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "failStatuses": [503, 600] }),
                "/sites/0/routes/0/proxy/failStatuses/1: 600 is not an HTTP status (100 to 599)",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "balance": { "hash": "{re.1}" } }),
                "/sites/0/routes/0/proxy/balance/hash: ",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "health": { "passive": { "cooldown": "500ms" } } }),
                "/sites/0/routes/0/proxy/health/passive/cooldown: an ejection lasts at least 1s",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "health": { "active": { "path": "health" } } }),
                "/sites/0/routes/0/proxy/health/active/path: \"health\" is not a request path: start it with / and leave out spaces",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "health": { "active": { "path": "/", "expect": [700] } } }),
                "/sites/0/routes/0/proxy/health/active/expect/0: 700 is not an HTTP status (100 to 599)",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "http://b:1"], "health": { "active": { "path": "/", "unhealthyAfter": 0 } } }),
                "/sites/0/routes/0/proxy/health/active/unhealthyAfter: count at least 1",
            ),
            (
                serde_json::json!({ "to": ["http://a:1", "https://b:1"], "tlsSkipVerify": true }),
                "/sites/0/routes/0/proxy/tlsSkipVerify: tlsSkipVerify applies to an https upstream",
            ),
        ];
        for (proxy, want) in cases {
            let got = errors(proxy.clone());
            assert!(
                got.len() == 1 && got[0].starts_with(want),
                "{proxy}: {got:?}"
            );
        }
    }

    #[cfg(not(feature = "kubernetes"))]
    #[test]
    fn a_kubernetes_source_needs_the_feature() {
        assert_eq!(
            errors(
                serde_json::json!({ "to": { "kubernetes": { "namespace": "n", "service": "s", "port": 80 } } })
            ),
            [
                "/sites/0/routes/0/proxy/to/kubernetes: this upstreamer is built without Kubernetes support; use the `kubernetes` package"
            ]
        );
    }

    #[cfg(feature = "kubernetes")]
    #[test]
    fn a_kubernetes_source_is_a_discovered_pool_labelled_by_what_it_watches() {
        use crate::plan::{KubePort, KubeSelect, SourceSpec};
        let (plan, id) = pool(serde_json::json!({
            "to": { "kubernetes": {
                "namespace": "web", "service": "shop", "port": "http",
                "scheme": "https", "serverName": "shop.web.svc",
            } },
            "health": { "active": { "path": "/ready" } },
        }));
        let p = &plan.pools[id];
        assert_eq!(
            (&p.members, p.retries),
            (&MembersPlan::Discovered(crate::plan::SourceId(0)), 1)
        );
        let SourceSpec::Kubernetes(k) = &plan.sources[0];
        assert_eq!(&*k.label, "kubernetes:web/shop:http");
        assert_eq!(k.watch.select, KubeSelect::Service("shop".into()));
        assert_eq!(k.watch.port, KubePort::Name("http".into()));
        assert!(k.https && k.verify);
        assert_eq!(k.server_name.as_deref(), Some("shop.web.svc"));
        let probe = String::from_utf8(k.probe.as_ref().unwrap().request.to_vec()).unwrap();
        assert!(probe.contains("\r\nHost: shop.web.svc\r\n"), "{probe}");

        let (plan, _) = compiled(&[
            serde_json::json!({ "to": { "kubernetes": { "namespace": "web", "selector": "app=shop", "port": 8080 } } }),
            serde_json::json!({ "to": { "kubernetes": { "namespace": "web", "selector": "app=shop", "port": 8080 } } }),
        ])
        .unwrap();
        assert_eq!(plan.sources.len(), 1, "equal sources are one source");
        let SourceSpec::Kubernetes(k) = &plan.sources[0];
        assert_eq!(&*k.label, "kubernetes:web/app=shop:8080");
        assert!(k.probe.is_none() && !k.https);

        for (source, want) in [
            (
                serde_json::json!({ "namespace": "web", "port": 80 }),
                "/sites/0/routes/0/proxy/to/kubernetes: name a `service` or a `selector`",
            ),
            (
                serde_json::json!({ "namespace": "web", "service": "a", "selector": "b", "port": 80 }),
                "/sites/0/routes/0/proxy/to/kubernetes: name a `service` or a `selector`, not both",
            ),
            (
                serde_json::json!({ "namespace": "web", "service": "a", "port": 80, "serverName": "a" }),
                "/sites/0/routes/0/proxy/to/kubernetes/serverName: serverName applies to `scheme = \"https\"`",
            ),
            (
                serde_json::json!({ "namespace": "web", "service": "a", "port": 80, "scheme": "h2c" }),
                "/sites/0/routes/0/proxy/to/kubernetes/scheme: scheme \"h2c\" is neither \"http\" nor \"https\"",
            ),
        ] {
            assert_eq!(
                errors(serde_json::json!({ "to": { "kubernetes": source } })),
                [want]
            );
        }
        assert_eq!(
            errors(serde_json::json!({
                "to": { "kubernetes": { "namespace": "web", "selector": "app=shop", "port": 80 } },
                "health": { "active": { "path": "/" } },
            })),
            [
                "/sites/0/routes/0/proxy/health/active/host: a selector names no single host: set the probe's `host`"
            ]
        );
    }
}
