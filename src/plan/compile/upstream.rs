//! Lowering of a proxy step's target: `to`, `balance`, `retries`, `failStatuses`, `health`.
//! `Compiler::proxy` keeps the header and timeout handling and calls [`Compiler::target`] for
//! the rest.
//!
//! A single origin with none of `balance`, `retries`, `failStatuses` or `health` compiles to
//! `Target::Origin`, the path with no balancing state. Everything else is a `PoolPlan`, interned
//! by value, whose static members are interned origins.

use super::{Compiler, MAX_IDLE_PER_CORE, Where, fmt_duration, parse_origin};
use crate::config::{Members, ProxySpec};
use crate::plan::template::Scope;
use crate::plan::{
    OriginAddr, OriginId, OriginSpec, PoolId, PoolPlan, ProbePlan, SourceSpec, Target, UpstreamTls,
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

impl Compiler<'_> {
    /// The target of a proxy step; `at` is the step's `proxy` value.
    ///
    /// - One origin, no `balance`/`retries`/`failStatuses`/`health`: `Target::Origin`.
    /// - Otherwise a `PoolPlan`, interned by value.
    pub(super) fn target(
        &mut self,
        spec: &ProxySpec,
        idle: Duration,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<Target> {
        let _ = scope;
        let idle_at = at.at("timeouts").at("idle");
        let full = match spec {
            ProxySpec::To(url) => {
                return self
                    .origin(url, at, None, idle, &idle_at, None)
                    .map(Target::Origin);
            }
            ProxySpec::Full(full) => full,
        };
        let unbuilt = |c: &mut Self, key: &str| {
            c.error(
                &at.at(key),
                format!("`{key}` is not supported by this upstreamer yet"),
            )
        };
        let mut supported = true;
        for (key, set) in [
            ("balance", full.balance.is_some()),
            ("retries", full.retries.is_some()),
            ("failStatuses", !full.fail_statuses.is_empty()),
            ("health", full.health.is_some()),
        ] {
            if set {
                unbuilt(self, key);
                supported = false;
            }
        }
        let url = match &full.to {
            Members::One(url) => url,
            Members::List(_) => {
                self.error(
                    &at.at("to"),
                    "a list of origins is not supported by this upstreamer yet",
                );
                return None;
            }
            Members::Kubernetes(_) => {
                self.error(
                    &at.at("to").at("kubernetes"),
                    "this upstreamer is built without Kubernetes support; use the `kubernetes` package",
                );
                return None;
            }
        };
        if !supported {
            return None;
        }
        let skip_verify = full.tls_skip_verify.then(|| at.at("tlsSkipVerify"));
        self.origin(
            url,
            &at.at("to"),
            skip_verify.as_ref(),
            idle,
            &idle_at,
            None,
        )
        .map(Target::Origin)
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
        probe: Option<ProbePlan>,
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
        let spec = OriginSpec {
            host: origin.host,
            port: origin.port,
            addr: origin.addr,
            tls,
            idle,
            max_idle_per_core: MAX_IDLE_PER_CORE,
            probe,
        };
        let key = spec.key();
        match self.upstreams.origins.iter().position(|o| o.key() == key) {
            Some(i) if self.upstreams.origins[i].idle != idle => {
                let theirs = fmt_duration(self.upstreams.origins[i].idle);
                let ours = fmt_duration(idle);
                self.error(
                    idle_at,
                    format!(
                        "origin {url} already has idle timeout {theirs} from another proxy step, not {ours}; one origin has one idle timeout"
                    ),
                );
                None
            }
            Some(i) => Some(OriginId(i as u16)),
            None => {
                self.upstreams.origins.push(spec);
                Some(OriginId(self.upstreams.origins.len() as u16 - 1))
            }
        }
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
