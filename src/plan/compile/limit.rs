//! Lowering of a `limit` step.

use super::{Compiler, Ctx, Where};
use crate::config::{LimitSpec as Spec, Rate};
use crate::plan::template::Scope;
use crate::plan::{KeyPlan, LimitId, LimitPlan, LimitSpec, RouteSlot};

/// The key of a limit that names none.
const DEFAULT_KEY: &str = "{remote_net}";
const DEFAULT_KEYS: u32 = 65536;
const MAX_KEYS: u32 = 1 << 24;
const MAX_RATE_PER_SECOND: u64 = 1_000_000;
/// `burst x interval` longer than this is an error: a bucket that takes a month to refill is a
/// block list, not a limit.
const MAX_TOLERANCE_SECONDS: u128 = 30 * 24 * 3600;
/// Slots of a table whose every request has the same key: one cache line.
const LINE_SLOTS: u32 = 8;

/// An interval of this many units or more keeps the rate within 2^-14 of what was asked.
const PRECISE: u64 = 1 << 14;
/// `limit::Table` calls a TAT live up to twice `tolerance + interval` ahead of now, and the
/// word holds 40 bits of them, so `tolerance + interval` stays below 2^37 units.
const REACH: u128 = 1 << 37;

impl Compiler<'_> {
    /// Rate, burst and key into the GCRA constants of a `LimitPlan`, and the
    /// `plan::LimitSpec` that identifies its table across reloads (site name, the step's
    /// diagnostic path, the key template's source text, slots, time unit).
    ///
    /// Errors: inside an error route; a rate of 0 or above 10^6/s; a burst of 0;
    /// `burst x interval` above 30 days; `keys` of 0 or above 2^24; a key template reading
    /// `{re.N}` or `{err.*}`. A constant key with no `when` on the step or around it is
    /// recorded for the site's `metrics` steps, which warn about it.
    pub(super) fn limit(
        &mut self,
        spec: &Spec,
        route: RouteSlot,
        ctx: Ctx,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<LimitPlan> {
        if ctx.in_error_route {
            self.error(
                at,
                "`limit` is not allowed in an error route: the response it would refuse is already an error",
            );
            return None;
        }
        let Rate { count, per } = spec.rate;
        let period = u128::from(per.as_secs());
        let mut valid = true;
        if count == 0 {
            self.error(&at.at("rate"), "a rate of 0 admits nothing");
            valid = false;
        } else if u64::from(count) > MAX_RATE_PER_SECOND * per.as_secs() {
            self.error(
                &at.at("rate"),
                format!("a rate above {MAX_RATE_PER_SECOND} requests a second is not supported"),
            );
            valid = false;
        }
        let burst = match spec.burst {
            Some(0) => {
                self.error(
                    &at.at("burst"),
                    "a burst of 0 admits nothing; the smallest is 1",
                );
                valid = false;
                1
            }
            Some(burst) => burst,
            None => u32::try_from(u128::from(count).div_ceil(period)).map_or(1, |n| n.max(1)),
        };
        if count > 0 && u128::from(burst) * period > MAX_TOLERANCE_SECONDS * u128::from(count) {
            self.error(
                &at.at("burst"),
                format!(
                    "a burst of {burst} at {count}/{unit} takes more than 30 days to refill",
                    unit = unit_name(per.as_secs()),
                ),
            );
            valid = false;
        }
        let keys = match spec.keys {
            Some(0) => {
                self.error(&at.at("keys"), "a table of 0 keys holds nothing");
                valid = false;
                DEFAULT_KEYS
            }
            Some(keys) if keys > MAX_KEYS => {
                self.error(
                    &at.at("keys"),
                    format!("{keys} keys is above the largest table, {MAX_KEYS}"),
                );
                valid = false;
                DEFAULT_KEYS
            }
            Some(keys) => keys,
            None => DEFAULT_KEYS,
        };
        let text = spec.key.as_deref().unwrap_or(DEFAULT_KEY);
        let key = self.key(text, &at.at("key"), scope)?;
        if !valid {
            return None;
        }
        if matches!(key, KeyPlan::Const(_)) && self.site.guarded == 0 {
            self.site.unguarded_limits.push(at.clone());
        }
        let (unit_shift, interval) = unit(u128::from(count), period, u128::from(burst));
        let slots = match key {
            KeyPlan::Const(_) => LINE_SLOTS,
            _ => keys.next_power_of_two().max(LINE_SLOTS),
        };
        let step = match &at.file {
            Some(file) => format!("{}:{}", file.display(), at.ptr),
            None => at.ptr.clone(),
        };
        let table = LimitId(self.limits.len() as u16);
        self.limits.push(LimitSpec {
            site: self.site.name.as_str().into(),
            step: step.into(),
            key: text.into(),
            slots,
            unit_shift,
        });
        Some(LimitPlan {
            table,
            key,
            interval,
            tolerance: interval * u64::from(burst),
            route,
        })
    }
}

/// The time unit of a table (`k` of 2^-k seconds) and the emission interval in it, for `count`
/// requests every `period` seconds and a burst of `burst`: the finest unit that makes the
/// interval [`PRECISE`] units, coarsened as far as `burst` needs to keep `tolerance + interval`
/// within [`REACH`].
fn unit(count: u128, period: u128, burst: u128) -> (u8, u64) {
    let interval = |k: u32| ((period << k) + count / 2) / count;
    let mut k = 0;
    while k < 40 && interval(k) < u128::from(PRECISE) && (burst + 1) * interval(k + 1) <= REACH {
        k += 1;
    }
    (k as u8, interval(k).max(1) as u64)
}

fn unit_name(seconds: u64) -> &'static str {
    match seconds {
        1 => "s",
        60 => "m",
        _ => "h",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{Action, Plan};

    fn compile(routes: &str) -> Result<Plan, Vec<String>> {
        let json = format!(
            r#"{{"version":1,"sites":[{{"name":"a","hosts":["a.example"],"routes":{routes},"errors":[{{"routes":[{{"respond":{{"body":"slow down {{err.retry_after}}"}}}}]}}]}}]}}"#
        );
        let config = crate::config::parse_config(crate::config::Format::Json, json.as_bytes())
            .unwrap_or_else(|e| panic!("{}: {}", e.pointer, e.message))
            .value;
        super::super::compile(&config, &super::super::FileSystem, 1)
            .map(|(plan, _)| plan)
            .map_err(|diagnostics| diagnostics.iter().map(ToString::to_string).collect())
    }

    /// The plan of a site that limits by `spec` and then answers, with its first limit.
    fn limited(spec: &str) -> Plan {
        compile(&format!(r#"[{{"limit":{spec}}},{{"respond":{{}}}}]"#)).unwrap()
    }

    fn first(plan: &Plan) -> (&LimitPlan, &LimitSpec) {
        let Action::Limit(limit) = &plan.sites[0].routes.steps[0].action else {
            panic!("the first step is the limit");
        };
        (limit, &plan.limits[usize::from(limit.table.0)])
    }

    fn errors(spec: &str) -> Vec<String> {
        compile(&format!(r#"[{{"limit":{spec}}}]"#)).expect_err("an invalid limit")
    }

    #[test]
    fn the_burst_defaults_to_the_rate_per_second_rounded_up_and_the_key_to_the_network() {
        for (rate, burst) in [
            ("50/s", 50),
            ("1/s", 1),
            ("90/m", 2),
            ("5/m", 1),
            ("7200/h", 2),
        ] {
            let plan = limited(&format!(r#"{{"rate":"{rate}"}}"#));
            let (limit, spec) = first(&plan);
            assert_eq!(limit.tolerance, limit.interval * burst, "{rate}");
            assert_eq!(limit.key, KeyPlan::RemoteNet, "{rate}");
            assert_eq!(&*spec.key, "{remote_net}");
            assert_eq!(spec.slots, 65536);
        }
    }

    #[test]
    fn an_interval_is_the_period_over_the_count_in_the_tables_unit() {
        for (rate, per_request) in [
            ("50/s", 1.0 / 50.0),
            ("1000000/s", 1e-6),
            ("3/m", 20.0),
            ("1/h", 3600.0),
            ("7/h", 3600.0 / 7.0),
        ] {
            let plan = limited(&format!(r#"{{"rate":"{rate}","burst":3}}"#));
            let (limit, spec) = first(&plan);
            let seconds = limit.interval as f64 / 2f64.powi(i32::from(spec.unit_shift));
            assert!(
                (seconds / per_request - 1.0).abs() < 1.0 / 4096.0,
                "{rate}: {seconds} s per request in 2^-{} s units",
                spec.unit_shift
            );
        }
    }

    #[test]
    fn a_huge_burst_coarsens_the_unit_to_keep_the_tolerance_inside_the_word() {
        let plan = limited(r#"{"rate":"1000000/s","burst":4000000000}"#);
        let (limit, spec) = first(&plan);
        assert!(
            (limit.tolerance + limit.interval) < 1 << 37,
            "{limit:?} in 2^-{} s",
            spec.unit_shift
        );
        assert!(limit.interval >= 32, "the interval keeps some resolution");
    }

    #[test]
    fn a_constant_key_gets_one_line_and_other_keys_a_power_of_two_of_slots() {
        let plan = limited(r#"{"rate":"5/s","key":"everyone"}"#);
        let (limit, spec) = first(&plan);
        assert!(matches!(limit.key, KeyPlan::Const(_)));
        assert_eq!((spec.slots, &*spec.key), (8, "everyone"));
        assert_eq!(limit_slots(r#"{"rate":"5/s","keys":1000}"#), 1024);
        assert_eq!(limit_slots(r#"{"rate":"5/s","keys":1}"#), 8);
        assert_eq!(limit_slots(r#"{"rate":"5/s","keys":16777216}"#), 1 << 24);
    }

    fn limit_slots(spec: &str) -> u32 {
        first(&limited(spec)).1.slots
    }

    #[test]
    fn a_table_is_named_by_its_site_step_key_slots_and_unit() {
        let plan = limited(r#"{"rate":"5/s","key":"{header.x-api-key}","keys":100}"#);
        let (_, spec) = first(&plan);
        assert_eq!(&*spec.site, "a");
        assert_eq!(&*spec.step, "/sites/0/routes/0/limit");
        assert_eq!(&*spec.key, "{header.x-api-key}");
        assert_eq!(spec.slots, 128);
    }

    #[test]
    fn invalid_limits_fail_at_the_key_that_is_wrong() {
        let cases = [
            (
                r#"{"rate":"0/s"}"#,
                "/sites/0/routes/0/limit/rate: a rate of 0 admits nothing",
            ),
            (
                r#"{"rate":"1000001/s"}"#,
                "/sites/0/routes/0/limit/rate: a rate above 1000000 requests a second is not supported",
            ),
            (
                r#"{"rate":"60000001/m"}"#,
                "/sites/0/routes/0/limit/rate: a rate above 1000000 requests a second is not supported",
            ),
            (
                r#"{"rate":"1/s","burst":0}"#,
                "/sites/0/routes/0/limit/burst: a burst of 0 admits nothing; the smallest is 1",
            ),
            (
                r#"{"rate":"1/h","burst":721}"#,
                "/sites/0/routes/0/limit/burst: a burst of 721 at 1/h takes more than 30 days to refill",
            ),
            (
                r#"{"rate":"1/s","keys":0}"#,
                "/sites/0/routes/0/limit/keys: a table of 0 keys holds nothing",
            ),
            (
                r#"{"rate":"1/s","keys":16777217}"#,
                "/sites/0/routes/0/limit/keys: 16777217 keys is above the largest table, 16777216",
            ),
            (
                r#"{"rate":"1/s","key":"{re.1}"}"#,
                "/sites/0/routes/0/limit/key: ",
            ),
            (
                r#"{"rate":"1/s","key":"{err.status_code}"}"#,
                "/sites/0/routes/0/limit/key: ",
            ),
            (
                r#"{"rate":"1/s","key":""}"#,
                "/sites/0/routes/0/limit/key: a key that is always empty never selects a bucket or an origin",
            ),
        ];
        for (spec, want) in cases {
            let got = errors(spec);
            assert_eq!(got.len(), 1, "{spec}: {got:?}");
            assert!(got[0].starts_with(want), "{spec}: {got:?}, wanted {want}");
        }
        assert!(
            compile(r#"[{"limit":{"rate":"720/h","burst":720}},{"respond":{}}]"#).is_ok(),
            "30 days exactly is allowed"
        );
    }

    #[test]
    fn every_wrong_key_of_one_limit_is_reported() {
        let got = errors(r#"{"rate":"0/s","burst":0,"keys":0}"#);
        assert_eq!(got.len(), 3, "{got:?}");
    }

    #[test]
    fn a_limit_in_an_error_route_is_an_error() {
        let json = r#"{"version":1,"sites":[{"name":"a","hosts":["a.example"],"routes":[],
            "errors":[{"routes":[{"limit":{"rate":"1/s"}},{"respond":{}}]}]}]}"#;
        let config = crate::config::parse_config(crate::config::Format::Json, json.as_bytes())
            .unwrap()
            .value;
        let got = super::super::compile(&config, &super::super::FileSystem, 1)
            .expect_err("an invalid config");
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(
            got[0]
                .to_string()
                .contains("`limit` is not allowed in an error route"),
            "{got:?}"
        );
    }

    #[test]
    fn two_limits_of_one_plan_have_tables_of_their_own() {
        let plan = compile(r#"[{"limit":{"rate":"1/s"}},{"limit":{"rate":"1/s"}},{"respond":{}}]"#)
            .unwrap();
        assert_eq!(plan.limits.len(), 2);
        assert_ne!(plan.limits[0], plan.limits[1], "their steps differ");
    }
}
