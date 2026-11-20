//! Lowering of `trustedProxies`.

use super::{Compiler, Where};
use crate::config::trust::TrustSpec;
use crate::trust::{self, Cidr, Header, Nets, TrustPlan};

const HEADERS: &str = "`CF-Connecting-IP`, `X-Forwarded-For` or `X-Real-IP`";

impl Compiler<'_> {
    /// The peers whose forwarded client address is believed, and where it is read.
    pub(super) fn trusted_proxies(&mut self, spec: &TrustSpec, at: &Where) -> Option<TrustPlan> {
        let mut ranges: Vec<Cidr> = Vec::new();
        let mut valid = true;
        if spec.from.is_empty() {
            self.error(
                &at.at("from"),
                "`from` names no proxy, so no peer would be trusted; list CIDR ranges or `cloudflare`",
            );
            valid = false;
        }
        for (i, entry) in spec.from.iter().enumerate() {
            if entry.eq_ignore_ascii_case("cloudflare") {
                ranges.extend(trust::cloudflare());
                continue;
            }
            match Cidr::parse(entry) {
                Ok(cidr) => {
                    if cidr.is_everything() {
                        self.warn(
                            &at.at("from").at(i),
                            format!(
                                "`{entry}` trusts every peer, so any client can choose the address \
                                 the proxy believes; list the ranges of your proxies"
                            ),
                        );
                    }
                    ranges.push(cidr);
                }
                Err(message) => {
                    self.error(&at.at("from").at(i), message);
                    valid = false;
                }
            }
        }
        let header = Header::parse(&spec.header);
        if header.is_none() {
            self.error(
                &at.at("header"),
                format!("`{}` is not a header to read; use {HEADERS}", spec.header),
            );
        }
        let header = header?;
        valid.then(|| TrustPlan::new(Nets::new(ranges), header))
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{self, Format};
    use crate::plan::compile::{FileSystem, compile};

    /// Diagnostics (errors first, then warnings) of a config with this `trustedProxies`.
    fn diagnostics(trusted: &str) -> (bool, Vec<String>) {
        let json = format!(r#"{{"version":1,"trustedProxies":{trusted},"sites":[]}}"#);
        let config = config::parse_config(Format::Json, json.as_bytes())
            .expect("schema")
            .value;
        match compile(&config, &FileSystem, 1) {
            Ok((plan, warnings)) => (
                plan.trust.is_some(),
                warnings.iter().map(ToString::to_string).collect(),
            ),
            Err(all) => (false, all.iter().map(ToString::to_string).collect()),
        }
    }

    #[test]
    fn a_valid_setting_compiles_to_a_trust_plan() {
        for trusted in [
            r#"{"from":["cloudflare"],"header":"CF-Connecting-IP"}"#,
            r#"{"from":["10.0.0.0/8","2001:db8::/32","192.0.2.7"],"header":"x-forwarded-for"}"#,
            r#"{"from":["Cloudflare","127.0.0.1"],"header":"X-Real-IP"}"#,
        ] {
            assert_eq!(diagnostics(trusted), (true, vec![]), "{trusted}");
        }
    }

    #[test]
    fn a_config_without_trusted_proxies_has_no_trust_plan() {
        let config = config::parse_config(Format::Json, br#"{"version":1,"sites":[]}"#)
            .expect("schema")
            .value;
        let (plan, _) = compile(&config, &FileSystem, 1).unwrap();
        assert!(plan.trust.is_none());
    }

    #[test]
    fn mistakes_are_named_at_their_pointer() {
        let cases = [
            (
                r#"{"from":[],"header":"CF-Connecting-IP"}"#,
                "/trustedProxies/from: `from` names no proxy, so no peer would be trusted; list CIDR ranges or `cloudflare`",
            ),
            (
                r#"{"from":["10.0.0.0/8","10.0.0.1/8"],"header":"X-Real-IP"}"#,
                "/trustedProxies/from/1: `10.0.0.1/8` has bits set past its prefix; write `10.0.0.0/8`",
            ),
            (
                r#"{"from":["cloudflare","example.com"],"header":"X-Real-IP"}"#,
                "/trustedProxies/from/1: `example.com` is not an IP address or a CIDR range",
            ),
            (
                r#"{"from":["10.0.0.0/40"],"header":"X-Real-IP"}"#,
                "/trustedProxies/from/0: `10.0.0.0/40`: the prefix length must be 0 to 32",
            ),
            (
                r#"{"from":["cloudflare"],"header":"Forwarded"}"#,
                "/trustedProxies/header: `Forwarded` is not a header to read; use `CF-Connecting-IP`, `X-Forwarded-For` or `X-Real-IP`",
            ),
        ];
        for (trusted, want) in cases {
            assert_eq!(
                diagnostics(trusted),
                (false, vec![want.to_owned()]),
                "{trusted}"
            );
        }
    }

    #[test]
    fn every_mistake_is_reported_at_once() {
        let (_, all) = diagnostics(r#"{"from":["x","y"],"header":"z"}"#);
        assert_eq!(all.len(), 3, "{all:?}");
    }

    #[test]
    fn trusting_every_address_warns() {
        for any in ["0.0.0.0/0", "::/0"] {
            let (compiled, messages) = diagnostics(&format!(
                r#"{{"from":["{any}"],"header":"X-Forwarded-For"}}"#
            ));
            assert!(compiled, "a warning, not an error");
            assert_eq!(messages.len(), 1, "{messages:?}");
            assert!(
                messages[0].starts_with("warning: /trustedProxies/from/0: `")
                    && messages[0].contains("trusts every peer"),
                "{messages:?}"
            );
        }
    }
}
