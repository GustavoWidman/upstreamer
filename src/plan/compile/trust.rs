//! Lowering of `trustedProxies`.

use super::{Compiler, Where};
use crate::config::trust::TrustSpec;
use crate::trust::TrustPlan;

impl Compiler<'_> {
    /// The peers whose forwarded client address is believed, and where it is read.
    pub(super) fn trusted_proxies(&mut self, spec: &TrustSpec, at: &Where) -> Option<TrustPlan> {
        let _ = spec;
        self.error(
            at,
            "`trustedProxies` is not supported by this upstreamer yet",
        );
        None
    }
}
