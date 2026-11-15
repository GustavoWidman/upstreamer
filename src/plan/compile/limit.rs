//! Lowering of a `limit` step.

use super::{Compiler, Ctx, Where};
use crate::config::LimitSpec as Spec;
use crate::plan::template::Scope;
use crate::plan::{LimitPlan, RouteSlot};

impl Compiler<'_> {
    /// Rate, burst and key into the GCRA constants of a `LimitPlan`, and the
    /// `plan::LimitSpec` that identifies its table across reloads (site name, the step's
    /// diagnostic path, the key template's source text, slots, time unit).
    pub(super) fn limit(
        &mut self,
        spec: &Spec,
        route: RouteSlot,
        ctx: Ctx,
        at: &Where,
        scope: &mut Scope<'_>,
    ) -> Option<LimitPlan> {
        let _ = (spec, route, ctx, scope);
        self.error(at, "`limit` is not supported by this upstreamer yet");
        None
    }
}
