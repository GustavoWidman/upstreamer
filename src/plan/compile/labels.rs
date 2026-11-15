//! Route slots, the `metrics` step, and each site's `Observe`.
//!
//! Every terminal and `limit` step of a site's main routes gets a [`RouteSlot`]: the label of
//! the nearest enclosing step with a `name` (the step itself included), `""` when none,
//! interned by (site, label) so the unnamed steps of a site share one slot. When no site
//! serves `metrics`, nothing reads the slots, so [`Compiler::observe`] removes them from the
//! terminals and the request path stores none.

use super::{Compiler, Ctx, REDIRECT_SITE, Where};
use crate::plan::{Action, Block, Observe, RouteLabel, RouteSlot, SitePlan};

impl Compiler<'_> {
    /// The slot for a terminal or `limit` step at the current walk position.
    pub(super) fn route_slot(&mut self) -> RouteSlot {
        let site = self.site.name.clone();
        let route = self.site.named.last().map_or("", |n| &**n).to_owned();
        self.intern_route(&site, &route)
    }

    /// The slot of a terminal: none inside error routes, whose answer keeps the label of the
    /// main route that failed.
    pub(super) fn slot(&mut self, ctx: Ctx) -> Option<RouteSlot> {
        (!ctx.in_error_route).then(|| self.route_slot())
    }

    /// The slots of the redirect site's two steps: the redirect, then the ACME token.
    pub(super) fn redirect_slots(&mut self) -> [Option<RouteSlot>; 2] {
        [
            Some(self.intern_route(REDIRECT_SITE, "redirect_http")),
            Some(self.intern_route(REDIRECT_SITE, "acme_challenge")),
        ]
    }

    fn intern_route(&mut self, site: &str, route: &str) -> RouteSlot {
        let index = match self
            .routes
            .iter()
            .position(|l| &*l.site == site && &*l.route == route)
        {
            Some(index) => index,
            None => {
                self.routes.push(RouteLabel {
                    site: site.into(),
                    route: route.into(),
                });
                self.routes.len() - 1
            }
        };
        RouteSlot(index as u16)
    }

    /// A `metrics` step: collection is on for the whole plan. Warns when neither the step nor
    /// an enclosing step has a `when` and the site listens on an address other than loopback.
    pub(super) fn metrics(&mut self, at: &Where) {
        self.metrics = true;
        if let (0, Some(addr)) = (self.site.guarded, self.site.exposed) {
            self.warn(
                at,
                format!(
                    "metrics are served to anyone who reaches {addr}; add a `when` or listen on loopback"
                ),
            );
        }
    }

    /// After every site is compiled, when the `metrics` flag is known: every site observes
    /// metrics when the plan collects them; otherwise route slots are dropped.
    pub(super) fn observe(&self, sites: &mut [SitePlan]) {
        for site in sites {
            if self.metrics {
                site.observe = Some(Observe {
                    log: site.observe.and_then(|o| o.log),
                    metrics: true,
                });
            } else {
                drop_slots(&mut site.routes);
            }
        }
    }
}

fn drop_slots(block: &mut Block) {
    for step in block.steps.iter_mut() {
        match &mut step.action {
            Action::Answer(_, slot) => *slot = None,
            Action::Block(nested) => drop_slots(nested),
            _ => {}
        }
    }
}
