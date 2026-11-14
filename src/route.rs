//! The router: interprets a site's step program against an exchange and returns what should
//! answer it. Synchronous and deterministic: its only inputs besides the plan and the exchange
//! are the core's regex caches, the file catalog (existence checks for `file` and `tryFiles`,
//! cached forever for immutable /nix/store roots) and the coarse clock (`after`).
//!
//! It never does network IO and never awaits, so a core-local `RefCell` borrow of the caches
//! for its duration cannot be held across an await.

use crate::exchange::{ASpan, Exchange};
use crate::files::catalog::Catalog;
use crate::msg::Status;
use crate::plan::cond::Test;
use crate::plan::{Action, Block, BlockKind, Cond, FilesPlan, Plan, ProxyPlan, SitePlan};
use crate::runtime::RegexCaches;

/// Core-local state routing may consult.
pub(crate) struct Effects<'c> {
    pub regex: &'c mut RegexCaches,
    pub catalog: &'c mut Catalog,
    /// Unix seconds, from the core's coarse clock.
    pub now: i64,
}

/// The terminal decision, with every template already expanded into the exchange's arena.
#[derive(Debug)]
pub(crate) enum Outcome<'p> {
    Proxy(&'p ProxyPlan),
    Files { plan: &'p FilesPlan, root: ASpan },
    Respond { status: Status, body: ASpan },
    Redirect { status: Status, location: ASpan },
    Error(Status),
}

/// Runs the site's routes. Reaching the end without a terminal step is `Error(404)`.
pub(crate) fn run<'p>(
    plan: &'p Plan,
    site: &'p SitePlan,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Outcome<'p> {
    match run_block(plan, &site.routes, ex, fx) {
        Flow::Answer(o) => o,
        Flow::Next => Outcome::Error(Status::NOT_FOUND),
    }
}

/// Runs the first error route whose statuses include `ex.error`'s status. Pending header ops
/// and vars from the main route are kept (the error route's ops apply after them). `None`
/// when no error route matches: the pipeline then answers with a bare status response.
pub(crate) fn run_error<'p>(
    plan: &'p Plan,
    site: &'p SitePlan,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Option<Outcome<'p>> {
    todo!()
}

enum Flow<'p> {
    Next,
    Answer(Outcome<'p>),
}

fn run_block<'p>(
    plan: &'p Plan,
    block: &'p Block,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Flow<'p> {
    for step in block.steps.iter() {
        ex.captures.clear();
        if let Some(cond) = &step.when
            && !eval(plan, cond, ex, fx)
        {
            continue;
        }
        if let Flow::Answer(outcome) = apply(plan, &step.action, ex, fx) {
            return Flow::Answer(outcome);
        }
        if block.kind == BlockKind::First {
            break;
        }
    }
    Flow::Next
}

/// Evaluates a matcher. Short-circuits; regex tests run last within an `All` (the compiler
/// orders tests cheapest first: path/method/constant tests before header scans and regexes).
fn eval(plan: &Plan, cond: &Cond, ex: &mut Exchange, fx: &mut Effects<'_>) -> bool {
    todo!()
}

fn test(plan: &Plan, t: &Test, ex: &mut Exchange, fx: &mut Effects<'_>) -> bool {
    todo!()
}

fn apply<'p>(
    plan: &'p Plan,
    action: &'p Action,
    ex: &mut Exchange,
    fx: &mut Effects<'_>,
) -> Flow<'p> {
    // Set: expand all templates, then assign.
    // Rewrite: expand, ex.req.rewrite(..) (bad path -> Answer(Error(400))).
    // StripPrefix: ex.req.strip_prefix(..).
    // TryFiles: expand root and candidates; first fx.catalog.probe(..) hit -> rewrite.
    // ResponseHeaders: expand values into the arena, push PendingOps.
    // RequestHeaders: expand, apply to ex.req.fields now.
    // Encode: ex.pending.encode = set.
    // Block: run_block.
    // Answer(Terminal::Files) -> Outcome::Files { root: expanded }, etc.
    todo!()
}
