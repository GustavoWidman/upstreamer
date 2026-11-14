//! The one request handler every downstream driver calls (h1 per request, h2/h3 per stream).
//! It owns three decisions nothing else makes: which site, how an error becomes a response
//! (error routes), and the final header edit order ([`finalize`]).

use crate::body::{Body, RequestBody};
use crate::exchange::{ErrorInfo, Exchange, Scheme};
use crate::files;
use crate::msg::{ResponseHead, Status};
use crate::plan::SitePlan;
use crate::proxy;
use crate::proxy::Upgrade;
use crate::route::{self, Effects, Outcome};
use crate::runtime::{Core, CoreSnapshot};

pub(crate) struct Response {
    pub head: ResponseHead,
    pub body: Body,
    /// Set only on a 101 from the upstream of an h1 request: after writing the head, the h1
    /// driver relays bytes both ways between the client and this connection.
    pub upgrade: Option<Upgrade>,
    /// Produced here (files, respond, redirect, error) rather than by an upstream: the driver
    /// adds `Date` (from the core's cached clock) only to these.
    pub local: bool,
}

/// Hot path, in order:
/// 1. host -> site (421 on TLS, 404 on cleartext when none).
/// 2. `route::run` with the core's regex caches and catalog borrowed (sync; the borrows end
///    before the first await).
/// 3. `answer`: proxy (await), files (sync, from the catalog), respond, redirect.
/// 4. An error status (from the outcome or the handler: 404 file, 502/504 upstream) goes
///    through `route::run_error` and `answer` once more; an error there answers bare.
/// 5. [`finalize`].
pub(crate) async fn handle(
    core: &Core,
    snap: &CoreSnapshot,
    ex: &mut Exchange,
    body: RequestBody<'_>,
) -> Response {
    let plan = &*snap.plan;
    let Some((site_id, site)) = plan.site_for(&ex.conn.listener, ex.req.host()) else {
        return bare(match ex.conn.scheme {
            Scheme::Https => Status::MISDIRECTED,
            Scheme::Http => Status::NOT_FOUND,
        });
    };
    ex.site = Some(site_id);

    let outcome = {
        let mut regex = core.regex.borrow_mut();
        let mut catalog = core.catalog.borrow_mut();
        let mut fx = Effects {
            regex: &mut regex,
            catalog: &mut catalog,
            now: core.clock.unix.get(),
        };
        route::run(plan, site, ex, &mut fx)
    };

    let mut resp = match answer(core, snap, outcome, ex, body).await {
        Ok(resp) => resp,
        Err(status) => answer_error(core, snap, site, ex, status).await,
    };
    finalize(site, ex, &mut resp);
    resp
}

/// Executes an outcome. Error statuses come back as `Err` so `handle` routes them.
async fn answer(
    core: &Core,
    snap: &CoreSnapshot,
    outcome: Outcome<'_>,
    ex: &mut Exchange,
    body: RequestBody<'_>,
) -> Result<Response, Status> {
    match outcome {
        Outcome::Proxy(plan) => proxy::forward(core, snap, plan, ex, body)
            .await
            .map_err(|e| e.status()),
        Outcome::Files { plan, root } => {
            files::serve(plan, root, ex, &mut core.catalog.borrow_mut())
        }
        Outcome::Respond { status, body } => Ok(respond(status, ex.arena.get(body))),
        Outcome::Redirect { status, location } => redirect(status, ex.arena.get(location)),
        Outcome::Error(status) => Err(status),
    }
}

/// Error handling: the site's first error route for `status`, else a bare response.
async fn answer_error(
    core: &Core,
    snap: &CoreSnapshot,
    site: &SitePlan,
    ex: &mut Exchange,
    status: Status,
) -> Response {
    ex.error = Some(ErrorInfo { status });
    let outcome = {
        let mut regex = core.regex.borrow_mut();
        let mut catalog = core.catalog.borrow_mut();
        let mut fx = Effects {
            regex: &mut regex,
            catalog: &mut catalog,
            now: core.clock.unix.get(),
        };
        route::run_error(&snap.plan, site, ex, &mut fx)
    };
    match outcome {
        Some(outcome) => match answer(core, snap, outcome, ex, RequestBody::Empty).await {
            Ok(resp) => resp,
            Err(_) => bare(status),
        },
        None => bare(status),
    }
}

fn respond(status: Status, body: &[u8]) -> Response {
    todo!("text/plain; charset=utf-8 when the body is non-empty")
}

/// 400 when the expanded location starts with `//` or `/\` or holds a control byte.
fn redirect(status: Status, location: &[u8]) -> Result<Response, Status> {
    todo!()
}

/// Final header edits, one fixed order for every response of a site:
/// 1. site headers,
/// 2. pending step ops in step order (main route, then error route),
/// 3. `Vary: Accept-Encoding` if negotiation chose an encoding or a sidecar could have been
///    chosen,
/// 4. `Alt-Svc` on h1/h2 TLS responses of HTTP/3 sites.
///
/// Framing headers are never touched here; the driver writes them.
pub(crate) fn finalize(site: &SitePlan, ex: &Exchange, resp: &mut Response) {
    todo!()
}

/// A bare response for statuses no error route handled: empty body, site headers still
/// applied by `finalize`.
pub(crate) fn bare(status: Status) -> Response {
    Response {
        head: ResponseHead::new(status),
        body: Body::Empty,
        upgrade: None,
        local: true,
    }
}
