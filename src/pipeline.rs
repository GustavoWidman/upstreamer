//! The one request handler every downstream driver calls (h1 per request, h2/h3 per stream).
//! It owns three decisions nothing else makes: which site, how an error becomes a response
//! (error routes), and the final header edit order ([`finalize`]).

use crate::body::{Body, RequestBody};
use crate::encode;
use crate::exchange::{ASpan, ErrorInfo, Exchange, Scheme};
use crate::files;
use crate::log::debug;
use crate::msg::{Fields, Known, ResponseHead, Status};
use crate::plan::SitePlan;
use crate::proxy;
use crate::proxy::Upgrade;
use crate::route::{self, Effects, Outcome};
use crate::runtime::{Core, CoreSnapshot};
use bytes::BytesMut;
use smallvec::SmallVec;
use std::cell::RefCell;

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
///
/// A response for a request that matched no site leaves `ex.site` unset.
pub(crate) async fn handle(
    core: &Core,
    snap: &CoreSnapshot,
    ex: &mut Exchange,
    body: RequestBody<'_>,
) -> Response {
    let plan = &*snap.plan;
    let Some((site_id, site)) = plan.site_for(&ex.conn.listener, ex.req.host()) else {
        let status = match ex.conn.scheme {
            Scheme::Https => Status::MISDIRECTED,
            Scheme::Http => Status::NOT_FOUND,
        };
        return bare(ex, status);
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

    let from_files = matches!(outcome, Outcome::Files { .. });
    let mut resp = match answer(core, snap, outcome, ex, body).await {
        Ok(resp) => resp,
        Err(status) => {
            let mut resp = answer_error(core, snap, site, ex, status).await;
            // The file server's 405 names the methods it does answer (RFC 9110 §15.5.6).
            if from_files && resp.head.status.code() == 405 {
                resp.head.fields.push(b"allow", b"GET, HEAD");
            }
            resp
        }
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
            .map_err(|e| {
                debug!("core {}: upstream of {:?}: {e:?}", core.index, ex.site);
                e.status()
            }),
        Outcome::Files { plan, root } => {
            files::serve(plan, root, ex, &mut core.catalog.borrow_mut())
        }
        Outcome::Respond { status, body } => Ok(respond(ex, status, body)),
        Outcome::Redirect { status, location } => redirect(ex, status, location),
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
            Err(_) => bare(ex, status),
        },
        None => bare(ex, status),
    }
}

thread_local! {
    /// Where `respond` bodies are copied out of the exchange. Each body is split off as its
    /// own `Bytes`, and the buffer reuses its allocation once that response was written.
    static RESPOND: RefCell<BytesMut> = RefCell::new(BytesMut::new());
}

/// A response from the config: `text/plain; charset=utf-8` when the body is not empty.
fn respond(ex: &mut Exchange, status: Status, body: ASpan) -> Response {
    let mut head = ex.response_head(status);
    let text = ex.arena.get(body);
    let body = if text.is_empty() {
        Body::Empty
    } else {
        head.fields
            .append_known(Known::ContentType, b"text/plain; charset=utf-8");
        Body::Bytes(RESPOND.with_borrow_mut(|scratch| {
            scratch.extend_from_slice(text);
            scratch.split().freeze()
        }))
    };
    Response {
        head,
        body,
        upgrade: None,
        local: true,
    }
}

/// 400 when the expanded location starts with `//` or `/\` or holds a control byte: a
/// location built from request bytes must not send the client to another origin.
fn redirect(ex: &mut Exchange, status: Status, location: ASpan) -> Result<Response, Status> {
    let to = ex.arena.get(location);
    if to.starts_with(b"//") || to.starts_with(b"/\\") || to.iter().any(u8::is_ascii_control) {
        return Err(Status::BAD_REQUEST);
    }
    let mut head = ex.response_head(status);
    head.fields.push(b"location", ex.arena.get(location));
    Ok(Response {
        head,
        body: Body::Empty,
        upgrade: None,
        local: true,
    })
}

/// Final header edits, one fixed order for every response of a site:
/// 1. site headers,
/// 2. pending step ops in step order (main route, then error route),
/// 3. dynamic compression, decided from the head as the ops left it,
/// 4. `Vary: Accept-Encoding` if negotiation chose an encoding or a sidecar could have been
///    chosen, merged into the Vary the ops set.
///
/// Framing headers are never touched here; the driver writes them.
pub(crate) fn finalize(site: &SitePlan, ex: &mut Exchange, resp: &mut Response) {
    let fields = &mut resp.head.fields;
    for op in site.headers.iter() {
        match &op.value {
            None => fields.remove(&op.name),
            Some(template) => match template.as_const() {
                Some(value) => fields.set(&op.name, value),
                None => {
                    let value = template.expand(ex);
                    fields.set(&op.name, ex.arena.get(value));
                }
            },
        }
    }
    for op in ex.pending.ops.iter() {
        let name = ex.arena.get(op.name);
        remove(fields, name, op.tag);
        if let Some(value) = op.value {
            fields.push(name, ex.arena.get(value));
        }
    }

    if let Some(encoding) = encode::decide(ex.pending.encode, &ex.req, &resp.head, resp.body.len())
    {
        let body = std::mem::replace(&mut resp.body, Body::Empty);
        resp.body = encode::wrap(encoding, body, &mut resp.head);
    }
    if resp.head.vary_accept_encoding {
        vary_accept_encoding(&mut resp.head.fields);
    }
}

/// Removes every field of a name the router resolved (lowercase, with its tag).
fn remove(fields: &mut Fields, name: &[u8], tag: Known) {
    if tag != Known::Other {
        return fields.remove_known(tag);
    }
    let Fields { buf, table } = fields;
    for field in table.iter_mut() {
        if field.live && field.tag == Known::Other && field.name.get(buf) == name {
            field.live = false;
        }
    }
}

/// Adds `Accept-Encoding` to the response's Vary, as one field with what is already there.
fn vary_accept_encoding(fields: &mut Fields) {
    const TOKEN: &[u8] = b"Accept-Encoding";
    if fields.has_token(Known::Vary, TOKEN) || fields.has_token(Known::Vary, b"*") {
        return;
    }
    let mut vary: SmallVec<[u8; 128]> = SmallVec::new();
    for value in fields.values_known(Known::Vary).filter(|v| !v.is_empty()) {
        vary.extend_from_slice(value);
        vary.extend_from_slice(b", ");
    }
    vary.extend_from_slice(TOKEN);
    fields.set_known(Known::Vary, &vary);
}

/// A bare response for statuses no error route handled: empty body, site headers still
/// applied by `finalize`.
pub(crate) fn bare(ex: &mut Exchange, status: Status) -> Response {
    Response {
        head: ex.response_head(status),
        body: Body::Empty,
        upgrade: None,
        local: true,
    }
}
