//! Per-request state. One `Exchange` per in-flight request: per h1 connection while it has a
//! request (taken from the core's pool when the request's first byte arrives, returned when
//! the response is written), per h2/h3 stream. Idle connections hold none.
//!
//! Everything a request produces while routing (expanded templates, var values, captures,
//! resolved header ops) lands in [`Arena`], a recycled byte buffer cleared per request. The
//! steady state allocates nothing.

use crate::encode::EncodingSet;
use crate::msg::{Known, RequestHead, ResponseHead, Status};
use crate::plan::{ListenerKey, SiteId, VarId};
use smallvec::SmallVec;
use std::net::SocketAddr;

/// Span into [`Arena`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ASpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Default)]
pub(crate) struct Arena {
    bytes: Vec<u8>,
}

impl Arena {
    pub fn push(&mut self, b: &[u8]) -> ASpan {
        self.build(|out| out.extend_from_slice(b))
    }
    /// Appends via a writer closure and returns the span it wrote (template expansion). The
    /// closure sees the whole arena, so it may copy earlier spans with `extend_from_within`; it
    /// must only append.
    pub fn build(&mut self, f: impl FnOnce(&mut Vec<u8>)) -> ASpan {
        let start = self.bytes.len();
        f(&mut self.bytes);
        debug_assert!(self.bytes.len() >= start, "arena writers only append");
        ASpan {
            start: start as u32,
            end: self.bytes.len() as u32,
        }
    }
    pub fn get(&self, s: ASpan) -> &[u8] {
        &self.bytes[s.start as usize..s.end as usize]
    }
    pub fn clear(&mut self) {
        self.bytes.clear();
    }
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Proto {
    H1,
    H2,
    H3,
}

/// Facts about the downstream connection, fixed for its life.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnInfo {
    pub remote: SocketAddr,
    pub local_port: u16,
    pub scheme: Scheme,
    pub proto: Proto,
    /// The listening socket this connection came from, by identity rather than by index into a
    /// plan, so host lookup stays right after a reload re-indexes listeners. A connection whose
    /// listener is gone from the new plan gets 421/404 and is closed.
    pub listener: ListenerKey,
}

/// A response header op resolved during routing, applied in order by `pipeline::finalize`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingOp {
    pub name: ASpan,
    pub tag: Known,
    /// `None` removes.
    pub value: Option<ASpan>,
}

/// What routing decided about the response before a handler produced it.
#[derive(Debug, Default)]
pub(crate) struct Pending {
    pub ops: SmallVec<[PendingOp; 8]>,
    pub encode: EncodingSet,
}

/// Set when the request entered error handling; read by `{err.*}` and by `files` (which
/// serves an error page with the error's status and ignores conditionals and ranges).
#[derive(Clone, Copy, Debug)]
pub(crate) struct ErrorInfo {
    pub status: Status,
}

#[derive(Debug)]
pub(crate) struct Exchange {
    pub req: RequestHead,
    pub conn: ConnInfo,
    pub site: Option<SiteId>,
    /// Indexed by [`VarId`]; sized to the plan's var count when the exchange starts.
    pub vars: SmallVec<[Option<ASpan>; 8]>,
    /// Capture groups of the regex in the current step's `when`; cleared before every step,
    /// so a `{re.N}` can never read a stale match (the compiler rejects `{re.N}` where no
    /// regex with N groups is in that step).
    pub captures: SmallVec<[Option<ASpan>; 4]>,
    pub arena: Arena,
    pub pending: Pending,
    pub error: Option<ErrorInfo>,
    /// Scratch for serialising heads this exchange writes (upstream request, h1 response);
    /// recycled with the exchange.
    pub out: Vec<u8>,
    /// Spare response head (buffer kept between requests).
    spare_head: Option<ResponseHead>,
}

impl Exchange {
    /// A fresh exchange for a request on `conn` under a plan with `vars` vars. The steady state
    /// recycles exchanges through [`ExchangePool`] instead.
    pub fn new(conn: ConnInfo, vars: u16) -> Exchange {
        let mut ex = Exchange {
            req: RequestHead::new(),
            conn,
            site: None,
            vars: SmallVec::new(),
            captures: SmallVec::new(),
            arena: Arena::default(),
            pending: Pending::default(),
            error: None,
            out: Vec::new(),
            spare_head: None,
        };
        ex.vars.resize(vars as usize, None);
        ex
    }
    /// Prepares a recycled exchange for a new request on `conn` under a plan with `vars` vars:
    /// clears everything, keeps capacities.
    pub fn begin(&mut self, conn: ConnInfo, vars: u16) {
        self.req.clear();
        self.conn = conn;
        self.site = None;
        self.vars.clear();
        self.vars.resize(vars as usize, None);
        self.captures.clear();
        self.arena.clear();
        self.pending.ops.clear();
        self.pending.encode = EncodingSet::default();
        self.error = None;
        self.out.clear();
    }
    /// A response head with this exchange's recycled buffer (proxied and local responses).
    pub fn response_head(&mut self, status: Status) -> ResponseHead {
        match self.spare_head.take() {
            Some(mut head) => {
                head.clear(status);
                head
            }
            None => ResponseHead::new(status),
        }
    }
    /// Takes a written response's head back so its buffer is reused by the next request.
    pub fn recycle(&mut self, head: ResponseHead) {
        self.spare_head = Some(head);
    }
    /// Bytes this exchange keeps allocated between requests.
    fn retained(&self) -> usize {
        self.req.fields.buf.capacity()
            + self.arena.capacity()
            + self.out.capacity()
            + self
                .spare_head
                .as_ref()
                .map_or(0, |h| h.fields.buf.capacity())
    }
    pub fn var(&self, id: VarId) -> Option<&[u8]> {
        self.vars[id.0 as usize].map(|s| self.arena.get(s))
    }
}

/// Per-core free list of exchanges, so neither a new connection nor a new h2 stream allocates
/// one in the steady state.
#[derive(Default)]
#[allow(
    clippy::vec_box,
    reason = "an exchange moves between the pool and its connection as a pointer"
)]
pub(crate) struct ExchangePool {
    free: std::cell::RefCell<Vec<Box<Exchange>>>,
}

/// Buffers above this are dropped with their exchange instead of pooled.
const RETAIN_BYTES: usize = 128 * 1024;
/// Free exchanges kept per core.
const RETAIN_COUNT: usize = 1024;

impl ExchangePool {
    pub fn take(&self, conn: ConnInfo, vars: u16) -> Box<Exchange> {
        match self.free.borrow_mut().pop() {
            Some(mut ex) => {
                ex.begin(conn, vars);
                ex
            }
            None => Box::new(Exchange::new(conn, vars)),
        }
    }
    /// Keeps the exchange unless its buffers grew past the retention cap (a huge head must
    /// not pin memory forever).
    pub fn put(&self, ex: Box<Exchange>) {
        let mut free = self.free.borrow_mut();
        if ex.retained() <= RETAIN_BYTES && free.len() < RETAIN_COUNT {
            free.push(ex);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ListenerKind;

    fn conn() -> ConnInfo {
        ConnInfo {
            remote: "192.0.2.1:5000".parse().unwrap(),
            local_port: 80,
            scheme: Scheme::Http,
            proto: Proto::H1,
            listener: ListenerKey {
                addr: "0.0.0.0:80".parse().unwrap(),
                kind: ListenerKind::Http,
            },
        }
    }

    #[test]
    fn arena_spans() {
        let mut arena = Arena::default();
        let a = arena.push(b"hello");
        let b = arena.build(|out| {
            out.extend_from_within(a.start as usize..a.end as usize);
            out.extend_from_slice(b" world");
        });
        assert_eq!(arena.get(a), b"hello");
        assert_eq!(arena.get(b), b"hello world");
    }

    #[test]
    fn pooled_exchange_is_reused_and_reset() {
        let pool = ExchangePool::default();
        let mut ex = pool.take(conn(), 2);
        ex.vars[1] = Some(ex.arena.push(b"x"));
        ex.req
            .set_line(b"GET", b"/a", crate::msg::Version::Http11)
            .unwrap();
        ex.error = Some(ErrorInfo {
            status: Status::NOT_FOUND,
        });
        let addr = &*ex as *const Exchange;
        pool.put(ex);
        let ex = pool.take(conn(), 3);
        assert_eq!(&*ex as *const Exchange, addr);
        assert_eq!(ex.vars.as_slice(), &[None, None, None]);
        assert!(ex.error.is_none());
        assert_eq!(ex.req.path().as_bytes(), b"");
    }
}
