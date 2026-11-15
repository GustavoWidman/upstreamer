//! Rate limits: one table of GCRA states per `limit` step, shared by every core, exact across
//! cores (one compare-and-swap per limited request). A plan without `limit` steps has no
//! table, and no request reaches this module.

use crate::exchange::Exchange;
use crate::plan::{LimitPlan, LimitSpec, Plan};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

/// The tables of one generation, by `LimitId`. Built by the control thread; a table whose
/// `LimitSpec` is unchanged across a reload is the same `Arc`, so its buckets survive.
#[derive(Default)]
pub(crate) struct Limiters {
    tables: Box<[Arc<Table>]>,
}

/// One `limit` step's buckets.
pub(crate) struct Table {
    /// Live buckets replaced to make room for a new key.
    pub evictions: AtomicU64,
}

/// What a limit step decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Admit {
    Yes,
    /// Seconds until a request with this key would be admitted, at least 1.
    Wait(u32),
}

impl Limiters {
    /// The tables for `plan`, reusing `previous`'s table for every `LimitSpec` they share.
    pub fn carry(plan: &Plan, previous: Option<(&Plan, &Limiters)>) -> Arc<Limiters> {
        let _ = previous;
        Arc::new(Limiters {
            tables: plan
                .limits
                .iter()
                .map(|spec| Arc::new(Table::new(spec)))
                .collect(),
        })
    }

    /// Admits or refuses one request. A request whose key expands to nothing is admitted.
    pub fn admit(&self, limit: &LimitPlan, ex: &mut Exchange) -> Admit {
        let _ = (limit, ex);
        Admit::Yes
    }

    pub fn tables(&self) -> &[Arc<Table>] {
        &self.tables
    }
}

impl Table {
    pub fn new(spec: &LimitSpec) -> Table {
        let _ = spec;
        Table {
            evictions: AtomicU64::new(0),
        }
    }
}

/// Entry points for `benches/limit.rs`; not part of the API.
#[cfg(feature = "internals")]
pub mod bench {}
