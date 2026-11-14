//! Host -> site, per listener. Exact names in a flat open-addressing table (lowercase,
//! FxHash), then `*.suffix` wildcards longest first, then `*`. The Host value is lowercased
//! into a 256-byte stack buffer for the lookup; no allocation.

use super::SiteId;

#[derive(Debug, Default)]
pub(crate) struct HostIndex {
    exact: Box<[(Box<[u8]>, SiteId)]>,
    suffixes: Box<[(Box<[u8]>, SiteId)]>,
    any: Option<SiteId>,
}

impl HostIndex {
    pub fn lookup(&self, host: &[u8]) -> Option<SiteId> {
        todo!()
    }
}
