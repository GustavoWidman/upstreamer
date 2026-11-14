//! Config -> Plan. Runs on the control thread at startup and reload, and in `upstreamer check`
//! at Nix build time. Pure apart from reading `include` files through [`Sources`].
//!
//! Passes, in one walk per site:
//! 1. Splice includes (cycle check; fragment headers join site headers, fragment errors are
//!    appended).
//! 2. Intern var names to [`VarId`]s (a var read before any `set` can reach it is a warning:
//!    it expands to empty, like an unset Caddy var).
//! 3. Parse templates; resolve `{re.N}` against the step's own `when` (error if no regex there
//!    has N groups).
//! 4. Compile matchers to [`Cond`]; fold constants (e.g. `value` of a constant template).
//! 5. Intern origins to [`UpstreamId`] (conflicting `idle` on one origin is an error).
//! 6. Validate header names (framing headers rejected), statuses, redirect codes.
//! 7. Flag unreachable steps after an unconditional terminal (warning).
//! 8. Derive listeners and host indexes: each TLS site on its https addresses (+ QUIC if
//!    http3), each plain site on its http addresses, and a synthetic redirect site on http for
//!    every TLS site with redirectHttp. Duplicate host on one listener is an error.

use super::{Diagnostic, Plan};
use crate::config::Config;
use std::path::Path;

/// Where include files come from. `run` reads the file system; tests use a map.
pub(crate) trait Sources {
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
}

/// Compiles a parsed config. `generation` is stamped into the plan. On error, every
/// diagnostic found is returned (not just the first), so one build shows all problems.
pub(crate) fn compile(
    config: &Config,
    sources: &dyn Sources,
    generation: u64,
) -> Result<(Plan, Vec<Diagnostic>), Vec<Diagnostic>> {
    todo!()
}
