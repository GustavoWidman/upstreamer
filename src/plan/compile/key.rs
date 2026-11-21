//! Request keys, for `balance.hash` and `limit.key`.

use super::{Compiler, Where};
use crate::plan::KeyPlan;
use crate::plan::template::{Captures, Placeholder, Scope};

impl Compiler<'_> {
    /// Parses a key template and specialises it: exactly `{remote_host}` -> `RemoteHost`,
    /// exactly `{remote_net}` -> `RemoteNet`, exactly `{header.Name}` -> `Header`, a constant
    /// -> `Const(hash)`, else `Template`.
    /// A key reads the request alone: `{re.N}` and `{err.*}` are errors, and so is a constant
    /// that is empty (a key that never exists).
    pub(super) fn key(&mut self, src: &str, at: &Where, scope: &mut Scope<'_>) -> Option<KeyPlan> {
        let mut own = Scope {
            vars: &mut *scope.vars,
            captures: Captures::Unavailable,
            in_error_route: false,
            uses_captures: false,
            reads: Vec::new(),
        };
        let template = self.template(src, at, &mut own);
        let reads = own.reads;
        scope.reads.extend(reads);
        let template = template?;
        if let Some(constant) = template.as_const() {
            if constant.is_empty() {
                self.error(
                    at,
                    "a key that is always empty never selects a bucket or an origin",
                );
                return None;
            }
            return Some(KeyPlan::Const(crate::key::constant(constant)));
        }
        Some(match template.as_placeholder() {
            Some(Placeholder::RemoteHost) => KeyPlan::RemoteHost,
            Some(Placeholder::RemoteNet) => KeyPlan::RemoteNet,
            Some(Placeholder::Header(name)) => KeyPlan::Header(name.clone()),
            _ => KeyPlan::Template(template),
        })
    }
}
