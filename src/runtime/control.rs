//! The control thread: startup, reload, shutdown, systemd notification.
//!
//! systemd: `Type=notify-reload`. Startup sends `READY=1` after every core bound its
//! listeners. SIGHUP (sent by `systemctl reload`, by the NixOS switch when the config file
//! changed, and by ACME renewals through `reloadServices`) sends `RELOADING=1` +
//! `MONOTONIC_USEC`, rebuilds, publishes, then `READY=1`. SIGTERM drains.
//!
//! Reload is idempotent and never makes things worse: an unparsable or invalid config keeps
//! the running generation (logged, `STATUS=` set); certificate problems keep the previous
//! certificate per name. Running reload twice with the same inputs publishes an equivalent
//! generation.

use super::{Generation, Worker};
use crate::plan::Diagnostic;
use crate::tls::CertProblem;
use crate::{RunOptions, StartError};
use std::sync::Arc;

pub(crate) fn run(opts: RunOptions) -> Result<(), StartError> {
    // 1. read + compile config (errors are fatal here: systemd shows them)
    // 2. tls::load certificates (problems are warnings)
    // 3. cpus from sched_getaffinity; spawn_workers; wait for every core's ready
    // 4. sd_notify READY=1; then block on signals (signalfd/tokio current-thread runtime)
    todo!()
}

/// Builds the next generation from disk. `Err` keeps the current one.
pub(crate) fn rebuild(
    opts: &RunOptions,
    current: &Generation,
    generation: u64,
) -> Result<(Generation, Vec<Diagnostic>, Vec<CertProblem>), Vec<Diagnostic>> {
    todo!()
}

/// Sends the generation to every core. Cores install it at their next loop turn.
pub(crate) fn publish(workers: &[Worker], generation: Arc<Generation>) {
    todo!()
}

/// SIGTERM: `STOPPING=1`, drain every core with the shutdown deadline, join threads.
pub(crate) fn shutdown(workers: Vec<Worker>, deadline: std::time::Duration) {
    todo!()
}

/// Writes to `$NOTIFY_SOCKET` (no-op without it).
pub(crate) fn notify(state: &str) {
    todo!()
}
