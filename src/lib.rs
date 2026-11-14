//! upstreamer: a reverse proxy and static file server for NixOS hosts.
//!
//! # Shape
//!
//! ```text
//!  NixOS module ──JSON──▶ config (wire schema, serde) ──compile──▶ plan::Plan (immutable, Arc)
//!                                                                   │ published by runtime::control
//!                                                                   ▼ to every core as CoreSnapshot
//!  per core (one OS thread, one current-thread tokio runtime, nothing shared but read-only Arcs):
//!
//!   net::listen (SO_REUSEPORT socket per core) ─▶ tls::accept ─▶ proto::{h1,h2,h3} driver
//!        driver builds an Exchange (msg::RequestHead + per-request scratch) and calls
//!        pipeline::handle ─▶ route::run (pure decision over the plan) ─▶ Outcome
//!                         ─▶ proxy::forward | files::serve | respond | redirect | error
//!                         ─▶ error routes ─▶ finalize headers ─▶ Response
//!        driver writes the Response (h1: own codec, relay/sendfile fast paths)
//! ```
//!
//! # Load-bearing decisions
//!
//! 1. Thread-per-core. Every connection, upstream pool, buffer pool, regex cache and file
//!    catalog belongs to one core and is `!Send` (`Rc`, `RefCell`). The only cross-core data
//!    are immutable `Arc`s swapped by the control thread at reload. No lock or atomic is
//!    touched per request.
//! 2. Our own HTTP/1.1 codec on both sides, with one owned head representation
//!    ([`msg::RequestHead`]) shared by h1, h2 and h3, and a [`body::Body`] enum whose variants
//!    keep the zero-copy paths (relay, sendfile, splice) open per downstream protocol.
//! 3. Routing is an ordered step program compiled from JSON into enums, interpreted by a pure
//!    function ([`route::run`]). Vars, captures and templates are resolved to indices at
//!    compile time; `upstreamer check` runs the same compiler at Nix build time.
//!
//! # Public surface
//!
//! [`run`] and [`check`]. Everything else is crate-private, so no caller can reach into the
//! hot path's internals.

// Modules whose bodies are still `todo!()` leave parameters and items unused.
#![allow(dead_code, unused_variables, unused_macros)]

mod body;
mod config;
mod encode;
mod exchange;
mod files;
mod log;
mod msg;
mod net;
mod pipeline;
mod plan;
mod proto;
mod proxy;
mod route;
mod runtime;
mod tls;

use std::fmt;
use std::path::PathBuf;

pub use plan::Diagnostic;

/// Options of `upstreamer run`.
pub struct RunOptions {
    /// The JSON config the NixOS module wrote (`/etc/upstreamer/config.json`). Read again on
    /// every SIGHUP; the path, not the content, is fixed for the life of the process.
    pub config: PathBuf,
    /// Worker count override; `None` takes the config's `workers`, else one per CPU in the
    /// process's affinity mask (which honours systemd `CPUAffinity=`/cgroup cpusets).
    pub workers: Option<u16>,
}

/// Why the process could not start. Every variant is fatal at startup only; the same failures
/// at reload keep the running generation and are logged instead.
#[derive(Debug)]
pub enum StartError {
    Config(Vec<Diagnostic>),
    Bind {
        addr: std::net::SocketAddr,
        error: std::io::Error,
    },
    Runtime(std::io::Error),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartError::Config(diagnostics) => {
                for (i, d) in diagnostics.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "{d}")?;
                }
                Ok(())
            }
            StartError::Bind { addr, error } => write!(f, "cannot bind {addr}: {error}"),
            StartError::Runtime(error) => write!(f, "{error}"),
        }
    }
}

/// Runs the proxy until SIGTERM/SIGINT, reloading on SIGHUP. Blocks the calling thread, which
/// becomes the control thread.
pub fn run(opts: RunOptions) -> Result<(), StartError> {
    runtime::control::run(opts)
}

/// What `upstreamer check` validates.
pub enum CheckInput {
    /// A whole config, with every `include` resolved and validated. Used by the NixOS module
    /// at build time, inside the sandbox: certificate files and static roots need not exist
    /// there and are not opened; include files must (they are store paths in the closure).
    Config {
        path: PathBuf,
        /// Ports the NixOS module computed for the firewall. The module derives them in Nix
        /// and the compiler derives listeners from the same sites; `check` fails when the two
        /// disagree, so the pair cannot drift apart.
        expect: Option<ExpectedPorts>,
    },
    /// One route fragment (`{ "fragment": 1, ... }`), validated as if included by a site.
    /// Used by packages that generate fragments (their installCheck).
    Fragment(PathBuf),
}

/// `--expect-tcp 80,443 --expect-udp 443`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedPorts {
    pub tcp: Vec<u16>,
    pub udp: Vec<u16>,
}

/// Summary printed by `upstreamer check` on success.
#[derive(Debug)]
pub struct CheckReport {
    pub sites: usize,
    pub steps: usize,
    pub warnings: Vec<Diagnostic>,
}

/// Compiles the config exactly as `run` would, minus the parts that touch the host (binding,
/// certificate files, static roots). Pure apart from reading the input and its includes.
pub fn check(input: CheckInput) -> Result<CheckReport, Vec<Diagnostic>> {
    plan::check(input)
}
