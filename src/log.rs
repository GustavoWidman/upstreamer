//! Logging to stderr with syslog priority prefixes (`<4>...`), which journald reads as the
//! message's level. No logging crate: nothing here runs per request unless debug logging is on,
//! and a disabled `debug!` costs one relaxed load.
//!
//! `UPSTREAMER_DEBUG=1` in the environment turns debug messages on; [`init`] reads it once.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

static DEBUG: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Error = 3,
    Warn = 4,
    Info = 6,
    Debug = 7,
}

/// Reads `UPSTREAMER_DEBUG` once, at startup.
pub(crate) fn init() {
    let on = std::env::var_os("UPSTREAMER_DEBUG").is_some_and(|v| !v.is_empty() && v != "0");
    DEBUG.store(on, Ordering::Relaxed);
}

pub(crate) fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

pub(crate) fn write(level: Level, args: fmt::Arguments<'_>) {
    eprintln!("<{}>{}", level as u8, args);
}

macro_rules! error {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Error, format_args!($($arg)*)) };
}

macro_rules! warning {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Warn, format_args!($($arg)*)) };
}

macro_rules! info {
    ($($arg:tt)*) => { $crate::log::write($crate::log::Level::Info, format_args!($($arg)*)) };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if $crate::log::debug_enabled() {
            $crate::log::write($crate::log::Level::Debug, format_args!($($arg)*))
        }
    };
}

#[allow(unused_imports)]
pub(crate) use {debug, error, info, warning};
