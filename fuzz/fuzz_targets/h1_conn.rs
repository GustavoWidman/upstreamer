//! HTTP/1.1 connections: whatever a client sends, pipelined, with bodies, `Expect` and
//! upgrades, through the connection driver to files, local answers and an origin.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::conn::h1_input(data));
