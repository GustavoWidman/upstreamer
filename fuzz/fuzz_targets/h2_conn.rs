//! HTTP/2 connections: whatever frames a client sends after its preface, through the
//! connection driver to files, local answers and an origin.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::conn::h2_input(data));
