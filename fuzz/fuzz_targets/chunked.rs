//! Chunked framing: scan and decode agree whole and split, and decoded data round-trips.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::codec::check_chunked(data));
