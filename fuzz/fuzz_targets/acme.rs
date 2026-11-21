//! Responses the ACME client reads from a CA: framing, then the JSON documents and the URLs
//! in them.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::acme::response_input(data));
