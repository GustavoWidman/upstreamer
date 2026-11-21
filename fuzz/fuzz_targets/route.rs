//! Routing: requests from any client through the fleet's configs and one that uses every
//! placeholder, matcher and key, from trusted and untrusted peers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::route::input(data));
