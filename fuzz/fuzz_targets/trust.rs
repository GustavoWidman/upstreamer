//! Client addresses from trusted peers: `CF-Connecting-IP`, `X-Real-IP` and `X-Forwarded-For`
//! values from any client, from trusted and untrusted peers.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::trust::input(data));
