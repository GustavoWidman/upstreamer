//! The TLS record layer after the handshake: whatever a client sends, sealed with its keys
//! or not, opens only as the records it sealed, with their bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::tls::input(data));
