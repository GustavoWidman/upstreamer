//! HTTP/2 frames: whatever a client sends after the preface, the connection engine neither
//! panics nor queues more than its limits allow, and everything it writes is well-formed
//! frames whose field blocks decode.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::h2::frames_input(data));
