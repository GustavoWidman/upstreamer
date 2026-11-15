//! HPACK field blocks: the decoder never panics, never yields more than the block can
//! stand for, and what it decodes survives the encoder and a second decoder. One state is
//! reused across inputs, as a connection reuses its tables.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::h2::hpack_input(data));
