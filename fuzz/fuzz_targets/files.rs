//! Static files: request targets and the headers of conditional and range requests against a
//! real tree, with files outside its root to find.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::files::input(data));
