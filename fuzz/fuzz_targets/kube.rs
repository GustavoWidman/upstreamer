//! Responses the Kubernetes client reads from an API server: a list, or a chunked watch
//! stream of JSON events, cut into reads of any size.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| upstreamer::fuzz::kube::watch_input(data));
