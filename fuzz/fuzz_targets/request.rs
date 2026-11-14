//! Request heads: whatever the codec accepts is forwarded as bytes that parse back to the same
//! request. One parser state is reused across inputs, as a connection reuses its exchange.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use upstreamer::codec::Requests;

thread_local! {
    static REQUESTS: RefCell<Requests> = RefCell::new(Requests::default());
}

fuzz_target!(|data: &[u8]| REQUESTS.with_borrow_mut(|r| r.check(data)));
