//! Upstream response heads: whatever the codec accepts is relayed as bytes that parse back to
//! the same response. The first byte picks whether the request was a HEAD.
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;
use upstreamer::codec::Responses;

thread_local! {
    static RESPONSES: RefCell<Responses> = RefCell::new(Responses::default());
}

fuzz_target!(|data: &[u8]| {
    if let Some((&flag, head)) = data.split_first() {
        RESPONSES.with_borrow_mut(|r| r.check(head, flag & 1 == 1));
    }
});
