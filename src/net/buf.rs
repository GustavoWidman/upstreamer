//! Per-core buffer pools. Two size classes: 16 KiB (heads, small bodies) and 64 KiB (bulk
//! relays, file reads). A buffer is taken when IO starts and returned when the connection goes
//! idle, so memory follows active requests, not open connections.

use bytes::BytesMut;
use std::cell::RefCell;

pub(crate) const SMALL: usize = 16 * 1024;
pub(crate) const LARGE: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct BufPool {
    small: RefCell<Vec<BytesMut>>,
    large: RefCell<Vec<BytesMut>>,
}

impl BufPool {
    pub fn take(&self) -> BytesMut {
        todo!()
    }
    pub fn take_large(&self) -> BytesMut {
        todo!()
    }
    /// Keeps the buffer if it is uniquely owned and of a pool size (cleared); drops it
    /// otherwise. Caps each free list so a burst does not pin memory.
    pub fn put(&self, buf: BytesMut) {
        todo!()
    }
}
