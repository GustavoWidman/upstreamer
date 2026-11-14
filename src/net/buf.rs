//! Per-core buffer pools. Two size classes: 16 KiB (heads, small bodies) and 64 KiB (bulk
//! relays, file reads). A buffer is taken when IO starts and returned when the connection goes
//! idle, so memory follows active requests, not open connections.

use bytes::BytesMut;
use std::cell::RefCell;

pub(crate) const SMALL: usize = 16 * 1024;
pub(crate) const LARGE: usize = 64 * 1024;

/// Free buffers kept per class: a burst of 1000 connections must not pin 16 MiB afterwards.
const KEEP_SMALL: usize = 256;
const KEEP_LARGE: usize = 64;

#[derive(Default)]
pub(crate) struct BufPool {
    small: RefCell<Vec<BytesMut>>,
    large: RefCell<Vec<BytesMut>>,
}

impl BufPool {
    pub fn take(&self) -> BytesMut {
        self.small
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(SMALL))
    }
    pub fn take_large(&self) -> BytesMut {
        self.large
            .borrow_mut()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(LARGE))
    }
    /// Keeps the buffer if it is uniquely owned and of a pool size (cleared); drops it
    /// otherwise. Caps each free list so a burst does not pin memory.
    pub fn put(&self, mut buf: BytesMut) {
        buf.clear();
        // `try_reclaim` succeeds only for a uniquely owned allocation of at least that size,
        // and moves the cursor back to its start, so a kept buffer has its full capacity.
        let (list, keep) = if buf.try_reclaim(LARGE) && buf.capacity() <= 2 * LARGE {
            (&self.large, KEEP_LARGE)
        } else if buf.try_reclaim(SMALL) && buf.capacity() < LARGE {
            (&self.small, KEEP_SMALL)
        } else {
            return;
        };
        let mut list = list.borrow_mut();
        if list.len() < keep {
            list.push(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffers_are_recycled_by_class() {
        let pool = BufPool::default();
        let mut small = pool.take();
        assert!(small.capacity() >= SMALL);
        small.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        let ptr = small.as_ptr();
        pool.put(small);
        let again = pool.take();
        assert_eq!(again.as_ptr(), ptr, "the small buffer comes back");
        assert!(again.is_empty());

        let large = pool.take_large();
        assert!(large.capacity() >= LARGE);
        let ptr = large.as_ptr();
        pool.put(large);
        assert_eq!(
            pool.take_large().as_ptr(),
            ptr,
            "the large buffer comes back"
        );
    }

    #[test]
    fn advanced_buffer_comes_back_whole() {
        let pool = BufPool::default();
        let mut buf = pool.take();
        buf.extend_from_slice(&[b'x'; 1000]);
        bytes::Buf::advance(&mut buf, 1000);
        pool.put(buf);
        let buf = pool.take();
        assert!(
            buf.capacity() >= SMALL,
            "an advanced buffer is reclaimed to full size"
        );
    }

    #[test]
    fn shared_and_odd_sized_buffers_are_dropped() {
        let pool = BufPool::default();
        let mut buf = pool.take();
        buf.extend_from_slice(b"abc");
        let frozen = buf.split().freeze();
        pool.put(buf);
        drop(frozen);
        pool.put(BytesMut::with_capacity(100));
        pool.put(BytesMut::with_capacity(10 * LARGE));
        assert!(pool.small.borrow().is_empty());
        assert!(pool.large.borrow().is_empty());
    }

    #[test]
    fn free_lists_are_capped() {
        let pool = BufPool::default();
        let bufs: Vec<_> = (0..KEEP_SMALL + 10).map(|_| pool.take()).collect();
        for b in bufs {
            pool.put(b);
        }
        assert_eq!(pool.small.borrow().len(), KEEP_SMALL);
    }
}
