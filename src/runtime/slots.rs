//! Recycled heap blocks for a future that a long-lived task runs only part of the time.
//!
//! A task's state is as large as the largest future it awaits inline, for its whole life. An
//! HTTP/1.1 connection spends most of its life waiting for the next request, in a few hundred
//! bytes of state, but the request it then runs (routing, the upstream exchange, the body
//! relay) needs a few KiB. Running the request in a block from [`Slots`] keeps the idle task
//! small, and recycling the blocks per core keeps the steady state free of allocations.

use std::alloc::{self, Layout};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::ptr::NonNull;
use std::task::{Context, Poll};

/// Free blocks kept: enough for every in-flight request of a busy core; a burst past it
/// returns the rest to the allocator.
const KEEP: usize = 256;

/// Per-core free list of blocks for one future type (the first type run fixes the layout; a
/// future of another layout gets a block of its own that is not kept).
#[derive(Default)]
pub(crate) struct Slots {
    layout: Cell<Option<Layout>>,
    free: RefCell<Vec<NonNull<u8>>>,
}

impl Slots {
    /// Moves `fut` into a block. The returned future polls it in place and gives the block back
    /// when it is dropped, finished or not.
    pub fn run<F: Future>(&self, fut: F) -> InSlot<'_, F> {
        const { assert!(size_of::<F>() > 0, "a future with state") };
        let layout = Layout::new::<F>();
        let recycled = match self.layout.get() {
            Some(kept) if kept == layout => self.free.borrow_mut().pop(),
            Some(_) => None,
            None => {
                self.layout.set(Some(layout));
                None
            }
        };
        let block = recycled.unwrap_or_else(|| {
            // SAFETY: `layout` has a nonzero size (asserted above).
            let ptr = unsafe { alloc::alloc(layout) };
            NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout))
        });
        let ptr = block.cast::<F>();
        // SAFETY: the block is valid for writes of `layout`, which is `F`'s.
        unsafe { ptr.as_ptr().write(fut) };
        InSlot {
            ptr,
            slots: self,
            _owns: PhantomData,
        }
    }

    fn put(&self, block: NonNull<u8>, layout: Layout) {
        let mut free = self.free.borrow_mut();
        if self.layout.get() == Some(layout) && free.len() < KEEP {
            free.push(block);
        } else {
            // SAFETY: the block was allocated with `layout` by `run`.
            unsafe { alloc::dealloc(block.as_ptr(), layout) };
        }
    }
}

impl Drop for Slots {
    fn drop(&mut self) {
        if let Some(layout) = self.layout.get() {
            for block in self.free.get_mut().drain(..) {
                // SAFETY: every kept block was allocated with the kept layout.
                unsafe { alloc::dealloc(block.as_ptr(), layout) };
            }
        }
    }
}

/// A future running in a block of [`Slots`].
pub(crate) struct InSlot<'a, F> {
    ptr: NonNull<F>,
    slots: &'a Slots,
    _owns: PhantomData<F>,
}

impl<F: Future> Future for InSlot<'_, F> {
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        // SAFETY: the future stays in its block, unmoved, until `drop`; `InSlot` is its only
        // owner.
        unsafe { Pin::new_unchecked(&mut *self.ptr.as_ptr()) }.poll(cx)
    }
}

impl<F> Drop for InSlot<'_, F> {
    fn drop(&mut self) {
        // SAFETY: `run` wrote the future and nothing else drops it.
        unsafe { self.ptr.as_ptr().drop_in_place() };
        self.slots.put(self.ptr.cast(), Layout::new::<F>());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::testing::thread_allocations;
    use std::rc::Rc;

    fn block_on<F: Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(fut)
    }

    async fn request(n: u64, pad: [u8; 512]) -> u64 {
        tokio::task::yield_now().await;
        n + pad.len() as u64
    }

    #[test]
    fn runs_the_future_to_its_output() {
        let slots = Slots::default();
        assert_eq!(block_on(slots.run(request(1, [0; 512]))), 513);
    }

    #[test]
    fn steady_state_runs_allocate_nothing() {
        let slots = Slots::default();
        block_on(async {
            slots.run(request(0, [0; 512])).await;
            let before = thread_allocations();
            for n in 0..100 {
                assert_eq!(slots.run(request(n, [0; 512])).await, n + 512);
            }
            assert_eq!(
                thread_allocations(),
                before,
                "every run reuses the first block"
            );
        });
    }

    #[test]
    fn a_future_dropped_unfinished_releases_what_it_holds() {
        let slots = Slots::default();
        let held = Rc::new(());
        let fut = {
            let held = held.clone();
            async move {
                std::future::pending::<()>().await;
                drop(held);
            }
        };
        let mut running = Box::pin(slots.run(fut));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert_eq!(Rc::strong_count(&held), 2);
        drop(running);
        assert_eq!(Rc::strong_count(&held), 1, "the future's state was dropped");
    }

    #[test]
    fn concurrent_runs_get_distinct_blocks_and_all_come_back() {
        let slots = Slots::default();
        block_on(async {
            let a = slots.run(request(1, [0; 512]));
            let b = slots.run(request(2, [0; 512]));
            assert_eq!(a.await + b.await, 1027);
            let before = thread_allocations();
            let a = slots.run(request(3, [0; 512]));
            let b = slots.run(request(4, [0; 512]));
            assert_eq!(a.await + b.await, 1031);
            assert_eq!(thread_allocations(), before, "both blocks were kept");
        });
    }
}
