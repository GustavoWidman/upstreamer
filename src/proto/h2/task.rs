//! A stream's work, polled in place in a heap block recycled per core.
//!
//! The work of a stream is a future of a few KiB that the connection task polls as soon as
//! the request arrives, and again whenever it was woken. It has to stay where it was first
//! polled, so it lives in a block of its own; the blocks come from a per-core free list, so
//! a stream allocates nothing once the core has served its busiest moment.

use std::alloc::{self, Layout};
use std::cell::{Cell, RefCell};
use std::future::Future;
use std::pin::Pin;
use std::ptr::NonNull;
use std::task::{Context, Poll};

/// Free blocks kept per core: every stream of a busy core's connections in flight at once.
const KEEP: usize = 1024;

/// Blocks of one layout: that of the first work run on the core. Work of another layout
/// gets a block of its own that is not kept.
struct Blocks {
    layout: Cell<Option<Layout>>,
    free: RefCell<Vec<NonNull<u8>>>,
}

thread_local! {
    static BLOCKS: Blocks = const {
        Blocks {
            layout: Cell::new(None),
            free: RefCell::new(Vec::new()),
        }
    };
}

impl Blocks {
    fn take(&self, layout: Layout) -> NonNull<u8> {
        let recycled = match self.layout.get() {
            Some(kept) if kept == layout => self.free.borrow_mut().pop(),
            Some(_) => None,
            None => {
                self.layout.set(Some(layout));
                None
            }
        };
        recycled.unwrap_or_else(|| {
            // SAFETY: `Task::new` asserts that the layout has a nonzero size.
            let ptr = unsafe { alloc::alloc(layout) };
            NonNull::new(ptr).unwrap_or_else(|| alloc::handle_alloc_error(layout))
        })
    }

    fn put(&self, block: NonNull<u8>, layout: Layout) {
        let mut free = self.free.borrow_mut();
        if self.layout.get() == Some(layout) && free.len() < KEEP {
            free.push(block);
        } else {
            // SAFETY: the block was allocated with `layout` by `take`.
            unsafe { alloc::dealloc(block.as_ptr(), layout) };
        }
    }
}

impl Drop for Blocks {
    fn drop(&mut self) {
        if let Some(layout) = self.layout.get() {
            for block in self.free.get_mut().drain(..) {
                // SAFETY: every kept block was allocated with the kept layout.
                unsafe { alloc::dealloc(block.as_ptr(), layout) };
            }
        }
    }
}

/// A future in a recycled block. Dropping it drops the future, finished or not.
pub(super) struct Task<'a> {
    work: NonNull<dyn Future<Output = ()> + 'a>,
    layout: Layout,
}

impl<'a> Task<'a> {
    #[inline(always)]
    pub fn new<F: Future<Output = ()> + 'a>(work: F) -> Task<'a> {
        const { assert!(size_of::<F>() > 0, "work with state") };
        let layout = Layout::new::<F>();
        let block = BLOCKS.with(|blocks| blocks.take(layout)).cast::<F>();
        // SAFETY: the block is valid for writes of `layout`, which is `F`'s.
        unsafe { block.as_ptr().write(work) };
        let work: *mut (dyn Future<Output = ()> + 'a) = block.as_ptr();
        Task {
            // SAFETY: `work` comes from a `NonNull`.
            work: unsafe { NonNull::new_unchecked(work) },
            layout,
        }
    }

    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the future stays in its block, unmoved, until `drop`, and `Task` is its
        // only owner.
        unsafe { Pin::new_unchecked(self.work.as_mut()) }.poll(cx)
    }
}

impl Drop for Task<'_> {
    fn drop(&mut self) {
        // SAFETY: `new` wrote the future and nothing else drops it.
        unsafe { self.work.as_ptr().drop_in_place() };
        let block = self.work.cast::<u8>();
        // A core thread that is exiting has already freed its list.
        if BLOCKS
            .try_with(|blocks| blocks.put(block, self.layout))
            .is_err()
        {
            // SAFETY: the block was allocated with `layout` by `Blocks::take`.
            unsafe { alloc::dealloc(block.as_ptr(), self.layout) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::testing::thread_allocations;
    use std::rc::Rc;
    use std::task::Waker;

    async fn work(done: &Cell<u32>, pad: [u8; 512], yields: u32) {
        for _ in 0..yields {
            let mut waited = false;
            std::future::poll_fn(|_| {
                if std::mem::replace(&mut waited, true) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        done.set(done.get() + u32::from(pad[0]) + 1);
    }

    #[test]
    fn work_runs_in_place_across_polls() {
        let done = Cell::new(0);
        let mut task = Task::new(work(&done, [1; 512], 2));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(task.poll(&mut cx).is_pending());
        assert!(task.poll(&mut cx).is_pending());
        assert!(task.poll(&mut cx).is_ready());
        assert_eq!(done.get(), 2);
    }

    #[test]
    fn blocks_are_recycled() {
        let done = Cell::new(0);
        let mut cx = Context::from_waker(Waker::noop());
        drop(Task::new(work(&done, [0; 512], 0)));
        let before = thread_allocations();
        for _ in 0..100 {
            let mut one = Task::new(work(&done, [0; 512], 0));
            assert!(one.poll(&mut cx).is_ready());
        }
        assert_eq!(
            thread_allocations(),
            before,
            "every task reuses the first block"
        );
        assert_eq!(done.get(), 100);
    }

    #[test]
    fn dropping_unfinished_work_releases_what_it_holds() {
        let held = Rc::new(());
        let mut task = Task::new({
            let held = held.clone();
            async move {
                std::future::pending::<()>().await;
                drop(held);
            }
        });
        assert!(
            task.poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(Rc::strong_count(&held), 2);
        drop(task);
        assert_eq!(Rc::strong_count(&held), 1);
    }

    #[test]
    fn work_of_another_size_gets_its_own_block() {
        let done = Cell::new(0);
        let mut cx = Context::from_waker(Waker::noop());
        let mut small = Task::new(work(&done, [0; 512], 0));
        let mut other = Task::new(async { done.set(done.get() + 10) });
        assert!(small.poll(&mut cx).is_ready());
        assert!(other.poll(&mut cx).is_ready());
        assert_eq!(done.get(), 11);
    }
}
