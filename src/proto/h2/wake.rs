//! Which of a connection's streams have work to do.
//!
//! The connection task polls its streams' work itself, each with a waker that names the
//! stream's slot. An upstream socket or a timer waking a stream sets the slot's bit and wakes
//! the connection task, which then polls only the streams whose bits are set. Events the
//! connection sees itself (a DATA frame, a window update) set the bit directly.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};

pub(super) struct Ready {
    bits: Box<[AtomicU64]>,
    /// The connection task's waker.
    driver: Mutex<Option<Waker>>,
    /// Whether the connection task was woken since it last looked, so a burst of stream
    /// wake-ups wakes it once.
    notified: AtomicBool,
}

impl Ready {
    /// A set for slots below `slots`.
    pub fn new(slots: u32) -> Arc<Ready> {
        Arc::new(Ready {
            bits: (0..slots.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
            driver: Mutex::new(None),
            notified: AtomicBool::new(false),
        })
    }

    /// Marks a slot from inside the connection task's poll, which looks at the set again
    /// before it waits.
    pub fn mark(&self, slot: u32) {
        if let Some(word) = self.bits.get(slot as usize / 64) {
            word.fetch_or(1 << (slot % 64), Ordering::AcqRel);
        }
    }

    /// Called at the start of the connection task's poll: wake-ups from here on reach
    /// `waker`.
    pub fn listen(&self, waker: &Waker) {
        self.notified.store(false, Ordering::Release);
        let mut driver = self.driver.lock().unwrap_or_else(|e| e.into_inner());
        if !driver.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *driver = Some(waker.clone());
        }
    }

    /// Whether a slot is marked.
    pub fn any(&self) -> bool {
        self.bits
            .iter()
            .any(|word| word.load(Ordering::Acquire) != 0)
    }

    /// Clears the set, calling `each` with every slot that was marked. False when none was.
    pub fn take(&self, mut each: impl FnMut(u32)) -> bool {
        let mut any = false;
        for (index, word) in self.bits.iter().enumerate() {
            if word.load(Ordering::Acquire) == 0 {
                continue;
            }
            let mut bits = word.swap(0, Ordering::AcqRel);
            while bits != 0 {
                any = true;
                each(index as u32 * 64 + bits.trailing_zeros());
                bits &= bits - 1;
            }
        }
        any
    }

    /// The waker of a slot's work.
    pub fn waker(self: &Arc<Self>, slot: u32) -> Waker {
        Waker::from(Arc::new(SlotWaker {
            ready: self.clone(),
            slot,
        }))
    }
}

struct SlotWaker {
    ready: Arc<Ready>,
    slot: u32,
}

impl Wake for SlotWaker {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.ready.mark(self.slot);
        if !self.ready.notified.swap(true, Ordering::AcqRel) {
            let driver = self.ready.driver.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(waker) = driver.as_ref() {
                waker.wake_by_ref();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct Count(AtomicUsize);

    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn taken(ready: &Ready) -> Vec<u32> {
        let mut slots = Vec::new();
        ready.take(|slot| slots.push(slot));
        slots
    }

    #[test]
    fn marked_slots_are_taken_once_in_order() {
        let ready = Ready::new(130);
        for slot in [129, 0, 64, 63, 0] {
            ready.mark(slot);
        }
        assert_eq!(taken(&ready), [0, 63, 64, 129]);
        assert!(taken(&ready).is_empty());
        ready.mark(4096);
        assert!(
            taken(&ready).is_empty(),
            "a slot outside the set is ignored"
        );
    }

    #[test]
    fn a_burst_of_stream_wake_ups_wakes_the_connection_once() {
        let ready = Ready::new(8);
        let woken = Arc::new(Count(AtomicUsize::new(0)));
        ready.listen(&Waker::from(woken.clone()));
        let (three, five) = (ready.waker(3), ready.waker(5));
        three.wake_by_ref();
        five.wake_by_ref();
        three.wake_by_ref();
        assert_eq!(woken.0.load(Ordering::SeqCst), 1);
        assert_eq!(taken(&ready), [3, 5]);

        ready.listen(&Waker::from(woken.clone()));
        five.wake();
        assert_eq!(
            woken.0.load(Ordering::SeqCst),
            2,
            "woken again after listening"
        );
        assert_eq!(taken(&ready), [5]);
    }
}
