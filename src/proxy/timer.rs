//! A timeout for waits that almost always end before it does. A connection moves its deadline
//! on every request (keep-alive, response header, tunnel idle), and the deadline almost never
//! passes. Creating a timer per wait would enter and leave the runtime's timer wheel each
//! time; here the wheel is touched only when the timer fires or the deadline moves earlier
//! than the registered wake-up. Moving the deadline later is a field write.

use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

#[derive(Default)]
pub(crate) struct Deadline {
    at: Option<Instant>,
    /// Registered for a moment at or before `at`; created by the first wait that blocks.
    sleep: Option<Pin<Box<Sleep>>>,
}

impl Deadline {
    /// Arms the deadline `after` from now, or disarms it.
    pub fn set(&mut self, after: Option<Duration>) {
        self.at = after.map(|d| Instant::now() + d);
    }

    /// Arms the deadline at `at`, or disarms it.
    pub fn set_at(&mut self, at: Option<Instant>) {
        self.at = at;
    }

    /// Ready once the deadline has passed; pending while disarmed. The caller polls it from
    /// the same task that polls the guarded IO, after that IO returned pending.
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(at) = self.at else {
            return Poll::Pending;
        };
        let sleep = self
            .sleep
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
        loop {
            if sleep.deadline() > at {
                sleep.as_mut().reset(at);
            }
            ready!(sleep.as_mut().poll(cx));
            if Instant::now() >= at {
                return Poll::Ready(());
            }
            sleep.as_mut().reset(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    const TICK: Duration = Duration::from_millis(40);

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    async fn expired(deadline: &mut Deadline) {
        poll_fn(|cx| deadline.poll_expired(cx)).await
    }

    /// Whether the deadline expires within `within`.
    async fn expires(deadline: &mut Deadline, within: Duration) -> bool {
        tokio::time::timeout(within, expired(deadline))
            .await
            .is_ok()
    }

    #[test]
    fn fires_at_the_deadline_not_before() {
        runtime().block_on(async {
            let mut deadline = Deadline::default();
            let start = Instant::now();
            deadline.set(Some(5 * TICK));
            expired(&mut deadline).await;
            assert!(start.elapsed() >= 5 * TICK, "{:?}", start.elapsed());
        });
    }

    #[test]
    fn a_deadline_moved_later_fires_at_the_later_time() {
        runtime().block_on(async {
            let mut deadline = Deadline::default();
            let start = Instant::now();
            deadline.set(Some(5 * TICK));
            assert!(!expires(&mut deadline, 3 * TICK).await);
            deadline.set(Some(5 * TICK));
            expired(&mut deadline).await;
            assert!(start.elapsed() >= 8 * TICK, "{:?}", start.elapsed());
        });
    }

    #[test]
    fn a_deadline_moved_earlier_fires_at_the_earlier_time() {
        runtime().block_on(async {
            let mut deadline = Deadline::default();
            deadline.set(Some(Duration::from_secs(3600)));
            assert!(!expires(&mut deadline, TICK).await);
            deadline.set(Some(2 * TICK));
            assert!(expires(&mut deadline, 50 * TICK).await);
        });
    }

    #[test]
    fn disarmed_never_fires_and_can_be_armed_again() {
        runtime().block_on(async {
            let mut deadline = Deadline::default();
            deadline.set(Some(TICK));
            expired(&mut deadline).await;
            deadline.set(None);
            assert!(!expires(&mut deadline, 3 * TICK).await);
            let start = Instant::now();
            deadline.set(Some(3 * TICK));
            expired(&mut deadline).await;
            assert!(start.elapsed() >= 3 * TICK, "{:?}", start.elapsed());
        });
    }
}
