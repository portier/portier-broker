use futures_util::future::{self, Either, FutureExt};
use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Duration as TokioDuration, Instant as TokioInstant};

/// Trait for converting various types to a timer deadline.
pub trait IntoDeadline {
    fn into_deadline(self) -> TokioInstant;
}

impl IntoDeadline for TokioInstant {
    fn into_deadline(self) -> TokioInstant {
        self
    }
}

impl IntoDeadline for Instant {
    fn into_deadline(self) -> TokioInstant {
        TokioInstant::from_std(self)
    }
}

impl IntoDeadline for Duration {
    fn into_deadline(self) -> TokioInstant {
        TokioInstant::now() + self
    }
}

impl IntoDeadline for SystemTime {
    fn into_deadline(self) -> TokioInstant {
        self.duration_since(SystemTime::now())
            .unwrap_or_default()
            .into_deadline()
    }
}

/// Task that runs a set of timers.
#[derive(Clone)]
pub struct DelayQueueTask<K: Clone + Eq + Hash + Send + 'static> {
    tx: mpsc::Sender<(K, TokioInstant)>,
}

impl<K: Clone + Eq + Hash + Send + 'static> DelayQueueTask<K> {
    /// Spawn a new task running a timer loop.
    ///
    /// The handler function is called when a timer expires with the timer key. Note that this
    /// function is called inside the Tokio run-time, and may not block.
    pub fn spawn<H>(mut handler: H) -> Self
    where
        H: (FnMut(K)) + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel(8);
        tokio::spawn(async move {
            // Arbitrary sleep duration to use while idle.
            let idle_wait = TokioDuration::new(86400 * 365, 0);
            let mut deadline = TokioInstant::now() + idle_wait;
            let mut items = HashMap::<K, TokioInstant>::new();
            loop {
                let recv = rx.recv().fuse();
                let sleep = sleep_until(deadline).fuse();
                tokio::pin!(recv, sleep);
                match future::select(recv, sleep).await {
                    Either::Left((Some((key, item_deadline)), _)) => {
                        items.insert(key, deadline);
                        if item_deadline < deadline {
                            deadline = item_deadline
                        }
                    }
                    Either::Left((None, _)) => break,
                    Either::Right(_) => {
                        let now = TokioInstant::now();
                        let mut expired_key = None;
                        deadline = now + idle_wait;
                        for (key, item_deadline) in &items {
                            if expired_key.is_none() && *item_deadline <= now {
                                expired_key = Some(key.clone());
                            } else if *item_deadline < deadline {
                                deadline = *item_deadline;
                            }
                        }
                        if let Some(key) = expired_key {
                            items.remove(&key);
                            handler(key);
                        }
                    }
                }
            }
        });
        DelayQueueTask { tx }
    }

    /// Insert or replace a timer.
    pub async fn insert(&mut self, key: K, deadline: impl IntoDeadline) {
        let deadline = deadline.into_deadline();
        if self.tx.send((key, deadline)).await.is_err() {
            panic!("Tried to send to DelayQueueTask that has panicked");
        }
    }
}
