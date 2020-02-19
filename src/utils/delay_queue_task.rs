use futures_util::future::poll_fn;
use std::collections::HashMap;
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::mpsc;
use tokio::time::{delay_until, Delay, Instant as TokioInstant};

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

enum Event<K> {
    Update((K, TokioInstant)),
    Timer,
    Cancelled,
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
            let mut items = HashMap::<K, TokioInstant>::new();
            let mut delay: Option<Delay> = None;
            loop {
                match poll_fn(|cx| match rx.poll_recv(cx) {
                    Poll::Ready(Some(update)) => Poll::Ready(Event::Update(update)),
                    Poll::Ready(None) => Poll::Ready(Event::Cancelled),
                    Poll::Pending => match delay
                        .as_mut()
                        .map(|delay| Delay::poll(Pin::new(delay), cx))
                        .unwrap_or(Poll::Pending)
                    {
                        Poll::Ready(_) => Poll::Ready(Event::Timer),
                        Poll::Pending => Poll::Pending,
                    },
                })
                .await
                {
                    Event::Update((key, deadline)) => {
                        items.insert(key, deadline);
                        delay = delay
                            .filter(|delay| delay.deadline() < deadline)
                            .or_else(|| Some(delay_until(deadline)));
                    }
                    Event::Timer => {
                        let now = TokioInstant::now();
                        let mut min_deadline: Option<TokioInstant> = None;
                        let mut expired_key = None;
                        for (key, deadline) in &items {
                            if expired_key.is_none() && *deadline <= now {
                                expired_key = Some(key.clone());
                            } else {
                                min_deadline = min_deadline
                                    .filter(|value| value < deadline)
                                    .or_else(|| Some(*deadline))
                            }
                        }
                        delay = min_deadline.map(delay_until);
                        if let Some(key) = expired_key {
                            items.remove(&key);
                            handler(key);
                        }
                    }
                    Event::Cancelled => break,
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
