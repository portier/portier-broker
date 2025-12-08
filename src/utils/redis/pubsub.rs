use std::{
    collections::{hash_map::Entry, HashMap},
    sync::Arc,
    task::Poll,
};

use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use redis::aio::AsyncPushSender;
use tokio::sync::{broadcast::Sender, Mutex};
use tokio_stream::wrappers::{errors::BroadcastStreamRecvError, BroadcastStream};

/// An `AsyncPushSender` that wraps a broadcast channel.
///
/// Filters only for regular messages, and converts to Bytes first.
pub struct FilteredBroadcast {
    sender: Sender<(Bytes, Bytes)>,
}

impl FilteredBroadcast {
    pub fn new(sender: Sender<(Bytes, Bytes)>) -> Self {
        Self { sender }
    }
}

impl AsyncPushSender for FilteredBroadcast {
    fn send(&self, info: redis::PushInfo) -> Result<(), redis::aio::SendError> {
        if info.kind != redis::PushKind::Message {
            return Ok(());
        }

        let mut it = info.data.into_iter();
        let (Some(chan), Some(message), None) = (it.next(), it.next(), it.next()) else {
            return Ok(());
        };

        let (Ok(chan), Ok(message)) = (
            redis::from_redis_value::<Vec<u8>>(chan),
            redis::from_redis_value::<Vec<u8>>(message),
        ) else {
            return Ok(());
        };

        let _ = self.sender.send((chan.into(), message.into()));
        Ok(())
    }
}

/// Map holding subscription counts.
type Subscriptions = Arc<Mutex<HashMap<Bytes, u16>>>;

/// Manages Redis pubsub subscriptions.
#[derive(Clone)]
pub struct Pubsub {
    conn: redis::aio::MultiplexedConnection,
    push_tx: Sender<(Bytes, Bytes)>,
    subscriptions: Subscriptions,
}

impl Pubsub {
    pub fn new(conn: redis::aio::MultiplexedConnection, push_tx: Sender<(Bytes, Bytes)>) -> Self {
        Self {
            conn,
            push_tx,
            subscriptions: Subscriptions::default(),
        }
    }

    pub fn subscribe(&self, chan: impl Into<Bytes>) -> Subscriber {
        Subscriber::new(self, chan.into())
    }
}

/// Represents a single subscription to a Redis channel.
pub struct Subscriber {
    conn: redis::aio::MultiplexedConnection,
    push_rx: BroadcastStream<(Bytes, Bytes)>,
    subscriptions: Subscriptions,
    chan: Bytes,
}

impl Subscriber {
    fn new(pubsub: &Pubsub, chan: Bytes) -> Self {
        let sub = {
            let conn = pubsub.conn.clone();
            let push_rx = BroadcastStream::new(pubsub.push_tx.subscribe());
            let subscriptions = pubsub.subscriptions.clone();
            let chan = chan.clone();
            Subscriber {
                conn,
                push_rx,
                subscriptions,
                chan,
            }
        };

        let mut conn = pubsub.conn.clone();
        let subscriptions = pubsub.subscriptions.clone();
        tokio::spawn(async move {
            let mut subscriptions = subscriptions.lock().await;
            let num = subscriptions.entry(chan.clone()).or_default();
            *num += 1;
            if *num == 1 {
                drop(subscriptions);
                if let Err(err) = conn.subscribe(chan.as_ref()).await {
                    log::error!("Redis subscribe failed: {err}");
                }
            }
        });

        sub
    }
}

impl Drop for Subscriber {
    fn drop(&mut self) {
        let mut conn = self.conn.clone();
        let subscriptions = self.subscriptions.clone();
        let chan = self.chan.clone();
        tokio::spawn(async move {
            let mut subscriptions = subscriptions.lock().await;
            match subscriptions.entry(chan.clone()) {
                Entry::Occupied(entry) if *entry.get() == 1 => {
                    entry.remove();
                    drop(subscriptions);
                    if let Err(err) = conn.unsubscribe(chan.as_ref()).await {
                        log::error!("Redis unsubscribe failed: {err}");
                    }
                }
                Entry::Occupied(mut entry) => {
                    let entry = entry.get_mut();
                    // Safety: entries are deleted before they reach zero.
                    assert!(*entry > 1);
                    *entry -= 1;
                }
                Entry::Vacant(_) => {
                    // Safety: subscriber shouldn't exist without an entry.
                    unreachable!()
                }
            };
        });
    }
}

impl Stream for Subscriber {
    type Item = Bytes;
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        loop {
            match self.push_rx.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok((chan, message)))) if chan == self.chan => {
                    return Poll::Ready(Some(message));
                }
                Poll::Ready(Some(
                    Ok(_) // Filter out other channels.
                    | Err(BroadcastStreamRecvError::Lagged(_)) // Ignore lag.
                )) => {}
                // Bubble EOS or pending.
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}
