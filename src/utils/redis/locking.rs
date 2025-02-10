use crate::utils::SecureRandom;
use bytes::Bytes;
use futures_util::StreamExt;
use redis::{aio::MultiplexedConnection, RedisResult, Script, Value};
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tokio_stream::wrappers::IntervalStream;

use super::pubsub::{self, Pubsub};

// TODO: Lock locally first, so multiple locks from the same machine are more efficient.

/// An active lock in Redis.
///
/// This will try to send a
pub struct LockGuard {
    key: Bytes,
    request: Vec<u8>,
    conn: MultiplexedConnection,
    unlock_script: Arc<Script>,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let key = self.key.clone();
        let request = self.request.clone();
        let mut conn = self.conn.clone();
        let unlock_script = self.unlock_script.clone();
        tokio::spawn(async move {
            let mut invocation = unlock_script.prepare_invoke();
            invocation.key(key.as_ref()).arg(&request[..]);
            let res: RedisResult<Value> = invocation.invoke_async(&mut conn).await;
            if let Err(err) = res {
                log::error!("Failed to release Redis lock: {:?}", err);
            }
        });
    }
}

/// A client used for locking in Redis.
///
/// This struct can be cheaply cloned.
#[derive(Clone)]
pub struct LockClient {
    conn: MultiplexedConnection,
    pubsub: Pubsub,
    rng: SecureRandom,
    unlock_script: Arc<Script>,
}

impl LockClient {
    /// Create a new instance.
    ///
    /// This takes a Redis connection and a Redis pubsub connection, which must both be connected
    /// to the same server.
    pub fn new(conn: MultiplexedConnection, pubsub: pubsub::Pubsub, rng: SecureRandom) -> Self {
        let unlock_script = Arc::new(Script::new(
            r"
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                redis.call('DEL', KEYS[1])
                redis.call('PUBLISH', KEYS[1], 'UNLOCK')
                return 1
            else
                return 0
            end
            ",
        ));
        Self {
            conn,
            pubsub,
            rng,
            unlock_script,
        }
    }

    /// Acquire a lock.
    ///
    /// Takes a lock key name, and a unique request ID.
    ///
    /// Note that the given key *is* the lock, and the key may not otherwise be written to.
    /// (Unlike, say, file locking, where the lock is conceptually metadata on the file.)
    pub async fn lock(&mut self, key: impl Into<Bytes>) -> LockGuard {
        let key = key.into();
        let request = self.rng.generate_async(16).await;
        // Try at an interval, as well as listening for unlock events.
        let mut stream = futures_util::stream::select(
            IntervalStream::new(interval(Duration::from_secs(2))).map(|_| ()),
            self.pubsub.subscribe(key.clone()).map(|_| ()),
        );
        loop {
            stream.next().await;
            if self.try_lock(key.as_ref(), &request).await {
                return self.make_guard(key, request);
            }
        }
    }

    /// Try to acquire a lock without waiting.
    async fn try_lock(&mut self, key: &[u8], request: &[u8]) -> bool {
        let value = redis::cmd("SET")
            .arg(key)
            .arg(request)
            .arg("nx")
            .arg("px")
            .arg("30000")
            .query_async(&mut self.conn)
            .await
            .expect("Could not make Redis lock request");
        match value {
            Value::Nil => false,
            Value::Okay => true,
            value => panic!("Unexpected lock result from Redis: {value:?}"),
        }
    }

    /// Create a lock guard, once we've acquired the lock.
    fn make_guard(&self, key: Bytes, request: Vec<u8>) -> LockGuard {
        LockGuard {
            key,
            request,
            conn: self.conn.clone(),
            unlock_script: self.unlock_script.clone(),
        }
    }
}
