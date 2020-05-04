use crate::agents::*;
use crate::config::LimitConfig;
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::*,
    redis::{locking, pubsub},
    SecureRandom,
};
use ::redis::{
    aio::MultiplexedConnection as RedisConn, pipe, AsyncCommands, Client as RedisClient,
    IntoConnectionInfo, RedisResult, Script,
};
use std::sync::Arc;
use std::time::Duration;

/// Internal message used to lock a key set.
struct LockKeys(SigningAlgorithm);
impl Message for LockKeys {
    type Reply = locking::LockGuard;
}

/// Internal message used to fetch a key set.
struct FetchKeys(SigningAlgorithm);
impl Message for FetchKeys {
    type Reply = RedisResult<KeySet>;
}

/// Internal message used to save a key set.
struct SaveKeys(KeySet);
impl Message for SaveKeys {
    type Reply = RedisResult<()>;
}

/// Internal message used to fetch keys and send an update to the key manager.
struct UpdateKeysLocked(SigningAlgorithm);
impl Message for UpdateKeysLocked {
    type Reply = ();
}

/// Store implementation using Redis.
pub struct RedisStore {
    /// A random unique ID for ourselves.
    id: Arc<Vec<u8>>,
    /// The connection.
    conn: RedisConn,
    /// Pubsub client.
    pubsub: pubsub::Subscriber,
    /// Locking client.
    locking: locking::LockClient,
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// The agent used for fetching on cache miss.
    fetcher: Addr<FetchAgent>,
    /// Key manager if rotating keys are enabled.
    key_manager: Option<Addr<RotatingKeys>>,
    /// Script used to check a limit.
    limit_script: Arc<Script>,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
}

impl RedisStore {
    pub async fn new(
        mut url: String,
        expire_sessions: Duration,
        expire_cache: Duration,
        limit_per_email_config: LimitConfig,
        fetcher: Addr<FetchAgent>,
        rng: SecureRandom,
    ) -> RedisResult<Self> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let id = Arc::new(rng.generate_async(16).await);
        let info = url.as_str().into_connection_info()?;
        let pubsub = pubsub::connect(&info).await?;
        let conn = RedisClient::open(info)?
            .get_multiplexed_tokio_connection()
            .await?;
        let locking = locking::LockClient::new(conn.clone(), pubsub.clone(), rng);

        log::warn!("Storing sessions and keys in Redis at {}", url);
        log::warn!("Please always double check this Redis and the connection to it are secure!");
        log::warn!("(This warning can't be fixed; it's a friendly reminder.)");

        let limit_script = Arc::new(Script::new(
            r"
            local count = redis.call('incr', KEYS[1])
            if count == 1 then
                redis.call('expire', KEYS[1], ARGV[1])
            end
            return count
            ",
        ));

        Ok(RedisStore {
            id,
            conn,
            pubsub,
            locking,
            expire_sessions,
            expire_cache,
            fetcher,
            key_manager: None,
            limit_script,
            limit_per_email_config,
        })
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}

impl Agent for RedisStore {
    fn started(&mut self, cx: Context<Self, AgentStarted>) {
        // Ping Redis at an interval.
        let mut conn = self.conn.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(20));
            // Ignore the first (immediate) tick.
            interval.tick().await;
            loop {
                interval.tick().await;
                let _: String = ::redis::cmd("PING")
                    .query_async(&mut conn)
                    .await
                    .expect("Redis ping failed");
            }
        });
        cx.reply(());
    }
}

impl Handler<SaveSession> for RedisStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        let mut conn = self.conn.clone();
        let ttl = self.expire_sessions;
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data = serde_json::to_string(&message.data)?;
            conn.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        });
    }
}

impl Handler<GetSession> for RedisStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        let mut conn = self.conn.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data: Option<String> = conn.get(&key).await?;
            if let Some(data) = data {
                Ok(Some(serde_json::from_str(&data)?))
            } else {
                Ok(None)
            }
        });
    }
}

impl Handler<DeleteSession> for RedisStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        let mut conn = self.conn.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            conn.del(&key).await?;
            Ok(())
        });
    }
}

impl Handler<FetchUrlCached> for RedisStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let mut conn = self.conn.clone();
        let mut locking = self.locking.clone();
        let fetcher = self.fetcher.clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            let key = format!("cache:{}", message.url);
            let _lock = locking.lock(format!("lock:{}", key).as_bytes()).await;
            if let Some(data) = conn.get(key).await? {
                Ok(data)
            } else {
                let key = message.url.as_str().to_owned();
                let result = fetcher.send(FetchUrl::get(&message.url)).await?;
                let ttl = std::cmp::max(expire_cache, result.max_age);
                conn.set_ex(key, result.data.clone(), ttl.as_secs() as usize)
                    .await?;
                Ok(result.data)
            }
        });
    }
}

impl Handler<IncrAndTestLimit> for RedisStore {
    fn handle(&mut self, message: IncrAndTestLimit, cx: Context<Self, IncrAndTestLimit>) {
        let mut conn = self.conn.clone();
        let script = self.limit_script.clone();
        let (key, config) = match message {
            IncrAndTestLimit::PerEmail { addr } => (
                format!("ratelimit:per-email:{}", addr),
                self.limit_per_email_config,
            ),
        };
        cx.reply_later(async move {
            let mut invocation = script.prepare_invoke();
            invocation.key(key).arg(config.duration.as_secs());
            let count: usize = invocation.invoke_async(&mut conn).await?;
            Ok(count <= config.max_count)
        });
    }
}

impl Handler<EnableRotatingKeys> for RedisStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        let me = cx.addr().clone();
        let my_id = self.id.clone();
        let mut pubsub = self.pubsub.clone();
        self.key_manager = Some(message.key_manager.clone());
        cx.reply_later(async move {
            for signing_alg in &message.signing_algs {
                let signing_alg = *signing_alg;
                // Listen for key changes by other workers.
                let chan = format!("keys-updated:{}", signing_alg).into_bytes();
                let mut sub = pubsub.subscribe(chan).await;
                let me2 = me.clone();
                let my_id2 = my_id.clone();
                tokio::spawn(async move {
                    loop {
                        let from_id = sub.recv().await.expect("Redis keys subscription failed");
                        if from_id != *my_id2 {
                            me2.send(UpdateKeysLocked(signing_alg));
                        }
                    }
                });
                // Fetch current keys.
                me.send(UpdateKeysLocked(signing_alg)).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for RedisStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        let me = cx.addr().clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let lock = me.send(LockKeys(message.0)).await;
            let key_set = me
                .send(FetchKeys(message.0))
                .await
                .expect("Failed to fetch keys from Redis");
            if let Some(key_set) = key_manager.send(RotateKeys(key_set)).await {
                me.send(SaveKeys(key_set.clone()))
                    .await
                    .expect("Failed to save keys to Redis");
                drop(lock);
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl Handler<ImportKeySet> for RedisStore {
    fn handle(&mut self, message: ImportKeySet, cx: Context<Self, ImportKeySet>) {
        let me = cx.addr().clone();
        cx.reply_later(async move {
            me.send(SaveKeys(message.0))
                .await
                .expect("Failed to save keys to Redis");
        });
    }
}

impl Handler<LockKeys> for RedisStore {
    fn handle(&mut self, message: LockKeys, cx: Context<Self, LockKeys>) {
        let mut locking = self.locking.clone();
        let lock_key = format!("lock:keys:{}", message.0);
        cx.reply_later(async move { locking.lock(lock_key.as_bytes()).await });
    }
}

impl Handler<FetchKeys> for RedisStore {
    fn handle(&mut self, message: FetchKeys, cx: Context<Self, FetchKeys>) {
        let mut conn = self.conn.clone();
        let signing_alg = message.0;
        let db_key = format!("keys:{}", signing_alg);
        cx.reply_later(async move {
            let key_set: Option<String> = conn.get(db_key).await?;
            let key_set = key_set.map_or_else(
                || KeySet::empty(signing_alg),
                |data| serde_json::from_str(&data).expect("Invalid key set JSON in Redis"),
            );
            Ok(key_set)
        })
    }
}

impl Handler<SaveKeys> for RedisStore {
    fn handle(&mut self, message: SaveKeys, cx: Context<Self, SaveKeys>) {
        let mut conn = self.conn.clone();
        let signing_alg = message.0.signing_alg;
        let db_key = format!("keys:{}", signing_alg);
        let data = serde_json::to_string(&message.0).expect("Could not encode key set as JSON");
        let mut pipe = pipe();
        pipe.atomic()
            .set(db_key, data)
            .publish(format!("keys-updated:{}", signing_alg), &self.id[..]);
        cx.reply_later(async move { pipe.query_async(&mut conn).await });
    }
}

impl Handler<UpdateKeysLocked> for RedisStore {
    fn handle(&mut self, message: UpdateKeysLocked, cx: Context<Self, UpdateKeysLocked>) {
        let me = cx.addr().clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let key_set = {
                let _lock = me.send(LockKeys(message.0)).await;
                me.send(FetchKeys(message.0))
                    .await
                    .expect("Failed to fetch keys from Redis")
            };
            key_manager.send(UpdateKeys(key_set)).await;
        });
    }
}

impl StoreSender for Addr<RedisStore> {}
