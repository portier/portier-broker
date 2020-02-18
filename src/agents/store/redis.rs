use crate::agents::*;
use crate::crypto::SigningAlgorithm;
use crate::utils::{agent::*, LimitConfig};
use ::redis::{
    aio::MultiplexedConnection as RedisConn, pipe, AsyncCommands, Client as RedisClient,
    RedisError, Script,
};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// TODO: Use pubsub to notify workers of changes to keys.

/// Store implementation using Redis.
pub struct RedisStore {
    /// The connection.
    client: RedisConn,
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
    ) -> Result<Self, RedisError> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let client = RedisClient::open(url.as_str())?
            .get_multiplexed_tokio_connection()
            .await?;

        log::warn!("Storing sessions in Redis at {}", url);
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
            client,
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

    async fn get_key_set(
        client: &mut RedisConn,
        signing_alg: SigningAlgorithm,
    ) -> Result<KeySet, RedisError> {
        let current_key = format!("keys:{}:current", signing_alg);
        let next_key = format!("keys:{}:next", signing_alg);
        let previous_key = format!("keys:{}:previous", signing_alg);
        let (current, current_ttl, next, next_ttl, previous): (
            Option<String>,
            i64,
            Option<String>,
            i64,
            Option<String>,
        ) = pipe()
            .atomic()
            .get(&current_key)
            .ttl(&current_key)
            .get(&next_key)
            .ttl(&next_key)
            .get(&previous_key)
            .query_async(client)
            .await?;
        let now = SystemTime::now();
        let parse_ttl = move |ttl: i64| -> SystemTime {
            if ttl <= 0 {
                now
            } else {
                now + Duration::from_secs(ttl as u64)
            }
        };
        Ok(KeySet {
            signing_alg,
            current: current.map(|value| Expiring {
                value,
                expires: parse_ttl(current_ttl),
            }),
            next: next.map(|value| Expiring {
                value,
                expires: parse_ttl(next_ttl),
            }),
            previous,
        })
    }

    async fn save_key_set(client: &mut RedisConn, key_set: &KeySet) -> Result<(), RedisError> {
        if let KeySet {
            current: Some(ref current),
            next: Some(ref next),
            ref previous,
            ..
        } = key_set
        {
            let current_key = format!("keys:{}:current", key_set.signing_alg);
            let next_key = format!("keys:{}:next", key_set.signing_alg);
            let previous_key = format!("keys:{}:previous", key_set.signing_alg);
            let mut pipe = pipe();
            fn to_unix(time: SystemTime) -> usize {
                time.duration_since(UNIX_EPOCH).unwrap().as_secs() as usize
            }
            pipe.atomic()
                .set(&current_key, &current.value)
                .expire_at(&current_key, to_unix(current.expires))
                .set(&next_key, &next.value)
                .expire_at(&next_key, to_unix(next.expires));
            if let Some(ref previous) = previous {
                pipe.set(&previous_key, previous);
            } else {
                pipe.del(&previous_key);
            }
            pipe.query_async(client).await
        } else {
            unreachable!();
        }
    }
}

impl Agent for RedisStore {}

impl Handler<SaveSession> for RedisStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        let mut client = self.client.clone();
        let ttl = self.expire_sessions;
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data = serde_json::to_string(&message.data)?;
            client.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        });
    }
}

impl Handler<GetSession> for RedisStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        let mut client = self.client.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            let data: String = client.get(&key).await?;
            let data = serde_json::from_str(&data)?;
            Ok(data)
        });
    }
}

impl Handler<DeleteSession> for RedisStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        let mut client = self.client.clone();
        cx.reply_later(async move {
            let key = Self::format_session_key(&message.session_id);
            client.del(&key).await?;
            Ok(())
        });
    }
}

impl Handler<FetchUrlCached> for RedisStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let mut client = self.client.clone();
        let fetcher = self.fetcher.clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            // TODO: Add locking to coordinate fetches across workers.
            let key = format!("cache:{}", message.url);
            if let Some(data) = client.get(key).await? {
                Ok(data)
            } else {
                let key = message.url.as_str().to_owned();
                let result = fetcher.send(FetchUrl { url: message.url }).await?;
                let ttl = std::cmp::max(expire_cache, result.max_age);
                client
                    .set_ex(key, result.data.clone(), ttl.as_secs() as usize)
                    .await?;
                Ok(result.data)
            }
        });
    }
}

impl Handler<IncrAndTestLimit> for RedisStore {
    fn handle(&mut self, message: IncrAndTestLimit, cx: Context<Self, IncrAndTestLimit>) {
        let mut client = self.client.clone();
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
            let count: usize = invocation.invoke_async(&mut client).await?;
            Ok(count <= config.max_count)
        });
    }
}

impl Handler<EnableRotatingKeys> for RedisStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        // TODO: Add locking to coordinate key generation across workers.
        let mut client = self.client.clone();
        self.key_manager = Some(message.key_manager.clone());
        cx.reply_later(async move {
            for signing_alg in &message.signing_algs {
                let key_set = Self::get_key_set(&mut client, *signing_alg)
                    .await
                    .expect("Failed to fetch keys from Redis");
                message.key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for RedisStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        // TODO: Add locking to coordinate key generation across workers.
        let mut client = self.client.clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let key_set = Self::get_key_set(&mut client, message.0)
                .await
                .expect("Failed to fetch keys from Redis");
            if let Some(key_set) = key_manager.send(RotateKeys(key_set)).await {
                Self::save_key_set(&mut client, &key_set)
                    .await
                    .expect("Failed to save keys to Redis");
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl StoreSender for Addr<RedisStore> {}
