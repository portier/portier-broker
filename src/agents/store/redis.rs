use crate::agents::*;
use crate::utils::{agent::*, LimitConfig};
use redis::{aio::MultiplexedConnection as RedisConn, AsyncCommands, RedisError, Script};
use std::sync::Arc;
use std::time::Duration;

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
        let client = redis::Client::open(url.as_str())?
            .get_multiplexed_tokio_connection()
            .await?;

        log::warn!("Storing sessions in: {}", url);
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
            limit_script,
            limit_per_email_config,
        })
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}

impl Agent for RedisStore {}

impl Handler<SaveSession> for RedisStore {
    fn handle(&mut self, message: SaveSession, reply: ReplySender<SaveSession>) {
        let mut client = self.client.clone();
        let ttl = self.expire_sessions;
        reply.later(move || async move {
            let key = Self::format_session_key(&message.session_id);
            let data = serde_json::to_string(&message.data)?;
            client.set_ex(&key, data, ttl.as_secs() as usize).await?;
            Ok(())
        });
    }
}

impl Handler<GetSession> for RedisStore {
    fn handle(&mut self, message: GetSession, reply: ReplySender<GetSession>) {
        let mut client = self.client.clone();
        reply.later(move || async move {
            let key = Self::format_session_key(&message.session_id);
            let data: String = client.get(&key).await?;
            let data = serde_json::from_str(&data)?;
            Ok(data)
        });
    }
}

impl Handler<DeleteSession> for RedisStore {
    fn handle(&mut self, message: DeleteSession, reply: ReplySender<DeleteSession>) {
        let mut client = self.client.clone();
        reply.later(move || async move {
            let key = Self::format_session_key(&message.session_id);
            client.del(&key).await?;
            Ok(())
        });
    }
}

impl Handler<CachedFetch> for RedisStore {
    fn handle(&mut self, message: CachedFetch, reply: ReplySender<CachedFetch>) {
        let mut client = self.client.clone();
        let fetcher = self.fetcher.clone();
        let expire_cache = self.expire_cache;
        reply.later(move || async move {
            // TODO: Locking
            let key = message.url.as_str().to_owned();
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
    fn handle(&mut self, message: IncrAndTestLimit, reply: ReplySender<IncrAndTestLimit>) {
        let mut client = self.client.clone();
        let script = self.limit_script.clone();
        let (key, config) = match message {
            IncrAndTestLimit::PerEmail { addr } => (
                format!("ratelimit::addr:{}", addr),
                self.limit_per_email_config,
            ),
        };
        reply.later(move || async move {
            let mut invocation = script.prepare_invoke();
            invocation.key(key).arg(config.duration.as_secs());
            let count: usize = invocation.invoke_async(&mut client).await?;
            Ok(count <= config.max_count)
        });
    }
}

impl StoreSender for Addr<RedisStore> {}
