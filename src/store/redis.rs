use crate::store::{CacheItem, CacheKey, CacheStore, LimitKey, LimitStore, SessionStore, Store};
use crate::utils::{BoxError, BoxFuture, LimitConfig};
use redis::{aio::MultiplexedConnection as RedisConn, AsyncCommands, RedisError, Script};
use std::sync::Arc;

/// Store implementation using Redis.
pub struct RedisStore {
    /// The connection.
    client: RedisConn,
    /// TTL of session keys, in seconds
    expire_sessions: usize,
    /// TTL of cache keys, in seconds
    expire_cache: usize,
    /// Script used to check a limit.
    limit_script: Arc<Script>,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
}

impl RedisStore {
    pub async fn new(
        mut url: String,
        expire_sessions: usize,
        expire_cache: usize,
        limit_per_email_config: LimitConfig,
    ) -> Result<Self, RedisError> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let client = redis::Client::open(url.as_str())?
            .get_multiplexed_tokio_connection()
            .await?;

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
            limit_script,
            limit_per_email_config,
        })
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }

    fn format_cache_key(key: CacheKey) -> String {
        match key {
            CacheKey::Discovery { acct } => format!("cache:discovery:{}", acct),
            CacheKey::OidcConfig { origin } => format!("cache:configuration:{}", origin),
            CacheKey::OidcKeySet { origin } => format!("cache:key-set:{}", origin),
        }
    }
}

impl SessionStore for RedisStore {
    fn store_session(&self, session_id: &str, data: String) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let key = Self::format_session_key(session_id);
        let ttl = self.expire_sessions;
        Box::pin(async move {
            client.set_ex(&key, data, ttl).await?;
            Ok(())
        })
    }

    fn get_session(&self, session_id: &str) -> BoxFuture<Result<Option<String>, BoxError>> {
        let mut client = self.client.clone();
        let key = Self::format_session_key(session_id);
        Box::pin(async move {
            let data = client.get(&key).await?;
            Ok(data)
        })
    }

    fn remove_session(&self, session_id: &str) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let key = Self::format_session_key(session_id);
        Box::pin(async move {
            client.del(&key).await?;
            Ok(())
        })
    }
}

impl CacheStore for RedisStore {
    fn get_cache_item(
        &self,
        key: CacheKey,
    ) -> BoxFuture<Result<Box<dyn CacheItem + Send + Sync>, BoxError>> {
        let key = RedisStore::format_cache_key(key);
        let client = self.client.clone();
        let expire_cache = self.expire_cache;
        Box::pin(async move {
            let item: Box<dyn CacheItem + Send + Sync> =
                Box::new(RedisCacheItem::new(key, client, expire_cache).await?);
            Ok(item)
        })
    }
}

impl LimitStore for RedisStore {
    fn incr_and_test_limit(&self, key: LimitKey<'_>) -> BoxFuture<Result<bool, BoxError>> {
        let (key, config) = match key {
            LimitKey::PerEmail { addr } => (
                format!("ratelimit::addr:{}", addr),
                &self.limit_per_email_config,
            ),
        };
        let LimitConfig {
            max_count,
            duration,
        } = *config;
        let mut client = self.client.clone();
        let script = self.limit_script.clone();
        Box::pin(async move {
            let mut invocation = script.prepare_invoke();
            invocation.key(key).arg(duration);
            let count: usize = invocation.invoke_async(&mut client).await?;
            Ok(count <= max_count)
        })
    }
}

impl Store for RedisStore {}

struct RedisCacheItem {
    key: String,
    client: RedisConn,
    expire_cache: usize,
}

impl RedisCacheItem {
    async fn new(key: String, client: RedisConn, expire_cache: usize) -> Result<Self, RedisError> {
        // TODO: Lock
        Ok(RedisCacheItem {
            client,
            key,
            expire_cache,
        })
    }
}

impl Drop for RedisCacheItem {
    fn drop(&mut self) {
        // TODO: Unlock
    }
}

impl CacheItem for RedisCacheItem {
    fn read(&self) -> BoxFuture<Result<Option<String>, BoxError>> {
        let mut client = self.client.clone();
        let key = self.key.clone();
        Box::pin(async move {
            let data = client.get(key).await?;
            Ok(data)
        })
    }

    fn write(&mut self, value: String, max_age: usize) -> BoxFuture<Result<(), BoxError>> {
        let mut client = self.client.clone();
        let key = self.key.clone();
        let seconds = std::cmp::max(self.expire_cache, max_age);
        Box::pin(async move {
            client.set_ex::<_, _, ()>(key, value, seconds).await?;
            Ok(())
        })
    }
}
