use crate::store::{CacheItem, CacheStore, LimitKey, LimitStore, SessionStore, Store};
use crate::utils::{BoxError, BoxFuture, LimitConfig};
use crate::web::Session;
use std::collections::hash_map::{Entry, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use url::Url;

struct Expiring<T> {
    inner: T,
    expires: Instant,
}

impl<T> Expiring<T> {
    fn from_duration(inner: T, duration: Duration) -> Self {
        let expires = Instant::now() + duration;
        Expiring { inner, expires }
    }
}

#[derive(Default)]
struct Storage {
    sessions: HashMap<String, Expiring<Session>>,
    cache: HashMap<Url, Expiring<String>>,
    limit_counters: HashMap<String, Expiring<usize>>,
}

type StorageRc = Arc<RwLock<Storage>>;

/// Store implementation using memory.
pub struct MemoryStore {
    /// Structure containing all storage.
    storage: StorageRc,
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
}

impl MemoryStore {
    pub fn new(
        expire_sessions: Duration,
        expire_cache: Duration,
        limit_per_email_config: LimitConfig,
    ) -> Self {
        log::warn!("Storing sessions in memory.");
        log::warn!("Note that sessions will be lost on restart!");

        MemoryStore {
            storage: Arc::new(RwLock::new(Storage::default())),
            expire_sessions,
            expire_cache,
            limit_per_email_config,
        }
    }
}

impl SessionStore for MemoryStore {
    fn store_session(&self, session_id: &str, data: Session) -> BoxFuture<Result<(), BoxError>> {
        let storage = self.storage.clone();
        let ttl = self.expire_sessions;
        let key = session_id.to_owned();
        Box::pin(async move {
            let mut storage = storage.write().await;
            storage
                .sessions
                .insert(key, Expiring::from_duration(data, ttl));
            Ok(())
        })
    }

    fn get_session(&self, session_id: &str) -> BoxFuture<Result<Option<Session>, BoxError>> {
        let storage = self.storage.clone();
        let key = session_id.to_owned();
        Box::pin(async move {
            let storage = storage.read().await;
            let data = storage
                .sessions
                .get(&key)
                .filter(|entry| entry.expires > Instant::now())
                .map(|entry| entry.inner.clone());
            Ok(data)
        })
    }

    fn remove_session(&self, session_id: &str) -> BoxFuture<Result<(), BoxError>> {
        let storage = self.storage.clone();
        let key = session_id.to_owned();
        Box::pin(async move {
            let mut storage = storage.write().await;
            storage.sessions.remove(&key);
            Ok(())
        })
    }
}

impl CacheStore for MemoryStore {
    fn get_cache_item(
        &self,
        url: &Url,
    ) -> BoxFuture<Result<Box<dyn CacheItem + Send + Sync>, BoxError>> {
        let url = url.clone();
        let storage = self.storage.clone();
        let expire_cache = self.expire_cache;
        Box::pin(async move {
            let item: Box<dyn CacheItem + Send + Sync> =
                Box::new(MemoryCacheItem::new(url, storage, expire_cache));
            Ok(item)
        })
    }
}

impl LimitStore for MemoryStore {
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
        let storage = self.storage.clone();
        Box::pin(async move {
            let mut storage = storage.write().await;
            let count: usize = match storage.limit_counters.entry(key) {
                Entry::Occupied(mut entry) => {
                    let mut expiring = entry.get_mut();
                    if expiring.expires <= Instant::now() {
                        *expiring = Expiring::from_duration(1, duration);
                        1
                    } else {
                        expiring.inner += 1;
                        expiring.inner
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(Expiring::from_duration(1, duration));
                    1
                }
            };
            Ok(count <= max_count)
        })
    }
}

impl Store for MemoryStore {}

struct MemoryCacheItem {
    url: Url,
    storage: StorageRc,
    expire_cache: Duration,
}

impl MemoryCacheItem {
    fn new(url: Url, storage: StorageRc, expire_cache: Duration) -> Self {
        // TODO: Lock
        MemoryCacheItem {
            url,
            storage,
            expire_cache,
        }
    }
}

impl Drop for MemoryCacheItem {
    fn drop(&mut self) {
        // TODO: Unlock
    }
}

impl CacheItem for MemoryCacheItem {
    fn read(&self) -> BoxFuture<Result<Option<String>, BoxError>> {
        let storage = self.storage.clone();
        let url = self.url.clone();
        Box::pin(async move {
            let storage = storage.read().await;
            let data = storage
                .cache
                .get(&url)
                .filter(|entry| entry.expires > Instant::now())
                .map(|entry| entry.inner.clone());
            Ok(data)
        })
    }

    fn write(&mut self, value: String, max_age: Duration) -> BoxFuture<Result<(), BoxError>> {
        let storage = self.storage.clone();
        let url = self.url.clone();
        let ttl = std::cmp::max(self.expire_cache, max_age);
        Box::pin(async move {
            let mut storage = storage.write().await;
            storage
                .cache
                .insert(url, Expiring::from_duration(value, ttl));
            Ok(())
        })
    }
}
