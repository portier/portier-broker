use crate::agents::*;
use crate::utils::{agent::*, LimitConfig};
use crate::web::Session;
use std::collections::hash_map::{Entry, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
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

    fn is_alive(&self) -> bool {
        self.expires > Instant::now()
    }
}

/// Message sent at an interval to collect garbage.
struct Gc;
impl Message for Gc {
    type Reply = ();
}

/// A cache slot in the cache `HashMap`.
///
/// We want to lock these individually while a fetch is in progress, so multiple requests for the
/// same URL result in only one fetch. Therefore, we use an `Arc<Mutex<_>>` to carry slots around,
/// and within an `Option` which indicates whether cache is actually present (despite the hash map
/// entry existing or not, which does not indicate anything).
type CacheSlot = Arc<Mutex<Option<Expiring<String>>>>;

/// Store implementation using memory.
pub struct MemoryStore {
    /// TTL of session keys
    expire_sessions: Duration,
    /// TTL of cache keys
    expire_cache: Duration,
    /// Configuration for per-email rate limiting.
    limit_per_email_config: LimitConfig,
    /// The agent used for fetching on cache miss.
    fetcher: Addr<FetchAgent>,
    /// Session storage.
    sessions: HashMap<String, Expiring<Session>>,
    /// Cache storage.
    cache: HashMap<Url, CacheSlot>,
    /// Rate limit storage.
    limits: HashMap<IncrAndTestLimit, Expiring<usize>>,
}

impl MemoryStore {
    pub fn new(
        expire_sessions: Duration,
        expire_cache: Duration,
        limit_per_email_config: LimitConfig,
        fetcher: Addr<FetchAgent>,
    ) -> Self {
        log::warn!("Storing sessions in memory.");
        log::warn!("Note that sessions will be lost on restart!");

        MemoryStore {
            expire_sessions,
            expire_cache,
            limit_per_email_config,
            fetcher,
            sessions: HashMap::new(),
            cache: HashMap::new(),
            limits: HashMap::new(),
        }
    }
}

impl Agent for MemoryStore {
    fn started(addr: &Addr<Self>) {
        // Start the garbage collection loop.
        let addr = addr.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                addr.send(Gc).await;
            }
        });
    }
}

impl Handler<Gc> for MemoryStore {
    fn handle(&mut self, _message: Gc, reply: ReplySender<Gc>) {
        // TODO
        reply.send(())
    }
}

impl Handler<SaveSession> for MemoryStore {
    fn handle(&mut self, message: SaveSession, reply: ReplySender<SaveSession>) {
        self.sessions.insert(
            message.session_id,
            Expiring::from_duration(message.data, self.expire_sessions),
        );
        reply.send(Ok(()))
    }
}

impl Handler<GetSession> for MemoryStore {
    fn handle(&mut self, message: GetSession, reply: ReplySender<GetSession>) {
        let data = self
            .sessions
            .get(&message.session_id)
            .filter(|entry| entry.is_alive())
            .map(|entry| entry.inner.clone());
        reply.send(Ok(data))
    }
}

impl Handler<DeleteSession> for MemoryStore {
    fn handle(&mut self, message: DeleteSession, reply: ReplySender<DeleteSession>) {
        self.sessions.remove(&message.session_id);
        reply.send(Ok(()))
    }
}

impl Handler<CachedFetch> for MemoryStore {
    fn handle(&mut self, message: CachedFetch, reply: ReplySender<CachedFetch>) {
        let fetcher = self.fetcher.clone();
        let slot = self.cache.entry(message.url.clone()).or_default().clone();
        let expire_cache = self.expire_cache;
        reply.later(move || async move {
            let mut slot = slot.lock().await;
            if let Some(entry) = slot.as_ref().filter(|entry| entry.is_alive()) {
                return Ok(entry.inner.clone());
            }
            let result = fetcher.send(FetchUrl { url: message.url }).await?;
            let ttl = std::cmp::max(expire_cache, result.max_age);
            *slot = Some(Expiring::from_duration(result.data.clone(), ttl));
            Ok(result.data)
        });
    }
}

impl Handler<IncrAndTestLimit> for MemoryStore {
    fn handle(&mut self, message: IncrAndTestLimit, reply: ReplySender<IncrAndTestLimit>) {
        let config = match message {
            IncrAndTestLimit::PerEmail { .. } => self.limit_per_email_config,
        };
        let count: usize = match self.limits.entry(message) {
            Entry::Occupied(mut entry) => {
                let mut expiring = entry.get_mut();
                if expiring.expires <= Instant::now() {
                    *expiring = Expiring::from_duration(1, config.duration);
                    1
                } else {
                    expiring.inner += 1;
                    expiring.inner
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(Expiring::from_duration(1, config.duration));
                1
            }
        };
        reply.send(Ok(count <= config.max_count));
    }
}

impl StoreSender for Addr<MemoryStore> {}
