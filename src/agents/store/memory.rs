use crate::agents::*;
use crate::config::LimitConfig;
use crate::crypto::SigningAlgorithm;
use crate::utils::agent::*;
use crate::web::Session;
use std::collections::hash_map::{Entry, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::Url;

/// Combines any type with an `Instant` expiry time.
struct Expiring<T> {
    value: T,
    expires: Instant,
}

impl<T> Expiring<T> {
    /// Create a value from a duration.
    fn from_duration(value: T, duration: Duration) -> Self {
        let expires = Instant::now() + duration;
        Expiring { value, expires }
    }

    /// Whether this value has not yet expired.
    fn is_alive(&self) -> bool {
        self.expires > Instant::now()
    }
}

/// Message sent at an interval to collect garbage.
struct Gc;
impl Message for Gc {
    type Reply = ();
}

/// A slot in the cache `HashMap`.
///
/// We want to lock these individually while a fetch is in progress, so multiple requests for the
/// same URL result in only one fetch. Therefore, we use an `Arc<Mutex<_>>` to carry slots around,
/// and within an `Option` which indicates whether cache is actually present (despite the hash map
/// entry existing or not, which does not indicate anything).
type CacheSlot = Arc<Mutex<Option<Expiring<String>>>>;

/// A slot in the keys `HashMap`.
///
/// It's technically not necessary for us to lock keys, because the key manager is our only client,
/// but we do so any ways to ensure correct behavior.
type KeysSlot = Arc<Mutex<KeySet>>;

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
    /// Key manager if rotating keys are enabled.
    key_manager: Option<Addr<RotatingKeys>>,
    /// Session storage.
    sessions: HashMap<String, Expiring<Session>>,
    /// Cache storage.
    cache: HashMap<Url, CacheSlot>,
    /// Rate limit storage.
    limits: HashMap<IncrAndTestLimit, Expiring<usize>>,
    /// Keys storage.
    keys: HashMap<SigningAlgorithm, KeysSlot>,
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
            key_manager: None,
            sessions: HashMap::new(),
            cache: HashMap::new(),
            limits: HashMap::new(),
            keys: HashMap::new(),
        }
    }
}

impl Agent for MemoryStore {
    fn started(addr: &Addr<Self>) {
        // Start the garbage collection loop.
        let addr = addr.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                addr.send(Gc).await;
            }
        });
    }
}

impl Handler<Gc> for MemoryStore {
    fn handle(&mut self, _message: Gc, cx: Context<Self, Gc>) {
        self.sessions = self
            .sessions
            .drain()
            .filter(|(_, ref entry)| entry.is_alive())
            .collect();
        self.cache = self
            .cache
            .drain()
            .filter(|(_, ref slot)| {
                // For cache items, only remove if we have the sole reference. Otherwise, a fetch
                // might still be in progress. Locking should be immediate if true.
                if let Ok(maybe_entry) = slot.try_lock() {
                    Arc::strong_count(slot) > 1
                        || maybe_entry
                            .as_ref()
                            .filter(|entry| entry.is_alive())
                            .is_some()
                } else {
                    true
                }
            })
            .collect();
        self.limits = self
            .limits
            .drain()
            .filter(|(_, ref entry)| entry.is_alive())
            .collect();
        cx.reply(())
    }
}

impl Handler<SaveSession> for MemoryStore {
    fn handle(&mut self, message: SaveSession, cx: Context<Self, SaveSession>) {
        self.sessions.insert(
            message.session_id,
            Expiring::from_duration(message.data, self.expire_sessions),
        );
        cx.reply(Ok(()))
    }
}

impl Handler<GetSession> for MemoryStore {
    fn handle(&mut self, message: GetSession, cx: Context<Self, GetSession>) {
        let data = self
            .sessions
            .get(&message.session_id)
            .filter(|entry| entry.is_alive())
            .map(|entry| entry.value.clone());
        cx.reply(Ok(data))
    }
}

impl Handler<DeleteSession> for MemoryStore {
    fn handle(&mut self, message: DeleteSession, cx: Context<Self, DeleteSession>) {
        self.sessions.remove(&message.session_id);
        cx.reply(Ok(()))
    }
}

impl Handler<FetchUrlCached> for MemoryStore {
    fn handle(&mut self, message: FetchUrlCached, cx: Context<Self, FetchUrlCached>) {
        let fetcher = self.fetcher.clone();
        let slot = self.cache.entry(message.url.clone()).or_default().clone();
        let expire_cache = self.expire_cache;
        cx.reply_later(async move {
            let mut slot = slot.lock().await;
            if let Some(entry) = slot.as_ref().filter(|entry| entry.is_alive()) {
                return Ok(entry.value.clone());
            }
            let result = fetcher.send(FetchUrl { url: message.url }).await?;
            let ttl = std::cmp::max(expire_cache, result.max_age);
            *slot = Some(Expiring::from_duration(result.data.clone(), ttl));
            Ok(result.data)
        });
    }
}

impl Handler<IncrAndTestLimit> for MemoryStore {
    fn handle(&mut self, message: IncrAndTestLimit, cx: Context<Self, IncrAndTestLimit>) {
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
                    expiring.value += 1;
                    expiring.value
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(Expiring::from_duration(1, config.duration));
                1
            }
        };
        cx.reply(Ok(count <= config.max_count));
    }
}

impl Handler<EnableRotatingKeys> for MemoryStore {
    fn handle(&mut self, message: EnableRotatingKeys, cx: Context<Self, EnableRotatingKeys>) {
        self.key_manager = Some(message.key_manager.clone());
        let mut update_msgs = Vec::with_capacity(message.signing_algs.len());
        for signing_alg in &message.signing_algs {
            let key_set = KeySet::empty(*signing_alg);
            update_msgs.push(UpdateKeys(key_set.clone()));
            self.keys
                .insert(*signing_alg, Arc::new(Mutex::new(key_set)));
        }
        cx.reply_later(async move {
            for update_msg in update_msgs {
                message.key_manager.send(update_msg).await;
            }
        });
    }
}

impl Handler<RotateKeysLocked> for MemoryStore {
    fn handle(&mut self, message: RotateKeysLocked, cx: Context<Self, RotateKeysLocked>) {
        let slot_rc = self.keys[&message.0].clone();
        let key_manager = self.key_manager.as_ref().unwrap().clone();
        cx.reply_later(async move {
            let mut slot = slot_rc
                .try_lock()
                .expect("Keys lock should never be locked twice");
            if let Some(key_set) = key_manager.send(RotateKeys(slot.clone())).await {
                *slot = key_set.clone();
                key_manager.send(UpdateKeys(key_set)).await;
            }
        });
    }
}

impl StoreSender for Addr<MemoryStore> {}
