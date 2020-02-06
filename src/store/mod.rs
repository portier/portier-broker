mod redis;

use crate::utils::{BoxError, BoxFuture};

pub use self::redis::*;

/// Interface for storing sessions.
pub trait SessionStore {
    fn store_session(&self, session_id: &str, data: String) -> BoxFuture<Result<(), BoxError>>;
    fn get_session(&self, session_id: &str) -> BoxFuture<Result<Option<String>, BoxError>>;
    fn remove_session(&self, session_id: &str) -> BoxFuture<Result<(), BoxError>>;
}

/// Key for cache items.
#[derive(Clone, Copy, Debug)]
pub enum CacheKey<'a> {
    Discovery { acct: &'a str },
    OidcConfig { origin: &'a str },
    OidcKeySet { origin: &'a str },
}

/// A cache query result.
///
/// Should be locked while alive, and unlock on `drop`.
pub trait CacheItem: Drop {
    fn read(&self) -> BoxFuture<Result<Option<String>, BoxError>>;
    fn write(&mut self, value: String, max_age: usize) -> BoxFuture<Result<(), BoxError>>;
}

/// Interface for storing cache.
pub trait CacheStore {
    fn get_cache_item(
        &self,
        key: CacheKey,
    ) -> BoxFuture<Result<Box<dyn CacheItem + Send + Sync>, BoxError>>;
}

/// Key for a rate limit.
#[derive(Clone, Copy, Debug)]
pub enum LimitKey<'a> {
    PerEmail { addr: &'a str },
}

/// Interface for storing rate limits.
pub trait LimitStore {
    fn incr_and_test_limit(&self, key: LimitKey<'_>) -> BoxFuture<Result<bool, BoxError>>;
}

/// Interface combining all store traits.
pub trait Store: SessionStore + CacheStore + LimitStore {}
