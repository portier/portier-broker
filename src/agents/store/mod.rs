use crate::utils::agent::{Message, Sender};
use crate::utils::BoxError;
use crate::web::Session;
use url::Url;

/// Message requesting a session be saved.
pub struct SaveSession {
    /// The session ID.
    pub session_id: String,
    /// Session data to save.
    pub data: Session,
}
impl Message for SaveSession {
    type Reply = Result<(), BoxError>;
}

/// Message requesting a session be fetched.
pub struct GetSession {
    /// The session ID.
    pub session_id: String,
}
impl Message for GetSession {
    type Reply = Result<Option<Session>, BoxError>;
}

/// Message requesting a session be deleted.
pub struct DeleteSession {
    /// The session ID.
    pub session_id: String,
}
impl Message for DeleteSession {
    type Reply = Result<(), BoxError>;
}

/// Message requesting a URL be fetched, possibly from cache.
pub struct CachedFetch {
    /// The URL to fetch.
    pub url: Url,
}
impl Message for CachedFetch {
    type Reply = Result<String, BoxError>;
}

/// Message requesting a rate limit be increased and tested.
#[derive(PartialEq, Eq, Hash)]
pub enum IncrAndTestLimit {
    /// Selects the per-email rate-limit.
    PerEmail { addr: String },
}
impl Message for IncrAndTestLimit {
    type Reply = Result<bool, BoxError>;
}

/// Store abstraction. Combines all message types.
///
/// Downside of this is that it needs to be implemented on the agent side as:
/// `impl StoreSender for Addr<FoobarStore> {}`
pub trait StoreSender:
    Sender<SaveSession>
    + Sender<GetSession>
    + Sender<DeleteSession>
    + Sender<CachedFetch>
    + Sender<IncrAndTestLimit>
{
}

mod memory;
pub use self::memory::*;

#[cfg(feature = "redis")]
mod redis;
#[cfg(feature = "redis")]
pub use self::redis::*;

#[cfg(feature = "rusqlite")]
mod rusqlite;
#[cfg(feature = "rusqlite")]
pub use self::rusqlite::*;
