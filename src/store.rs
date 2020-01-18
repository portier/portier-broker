use crate::error::{BrokerError, BrokerResult};
use redis::AsyncCommands;

pub struct Store {
    pub client: redis::aio::MultiplexedConnection,
    pub expire_sessions: usize, // TTL of session keys, in seconds
    pub expire_cache: usize,    // TTL of cache keys, in seconds
}

impl Store {
    pub async fn new(
        mut url: String,
        expire_sessions: usize,
        expire_cache: usize,
    ) -> Result<Store, String> {
        if url.starts_with("http://") {
            url = url.replace("http://", "redis://");
        } else if !url.starts_with("redis://") {
            url = format!("redis://{}", &url);
        }
        let client = redis::Client::open(url.as_str())
            .map_err(|e| format!("error opening redis client: {} (url={})", e, url))?;

        let client = client
            .get_multiplexed_tokio_connection()
            .await
            .map_err(|e| format!("error connecting to redis server: {} (url={})", e, url))?;

        Ok(Store {
            client,
            expire_sessions,
            expire_cache,
        })
    }

    pub async fn store_session(&self, session_id: &str, data: &str) -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        self.client
            .clone()
            .set_ex(&key, data, self.expire_sessions)
            .await
            .map_err(|e| BrokerError::Internal(format!("could not save a session: {}", e)))
    }

    pub async fn get_session(&self, session_id: &str) -> BrokerResult<String> {
        let key = Self::format_session_key(session_id);
        let stored: Option<String> = self
            .client
            .clone()
            .get(&key)
            .await
            .map_err(|e| BrokerError::Internal(format!("could not load a session: {}", e)))?;
        stored.ok_or_else(|| BrokerError::SessionExpired)
    }

    pub async fn remove_session(&self, session_id: &str) -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        self.client
            .clone()
            .del(&key)
            .await
            .map_err(|e| BrokerError::Internal(format!("could not remove a session: {}", e)))
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}
