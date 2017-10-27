use error::{BrokerResult, BrokerError};
use redis::{self, Commands};


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
    pub expire_sessions: usize, // TTL of session keys, in seconds
    pub expire_cache: usize, // TTL of cache keys, in seconds
}

impl Store {
    pub fn new(url: &str, expire_sessions: usize, expire_cache: usize)
               -> Result<Store, &'static str> {

        match redis::Client::open(url) {
            Err(_) => Err("error opening store connection"),
            Ok(client) => Ok(Store {
                client: client,
                expire_sessions: expire_sessions,
                expire_cache: expire_cache,
            }),
        }
    }

    pub fn store_session(&self, session_id: &str, data: &str)
            -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        self.client.set_ex(&key, data, self.expire_sessions)
            .map_err(|e| BrokerError::Internal(format!("could not save a session: {}", e)))
    }

    pub fn get_session(&self, session_id: &str)
            -> BrokerResult<String> {
        let key = Self::format_session_key(session_id);
        let stored: Option<String> = self.client.get(&key)
            .map_err(|e| BrokerError::Internal(format!("could not load a session: {}", e)))?;
        stored.ok_or_else(|| BrokerError::SessionExpired)
    }

    pub fn remove_session(&self, session_id: &str)
            -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        self.client.del(&key)
            .map_err(|e| BrokerError::Internal(format!("could not remove a session: {}", e)))
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}
