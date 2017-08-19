use error::{BrokerResult, BrokerError};
use redis::{self, Commands, PipelineCommands};
use std::collections::HashMap;


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

    pub fn store_session(&self, session_id: &str, data: &[(&str, &str)])
                         -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        redis::pipe()
            .atomic()
            .hset_multiple(&key, data).ignore()
            .expire(&key, self.expire_sessions).ignore()
            .query::<()>(&self.client)
            .map_err(|e| BrokerError::Internal(format!("could not save a session: {}", e)))
    }

    pub fn get_session(&self, session_id: &str)
                       -> BrokerResult<HashMap<String, String>> {
        let key = Self::format_session_key(session_id);
        let stored: HashMap<String, String> = self.client.hgetall(&key)
            .map_err(|e| BrokerError::Internal(format!("could not load a session: {}", e)))?;
        if stored.is_empty() {
            return Err(BrokerError::Input("session not found".to_owned()));
        }
        Ok(stored)
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}
