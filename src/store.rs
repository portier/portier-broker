use std::collections::HashMap;
use super::error::{BrokerResult, BrokerError};
use super::redis::{self, Commands, PipelineCommands};
use super::store_cache::StoreCache;


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
    pub cache: StoreCache,
    pub expire_sessions: usize, // TTL of session keys, in seconds
    pub expire_cache: usize, // TTL of cache keys, in seconds
    pub max_response_size: u64, // Maximum size of HTTP GET responses
}

impl Store {
    pub fn new(url: &str, expire_sessions: usize, expire_cache: usize, max_response_size: u64)
               -> Result<Store, &'static str> {
        let res = redis::Client::open(url);
        if res.is_err() {
            return Err("error opening store connection");
        }
        Ok(Store {
            client: res.unwrap(),
            cache: StoreCache,
            expire_sessions: expire_sessions,
            expire_cache: expire_cache,
            max_response_size: max_response_size,
        })
    }

    pub fn store_session(&self, session_id: &str, data: &[(&str, &str)])
                         -> BrokerResult<()> {
        let key = Self::format_session_key(session_id);
        try!(redis::pipe()
                .atomic()
                .hset_multiple(&key, data).ignore()
                .expire(&key, self.expire_sessions).ignore()
                .query(&self.client));
        Ok(())
    }

    pub fn get_session(&self, session_id: &str)
                       -> BrokerResult<HashMap<String, String>> {
        let key = Self::format_session_key(session_id);
        let stored: HashMap<String, String> = try!(self.client.hgetall(&key));
        if stored.is_empty() {
            return Err(BrokerError::Custom("session not found".to_string()));
        }
        Ok(stored)
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}
