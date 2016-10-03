use std::collections::HashMap;
use super::redis::{self, Commands, RedisResult};


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
    pub expire_keys: u64, // Redis key TTL, in seconds
}

impl Store {
    pub fn new(url: &str, expire_keys: u64) -> Result<Store, &'static str> {
        let res = redis::Client::open(url);
        if res.is_err() {
            return Err("error opening store connection");
        }
        Ok(Store { client: res.unwrap(), expire_keys: expire_keys })
    }

    pub fn store_session(&self, session_id: &str, data: &[(&str, &str)])
                         -> Result<(), String> {
        let key = Self::format_session_key(session_id);
        let res: RedisResult<String> = self.client.hset_multiple(&key, data);
        if res.is_err() {
            return Err(res.unwrap_err().to_string());
        }
        let res: RedisResult<bool> =
            self.client.expire(&key, self.expire_keys as usize);
        if res.is_err() {
            return Err(res.unwrap_err().to_string());
        }
        Ok(())
    }

    pub fn get_session(&self, session_id: &str)
                       -> Result<HashMap<String, String>, String> {
        let key = Self::format_session_key(session_id);
        let res: RedisResult<HashMap<String, String>> =
            self.client.hgetall(&key);
        if res.is_err() {
            return Err(res.unwrap_err().to_string());
        }
        let stored = res.unwrap();
        if stored.is_empty() {
            return Err("session not found".to_string());
        }
        Ok(stored)
    }

    fn format_session_key(session_id: &str) -> String {
        format!("session:{}", session_id)
    }
}
