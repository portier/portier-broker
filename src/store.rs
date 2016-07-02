use super::redis::{self, Commands, RedisResult};


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
    pub expire_keys: usize, // Redis key TTL, in seconds
}

impl Store {
    pub fn store_session(&self, key: &str, data: &[(&str, &str)])
                         -> Result<(), String> {
        let res: RedisResult<String> = self.client.hset_multiple(key, data);
        if res.is_err() {
            return Err(res.unwrap_err().to_string());
        }
        let res: RedisResult<bool> = self.client.expire(key, self.expire_keys);
        if res.is_err() {
            return Err(res.unwrap_err().to_string());
        }
        Ok(())
    }
}
