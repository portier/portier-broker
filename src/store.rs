use super::redis;


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
    pub expire_keys: usize, // Redis key TTL, in seconds
}
