use super::redis;


#[derive(Clone)]
pub struct Store {
    pub client: redis::Client,
}
