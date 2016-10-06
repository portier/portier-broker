use std::io::Read;
use super::hyper::client::Client as HttpClient;
use super::redis::Commands;
use super::error::BrokerResult;
use super::store::Store;


/// Represents a Redis key.
pub enum CacheKey<'a> {
    Discovery { domain: &'a str },
    KeySet { domain: &'a str },
}

impl<'a> CacheKey<'a> {
    fn to_string(&self) -> String {
        match *self {
            CacheKey::Discovery { domain } => {
                format!("cache:discovery:{}", domain)
            },
            CacheKey::KeySet { domain } => {
                format!("cache:key-set:{}", domain)
            }
        }
    }
}


#[derive(Clone)]
pub struct StoreCache;

impl StoreCache {
    /// Fetch `url` from cache or using a HTTP GET request. The cache is stored in `store` with
    /// `key`. The `session` is used to make the HTTP GET request, if necessary.
    pub fn fetch_url(&self, store: &Store, key: CacheKey, session: &HttpClient, url: &str)
                     -> BrokerResult<String> {

        // Try to retrieve the result from cache.
        let key_str = key.to_string();
        let stored: Option<String> = try!(store.client.get(&key_str));
        stored.map_or_else(|| {

            // Cache miss, make a request.
            let mut rsp = try!(session.get(url).send());
            let mut data = String::new();
            try!(rsp.read_to_string(&mut data));

            // Cache the response for `expire_cache`.
            try!(store.client.set_ex(&key_str, &data, store.expire_cache));

            Ok(data)

        }, |data| {
            Ok(data)
        })

    }
}
