use std::cmp::max;
use std::io::Read;
use super::hyper::client::Client as HttpClient;
use super::hyper::header::{
    CacheControl as HyCacheControl,
    CacheDirective as HyCacheDirective
};
use super::redis::Commands;
use super::error::{BrokerError, BrokerResult};
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
            let rsp = try!(session.get(url).send());

            // Grab the max-age directive from the Cache-Control header.
            let max_age = rsp.headers.get().map_or(0, |header: &HyCacheControl| {
                for dir in header.iter() {
                    if let HyCacheDirective::MaxAge(seconds) = *dir {
                        return seconds;
                    }
                }
                0
            });

            // We read up to size+1, because we use the extra byte as a
            // sentinel to detect responses that exceed our maximum size.
            let mut data = String::new();
            let bytes_read = try!(rsp.take(store.max_response_size + 1).read_to_string(&mut data));
            if bytes_read as u64 > store.max_response_size {
                return Err(BrokerError::Custom("response exceeded the size limit".to_string()))
            }

            // Cache the response for at least `expire_cache`, but honor longer `max-age`.
            let seconds = max(store.expire_cache, max_age as usize);
            try!(store.client.set_ex(&key_str, &data, seconds));

            Ok(data)

        }, |data| {
            Ok(data)
        })

    }
}
