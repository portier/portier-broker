use error::{BrokerError, BrokerResult};
use futures::{Future, Stream};
use config::HttpClient;
use hyper::header::{ContentLength, CacheControl, CacheDirective};
use redis::Commands;
use serde_json::de::from_str;
use serde_json::value::Value;
use std::cmp::max;
use std::str::from_utf8;
use store::Store;


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


/// Fetch `url` from cache or using a HTTP GET request, and parse the response as JSON. The
/// cache is stored in `store` with `key`. The `client` is used to make the HTTP GET request,
/// if necessary.
pub fn fetch_json_url(store: &Store, key: &CacheKey, client: &HttpClient, url: &str)
                      -> BrokerResult<Value> {

    // Try to retrieve the result from cache.
    let key_str = key.to_string();
    let stored: Option<String> = store.client.get(&key_str)?;
    stored.map_or_else(|| {

        // Cache miss, make a request.
        let rsp = client.get(
            url.parse().expect("could not parse request url")
        ).wait()?;

        // Check the Content-Length. We require it.
        rsp.headers().get()
            .ok_or_else(|| BrokerError::Custom("missing content-length header in response".to_string()))
            .and_then(|header: &ContentLength| {
                if header.0 > store.max_response_size {
                    Err(BrokerError::Custom("response exceeds the size limit".to_string()))
                } else {
                    Ok(())
                }
            })?;

        // Grab the max-age directive from the Cache-Control header.
        let max_age = rsp.headers().get().map_or(0, |header: &CacheControl| {
            for dir in header.iter() {
                if let CacheDirective::MaxAge(seconds) = *dir {
                    return seconds;
                }
            }
            0
        });

        // Receive the body.
        let chunk = rsp.body().concat2().wait()?;
        let data = from_utf8(&chunk)
            .map_err(|_| BrokerError::Custom("response contained invalid utf-8".to_string()))?;

        // Cache the response for at least `expire_cache`, but honor longer `max-age`.
        let seconds = max(store.expire_cache, max_age as usize);
        store.client.set_ex::<_, _, ()>(&key_str, data, seconds)?;

        Ok(data.to_owned())

    }, |data| {
        Ok(data)
    }).and_then(|data| {

        from_str(&data).map_err(|_| {
            BrokerError::Custom("failed to parse response as JSON".to_string())
        })

    })

}
