use crate::config::Config;
use crate::error::BrokerError;
use crate::http;
use futures::{future, Future};
use hyper::header::{CacheControl, CacheDirective};
use hyper::StatusCode;
use log::info;
use redis::Commands;
use serde::de::DeserializeOwned;
use serde_json as json;
use std::{cmp::max, fmt, rc::Rc, str::from_utf8};
use url::Url;

/// Represents a Redis key.
pub enum CacheKey<'a> {
    Discovery { acct: &'a str },
    OidcConfig { origin: &'a str },
    OidcKeySet { origin: &'a str },
}

impl<'a> fmt::Display for CacheKey<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CacheKey::Discovery { acct } => write!(f, "cache:discovery:{}", acct),
            CacheKey::OidcConfig { origin } => write!(f, "cache:configuration:{}", origin),
            CacheKey::OidcKeySet { origin } => write!(f, "cache:key-set:{}", origin),
        }
    }
}

/// Fetch `url` from cache or using a HTTP GET request, and parse the response as JSON. The
/// cache is stored in `app.store` with `key`. The `client` is used to make the HTTP GET request,
/// if necessary.
pub fn fetch_json_url<T>(
    app: &Rc<Config>,
    url: Url,
    key: &CacheKey,
) -> Box<dyn Future<Item = T, Error = BrokerError>>
where
    T: 'static + DeserializeOwned,
{
    let url = Rc::new(url);

    // Try to retrieve the result from cache.
    let key_str = key.to_string();
    let data: Option<String> = match app.store.client.get(&key_str) {
        Ok(data) => data,
        Err(e) => {
            return Box::new(future::err(BrokerError::Internal(format!(
                "cache lookup failed: {}",
                e
            ))))
        }
    };

    let f: Box<dyn Future<Item = String, Error = BrokerError>> = if let Some(data) = data {
        info!("HIT {} - {}", key_str, url);
        Box::new(future::ok(data))
    } else {
        // Cache miss, make a request.
        // TODO: Also cache failed requests, perhaps for a shorter time.
        info!("MISS {} - {}", key_str, url);

        let url2 = Rc::clone(&url);
        let hyper_url = url
            .as_str()
            .parse()
            .expect("failed to convert Url to Hyper Url");
        let f = app
            .http_client
            .get(hyper_url)
            .map_err(move |e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url2)));

        let url2 = Rc::clone(&url);
        let f = f.and_then(move |res| {
            if res.status() != StatusCode::Ok {
                Err(BrokerError::Provider(format!(
                    "fetch failed ({}): {}",
                    res.status(),
                    url2
                )))
            } else {
                Ok(res)
            }
        });

        let url2 = Rc::clone(&url);
        let f = f.and_then(move |res| {
            // Grab the max-age directive from the Cache-Control header.
            let max_age = res.headers().get().map_or(0, |header: &CacheControl| {
                for dir in header.iter() {
                    if let CacheDirective::MaxAge(seconds) = *dir {
                        return seconds;
                    }
                }
                0
            });

            // Receive the body.
            http::read_body(res.body())
                .map_err(move |e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url2)))
                .map(move |chunk| (chunk, max_age))
        });

        let app = Rc::clone(app);
        let url2 = Rc::clone(&url);
        let f = f.and_then(move |(chunk, max_age)| {
            from_utf8(&chunk)
                .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url2)))
                .map(|data| data.to_owned())
                .and_then(move |data| {
                    // Cache the response for at least `expire_cache`, but honor longer `max-age`.
                    let seconds = max(app.store.expire_cache, max_age as usize);
                    app.store
                        .client
                        .set_ex::<_, _, ()>(&key_str, &data, seconds)
                        .map_err(|e| BrokerError::Internal(format!("cache write failed: {}", e)))
                        .map(|_| data)
                })
        });

        Box::new(f)
    };

    let f = f.and_then(move |data| {
        json::from_str(&data)
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))
    });

    Box::new(f)
}
