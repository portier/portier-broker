use error::BrokerError;
use futures::{Future, Stream, future};
use config::    Config;
use hyper::header::{ContentLength, CacheControl, CacheDirective};
use redis::Commands;
use serde_json::de::from_str;
use serde_json::value::Value;
use std::cmp::max;
use std::rc::Rc;
use std::str::from_utf8;


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
/// cache is stored in `app.store` with `key`. The `client` is used to make the HTTP GET request,
/// if necessary.
pub fn fetch_json_url(app: &Rc<Config>, url: &str, key: &CacheKey)
                      -> Box<Future<Item=Value, Error=BrokerError>> {

    // Try to retrieve the result from cache.
    let key_str = key.to_string();
    let data: Option<String> = match app.store.client.get(&key_str) {
        Ok(data) => data,
        Err(e) => return Box::new(future::err(e.into())),
    };

    let f: Box<Future<Item=String, Error=BrokerError>> = if let Some(data) = data {
        Box::new(future::ok(data))
    } else {
        // Cache miss, make a request.
        let url = url.parse().expect("could not parse request url");
        let f = app.http_client.get(url).map_err(|err| err.into());

        let app = app.clone();
        let f = f.and_then(move |res| {
            // Check the Content-Length. We require it.
            let size = match res.headers().get() {
                Some(&ContentLength(size)) => size,
                None => return future::err(BrokerError::Custom(
                    "missing content-length header in response".to_string())),
            };

            if size > app.store.max_response_size {
                return future::err(BrokerError::Custom(
                    "response exceeds the size limit".to_string()));
            }

            // Grab the max-age directive from the Cache-Control header.
            let max_age = res.headers().get().map_or(0, |header: &CacheControl| {
                for dir in header.iter() {
                    if let CacheDirective::MaxAge(seconds) = *dir {
                        return seconds;
                    }
                }
                0
            });

            future::ok((app, res, max_age))
        });

        // Receive the body.
        let f = f.and_then(|(app, res, max_age)| {
            res.body().concat2()
                .map(move |chunk| (app, chunk, max_age))
                .map_err(|err| err.into())
        });

        let f = f.and_then(|(app, chunk, max_age)| {
            let result = from_utf8(&chunk)
                .map_err(|_| BrokerError::Custom("response contained invalid utf-8".to_string()))
                .map(|data| data.to_owned())
                .and_then(move |data| {
                    // Cache the response for at least `expire_cache`, but honor longer `max-age`.
                    let seconds = max(app.store.expire_cache, max_age as usize);
                    app.store.client.set_ex::<_, _, ()>(&key_str, &data, seconds)
                        .map_err(|err| err.into())
                        .map(|_| data)
                });
            future::result(result)
        });

        Box::new(f)
    };

    let f = f.and_then(|data| {
        future::result(from_str(&data).map_err(|_| {
            BrokerError::Custom("failed to parse response as JSON".to_string())
        }))
    });

    Box::new(f)
}
