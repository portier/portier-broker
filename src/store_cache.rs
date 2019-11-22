use crate::config::ConfigRc;
use crate::error::BrokerError;
use crate::web::read_body;
use headers::{CacheControl, HeaderMapExt};
use http::StatusCode;
use log::info;
use redis::Commands;
use serde::de::DeserializeOwned;
use serde_json as json;
use std::{cmp::max, fmt, str::from_utf8};
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
pub async fn fetch_json_url<T>(
    app: &ConfigRc,
    url: Url,
    key: &CacheKey<'_>,
) -> Result<T, BrokerError>
where
    T: 'static + DeserializeOwned,
{
    // Try to retrieve the result from cache.
    let key_str = key.to_string();
    let data: Option<String> = app
        .store
        .client
        .get(&key_str)
        .map_err(|e| BrokerError::Internal(format!("cache lookup failed: {}", e)))?;

    if let Some(ref data) = data {
        info!("HIT {} - {}", key_str, url);

        json::from_str(data)
            .map_err(|e| BrokerError::Internal(format!("bad cache value ({}): {}", e, url)))
    } else {
        // Cache miss, make a request.
        // TODO: Also cache failed requests, perhaps for a shorter time.
        info!("MISS {} - {}", key_str, url);

        let hyper_url = url
            .as_str()
            .parse()
            .expect("failed to convert Url to Hyper Url");

        let res = app
            .http_client
            .get(hyper_url)
            .await
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?;

        if res.status() != StatusCode::OK {
            return Err(BrokerError::Provider(format!(
                "fetch failed ({}): {}",
                res.status(),
                url
            )));
        }

        // Grab the max-age directive from the Cache-Control header.
        let max_age = res.headers().typed_get().map_or(0, |header: CacheControl| {
            header.max_age().map(|d| d.as_secs()).unwrap_or(0)
        });

        // Receive the body.
        let chunk = read_body(res.into_body())
            .await
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?;

        let data = from_utf8(&chunk)
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?;

        let value = json::from_str(data)
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?;

        // Cache the response for at least `expire_cache`, but honor longer `max-age`.
        let seconds = max(app.store.expire_cache, max_age as usize);
        app.store
            .client
            .set_ex::<_, _, ()>(&key_str, data, seconds)
            .map_err(|e| BrokerError::Internal(format!("cache write failed: {}", e)))?;

        Ok(value)
    }
}
