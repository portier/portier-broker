use crate::config::ConfigRc;
use crate::error::BrokerError;
use crate::web::read_body;
use headers::{CacheControl, HeaderMapExt};
use http::StatusCode;
use serde::de::DeserializeOwned;
use serde_json as json;
use url::Url;

/// Fetch `url` from cache or using a HTTP GET request, and parse the response as JSON. The
/// cache is stored in `app.store` with `key`. The `client` is used to make the HTTP GET request,
/// if necessary.
pub async fn fetch_json_cached<T>(
    app: &ConfigRc,
    url: Url,
) -> Result<T, BrokerError>
where
    T: 'static + DeserializeOwned,
{
    // Try to retrieve the result from cache.
    let mut cache_item = app
        .store
        .get_cache_item(&url)
        .await
        .map_err(|e| BrokerError::Internal(format!("cache lookup failed: {}", e)))?;
    let data = cache_item
        .read()
        .await
        .map_err(|e| BrokerError::Internal(format!("cache read failed: {}", e)))?;
    if let Some(data) = data {
        log::info!("HIT {}", url);

        json::from_str(&data)
            .map_err(|e| BrokerError::Internal(format!("bad cache value ({}): {}", e, url)))
    } else {
        // Cache miss, make a request.
        // TODO: Also cache failed requests, perhaps for a shorter time.
        log::info!("MISS {}", url);

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

        let data = std::str::from_utf8(&chunk)
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?
            .to_owned();

        let value = json::from_str(&data)
            .map_err(|e| BrokerError::Provider(format!("fetch failed ({}): {}", e, url)))?;

        // Cache the response for at least `expire_cache`, but honor longer `max-age`.
        cache_item
            .write(data, max_age as usize)
            .await
            .map_err(|e| BrokerError::Internal(format!("cache write failed: {}", e)))?;

        Ok(value)
    }
}
