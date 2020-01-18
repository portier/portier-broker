use crate::error::{BrokerError, BrokerResult};
use crate::store::Store;
use redis::Script;

/// Represents a ratelimit
#[derive(Clone, Debug)]
pub struct Ratelimit {
    /// Maximum request count within the window before we refuse.
    pub count: usize,
    /// Timespan of the entire window, in seconds.
    pub duration: usize,
}

/// Increment and check a ratelimit for a specific email address.
pub async fn addr_limiter(store: &Store, addr: &str, limit: &Ratelimit) -> BrokerResult<bool> {
    let key = format!("ratelimit:addr:{}", addr.to_lowercase());
    incr_and_test_limits(store, &key, limit).await
}

/// Increment the given key, and test if the counter is within limits.
async fn incr_and_test_limits(
    store: &Store,
    key: &str,
    ratelimit: &Ratelimit,
) -> BrokerResult<bool> {
    let script = Script::new(
        r"
        local count = redis.call('incr', KEYS[1])
        if count == 1 then
            redis.call('expire', KEYS[1], ARGV[1])
        end
        return count
    ",
    );

    let count: usize = script
        .prepare_invoke()
        .key(key)
        .arg(ratelimit.duration)
        .invoke_async(&mut store.client.clone())
        .await
        .map_err(|e| BrokerError::Internal(format!("could not test rate limit: {}", e)))?;

    Ok(count <= ratelimit.count)
}
