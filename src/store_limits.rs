use super::redis::Script;
use super::error::BrokerResult;
use super::store::Store;


/// Represents a ratelimit
#[derive(Clone,Debug)]
pub struct Ratelimit {
    /// Maximum request count within the window before we refuse.
    pub count: usize,
    /// Timespan of the entire window, in seconds.
    pub duration: usize,
}


/// Represents a Redis key.
pub enum RatelimitKey<'a> {
    Email { email: &'a str },
}

impl<'a> RatelimitKey<'a> {
    fn to_string(&self) -> String {
        match *self {
            RatelimitKey::Email { email } => {
                format!("ratelimit:email:{}", email)
            },
        }
    }
}

/// Increment the given key, and test if the counter is within limits.
pub fn incr_and_test_limits(store: &Store, key: RatelimitKey, ratelimit: &Ratelimit) -> BrokerResult<bool> {
    let script = Script::new(r"
        local count = redis.call('incr', KEYS[1])
        if count == 1 then
            redis.call('expire', KEYS[1], ARGV[1])
        end
        return count
    ");

    let count: usize = script
        .key(key.to_string())
        .arg(ratelimit.duration)
        .invoke(&store.client)?;

    Ok(count <= ratelimit.count)
}
