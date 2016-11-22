use super::redis::{self, PipelineCommands};
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

    // Note: If quota exceeded, additional requests keep extending the ban.
    // Thus, with a 5/min ratelimit, it only takes one request each minute to
    // prevent a ratelimiting from expiring once exceeded.
    //
    // TODO? Implement this in Lua to ensure the limit expires every duration.
    // Pseudocode: return TTL(key) ? INCR(key, 1) : SETEX(key, duration, 1)
    // Does the INCR above need an EXPIRE to keep keys with TTL=ε from leaking?
    let k = key.to_string();
    let (count, ): (usize, ) = redis::pipe()
        .atomic()
        .incr(&k, 1)
        .expire(&k, ratelimit.duration).ignore()
        .query(&store.client)?;

    Ok(count > ratelimit.count)
}
