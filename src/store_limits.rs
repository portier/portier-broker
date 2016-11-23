use std::error::Error;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use super::redis::{self, PipelineCommands};
use super::error::BrokerResult;
use super::store::Store;
use super::serde::de::{Deserialize, Deserializer, Error as SerdeError};


/// Represents a limit configuration.
///
/// Typically provided as a string `<name>:<max_count>:<timespan>:<granularity>`.
#[derive(Clone,Debug)]
pub struct LimitConfig {
    /// A name for this config, appended to the Redis key.
    pub name: String,
    /// Maximum request count within the window before we refuse.
    pub max_count: u64,
    /// Timespan of the entire window, in seconds.
    pub timespan: u64,
    /// Timespan of a single bucket in the window, which defines the
    /// time granularity with which we store request counts.
    pub granularity: u64,
}

impl FromStr for LimitConfig {
    type Err = String;
    fn from_str(s: &str) -> Result<LimitConfig, String> {
        let parts: Vec<&str> = s.split(":").collect();
        if parts.len() != 4 {
            return Err("Limit config must be 4 colon-separated parts".to_string());
        }

        let max_count = parts[1].parse::<u64>().map_err(|e| e.description().to_string())?;
        let timespan = parts[2].parse::<u64>().map_err(|e| e.description().to_string())?;
        let granularity = parts[3].parse::<u64>().map_err(|e| e.description().to_string())?;
        if timespan % granularity != 0 {
            return Err("Limit timespan must be a multiple of granularity".to_string());
        }

        Ok(LimitConfig {
            name: parts[0].to_string(),
            max_count: max_count,
            timespan: timespan,
            granularity: granularity,
        })
    }
}

impl Deserialize for LimitConfig {
    fn deserialize<D: Deserializer>(deserializer: &mut D) -> Result<LimitConfig, D::Error> {
        let s = String::deserialize(deserializer)?;
        LimitConfig::from_str(&s).map_err(|msg| D::Error::custom(msg))
    }
}


/// Represents a Redis key.
pub enum LimitKey<'a> {
    Auth { email: &'a str },
    AuthEmail { email: &'a str },
}

impl<'a> LimitKey<'a> {
    fn to_string(&self, config: &LimitConfig) -> String {
        match *self {
            LimitKey::Auth { email } => {
                format!("limit:auth:{}:{}", email, &config.name)
            },
            LimitKey::AuthEmail { email } => {
                format!("limit:auth-email:{}:{}", email, &config.name)
            },
        }
    }
}


/// Increment the given key, and test if the counter is within limits.
///
/// The Redis hash key represents a ring of counters. Each field in the hash counts requests
/// for a small amount of time specified by the granularity. The sum of all hash fields then
/// represents the count for the full configured timespan.
///
/// The hash has a TTL equal to the timespan, which is updated on every request, but individual
/// hash fields must also expire. To accomplish this, we double the size of the hash, and clear
/// the 'upcoming' half as we go. Thus, we'll never circle around to old counters before the
/// key TTL expires.
pub fn incr_and_test_limits(store: &Store, key: LimitKey, configs: &[LimitConfig]) -> BrokerResult<bool> {

    let unixtime = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut result = true;

    for ref config in configs {
        let key_str = key.to_string(config);

        let num_buckets = config.timespan / config.granularity * 2;
        let bucket = (unixtime / config.granularity) % num_buckets;

        // Hash fields to delete, for the upcoming half of the counter ring.
        let hdel_fields: Vec<u64> = (0..num_buckets / 2)
            .map(|i| (bucket + 1 + i) % num_buckets)
            .collect();

        let (counts,): (Vec<u64>,) = redis::pipe()
            .atomic()
            .hincr(&key_str, bucket, 1).ignore()
            .hdel(&key_str, hdel_fields).ignore()
            .expire_at(&key_str, (unixtime + config.timespan) as usize).ignore()
            .hvals(&key_str)
            .query(&store.client)?;
        let count = counts.iter().fold(0, |acc, val| acc + val);

        // Aggregate result, but don't break (increment all counters)
        result = result && count <= config.max_count;
    }

    Ok(result)
}
