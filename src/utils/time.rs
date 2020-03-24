use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Get a duration since Unix epoch.
pub fn unix_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current system time is before Unix epoch")
}

/// Get a Unix timestamp for the current time.
pub fn unix_timestamp() -> u64 {
    unix_duration().as_secs()
}
