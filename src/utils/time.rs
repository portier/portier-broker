use std::time::{SystemTime, UNIX_EPOCH};

/// Get a Unix timestamp for the current time.
pub fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("current system time is before unix epoch")
        .as_secs()
}
