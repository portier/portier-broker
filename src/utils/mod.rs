pub mod base64url;
mod fetch_json_cached;
pub mod http;
mod limit_config;
pub mod pem;
pub mod serde;

use std::{error::Error, future::Future, pin::Pin};

pub use fetch_json_cached::fetch_json_cached;
pub use limit_config::LimitConfig;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
