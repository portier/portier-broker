pub mod agent;
pub mod base64url;
pub mod http;
mod limit_config;
pub mod pem;

use std::{error::Error, future::Future, pin::Pin};

pub use limit_config::LimitConfig;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
