pub mod agent;
pub mod base64url;
mod delay_queue_task;
pub mod http;
pub mod keys;
mod limit_config;
pub mod pem;
mod time;

use std::{error::Error, future::Future, pin::Pin};

pub use delay_queue_task::DelayQueueTask;
pub use limit_config::LimitConfig;
pub use time::unix_timestamp;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
