pub mod agent;
pub mod base64url;
mod delay_queue_task;
pub mod http;
pub mod keys;
pub mod logger;
pub mod pem;
mod real_ip;
#[cfg(feature = "redis")]
pub mod redis;
mod rng;
mod time;
mod tlds;

use std::{error::Error, future::Future, pin::Pin};

pub use delay_queue_task::*;
pub use real_ip::*;
pub use rng::*;
pub use time::*;
pub use tlds::*;

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
