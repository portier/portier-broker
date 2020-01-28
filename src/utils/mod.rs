pub mod base64url;
pub mod http;
pub mod pem;
pub mod serde;

use std::{error::Error, future::Future, pin::Pin};

pub type BoxError = Box<dyn Error + Send + Sync>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
