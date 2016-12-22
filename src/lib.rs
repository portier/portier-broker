extern crate chrono;
extern crate emailaddress;
#[macro_use]
extern crate log;
#[macro_use]
extern crate hyper;
extern crate iron;
extern crate lettre;
extern crate mustache;
extern crate redis;
extern crate serde;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

use chrono::{UTC};
use serde_json::builder::ObjectBuilder;

pub mod error;
pub mod config;
pub use config::{Config, ConfigBuilder};
pub mod crypto;
pub mod email_bridge;
pub mod middleware;
pub mod handlers;
pub mod oidc_bridge;
pub mod store;
pub mod store_cache;
pub mod store_limits;
pub mod validation;


/// Helper method to create a JWT for a given email address and origin.
///
/// Builds the JSON payload, then signs it using the last valid key provided
/// in the configuration object.
fn create_jwt(app: &Config, email: &str, origin: &str, nonce: &str)
              -> Result<String, String> {
    let now = UTC::now();
    let timestamp = now.timestamp();

    let payload = &ObjectBuilder::new()
        .insert("aud", origin)
        .insert("email", email)
        .insert("email_verified", email)
        .insert("exp", timestamp + app.token_ttl as i64)
        .insert("iat", timestamp)
        .insert("iss", &app.public_url)
        .insert("sub", email)
        .insert("nonce", nonce)
        .build();

    let key = app.keys.iter().rev().find(|key| key.is_valid_at(&now))
        .ok_or("no valid key found")?;
    Ok(key.sign_jws(payload))
}
