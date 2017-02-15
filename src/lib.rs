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
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;
extern crate gettext;

use time::now_utc;

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
/// Builds the JSON payload, then signs it using the last key provided in
/// the configuration object.
fn create_jwt(app: &Config, email: &str, origin: &str, nonce: &str) -> String {
    let now = now_utc().to_timespec().sec;
    let payload = json!({
        "aud": origin,
        "email": email,
        "email_verified": email,
        "exp": now + app.token_ttl as i64,
        "iat": now,
        "iss": &app.public_url,
        "sub": email,
        "nonce": nonce,
    });
    let key = app.keys.last().expect("unable to locate signing key");
    key.sign_jws(&payload)
}
