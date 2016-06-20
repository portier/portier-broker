extern crate iron;
extern crate openssl;
extern crate rustc_serialize;
extern crate serde_json;

use iron::headers::ContentType;
use iron::prelude::{IronResult, Response};
use iron::status;
use openssl::bn::BigNum;
use rustc_serialize::base64::{self, ToBase64};
use serde_json::value::Value;

mod welcome;
mod oidc_config;
mod keys;
mod auth;
mod callback;
mod confirm;

pub use self::welcome::Welcome;
pub use self::oidc_config::OIDCConfig;
pub use self::keys::Keys;
pub use self::auth::Auth;
pub use self::callback::Callback;
pub use self::confirm::Confirm;


/// Helper function for returning an Iron response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
fn json_response(obj: &Value) -> IronResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    let mut rsp = Response::with((status::Ok, content));
    rsp.headers.set(ContentType::json());
    Ok(rsp)
}


/// Helper function to encode a `BigNum` as URL-safe base64-encoded bytes.
///
/// This is used for the public RSA key components returned by the
/// `KeysHandler`.
fn json_big_num(n: &BigNum) -> String {
    n.to_vec().to_base64(base64::URL_SAFE)
}
