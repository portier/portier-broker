extern crate iron;
extern crate openssl;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;

use iron::headers::ContentType;
use iron::prelude::{IronResult, Response};
use iron::status;
use openssl::bn::BigNum;
use rustc_serialize::base64::{self, ToBase64};
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use time::now_utc;
use {AppConfig, create_jwt};

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


/// HTML template used to have the user agent POST the identity token built
/// by the daemon instance to the RP's `redirect_uri`.
const FORWARD_TEMPLATE: &'static str = r#"<!DOCTYPE html>
<html>
  <head>
    <title>Let's Auth</title>
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        document.getElementById('form').submit();
      });
    </script>
  </head>
  <body>
    <form id="form" action="{{ return_url }}" method="post">
      <input type="hidden" name="id_token" value="{{ jwt }}">
    </form>
  </body>
</html>"#;


/// Iron handler for sending an identity token to the Relying Party.
///
/// Builds the JWT header and payload JSON data and signs it with the
/// configured private RSA key. Then uses `FORWARD_TEMPLATE` to embed the token
/// in a form that's POSTed to the RP's `redirect_uri` as soon as the page
/// is loaded.
fn send_jwt_response(app: &AppConfig, email: &str, origin: &str, redirect: &str) -> IronResult<Response> {
    let now = now_utc().to_timespec().sec;
    let payload = ObjectBuilder::new()
        .insert("aud", origin)
        .insert("email", email)
        .insert("email_verified", email)
        .insert("exp", now + app.token_validity)
        .insert("iat", now)
        .insert("iss", &app.base_url)
        .insert("sub", email)
        .unwrap();
    let headers = ObjectBuilder::new()
        .insert("kid", "base")
        .insert("alg", "RS256")
        .unwrap();
    let jwt = create_jwt(&app.priv_key,
                         &serde_json::to_string(&headers).unwrap(),
                         &serde_json::to_string(&payload).unwrap());

    let html = FORWARD_TEMPLATE.replace("{{ return_url }}", redirect)
        .replace("{{ jwt }}", &jwt);
    let mut rsp = Response::with((status::Ok, html));
    rsp.headers.set(ContentType::html());
    Ok(rsp)
}
