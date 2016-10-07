extern crate emailaddress;
#[macro_use]
extern crate log;
extern crate hyper;
extern crate iron;
extern crate redis;
extern crate serde;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

use emailaddress::EmailAddress;
use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::modifiers;
use iron::method::Method;
use iron::prelude::*;
use iron::status;
use serde_json::builder::{ArrayBuilder, ObjectBuilder};
use serde_json::value::Value;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::sync::Arc;
use time::now_utc;
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};

pub mod error;
pub mod config;
pub use config::AppConfig;
pub mod crypto;
pub mod email;
pub mod oidc;
pub mod store;
pub mod store_cache;


/// Macro that creates Handler implementations that log the request,
/// and keep a reference to the AppConfig.
macro_rules! broker_handler {
    ( $name:ident , | $app:ident, $req:ident | $body:block ) => {
        pub struct $name {
            pub app: Arc<AppConfig>,
        }
        impl $name {
            pub fn new(app: &Arc<AppConfig>) -> Self {
                $name { app: app.clone() }
            }
        }
        impl Handler for $name {
            fn handle(&self, $req: &mut Request) -> IronResult<Response> {
                info!("{} {}", $req.method, $req.url);
                let $app = &self.app;
                $body
            }
        }
    }
}


/// Helper function for returning an Iron response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
fn json_response(obj: &Value) -> IronResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    Ok(Response::with((status::Ok,
                       modifiers::Header(ContentType::json()),
                       content)))
}


/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
broker_handler!(WelcomeHandler, |_app, req| {
    json_response(&ObjectBuilder::new()
        .insert("ladaemon", "Welcome")
        .insert("version", env!("CARGO_PKG_VERSION"))
        .build())
});


/// Iron handler for files in .well-known.
///
/// Mainly directed at Let's Encrypt verification. Returns text/plain always.
broker_handler!(WellKnownHandler, |_app, req| {
    let mut file_name = env::current_dir().unwrap();
    file_name.push(req.url.path().join("/"));
    let file_res = File::open(file_name);
    if file_res.is_err() {
        return Ok(Response::with((status::NotFound)));
    }
    let mut bytes = Vec::<u8>::new();
    let mut reader = BufReader::new(file_res.unwrap());
    let _ = reader.read_to_end(&mut bytes).unwrap();
    Ok(Response::with((status::Ok,
                       modifiers::Header(ContentType::plaintext()),
                       bytes)))
});


/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `base_url` configuration value.
broker_handler!(OIDConfigHandler, |app, req| {
    json_response(&ObjectBuilder::new()
        .insert("issuer", &app.base_url)
        .insert("authorization_endpoint",
                format!("{}/auth", app.base_url))
        .insert("jwks_uri", format!("{}/keys.json", app.base_url))
        .insert("scopes_supported", vec!["openid", "email"])
        .insert("claims_supported",
                vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
        .insert("response_types_supported", vec!["id_token"])
        .insert("response_modes_supported", vec!["form_post"])
        .insert("grant_types_supported", vec!["implicit"])
        .insert("subject_types_supported", vec!["public"])
        .insert("id_token_signing_alg_values_supported", vec!["RS256"])
        .build())
});


/// Iron handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
broker_handler!(KeysHandler, |app, req| {
    let mut keys = ArrayBuilder::new();
    for key in &app.keys {
        keys = keys.push(key.public_jwk())
    }
    json_response(&ObjectBuilder::new()
                      .insert("keys", keys.build())
                      .build())
});


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
broker_handler!(AuthHandler, |app, req| {
    let params = try!(
        match req.method {
            Method::Get => {
                req.get_ref::<UrlEncodedQuery>()
                    .map_err(|e| IronError::new(e, (status::BadRequest,
                                                    "no query string in GET request")))
            },
            Method::Post => {
                req.get_ref::<UrlEncodedBody>()
                    .map_err(|e| IronError::new(e, (status::BadRequest,
                                                    "no query string in POST data")))
            },
            _ => {
                panic!("Unsupported method: {}", req.method)
            }
        }
    );
    let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
    let client_id = &params.get("client_id").unwrap()[0];
    let nonce = &params.get("nonce").unwrap()[0];
    let redirect_uri = &params.get("redirect_uri").unwrap()[0];
    if app.providers.contains_key(&email_addr.domain) {

        // OIDC authentication. Using 302 Found for redirection here. Note
        // that, per RFC 7231, a user agent MAY change the request method
        // from POST to GET for the subsequent request.
        let auth_url = oidc::request(app, email_addr, client_id, nonce, redirect_uri);
        Ok(Response::with((status::Found, modifiers::Redirect(auth_url))))

    } else {

        // Email loop authentication. For now, returns 204.
        // TODO: Return a form that allows the user to enter the code.
        email::request(app, email_addr, client_id, nonce, redirect_uri);
        Ok(Response::with((status::NoContent)))

    }
});


/// Helper method to create a JWT for a given email address and origin.
///
/// Builds the JSON payload, then signs it using the last key provided in
/// the configuration object.
fn create_jwt(app: &AppConfig, email: &str, origin: &str, nonce: &str) -> String {
    let now = now_utc().to_timespec().sec;
    let payload = &ObjectBuilder::new()
        .insert("aud", origin)
        .insert("email", email)
        .insert("email_verified", email)
        .insert("exp", now + app.token_validity as i64)
        .insert("iat", now)
        .insert("iss", &app.base_url)
        .insert("sub", email)
        .insert("nonce", nonce)
        .build();
    app.keys.last().unwrap().sign_jws(&payload)
}


/// HTML template used to have the user agent POST the identity token built
/// by the daemon instance to the RP's `redirect_uri`.
const FORWARD_TEMPLATE: &'static str = include_str!("forward-template.html");


/// Helper function for returning result to the Relying Party.
///
/// Takes a `Result` from one of the verification functions and embeds it in
/// a form in the `FORWARD_TEMPLATE`, from where it's POSTED to the RP's
/// `redirect_ur` as soon as the page has loaded. Result can either be an error
/// message or a JWT asserting the user's email address identity.
/// TODO: return error to RP instead of in a simple HTTP response.
fn return_to_relier(result: Result<(String, String), String>)
                    -> IronResult<Response> {

    if result.is_err() {
        return json_response(&ObjectBuilder::new()
                            .insert("error", result.unwrap_err())
                            .build());
    }

    let (jwt, redirect) = result.unwrap();
    let html = FORWARD_TEMPLATE.replace("{{ return_url }}", &redirect)
        .replace("{{ jwt }}", &jwt);
    let mut rsp = Response::with((status::Ok, html));
    rsp.headers.set(ContentType::html());
    Ok(rsp)

}


/// Iron handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
broker_handler!(ConfirmHandler, |app, req| {
    let params = req.get_ref::<UrlEncodedQuery>().unwrap();
    let session_id = &params.get("session").unwrap()[0];
    let code = &params.get("code").unwrap()[0];
    return_to_relier(email::verify(app, session_id, code))
});


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
/// Verify the callback data and return the resulting token or error.
broker_handler!(CallbackHandler, |app, req| {
    let params = req.get_ref::<UrlEncodedQuery>().unwrap();
    let session = &params.get("state").unwrap()[0];
    let code = &params.get("code").unwrap()[0];
    return_to_relier(oidc::verify(app, session, code))
});
