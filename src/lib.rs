extern crate emailaddress;
extern crate iron;
extern crate openssl;
extern crate rand;
extern crate redis;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

pub mod email;
pub mod oidc;

use emailaddress::EmailAddress;
use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::modifiers;
use iron::prelude::*;
use iron::status;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use serde_json::builder::ObjectBuilder;
use serde_json::de::from_reader;
use serde_json::value::Value;
use rand::{OsRng, Rng};
use redis::Client;
use rustc_serialize::base64::{self, ToBase64};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::iter::Iterator;
use time::now_utc;
use urlencoded::UrlEncodedBody;


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


/// Configuration data for a "famous" identity provider.
///
/// Used as part of the `AppConfig` struct.
#[derive(Clone)]
struct ProviderConfig {
    /// URL pointing to the OpenID configuration document.
    discovery: String,
    /// Client ID issued for this daemon instance by the provider.
    client_id: String,
    /// Secret issued for this daemon instance by the provider.
    secret: String,
    /// Issuer origin as used in identity tokens issued by the provider.
    /// Used to check that the issuer in the token matches expectations.
    issuer: String,
}


/// Configuration data for this daemon instance.
#[derive(Clone)]
pub struct AppConfig {
    /// Version of the daemon (used in the `WelcomeHandler`).
    version: String,
    /// Base URL where this daemon can be found. This is used to construct
    /// callback URLs.
    base_url: String,
    /// Private key used to sign identity tokens.
    priv_key: PKey,
    /// Redis database connector.
    store: Client,
    /// Duration in seconds for expiry of data stored in Redis.
    expire_keys: usize,
    /// Email sender (email address, then human-readable name).
    sender: (String, String),
    /// Duration in seconds for expiration of identity tokens.
    token_validity: i64,
    /// A map of "famous" identity providers. Each key is an email domain,
    /// the value holds the configuration required to act as an application
    /// doing OpenID Connect against the provider.
    providers: BTreeMap<String, ProviderConfig>,
}


/// Implementation with single method to read configuration from JSON.
impl AppConfig {
    pub fn from_json_file(file_name: &str) -> AppConfig {

        let config_file = File::open(file_name).unwrap();
        let config_value: Value = from_reader(BufReader::new(config_file)).unwrap();
        let config = config_value.as_object().unwrap();

        // The `private_key_file` key in the JSON object should hold a file
        // name pointing to a PEM-encoded private RSA key.
        let key_file_name = config["private_key_file"].as_string().unwrap();
        let priv_key_file = File::open(key_file_name).unwrap();
        let mut reader = BufReader::new(priv_key_file);
        let sender = config["sender"].as_object().unwrap();
        AppConfig {
            // Use the crate's version as defined in Cargo.toml.
            version: env!("CARGO_PKG_VERSION").to_string(),
            base_url: config["base_url"].as_string().unwrap().to_string(),
            priv_key: PKey::private_key_from_pem(&mut reader).unwrap(),
            store: Client::open(config["redis"].as_string().unwrap()).unwrap(),
            expire_keys: config["expire_keys"].as_u64().unwrap() as usize,
            sender: (
                sender["address"].as_string().unwrap().to_string(),
                sender["name"].as_string().unwrap().to_string(),
            ),
            token_validity: config["token_validity"].as_i64().unwrap(),
            providers: config["providers"].as_object().unwrap().iter()
                .map(|(host, params)| {
                    let pobj = params.as_object().unwrap();
                    (host.clone(), ProviderConfig {
                        discovery: pobj["discovery"].as_string().unwrap().to_string(),
                        client_id: pobj["client_id"].as_string().unwrap().to_string(),
                        secret: pobj["secret"].as_string().unwrap().to_string(),
                        issuer: pobj["issuer"].as_string().unwrap().to_string(),
                    })
                })
                .collect::<BTreeMap<String, ProviderConfig>>(),
        }

    }
}


/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
pub struct WelcomeHandler { pub app: AppConfig }
impl Handler for WelcomeHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("ladaemon", "Welcome")
            .insert("version", &self.app.version)
            .unwrap())
    }
}


/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `base_url` configuration value.
pub struct OIDConfigHandler { pub app: AppConfig }
impl Handler for OIDConfigHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("issuer", &self.app.base_url)
            .insert("authorization_endpoint",
                    format!("{}/auth", self.app.base_url))
            .insert("jwks_uri", format!("{}/keys.json", self.app.base_url))
            .insert("scopes_supported", vec!["openid", "email"])
            .insert("claims_supported",
                    vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
            .insert("response_types_supported", vec!["id_token"])
            .insert("response_modes_supported", vec!["form_post"])
            .insert("grant_types_supported", vec!["implicit"])
            .insert("subject_types_supported", vec!["public"])
            .insert("id_token_signing_alg_values_supported", vec!["RS256"])
            .unwrap())
    }
}


/// Helper function to encode a `BigNum` as URL-safe base64-encoded bytes.
///
/// This is used for the public RSA key components returned by the
/// `KeysHandler`.
fn json_big_num(n: &BigNum) -> String {
    n.to_vec().to_base64(base64::URL_SAFE)
}


/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
fn session_id(email: &EmailAddress, client_id: &str) -> String {
    let mut rng = OsRng::new().unwrap();
    let mut bytes_iter = rng.gen_iter();
    let rand_bytes: Vec<u8> = (0..16).map(|_| bytes_iter.next().unwrap()).collect();

    let mut hasher = hash::Hasher::new(hash::Type::SHA256);
    hasher.write(email.to_string().as_bytes()).unwrap();
    hasher.write(client_id.as_bytes()).unwrap();
    hasher.write(&rand_bytes).unwrap();
    hasher.finish().to_base64(base64::URL_SAFE)
}


/// Iron handler for the JSON Web Key Set document.
///
/// Currently only supports a single RSA key (as configured), which is
/// published with the `"base"` key ID, scoped to signing usage. Relying
/// Parties will need to fetch this data to be able to verify identity tokens
/// issued by this daemon instance.
pub struct KeysHandler { pub app: AppConfig }
impl Handler for KeysHandler {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        let rsa = self.app.priv_key.get_rsa();
        json_response(&ObjectBuilder::new()
            .insert_array("keys", |builder| {
                builder.push_object(|builder| {
                    builder.insert("kty", "RSA")
                        .insert("alg", "RS256")
                        .insert("use", "sig")
                        .insert("kid", "base")
                        .insert("n", json_big_num(&rsa.n().unwrap()))
                        .insert("e", json_big_num(&rsa.e().unwrap()))
                })
            })
            .unwrap())
    }
}


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
pub struct AuthHandler { pub app: AppConfig }
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
        if self.app.providers.contains_key(&email_addr.domain) {

            // OIDC authentication. Using 302 Found for redirection here. Note
            // that, per RFC 7231, a user agent MAY change the request method
            // from POST to GET for the subsequent request.
            let auth_url = oidc::request(&self.app, params);
            Ok(Response::with((status::Found, modifiers::Redirect(auth_url))))

        } else {

            // Email loop authentication. For now, returns a JSON response;
            // empty if successful, otherwise contains an error.
            let obj = email::request(&self.app, params);
            json_response(&obj)

        }
    }
}



/// Helper method to create a JWT for a given email address and origin.
///
/// Builds the JSON payload and header, encoding with (URL-safe)
/// base64-encoding, then hashing and signing with the provided private key.
/// Returns the full JWT.
fn create_jwt(app: &AppConfig, email: &str, origin: &str) -> String {

    let now = now_utc().to_timespec().sec;
    let payload = serde_json::to_string(
        &ObjectBuilder::new()
            .insert("aud", origin)
            .insert("email", email)
            .insert("email_verified", email)
            .insert("exp", now + app.token_validity)
            .insert("iat", now)
            .insert("iss", &app.base_url)
            .insert("sub", email)
            .unwrap()
        ).unwrap();
    let header = serde_json::to_string(
        &ObjectBuilder::new()
            .insert("kid", "base")
            .insert("alg", "RS256")
            .unwrap()
        ).unwrap();

    let mut input = Vec::<u8>::new();
    input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    input.push(b'.');
    input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    let sha256 = hash::hash(hash::Type::SHA256, &input);
    let sig = app.priv_key.sign(&sha256);
    input.push(b'.');
    input.extend(sig.to_base64(base64::URL_SAFE).into_bytes());
    String::from_utf8(input).unwrap()

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


/// Helper function for sending an identity token to the Relying Party.
///
/// Builds the JWT header and payload JSON data and signs it with the
/// configured private RSA key. Then uses `FORWARD_TEMPLATE` to embed the token
/// in a form that's POSTed to the RP's `redirect_uri` as soon as the page
/// is loaded.
fn send_jwt_response(jwt: &str, redirect: &str) -> IronResult<Response> {
    let html = FORWARD_TEMPLATE.replace("{{ return_url }}", redirect)
        .replace("{{ jwt }}", jwt);
    let mut rsp = Response::with((status::Ok, html));
    rsp.headers.set(ContentType::html());
    Ok(rsp)
}
