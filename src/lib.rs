pub mod handlers;

extern crate emailaddress;
extern crate hyper;
extern crate iron;
extern crate lettre;
extern crate openssl;
extern crate rand;
extern crate redis;
extern crate router;
extern crate rustc_serialize;
extern crate serde_json;
extern crate time;
extern crate url;
extern crate urlencoded;

use emailaddress::EmailAddress;
use hyper::client::Client as HttpClient;
use iron::headers::ContentType;
use iron::modifiers;
use iron::prelude::{IronResult, Response};
use iron::status;
use iron::Url;
use lettre::transport::EmailTransport;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use serde_json::builder::ObjectBuilder;
use serde_json::de::from_reader;
use serde_json::value::Value;
use rand::{OsRng, Rng};
use redis::{Client, Commands};
use rustc_serialize::base64::{self, ToBase64};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Write};
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::QueryMap;


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
    /// Version of the daemon (used in the `Welcome` Handler).
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


/// Helper method to issue an OAuth authorization request.
///
/// When an authentication request comes in and matches one of the "famous"
/// identity providers configured in the `AppConfig`, we redirect the client
/// to an Authentication Request URL, which we discover by reading the
/// provider's configured Discovery URL. We pass in the client ID we received
/// when pre-registering for the provider, as well as a callback URL which the
/// user will be redirected back to after confirming (or denying) the
/// Authentication Request. Included in the request is a nonce which we can
/// later use to definitively match the callback to this request.
fn oauth_request(app: &AppConfig, params: &QueryMap) -> IronResult<Response> {
    let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
    let client_id = &params.get("client_id").unwrap()[0];
    let session = session_id(&email_addr, client_id);

    // Store the nonce and the RP's `redirect_uri` in Redis for use in the
    // callback handler.
    let key = format!("session:{}", session);
    let _: String = app.store.hset_multiple(key.clone(), &[
        ("email", email_addr.to_string()),
        ("client_id", client_id.clone()),
        ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
    ]).unwrap();
    let _: bool = app.store.expire(key.clone(), app.expire_keys).unwrap();

    // Retrieve the provider's Discovery document and extract the
    // `authorization_endpoint` from it.
    // TODO: cache other data for use in the callback handler, so that we
    // don't have to request the Discovery document twice. We could even store
    // per-provider data in Redis so we can amortize the cost of discovery.
    let provider = &app.providers[&email_addr.domain];
    let client = HttpClient::new();
    let rsp = client.get(&provider.discovery).send().unwrap();
    let val: Value = from_reader(rsp).unwrap();
    let config = val.as_object().unwrap();
    let authz_base = config["authorization_endpoint"].as_string().unwrap();

    // Create the URL to redirect to, properly escaping all parameters.
    let auth_url = Url::parse(&vec![
        authz_base,
        "?",
        "client_id=",
        &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
        "&response_type=code",
        "&scope=",
        &utf8_percent_encode("openid email", QUERY_ENCODE_SET).to_string(),
        "&redirect_uri=",
        &utf8_percent_encode(&format!("{}/callback", &app.base_url),
                             QUERY_ENCODE_SET).to_string(),
        "&state=",
        &utf8_percent_encode(&session, QUERY_ENCODE_SET).to_string(),
        "&login_hint=",
        &utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET).to_string(),
    ].join("")).unwrap();
    // Using 302 Found for redirection here. Note that, per RFC 7231, a user
    // agent MAY change the request method from POST to GET for the subsequent
    // request.
    Ok(Response::with((status::Found, modifiers::Redirect(auth_url))))
}


/// Characters eligible for inclusion in the email loop one-time pad.
///
/// Currently includes all numbers, lower- and upper-case ASCII letters,
/// except those that could potentially cause confusion when reading back.
/// (That is, '1', '5', '8', '0', 'b', 'i', 'l', 'o', 's', 'u', 'B', 'D', 'I'
/// and 'O'.)
const CODE_CHARS: &'static [char] = &[
    '2', '3', '4', '6', '7', '9', 'a', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 't', 'v', 'w', 'x', 'y', 'z', 'A', 'C', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z',
];


/// Helper method to create a JWT from given header and payload.
///
/// Takes care of UTF-8 and (URL-safe) base64-encoding, then hashing and
/// signing with the provided private key. Returns the full JWT.
fn create_jwt(key: &PKey, header: &str, payload: &str) -> String {
    let mut input = Vec::<u8>::new();
    input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    input.push(b'.');
    input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
    let sha256 = hash::hash(hash::Type::SHA256, &input);
    let sig = key.sign(&sha256);
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
