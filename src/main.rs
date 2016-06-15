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
use hyper::header::ContentType as HyContentType;
use hyper::header::Headers;
use iron::headers::ContentType;
use iron::middleware::Handler;
use iron::modifiers;
use iron::prelude::*;
use iron::status;
use iron::Url;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use openssl::crypto::rsa::RSA;
use serde_json::builder::ObjectBuilder;
use serde_json::de::{from_reader, from_slice};
use serde_json::value::Value;
use rand::{OsRng, Rng};
use redis::{Client, Commands, RedisResult};
use router::Router;
use rustc_serialize::base64::{self, FromBase64, ToBase64};
use rustc_serialize::hex::ToHex;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Write};
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::{QueryMap, UrlEncodedBody, UrlEncodedQuery};

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
struct AppConfig {
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
    fn from_json_file(file_name: &str) -> AppConfig {

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
struct WelcomeHandler { app: AppConfig }
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
struct OIDConfigHandler { app: AppConfig }
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


/// Iron handler for the JSON Web Key Set document.
///
/// Currently only supports a single RSA key (as configured), which is
/// published with the `"base"` key ID, scoped to signing usage. Relying
/// Parties will need to fetch this data to be able to verify identity tokens
/// issued by this daemon instance.
struct KeysHandler { app: AppConfig }
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
    let key = format!("{}:{}", email_addr, client_id);

    // Generate random bytes in hex to act as our nonce.
    let mut rng = OsRng::new().unwrap();
    let mut bytes_iter = rng.gen_iter();
    let rand_bytes: Vec<u8> = (0..128).map(|_| bytes_iter.next().unwrap()).collect();
    let state = hash::hash(hash::Type::SHA256, &rand_bytes).to_hex();

    // Store the nonce and the RP's `redirect_uri` in Redis for use in the
    // callback handler.
    let _: String = app.store.hset_multiple(key.clone(), &[
        ("state", state.clone()),
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
        &utf8_percent_encode(&format!("{}:{}", key, state), QUERY_ENCODE_SET).to_string(),
        "&login_hint=",
        &utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET).to_string(),
    ].join("")).unwrap();
    // Using 302 Found for redirection here. Note that, per RFC 7231, a user
    // agent MAY change the request method from POST to GET for the subsequent
    // request.
    Ok(Response::with((status::Found, modifiers::Redirect(auth_url))))

}


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oauth_request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, sends an
/// email to the user with a randomly generated one-time pad. This code is
/// stored in Redis (with timeout) for later verification.
struct AuthHandler { app: AppConfig }
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        // Generate a 6-character one-time pad.
        let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();
        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
        if self.app.providers.contains_key(&email_addr.domain) {
            return oauth_request(&self.app, &params);
        }

        // Store data for this request in Redis, to reference when user uses
        // the generated link. TODO: the Redis key here and elsewhere scope by
        // RP origin and user email. This means separate login attempts cannot
        // be distinguished. Origin and email are also exposed in the generated
        // URL. It might be better to hash or HMAC the key.
        let client_id = &params.get("client_id").unwrap()[0];
        let key = format!("{}:{}", email_addr, client_id);
        let set_res: RedisResult<String> = self.app.store.hset_multiple(key.clone(), &[
            ("code", chars.clone()),
            ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
        ]);
        let exp_res: RedisResult<bool> = self.app.store.expire(key.clone(), self.app.expire_keys);

        // Generate the URL used to verify email address ownership.
        let href = format!("{}/confirm?email={}&origin={}&code={}",
                           self.app.base_url,
                           utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET),
                           utf8_percent_encode(client_id, QUERY_ENCODE_SET),
                           utf8_percent_encode(&chars, QUERY_ENCODE_SET));

        // Generate a simple email and send it through the SMTP server running
        // on localhost. TODO: make the SMTP host configurable. Also, consider
        // using templates for the email message.
        let email = EmailBuilder::new()
            .to(email_addr.to_string().as_str())
            .from((self.app.sender.0.as_str(), self.app.sender.1.as_str()))
            .body(&format!("Enter your login code:\n\n{}\n\nOr click this link:\n\n{}",
                           chars, href))
            .subject(&format!("Code: {} - Finish logging in to {}", chars, client_id))
            .build().unwrap();
        let mut mailer = SmtpTransportBuilder::localhost().unwrap().build();
        let result = mailer.send(email);
        mailer.close();

        // TODO: for debugging, this part returns a JSON response with some
        // debugging stuff/diagnostics. Instead, it should return a form that
        // allows the user to enter the code they have received.
        let mut obj = ObjectBuilder::new();
        if !result.is_ok() {
            let error = result.unwrap_err();
            obj = obj.insert("error", error.to_string());
            obj = match error {
                lettre::transport::error::Error::IoError(inner) => {
                    obj.insert("cause", inner.description())
                }
                _ => obj,
            }
        }
        if !set_res.is_ok() {
            obj = obj.insert("hset_multiple", set_res.unwrap_err().to_string());
        }
        if !exp_res.is_ok() {
            obj = obj.insert("expire", exp_res.unwrap_err().to_string());
        }
        json_response(&obj.unwrap())

    }
}


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
/// Here, we match the returned email address and nonce against our Redis data,
/// then extract the identity token returned by the provider and verify it.
/// If it checks out, we create and sign a new token, which is returned in a
/// short HTML form that POSTs it back to the RP (see `send_jwt_reponse()`).
struct CallbackHandler { app: AppConfig }
impl Handler for CallbackHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        // Extract arguments from the query string.
        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let state: Vec<&str> = params.get("state").unwrap()[0].split(":").collect();
        let email_addr = EmailAddress::new(state[0]).unwrap();
        let origin = state[1..state.len() - 1].join(":");
        let nonce = state[state.len() - 1];

        // Validate that the callback matches an auth request in Redis.
        let key = format!("{}:{}", state[0], origin);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.get("state").is_none() || nonce != stored.get("state").unwrap() {
            let obj = ObjectBuilder::new()
                .insert("error", "nonce fail")
                .insert("key", key)
                .insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        // Request the provider's Discovery document to get the
        // `token_endpoint` and `jwks_uri` values from it. TODO: save these
        // when requesting the Discovery document in the `oauth_request()`
        // function, and/or cache them by provider host.
        let client = HttpClient::new();
        let provider = &self.app.providers[&email_addr.domain];
        let rsp = client.get(&provider.discovery).send().unwrap();
        let val: Value = from_reader(rsp).unwrap();
        let config = val.as_object().unwrap();
        let token_url = config["token_endpoint"].as_string().unwrap();

        // Create form data for the Token Request, where we exchange the code
        // received in this callback request for an identity token (while
        // proving our identity by passing the client secret value).
        let code = &params.get("code").unwrap()[0];
        let body: String = vec![
            "code=",
            &utf8_percent_encode(code, QUERY_ENCODE_SET).to_string(),
            "&client_id=",
            &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
            "&client_secret=",
            &utf8_percent_encode(&provider.secret, QUERY_ENCODE_SET).to_string(),
            "&redirect_uri=",
            &utf8_percent_encode(&format!("{}/callback", &self.app.base_url),
                                 QUERY_ENCODE_SET).to_string(),
            "&grant_type=authorization_code",
        ].join("");

        // Send the Token Request and extract the `id_token` from the response.
        let mut headers = Headers::new();
        headers.set(HyContentType::form_url_encoded());
        let token_rsp = client.post(token_url).headers(headers).body(&body).send().unwrap();
        let token_obj: Value = from_reader(token_rsp).unwrap();
        let id_token = token_obj.find("id_token").unwrap().as_string().unwrap();

        // Extract the header from the JWT structure. First order of business
        // is to determine what key was used to sign the token, so we can then
        // verify the signature.
        let parts: Vec<&str> = id_token.split(".").collect();
        let jwt_header: Value = from_slice(&parts[0].from_base64().unwrap()).unwrap();
        let kid = jwt_header.find("kid").unwrap().as_string().unwrap();

        // Grab the keys from the provider and find keys that match the key ID
        // used to sign the identity token.
        let keys_url = config["jwks_uri"].as_string().unwrap();
        let keys_rsp = client.get(keys_url).send().unwrap();
        let keys_doc: Value = from_reader(keys_rsp).unwrap();
        let keys = keys_doc.find("keys").unwrap().as_array().unwrap().iter()
            .filter(|key_obj| {
                key_obj.find("kid").unwrap().as_string().unwrap() == kid &&
                key_obj.find("use").unwrap().as_string().unwrap() == "sig"
            })
            .collect::<Vec<&Value>>();

        // Verify that we found exactly one key matching the key ID.
        // Then, use the data to build a public key object for verification.
        assert!(keys.len() == 1);
        let n_b64 = keys[0].find("n").unwrap().as_string().unwrap();
        let e_b64 = keys[0].find("e").unwrap().as_string().unwrap();
        let n = BigNum::new_from_slice(&n_b64.from_base64().unwrap()).unwrap();
        let e = BigNum::new_from_slice(&e_b64.from_base64().unwrap()).unwrap();
        let mut pub_key = PKey::new();
        pub_key.set_rsa(&RSA::from_public_components(n, e).unwrap());

        // Verify the identity token's signature.
        let message = format!("{}.{}", parts[0], parts[1]);
        let sha256 = hash::hash(hash::Type::SHA256, &message.as_bytes());
        let sig = parts[2].from_base64().unwrap();
        let verified = pub_key.verify(&sha256, &sig);
        assert!(verified);

        // Verify that the issuer matches the configured value.
        let jwt_payload: Value = from_slice(&parts[1].from_base64().unwrap()).unwrap();
        let iss = jwt_payload.find("iss").unwrap().as_string().unwrap();
        let issuer_origin = vec!["https://", &provider.issuer].join("");
        assert!(iss == provider.issuer || iss == issuer_origin);

        // Verify the audience, subject, and expiry.
        let aud = jwt_payload.find("aud").unwrap().as_string().unwrap();
        assert!(aud == provider.client_id);
        let token_addr = jwt_payload.find("email").unwrap().as_string().unwrap();
        assert!(token_addr == state[0]);
        let now = now_utc().to_timespec().sec;
        let exp = jwt_payload.find("exp").unwrap().as_i64().unwrap();
        assert!(now < exp);

        // If everything is okay, build a new identity token and send it
        // to the relying party.
        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(&self.app, state[0], &origin, redirect)

    }
}


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


/// Iron handler for one-time pad email loop confirmation.
///
/// Verifies the one-time pad as provided in the query string arguments against
/// the data saved in Redis. If the code matches, send an identity token to the
/// RP using `send_jwt_response()`. Otherwise, returns a JSON response with an
/// error message. TODO: the latter is obviously wrong.
struct ConfirmHandler { app: AppConfig }
impl Handler for ConfirmHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let email = &params.get("email").unwrap()[0];
        let origin = &params.get("origin").unwrap()[0];
        let key = format!("{}:{}", email, origin);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();

        let req_code = &params.get("code").unwrap()[0];
        if stored.get("code").is_none() || req_code != stored.get("code").unwrap() {
            let mut obj = ObjectBuilder::new().insert("error", "code fail");
            obj = obj.insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(&self.app, email, origin, redirect)

    }
}


/// The `main()` method. Will loop forever to serve HTTP requests.
fn main() {

    // Make sure we get a file name where we can find configuration.
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        io::stderr().write(b"no configuration file specified\n").unwrap();
        return;
    }

    // Read the configuration from the provided file.
    let app = AppConfig::from_json_file(&args[1]);

    // Register all handlers with a router object. TODO: cloning the
    // configuration object is kind of ugly, but is apparently needed with
    // the way the Iron `Handler` trait is defined. Also, it would be cleaner
    // if the handlers could just be a function, instead of single-method
    // impls.
    let mut router = Router::new();
    router.get("/", WelcomeHandler { app: app.clone() });
    router.get("/.well-known/openid-configuration",
               OIDConfigHandler { app: app.clone() });
    router.get("/keys.json", KeysHandler { app: app.clone() });
    router.post("/auth", AuthHandler { app: app.clone() });
    router.get("/confirm", ConfirmHandler { app: app.clone() });
    router.get("/callback", CallbackHandler { app: app.clone() });

    // Iron will take care of stuff from here. It should spin up a number of
    // threads according to the number of cores available. TODO: make the
    // interface on which we listen configurable.
    Iron::new(router).http("0.0.0.0:3333").unwrap();

}
