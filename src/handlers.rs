extern crate lettre;
extern crate rand;

use emailaddress::EmailAddress;
use hyper::client::Client as HttpClient;
use hyper::header::ContentType as HyContentType;
use hyper::header::Headers;
use iron::middleware::Handler;
use iron::prelude::*;
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
use redis::{Commands, RedisResult};
use rustc_serialize::base64::FromBase64;
use std::collections::HashMap;
use std::error::Error;
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use super::{CODE_CHARS, AppConfig, json_big_num, json_response, oauth_request, send_jwt_response, session_id};

/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
pub struct Welcome { pub app: AppConfig }
impl Handler for Welcome {
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
/// Calls the `oauth_request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, sends an
/// email to the user with a randomly generated one-time pad. This code is
/// stored in Redis (with timeout) for later verification.
pub struct AuthHandler { pub app: AppConfig }
impl Handler for AuthHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
        if self.app.providers.contains_key(&email_addr.domain) {
            return oauth_request(&self.app, &params);
        }

        // Generate a 6-character one-time pad.
        let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

        // Store data for this request in Redis, to reference when user uses
        // the generated link.
        let client_id = &params.get("client_id").unwrap()[0];
        let session = session_id(&email_addr, client_id);
        let key = format!("session:{}", session);
        let set_res: RedisResult<String> = self.app.store.hset_multiple(key.clone(), &[
            ("email", email_addr.to_string()),
            ("client_id", client_id.clone()),
            ("code", chars.clone()),
            ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
        ]);
        let exp_res: RedisResult<bool> = self.app.store.expire(key.clone(), self.app.expire_keys);

        // Generate the URL used to verify email address ownership.
        let href = format!("{}/confirm?session={}&code={}",
                           self.app.base_url,
                           utf8_percent_encode(&session, QUERY_ENCODE_SET),
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
pub struct CallbackHandler { pub app: AppConfig }
impl Handler for CallbackHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        // Extract arguments from the query string.
        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let session = &params.get("state").unwrap()[0];

        // Validate that the callback matches an auth request in Redis.
        let key = format!("session:{}", session);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.len() == 0 {
            let obj = ObjectBuilder::new()
                .insert("error", "nonce fail")
                .insert("key", key);
            return json_response(&obj.unwrap());
        }

        let email_addr = EmailAddress::new(stored.get("email").unwrap()).unwrap();
        let origin = stored.get("client_id").unwrap();

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
        assert!(token_addr == email_addr.to_string());
        let now = now_utc().to_timespec().sec;
        let exp = jwt_payload.find("exp").unwrap().as_i64().unwrap();
        assert!(now < exp);

        // If everything is okay, build a new identity token and send it
        // to the relying party.
        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(&self.app, &email_addr.to_string(), &origin, redirect)

    }
}


/// Iron handler for one-time pad email loop confirmation.
///
/// Verifies the one-time pad as provided in the query string arguments against
/// the data saved in Redis. If the code matches, send an identity token to the
/// RP using `send_jwt_response()`. Otherwise, returns a JSON response with an
/// error message. TODO: the latter is obviously wrong.
pub struct ConfirmHandler { pub app: AppConfig }
impl Handler for ConfirmHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let session = &params.get("session").unwrap()[0];
        let key = format!("session:{}", session);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.len() == 0 {
            let obj = ObjectBuilder::new().insert("error", "not found");
            return json_response(&obj.unwrap());
        }

        let req_code = &params.get("code").unwrap()[0];
        if req_code != stored.get("code").unwrap() {
            let mut obj = ObjectBuilder::new().insert("error", "code fail");
            obj = obj.insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        let email = stored.get("email").unwrap();
        let client_id = stored.get("client_id").unwrap();
        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(&self.app, email, client_id, redirect)

    }
}
