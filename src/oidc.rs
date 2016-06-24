extern crate hyper;

use emailaddress::EmailAddress;
use iron::Url;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use openssl::crypto::rsa::RSA;
use serde_json::de::{from_reader, from_slice};
use serde_json::value::Value;
use redis::Commands;
use rustc_serialize::base64::FromBase64;
use self::hyper::client::Client as HttpClient;
use self::hyper::header::ContentType as HyContentType;
use self::hyper::header::Headers;
use super::{AppConfig, create_jwt, session_id};
use std::collections::HashMap;
use std::iter::Iterator;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::QueryMap;


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
pub fn request(app: &AppConfig, params: &QueryMap) -> Url {

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
    Url::parse(&vec![
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
    ].join("")).unwrap()

}


/// Helper method to verify OAuth authentication result.
///
/// Match the returned email address and nonce against our Redis data, then
/// extract the identity token returned by the provider and verify it. Return
/// an identity token for the RP if successful, or an error message otherwise.
pub fn verify(app: &AppConfig, session_id: &str, code: &str)
              -> Result<(String, String), &'static str> {

    // Validate that the callback matches an auth request in Redis.
    let key = format!("session:{}", session_id);
    let stored: HashMap<String, String> = app.store.hgetall(key.clone()).unwrap();
    if stored.is_empty() {
        return Err("session not found");
    }

    let email_addr = EmailAddress::new(stored.get("email").unwrap()).unwrap();
    let origin = stored.get("client_id").unwrap();

    // Request the provider's Discovery document to get the
    // `token_endpoint` and `jwks_uri` values from it. TODO: save these
    // when requesting the Discovery document in the `oauth_request()`
    // function, and/or cache them by provider host.
    let client = HttpClient::new();
    let provider = &app.providers[&email_addr.domain];
    let rsp = client.get(&provider.discovery).send().unwrap();
    let val: Value = from_reader(rsp).unwrap();
    let config = val.as_object().unwrap();
    let token_url = config["token_endpoint"].as_string().unwrap();

    // Create form data for the Token Request, where we exchange the code
    // received in this callback request for an identity token (while
    // proving our identity by passing the client secret value).
    let body: String = vec![
        "code=",
        &utf8_percent_encode(code, QUERY_ENCODE_SET).to_string(),
        "&client_id=",
        &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
        "&client_secret=",
        &utf8_percent_encode(&provider.secret, QUERY_ENCODE_SET).to_string(),
        "&redirect_uri=",
        &utf8_percent_encode(&format!("{}/callback", &app.base_url),
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
    let parts: Vec<&str> = id_token.split('.').collect();
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
    let sha256 = hash::hash(hash::Type::SHA256, message.as_bytes());
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
    let id_token = create_jwt(app, &email_addr.to_string(), origin);
    let redirect = stored.get("redirect").unwrap();
    Ok((id_token, redirect.to_string()))

}
