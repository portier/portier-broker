//! Authenticate users via a Gmail OAuth / OpenID Connect

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
use iron::modifiers;
use iron::prelude::{IronResult, Response};
use iron::status;
use iron::Url;
use serde_json::de::from_reader;
use serde_json::value::Value;
use redis::Commands;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::QueryMap;
use {AppConfig, session_id};


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
pub fn authenticate(app: &AppConfig, params: &QueryMap) -> IronResult<Response> {
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
