use std::error::Error;
use std::collections::HashMap;
use emailaddress::EmailAddress;
use iron::Url;
use serde_json::de::from_reader;
use serde_json::value::Value;
use super::error::{BrokerError, BrokerResult};
use super::hyper::client::Client as HttpClient;
use super::hyper::header::ContentType as HyContentType;
use super::hyper::header::Headers;
use super::{Config, create_jwt};
use super::crypto::{session_id, verify_jws};
use super::store_cache::CacheKey;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// Macro used to extract a typed field from a JSON Value.
///
/// Will return from the caller with a BrokerError if the field is missing or its value is an
/// incompatible type. `descr` is used to format the error message.
///
/// ```
/// let foo = try_get_json_field!(value, "foo", as_str, "example document");
/// ```
macro_rules! try_get_json_field {
    ( $input:expr, $key:tt, $conv:ident, $descr:expr ) => {
        try!($input.find($key).and_then(|v| v.$conv()).ok_or_else(|| {
            BrokerError::Provider(format!("{} missing from {}", $key, $descr))
        }))
    }
}


/// Helper method to issue an OAuth authorization request.
///
/// When an authentication request comes in and matches one of the "famous"
/// identity providers configured in the `Config`, we redirect the client
/// to an Authentication Request URL, which we discover by reading the
/// provider's configured Discovery URL. We pass in the client ID we received
/// when pre-registering for the provider, as well as a callback URL which the
/// user will be redirected back to after confirming (or denying) the
/// Authentication Request. Included in the request is a nonce which we can
/// later use to definitively match the callback to this request.
pub fn request(app: &Config, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &Url)
               -> BrokerResult<Url> {

    let session = session_id(&email_addr, client_id);

    // Store the nonce and the RP's `redirect_uri` in Redis for use in the
    // callback handler.
    try!(app.store.store_session(&session, &[
        ("type", "oidc"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("redirect", &redirect_uri.to_string()),
    ]));

    let client = HttpClient::new();

    // Retrieve the provider's Discovery document and extract the
    // `authorization_endpoint` from it.
    let domain = &email_addr.domain;
    let provider = &app.providers[domain];
    let config_obj: Value = try!(
        app.store.cache.fetch_json_url(
            &app.store,
            CacheKey::Discovery { domain: &email_addr.domain },
            &client,
            &provider.discovery_url
        ).map_err(|e| {
            BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                          domain, e.description()))
        })
    );
    let descr = format!("{}'s discovery document", domain);
    let authz_base = try_get_json_field!(config_obj, "authorization_endpoint", as_str, descr);

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
        &utf8_percent_encode(&format!("{}/callback", &app.public_url),
                             QUERY_ENCODE_SET).to_string(),
        "&state=",
        &utf8_percent_encode(&session, QUERY_ENCODE_SET).to_string(),
        "&login_hint=",
        &utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET).to_string(),
    ].join("")).map_err(|_| {
        BrokerError::Provider(format!("failed to build valid authorization URL from {}'s 'authorization_endpoint'", domain))
    })

}

pub fn canonicalize_google(email: String) -> String {
    let at = email.find('@').unwrap();
    let (user, domain) = email.split_at(at);
    let domain = &domain[1..];
    let user = &user.replace(".", ""); // Ignore dots

    // Trim plus addresses
    let user = match user.find('+') {
        Some(pos) => user.split_at(pos).0,
        None => user,
    };

    // Normalize googlemail.com to gmail.com
    let domain = if domain == "googlemail.com" {
        "gmail.com"
    } else {
        domain
    };
    user.to_string() + "@" + domain
}

pub fn canonicalized(email: &str) -> String {
    let normalized = email.to_lowercase();
    if normalized.ends_with("@gmail.com") || normalized.ends_with("@googlemail.com") {
        canonicalize_google(normalized)
    } else {
        normalized
    }
}

/// Helper method to verify OAuth authentication result.
///
/// Match the returned email address and nonce against our Redis data, then
/// extract the identity token returned by the provider and verify it. Return
/// an identity token for the RP if successful, or an error message otherwise.
pub fn verify(app: &Config, stored: &HashMap<String, String>, code: &str)
              -> BrokerResult<(String, String)> {

    let email_addr = EmailAddress::new(&stored["email"]).unwrap();
    let origin = &stored["client_id"];
    let nonce = &stored["nonce"];

    let client = HttpClient::new();

    // Request the provider's Discovery document to get the
    // `token_endpoint` and `jwks_uri` values from it. TODO: save these
    // when requesting the Discovery document in the `oauth_request()`
    // function, and/or cache them by provider host.
    let domain = &email_addr.domain;
    let provider = &app.providers[domain];
    let config_obj: Value = try!(
        app.store.cache.fetch_json_url(
            &app.store,
            CacheKey::Discovery { domain: domain },
            &client,
            &provider.discovery_url
        ).map_err(|e| {
            BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                          domain, e.description()))
        })
    );
    let descr = format!("{}'s discovery document", domain);
    let token_url = try_get_json_field!(config_obj, "token_endpoint", as_str, descr);
    let revoke_url = try_get_json_field!(config_obj, "revocation_endpoint", as_str, descr);
    let jwks_url = try_get_json_field!(config_obj, "jwks_uri", as_str, descr);

    let mut post_headers = Headers::new();
    post_headers.set(HyContentType::form_url_encoded());

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
        &utf8_percent_encode(&format!("{}/callback", &app.public_url),
                             QUERY_ENCODE_SET).to_string(),
        "&grant_type=authorization_code",
    ].join("");

    // Send the Token Request and extract the `id_token` from the response.
    let token_obj: Value = {
        try!(
            client.post(token_url).headers(post_headers.clone()).body(&body).send()
                .map_err(BrokerError::Http)
                .and_then(|rsp| from_reader(rsp).map_err(|_| {
                    BrokerError::Provider("failed to parse response as JSON".to_string())
                }))
                .map_err(|e| {
                    BrokerError::Provider(format!("{} token request failed: {}",
                                                  domain, e.description()))
                })
        )
    };
    let descr = format!("{}'s token response", domain);
    let access_token = try_get_json_field!(token_obj, "access_token", as_str, descr);
    let id_token = try_get_json_field!(token_obj, "id_token", as_str, descr);

    // Immediately revoke the access token. We only care about the id_token,
    // and this way we prevent scary 'offline access' requests on subsequent
    // authorization for the same user.
    try!(client.post(revoke_url).headers(post_headers.clone()).body(&vec![
        "token=",
        &utf8_percent_encode(access_token, QUERY_ENCODE_SET).to_string(),
    ].join("")).send().map_err(BrokerError::Http));

    // Grab the keys from the provider, then verify the signature.
    let jwt_payload = {
        let keys_obj: Value = try!(
            app.store.cache.fetch_json_url(
                &app.store,
                CacheKey::KeySet { domain: domain },
                &client,
                &jwks_url
            ).map_err(|e| {
                BrokerError::Provider(format!("could not fetch {}'s keys: {}",
                                              domain, e.description()))
            })
        );
        try!(
            verify_jws(id_token, &keys_obj).map_err(|_| {
                BrokerError::Provider(format!("could not verify the token received from {}", domain))
            })
        )
    };

    // Verify the claims contained in the token.
    let descr = format!("{}'s token payload", domain);
    let iss = try_get_json_field!(jwt_payload, "iss", as_str, descr);
    let aud = try_get_json_field!(jwt_payload, "aud", as_str, descr);
    let token_addr = try_get_json_field!(jwt_payload, "email", as_str, descr);
    let exp = try_get_json_field!(jwt_payload, "exp", as_i64, descr);
    let issuer_origin = vec!["https://", &provider.issuer_domain].join("");
    assert!(iss == provider.issuer_domain || iss == issuer_origin);
    assert!(aud == provider.client_id);
    assert!(canonicalized(token_addr) == canonicalized(&email_addr.to_string()));
    let now = now_utc().to_timespec().sec;
    assert!(now < exp);

    // If everything is okay, build a new identity token and send it
    // to the relying party.
    let id_token = create_jwt(app, &email_addr.to_string(), origin, nonce);
    let redirect = &stored["redirect"];
    Ok((id_token, redirect.to_string()))

}


#[cfg(test)]
mod tests {
    use super::canonicalized;
    #[test]
    fn test_canonicalized_google() {
        assert_eq!(canonicalized("example.foo+bar@example.com"),
                   "example.foo+bar@example.com");
        assert_eq!(canonicalized("example@gmail.com"),
                   "example@gmail.com");
        assert_eq!(canonicalized("example@googlemail.com"),
                   "example@gmail.com");
        assert_eq!(canonicalized("example.foo@gmail.com"),
                   "examplefoo@gmail.com");
        assert_eq!(canonicalized("example+bar@gmail.com"),
                   "example@gmail.com");
        assert_eq!(canonicalized("example.foo+bar@googlemail.com"),
                   "examplefoo@gmail.com");
    }
}
