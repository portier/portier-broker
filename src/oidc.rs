use emailaddress::EmailAddress;
use iron::Url;
use serde_json::de::from_reader;
use serde_json::value::Value;
use super::error::{BrokerError, BrokerResult};
use super::hyper::client::Client as HttpClient;
use super::hyper::header::ContentType as HyContentType;
use super::hyper::header::Headers;
use super::{AppConfig, create_jwt};
use super::crypto::{session_id, verify_jws};
use super::store_cache::CacheKey;
use time::now_utc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// Macro used to extract a bunch of parameters from a JSON Value.
///
/// This macro will return from the contained method with a BrokerResult when
/// it fails to parse one of the params. The error will contain the description
/// string from the second parameter.
///
/// ```
/// extract_json_fields!(value, "example document", {
///     foo = as_str("foo"),
///     bar = as_i64("BAR"),
/// });
/// ```
macro_rules! extract_json_fields {
    ( $input:expr , $descr:expr , { $( $var:ident = $conv:ident ( $key:tt ) ),* } ) => {
        let descr = $descr;
        $(
            let $var = match $input.find($key).and_then(|v| v.$conv()) {
                None => {
                    return Err(BrokerError::Custom(format!("{} missing from {}", $key, descr)))
                },
                Some(value) => {
                    value
                }
            };
        )*
    }
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
pub fn request(app: &AppConfig, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &str)
               -> BrokerResult<Url> {

    let session = session_id(&email_addr, client_id);

    // Store the nonce and the RP's `redirect_uri` in Redis for use in the
    // callback handler.
    try!(app.store.store_session(&session, &[
        ("type", "oidc"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("redirect", redirect_uri),
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
            &provider.discovery
        )
    );
    extract_json_fields!(config_obj, format!("{} discovery document", domain), {
        authz_base = as_str("authorization_endpoint")
    });

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
    ].join("")).map_err(|_| {
        BrokerError::Custom("authorization_endpoint is an invalid URL".to_string())
    })

}

pub fn canonicalize_google(email: String) -> String {
    let at = email.find("@").unwrap();
    let (user, domain) = email.split_at(at);
    let domain = &domain[1..];
    let user = &user.replace(".", ""); // Ignore dots

    // Trim plus addresses
    let user = match user.find("+") {
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
pub fn verify(app: &AppConfig, session: &str, code: &str)
              -> BrokerResult<(String, String)> {

    // Validate that the callback matches an auth request in Redis.
    let stored = try!(app.store.get_session(&session));
    if &stored["type"] != "oidc" {
        return Err(BrokerError::Custom("invalid session".to_string()));
    }

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
            CacheKey::Discovery { domain: &email_addr.domain },
            &client,
            &provider.discovery
        )
    );
    extract_json_fields!(config_obj, format!("{} discovery document", domain), {
        token_url = as_str("token_endpoint"),
        jwks_url = as_str("jwks_uri")
    });

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
    let token_obj: Value = {
        let mut headers = Headers::new();
        headers.set(HyContentType::form_url_encoded());
        let rsp = client.post(token_url).headers(headers).body(&body).send().unwrap();
        from_reader(rsp).unwrap()
    };
    extract_json_fields!(token_obj, format!("{} token response", domain), {
        id_token = as_str("id_token")
    });

    // Grab the keys from the provider, then verify the signature.
    let jwt_payload = {
        let keys_obj: Value = try!(
            app.store.cache.fetch_json_url(
                &app.store,
                CacheKey::KeySet { domain: &email_addr.domain },
                &client,
                &jwks_url
            )
        );
        verify_jws(id_token, &keys_obj).unwrap()
    };

    // Verify the claims contained in the token.
    extract_json_fields!(jwt_payload, format!("{} token", domain), {
        iss = as_str("iss"),
        aud = as_str("aud"),
        token_addr = as_str("email"),
        exp = as_i64("exp")
    });
    let issuer_origin = vec!["https://", &provider.issuer].join("");
    assert!(iss == provider.issuer || iss == issuer_origin);
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
