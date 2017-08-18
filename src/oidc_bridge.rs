use config::Config;
use crypto;
use emailaddress::EmailAddress;
use error::BrokerError;
use futures::{Future, future};
use std::collections::HashMap;
use std::error::Error;
use std::rc::Rc;
use super::store_cache::{CacheKey, fetch_json_url};
use time::now_utc;
use url::Url;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// Macro used to extract a typed field from a JSON Value.
///
/// Will return from the caller with a `BrokerError` if the field is missing or its value is an
/// incompatible type. `descr` is used to format the error message.
///
/// ```
/// let foo = try_get_json_field!(value, "foo", "example document");
/// ```
macro_rules! try_get_json_field {
    ( $input:expr, $key:tt, $conv:expr, $descr:expr ) => {
        match $input.get($key).and_then($conv) {
            Some(v) => v,
            None => return future::err(BrokerError::Provider(
                format!("{} missing from {}", $key, $descr))),
        }
    };
    ( $input:expr, $key:tt, $descr:expr ) => {
        try_get_json_field!($input, $key,
            |v| v.as_str().map(|s| s.to_owned()), $descr)
    };
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
pub fn request(app: Rc<Config>, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &Url)
               -> Box<Future<Item=Url, Error=BrokerError>> {

    let session = crypto::session_id(&email_addr, client_id);

    // Generate a nonce for the provider.
    let provider_nonce = crypto::nonce();

    // Store the nonce and the RP's `redirect_uri` in Redis for use in the
    // callback handler.
    let f = future::result(app.store.store_session(&session, &[
        ("type", "oidc"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("provider_nonce", &provider_nonce),
        ("redirect", &redirect_uri.to_string()),
    ]));

    // Retrieve the provider's Discovery document and extract the
    // `authorization_endpoint` from it.
    let app = app.clone();
    let f = f.and_then(move |_| {
        let domain = Rc::new(email_addr.domain.to_lowercase());
        let domain2 = domain.clone();
        {
            let provider = &app.providers[&*domain];
            fetch_json_url(&app, &provider.discovery_url, &CacheKey::Discovery { domain: &*domain })
        }
            .map_err(move |e| {
                BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                              domain2, e.description()))
            })
            .and_then(move |config_obj| {
                let descr = format!("{}'s discovery document", domain);
                let authz_base = try_get_json_field!(config_obj, "authorization_endpoint", descr);
                future::ok((app, email_addr, domain, authz_base))
            })
    });

    // Create the URL to redirect to, properly escaping all parameters.
    let f = f.and_then(move |(app, email_addr, domain, authz_base)| {
        let provider = &app.providers[&*domain];
        let result = Url::parse(&vec![
            authz_base.as_str(),
            "?",
            "client_id=",
            &utf8_percent_encode(&provider.client_id, QUERY_ENCODE_SET).to_string(),
            "&response_type=id_token",
            "&scope=",
            &utf8_percent_encode("openid email", QUERY_ENCODE_SET).to_string(),
            "&redirect_uri=",
            &utf8_percent_encode(&format!("{}/callback", &app.public_url),
                                 QUERY_ENCODE_SET).to_string(),
            "&state=",
            &utf8_percent_encode(&session, QUERY_ENCODE_SET).to_string(),
            "&nonce=",
            &utf8_percent_encode(&provider_nonce, QUERY_ENCODE_SET).to_string(),
            "&login_hint=",
            &utf8_percent_encode(&email_addr.to_string(), QUERY_ENCODE_SET).to_string(),
        ].join("")).map_err(|_| {
            BrokerError::Provider(format!("failed to build valid authorization URL from {}'s 'authorization_endpoint'", domain))
        });
        future::result(result)
    });

    Box::new(f)
}

pub fn canonicalize_google(email: &str) -> String {
    let at = email.find('@').expect("no @ sign in email address");
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
        canonicalize_google(&normalized)
    } else {
        normalized
    }
}

/// Helper method to verify OAuth authentication result.
///
/// Match the returned email address and nonce against our Redis data, then
/// extract the identity token returned by the provider and verify it. Return
/// an identity token for the RP if successful, or an error message otherwise.
pub fn verify(app: Rc<Config>, stored: HashMap<String, String>, id_token: String)
              -> Box<Future<Item=String, Error=BrokerError>> {

    let email_addr = match EmailAddress::new(&stored["email"]) {
        Ok(addr) => addr,
        Err(e) => return Box::new(future::err(e.into())),
    };

    // Request the provider's Discovery document to get the `jwks_uri` values from it.
    let app = app.clone();
    let domain = Rc::new(email_addr.domain.to_lowercase());
    let domain2 = domain.clone();
    let f = {
        let provider = &app.providers[&*domain];
        fetch_json_url(&app, &provider.discovery_url, &CacheKey::Discovery { domain: &*domain })
    }
        .map_err(move |e| {
            BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                          domain2, e.description()))
        })
        .and_then(move |config_obj| {
            let descr = format!("{}'s discovery document", domain);
            let jwks_url = try_get_json_field!(config_obj, "jwks_uri", descr);
            future::ok((app, domain, jwks_url))
        });

    // Grab the keys from the provider, then verify the signature.
    let f = f.and_then(|(app, domain, jwks_url)| {
        let domain2 = domain.clone();
        fetch_json_url(&app, &jwks_url, &CacheKey::KeySet { domain: &*domain })
            .map_err(move |e| {
                BrokerError::Provider(format!("could not fetch {}'s keys: {}",
                                              domain2, e.description()))
            })
            .and_then(move |keys_obj| {
                let result = crypto::verify_jws(&id_token, &keys_obj)
                    .map_err(|_| BrokerError::Provider(
                        format!("could not verify the token received from {}", domain)))
                    .map(|jwt_payload| (app, domain, jwt_payload));
                future::result(result)
            })
    });

    let str_email_addr = email_addr.to_string();
    let f = f.and_then(move |(app, domain, jwt_payload)| {
        let provider = &app.providers[&*domain];

        // Verify the claims contained in the token.
        let descr = format!("{}'s token payload", domain);
        let iss = try_get_json_field!(jwt_payload, "iss", descr);
        let aud = try_get_json_field!(jwt_payload, "aud", descr);
        let token_addr = try_get_json_field!(jwt_payload, "email", descr);
        let exp = try_get_json_field!(jwt_payload, "exp", |v| v.as_i64(), descr);
        let nonce = try_get_json_field!(jwt_payload, "nonce", descr);
        let issuer_origin = vec!["https://", &provider.issuer_domain].join("");
        assert!(iss == provider.issuer_domain || iss == issuer_origin);
        assert_eq!(aud, provider.client_id);
        assert_eq!(canonicalized(&token_addr), canonicalized(&str_email_addr));
        let now = now_utc().to_timespec().sec;
        assert!(now < exp);
        assert_eq!(nonce, stored["provider_nonce"]);

        // If everything is okay, build a new identity token and send it
        // to the relying party.
        future::ok(crypto::create_jwt(&*app, &str_email_addr, &stored["client_id"], &stored["nonce"]))
    });

    Box::new(f)
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

    #[test]
    fn test_canonicalized_casing() {
        assert_eq!(canonicalized("EXAMPLE.FOO+BAR@EXAMPLE.COM"),
                   "example.foo+bar@example.com");
        assert_eq!(canonicalized("EXAMPLE@GOOGLEMAIL.COM"),
                   "example@gmail.com");
    }
}
