use config::Config;
use crypto;
use email_address::EmailAddress;
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
        ("email", email_addr.as_str()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("provider_nonce", &provider_nonce),
        ("redirect", redirect_uri.as_str()),
    ]));

    // Retrieve the provider's Discovery document and extract the
    // `authorization_endpoint` from it.
    let app2 = app.clone();
    let email_addr = Rc::new(email_addr);
    let email_addr2 = email_addr.clone();
    let email_addr3 = email_addr.clone();
    let f = f.and_then(move |_| {
        {
            let domain = email_addr2.domain();
            let provider = &app2.providers[domain];
            fetch_json_url(&app2, &provider.discovery_url, &CacheKey::Discovery { domain })
        }
            .map_err(move |e| {
                BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                              email_addr3.domain(), e.description()))
            })
            .and_then(move |config_obj| {
                let descr = format!("{}'s discovery document", email_addr2.domain());
                let authz_base = try_get_json_field!(config_obj, "authorization_endpoint", descr);
                future::ok(authz_base)
            })
    });

    // Create the URL to redirect to, properly escaping all parameters.
    let f = f.and_then(move |authz_base| {
        let provider = &app.providers[email_addr.domain()];
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
            &utf8_percent_encode(email_addr.as_str(), QUERY_ENCODE_SET).to_string(),
        ].join("")).map_err(|_| {
            let domain = email_addr.domain();
            BrokerError::Provider(format!("failed to build valid authorization URL from {}'s 'authorization_endpoint'", domain))
        });
        future::result(result)
    });

    Box::new(f)
}

/// Helper method to verify OAuth authentication result.
///
/// Match the returned email address and nonce against our Redis data, then
/// extract the identity token returned by the provider and verify it. Return
/// an identity token for the RP if successful, or an error message otherwise.
pub fn verify(app: Rc<Config>, stored: HashMap<String, String>, id_token: String)
              -> Box<Future<Item=String, Error=BrokerError>> {

    let email_addr = Rc::new(EmailAddress::from_trusted(&stored["email"]));

    // Request the provider's Discovery document to get the `jwks_uri` values from it.
    let app2 = app.clone();
    let email_addr2 = email_addr.clone();
    let email_addr3 = email_addr.clone();
    let f = {
        let domain = email_addr2.domain();
        let provider = &app2.providers[domain];
        fetch_json_url(&app2, &provider.discovery_url, &CacheKey::Discovery { domain })
    }
        .map_err(move |e| {
            BrokerError::Provider(format!("could not fetch {}'s discovery document: {}",
                                          email_addr3.domain(), e.description()))
        })
        .and_then(move |config_obj| {
            let descr = format!("{}'s discovery document", email_addr2.domain());
            let jwks_url = try_get_json_field!(config_obj, "jwks_uri", descr);
            future::ok(jwks_url)
        });

    // Grab the keys from the provider, then verify the signature.
    let app2 = app.clone();
    let email_addr2 = email_addr.clone();
    let email_addr3 = email_addr.clone();
    let f = f.and_then(move |jwks_url| {
        {
            let domain = email_addr2.domain();
            fetch_json_url(&app2, &jwks_url, &CacheKey::KeySet { domain })
        }
            .map_err(move |e| {
                BrokerError::Provider(format!("could not fetch {}'s keys: {}",
                                              email_addr3.domain(), e.description()))
            })
            .and_then(move |keys_obj| {
                match crypto::verify_jws(&id_token, &keys_obj) {
                    Err(_) => future::err(BrokerError::Provider(
                        format!("could not verify the token received from {}", email_addr2.domain()))),
                    Ok(jwt_payload) => future::ok(jwt_payload),
                }
            })
    });

    let f = f.and_then(move |jwt_payload| {
        let domain = email_addr.domain();
        let provider = &app.providers[domain];

        // Verify the claims contained in the token.
        let descr = format!("{}'s token payload", domain);
        let iss = try_get_json_field!(jwt_payload, "iss", descr);
        let aud = try_get_json_field!(jwt_payload, "aud", descr);
        let token_addr = try_get_json_field!(jwt_payload, "email", descr);
        let exp = try_get_json_field!(jwt_payload, "exp", |v| v.as_i64(), descr);
        let nonce = try_get_json_field!(jwt_payload, "nonce", descr);
        let issuer_origin = vec!["https://", &provider.issuer_domain].join("");
        // TODO: Turn these into provider errors.
        let token_addr: EmailAddress = token_addr.parse()
            .expect("failed to parse provider token email address");
        assert!(iss == provider.issuer_domain || iss == issuer_origin);
        assert_eq!(aud, provider.client_id);
        // TODO: This normalization is here because we currently support only Google.
        // Eventually, we'd only do this when Google is explicitely selected.
        assert_eq!(token_addr.normalize_google(), email_addr.normalize_google());
        let now = now_utc().to_timespec().sec;
        assert!(now < exp);
        assert_eq!(nonce, stored["provider_nonce"]);

        // If everything is okay, build a new identity token and send it
        // to the relying party.
        future::ok(crypto::create_jwt(&*app, &*email_addr, &stored["client_id"], &stored["nonce"]))
    });

    Box::new(f)
}
