use bridges::{BridgeData, complete_auth};
use config::GoogleConfig;
use crypto;
use email_address::EmailAddress;
use error::BrokerError;
use futures::{Future, future};
use http::{ContextHandle, HandlerResult};
use hyper::{Response, StatusCode};
use hyper::header::{ContentType, Location};
use serde_helpers::UrlDef;
use std::rc::Rc;
use store_cache::{CacheKey, fetch_json_url};
use time::now_utc;
use url::Url;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use validation;
use webfinger::{Link, Relation};


/// The origin of the Google identity provider.
pub const GOOGLE_IDP_ORIGIN: &'static str = "https://accounts.google.com";


/// Normalization to apply to an email address.
#[derive(Serialize,Deserialize)]
pub enum Normalization {
    None,
    Google,
}

impl Normalization {
    /// Apply normalization to an email address.
    pub fn apply(&self, email_addr: EmailAddress) -> EmailAddress {
        match *self {
            Normalization::None => email_addr,
            Normalization::Google => email_addr.normalize_google(),
        }
    }
}


/// Data we store in the session.
#[derive(Serialize,Deserialize)]
pub struct OidcBridgeData {
    pub origin: String,
    pub client_id: String,
    pub nonce: String,
    pub normalization: Normalization,
}


/// OpenID Connect configuration document.
#[derive(Deserialize)]
struct ProviderConfig {
    #[serde(with = "UrlDef")]
    authorization_endpoint: Url,
    #[serde(with = "UrlDef")]
    jwks_uri: Url,
}


/// OpenID Connect key set document.
#[derive(Deserialize)]
struct ProviderKeys {
    #[serde(default)]
    keys: Vec<ProviderKey>,
}

#[derive(Deserialize)]
pub struct ProviderKey {
    #[serde(default)]
    pub kid: String,
    #[serde(rename = "use")]
    #[serde(default)]
    pub use_: String,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub e: String,
}


/// Provide authentication using OpenID Connect.
///
/// Redirect the user agent to the provider authorization endpoint, which we discover by reading
/// the providers configuration document. Included in the request is a nonce which we can later use
/// to definitively match the callback to this request.
///
/// This function handles both Portier providers, which works without registration, as well as
/// the Google provider, for which we have a preregistered `client_id`.
pub fn auth(ctx_handle: &ContextHandle, email_addr: &Rc<EmailAddress>, link: &Link)
    -> HandlerResult {

    let ctx = ctx_handle.borrow();

    // Generate a nonce for the provider.
    let provider_nonce = crypto::nonce();

    // Determine the parameters to use, based on the webfinger link.
    let provider_origin = match validation::parse_oidc_href(&link.href) {
        Some(origin) => origin,
        None => return Box::new(future::err(BrokerError::Provider(
            format!("invalid href: {}", link.href)))),
    };
    let bridge_data = Rc::new(match link.rel {
        Relation::Portier => {
            OidcBridgeData {
                origin: provider_origin,
                client_id: ctx.app.public_url.clone(),
                nonce: provider_nonce,
                normalization: Normalization::None,
            }
        },
        // Delegate to the OpenID Connect bridge for Google, if configured.
        Relation::Google => {
            let client_id = match ctx.app.google {
                Some(GoogleConfig { ref client_id }) => client_id,
                None => return Box::new(future::err(BrokerError::ProviderCancelled)),
            };
            if provider_origin != GOOGLE_IDP_ORIGIN {
                return Box::new(future::err(BrokerError::Provider(
                    format!("invalid href: Google provider only supports {}", GOOGLE_IDP_ORIGIN))));
            }
            OidcBridgeData {
                origin: provider_origin,
                client_id: client_id.clone(),
                nonce: provider_nonce,
                normalization: Normalization::Google,
            }
        },
    });

    // Retrieve the provider's configuration and extract the
    // `authorization_endpoint` from it.
    let bridge_data2 = bridge_data.clone();
    let f = {
        let config_url = build_config_url(&bridge_data2.origin);
        fetch_json_url(&ctx.app, config_url, &CacheKey::OidcConfig {
            origin: bridge_data2.origin.as_str(),
        }).map_err(move |e| BrokerError::Provider(
            format!("could not fetch {}'s configuration: {}", bridge_data2.origin, e)))
    };

    let ctx_handle = ctx_handle.clone();
    let email_addr = email_addr.clone();
    let f = f.and_then(move |provider_config: ProviderConfig| {
        let mut ctx = ctx_handle.borrow_mut();

        // Create the URL to redirect to, properly escaping all parameters.
        let result = Url::parse(&vec![
            provider_config.authorization_endpoint.as_str(),
            "?",
            "client_id=",
            &utf8_percent_encode(&bridge_data.client_id, QUERY_ENCODE_SET).to_string(),
            "&response_type=id_token",
            "&scope=",
            &utf8_percent_encode("openid email", QUERY_ENCODE_SET).to_string(),
            "&redirect_uri=",
            &utf8_percent_encode(&format!("{}/callback", &ctx.app.public_url),
                                 QUERY_ENCODE_SET).to_string(),
            "&state=",
            &utf8_percent_encode(&ctx.session_id, QUERY_ENCODE_SET).to_string(),
            "&nonce=",
            &utf8_percent_encode(&bridge_data.nonce, QUERY_ENCODE_SET).to_string(),
            "&login_hint=",
            &utf8_percent_encode(email_addr.as_str(), QUERY_ENCODE_SET).to_string(),
        ].join(""));
        let auth_url = match result {
            Ok(url) => url,
            Err(_) => {
                let domain = email_addr.domain();
                return future::err(BrokerError::Provider(
                    format!("failed to build valid authorization URL from {}'s 'authorization_endpoint'", domain)));
            },
        };

        // Save session data, committing the session to this provider.
        let bridge_data = Rc::try_unwrap(bridge_data).map_err(|_| ()).expect("lingering oidc bridge data references");
        match ctx.save_session(BridgeData::Oidc(bridge_data)) {
            Ok(true) => {},
            Ok(false) => return future::err(BrokerError::ProviderCancelled),
            Err(e) => return future::err(e),
        }

        let res = Response::new()
            .with_status(StatusCode::SeeOther)
            .with_header(Location::new(auth_url.into_string()));
        future::ok(res)
    });

    Box::new(f)
}


/// Request handler for OpenID Connect callbacks with response mode 'fragment'
///
/// For providers that don't support `response_mode=form_post`, we capture the fragment parameters
/// in javascript and emulate the POST request.
pub fn fragment_callback(ctx_handle: ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(ctx.app.templates.fragment_callback.render(&[]));
    Box::new(future::ok(res))
}


/// Request handler for OpenID Connect callbacks.
///
/// Match the returned email address and nonce against our session data, then extract the identity
/// token returned by the provider and verify it. Return an identity token for the relying party if
/// successful, or an error message otherwise.
pub fn callback(ctx_handle: ContextHandle) -> HandlerResult {
    let (bridge_data, id_token) = {
        let mut ctx = ctx_handle.borrow_mut();

        let session_id = try_get_param!(ctx, "state");
        let bridge_data = match ctx.load_session(&session_id) {
            Ok(BridgeData::Oidc(bridge_data)) => Rc::new(bridge_data),
            Ok(_) => return Box::new(future::err(BrokerError::Input("invalid session".to_owned()))),
            Err(e) => return Box::new(future::err(e)),
        };

        let id_token = try_get_param!(ctx, "id_token");
        (bridge_data, id_token)
    };

    // Request the provider's configuration to get the `jwks_uri` values from it.
    let bridge_data2 = bridge_data.clone();
    let f = {
        let ctx = ctx_handle.borrow();
        let config_url = build_config_url(&bridge_data2.origin);
        fetch_json_url(&ctx.app, config_url, &CacheKey::OidcConfig {
            origin: bridge_data2.origin.as_str(),
        }).map_err(move |e| BrokerError::Provider(
            format!("could not fetch {}'s configuration: {}", bridge_data2.origin, e)))
    };

    // Grab the keys from the provider, then verify the signature.
    let ctx_handle2 = ctx_handle.clone();
    let bridge_data2 = bridge_data.clone();
    let f = f.and_then(move |provider_config: ProviderConfig| {
        let ctx = ctx_handle2.borrow();
        fetch_json_url(&ctx.app, provider_config.jwks_uri, &CacheKey::OidcKeySet {
            origin: bridge_data2.origin.as_str(),
        })
            .then(move |result| {
                let key_set: ProviderKeys = result.map_err(|e| BrokerError::Provider(
                    format!("could not fetch {}'s keys: {}", &bridge_data2.origin, e)))?;
                crypto::verify_jws(&id_token, &key_set.keys).map_err(|_| BrokerError::Provider(
                    format!("could not verify the token received from {}", &bridge_data2.origin)))
            })
    });

    let ctx_handle = ctx_handle.clone();
    let f = f.and_then(move |jwt_payload| {
        let ctx = ctx_handle.borrow();
        let data = ctx.session_data.as_ref().expect("session vanished");

        // Normalize the email address according to provider rules.
        let email_addr = bridge_data.normalization.apply(data.email_addr.clone());

        // Extract the token claims.
        let descr = format!("{}'s token payload", email_addr.domain());
        let iss = try_get_json_field!(jwt_payload, "iss", descr);
        let aud = try_get_json_field!(jwt_payload, "aud", descr);
        let token_addr = try_get_json_field!(jwt_payload, "email", descr);
        let exp = try_get_json_field!(jwt_payload, "exp", |v| v.as_i64(), descr);
        let nonce = try_get_json_field!(jwt_payload, "nonce", descr);

        // Normalize the token email address too.
        let token_addr: EmailAddress = match token_addr.parse() {
            Ok(addr) => bridge_data.normalization.apply(addr),
            Err(_) => return future::err(BrokerError::Provider(format!(
                    "failed to parse email from {}", descr))),
        };

        // Verify the token claims.
        check_field!(iss == bridge_data.origin, "iss", descr);
        check_field!(aud == *bridge_data.client_id, "aud", descr);
        check_field!(nonce == *bridge_data.nonce, "nonce", descr);
        check_field!(token_addr == email_addr, "email", descr);

        let now = now_utc().to_timespec().sec;
        check_field!(now < exp, "exp", descr);

        // If everything is okay, build a new identity token and send it
        // to the relying party.
        future::ok(complete_auth(&*ctx))
    });

    Box::new(f)
}

/// Build the URL to the OpenID Connect configuration for a provider at the given origin.
fn build_config_url(provider_origin: &str) -> Url {
    format!("{}/.well-known/openid-configuration", provider_origin).parse()
        .expect("could not build the OpenID Connect configuration URL")
}
