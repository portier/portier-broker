use bridges::{complete_auth, BridgeData};
use config::GoogleConfig;
use crypto;
use email_address::EmailAddress;
use error::BrokerError;
use futures::{future, Future};
use http::{ContextHandle, HandlerResult};
use hyper::header::Location;
use hyper::{Response, StatusCode};
use serde_helpers::UrlDef;
use std::rc::Rc;
use store_cache::{fetch_json_url, CacheKey};
use time::now_utc;
use url::Url;
use validation;
use webfinger::{Link, Relation};

/// The origin of the Google identity provider.
pub const GOOGLE_IDP_ORIGIN: &str = "https://accounts.google.com";
/// The leeway allowed when verifying iat & exp claims, in seconds.
pub const LEEWAY: i64 = 30;

/// Data we store in the session.
#[derive(Serialize, Deserialize)]
pub struct OidcBridgeData {
    pub link: Link,
    pub origin: String,
    pub client_id: String,
    pub nonce: String,
}

/// OpenID Connect configuration document.
#[derive(Deserialize)]
struct ProviderConfig {
    #[serde(with = "UrlDef")]
    authorization_endpoint: Url,
    #[serde(with = "UrlDef")]
    jwks_uri: Url,
    #[serde(default = "default_response_modes_supported")]
    response_modes_supported: Vec<String>,
}

fn default_response_modes_supported() -> Vec<String> {
    vec!["fragment".to_owned()]
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
pub fn auth(
    ctx_handle: &ContextHandle,
    email_addr: &Rc<EmailAddress>,
    link: &Link,
) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    // Generate a nonce for the provider.
    let provider_nonce = crypto::nonce();

    // Determine the parameters to use, based on the webfinger link.
    let provider_origin = match validation::parse_oidc_href(&link.href) {
        Some(origin) => origin,
        None => {
            return Box::new(future::err(BrokerError::Provider(format!(
                "invalid href (validation failed): {}",
                link.href
            ))))
        }
    };
    let bridge_data = Rc::new(match link.rel {
        Relation::Portier => {
            #[cfg(not(feature = "insecure"))]
            {
                if link.href.scheme() != "https" {
                    return Box::new(future::err(BrokerError::Provider(format!(
                        "invalid href (not HTTPS): {}",
                        link.href
                    ))));
                }
            }
            OidcBridgeData {
                link: link.clone(),
                origin: provider_origin,
                client_id: ctx.app.public_url.clone(),
                nonce: provider_nonce,
            }
        }
        // Delegate to the OpenID Connect bridge for Google, if configured.
        Relation::Google => {
            let client_id = match ctx.app.google {
                Some(GoogleConfig { ref client_id }) => client_id,
                None => return Box::new(future::err(BrokerError::ProviderCancelled)),
            };
            if provider_origin != GOOGLE_IDP_ORIGIN {
                return Box::new(future::err(BrokerError::Provider(format!(
                    "invalid href: Google provider only supports {}",
                    GOOGLE_IDP_ORIGIN
                ))));
            }
            OidcBridgeData {
                link: link.clone(),
                origin: provider_origin,
                client_id: client_id.clone(),
                nonce: provider_nonce,
            }
        }
    });

    // Retrieve the provider's configuration.
    let f = fetch_config(ctx_handle, &bridge_data);

    let ctx_handle = Rc::clone(ctx_handle);
    let email_addr = Rc::clone(email_addr);
    let f = f.and_then(move |provider_config: ProviderConfig| {
        let mut ctx = ctx_handle.borrow_mut();
        let ProviderConfig {
            authorization_endpoint: mut auth_url,
            response_modes_supported: response_modes,
            ..
        } = provider_config;

        {
            // Create the URL to redirect to.
            let mut query = auth_url.query_pairs_mut();
            query.extend_pairs(&[
                ("login_hint", email_addr.as_str()),
                ("scope", "openid email"),
                ("nonce", &bridge_data.nonce),
                ("state", &ctx.session_id),
                ("response_type", "id_token"),
                ("client_id", &bridge_data.client_id),
                ("redirect_uri", &format!("{}/callback", &ctx.app.public_url)),
            ]);

            // Prefer `form_post` response mode, otherwise use `fragment`.
            if response_modes.iter().any(|mode| mode == "form_post") {
                query.append_pair("response_mode", "form_post");
            } else if !response_modes.iter().any(|mode| mode == "fragment") {
                return Err(BrokerError::Provider(format!(
                    "neither form_post nor fragment response modes supported by {}'s IdP ",
                    email_addr.domain()
                )));
            }

            query.finish();
        }

        // Save session data, committing the session to this provider.
        let bridge_data = Rc::try_unwrap(bridge_data)
            .map_err(|_| ())
            .expect("lingering oidc bridge data references");
        if !ctx.save_session(BridgeData::Oidc(bridge_data))? {
            return Err(BrokerError::ProviderCancelled);
        }

        let res = Response::new()
            .with_status(StatusCode::SeeOther)
            .with_header(Location::new(auth_url.into_string()));
        Ok(res)
    });

    Box::new(f)
}

/// Request handler for OpenID Connect callbacks.
///
/// Match the returned email address and nonce against our session data, then extract the identity
/// token returned by the provider and verify it. Return an identity token for the relying party if
/// successful, or an error message otherwise.
pub fn callback(ctx_handle: &ContextHandle) -> HandlerResult {
    let (bridge_data, id_token) = {
        let mut ctx = ctx_handle.borrow_mut();
        let mut params = ctx.form_params();

        let session_id = try_get_provider_param!(params, "state");
        let bridge_data = match ctx.load_session(&session_id) {
            Ok(BridgeData::Oidc(bridge_data)) => Rc::new(bridge_data),
            Ok(_) => {
                return Box::new(future::err(BrokerError::ProviderInput(
                    "invalid session".to_owned(),
                )))
            }
            Err(e) => return Box::new(future::err(e)),
        };

        let id_token = try_get_provider_param!(params, "id_token");
        (bridge_data, id_token)
    };

    // Retrieve the provider's configuration.
    let f = fetch_config(ctx_handle, &bridge_data);

    // Grab the keys from the provider, then verify the signature.
    let ctx_handle2 = Rc::clone(ctx_handle);
    let bridge_data2 = Rc::clone(&bridge_data);
    let f = f.and_then(move |provider_config: ProviderConfig| {
        let ctx = ctx_handle2.borrow();
        fetch_json_url(
            &ctx.app,
            provider_config.jwks_uri,
            &CacheKey::OidcKeySet {
                origin: bridge_data2.origin.as_str(),
            },
        )
        .then(move |result| {
            let key_set: ProviderKeys = result.map_err(|e| {
                BrokerError::Provider(format!(
                    "could not fetch {}'s keys: {}",
                    &bridge_data2.origin, e
                ))
            })?;
            crypto::verify_jws(&id_token, &key_set.keys).map_err(|_| {
                BrokerError::ProviderInput(format!(
                    "could not verify the token received from {}",
                    &bridge_data2.origin
                ))
            })
        })
    });

    let ctx_handle = Rc::clone(ctx_handle);
    let f = f.and_then(move |jwt_payload| {
        let ctx = ctx_handle.borrow();
        let data = ctx.session_data.as_ref().expect("session vanished");

        // Extract the token claims.
        let descr = format!("{}'s token payload", data.email_addr.domain());
        let iss = try_get_token_field!(jwt_payload, "iss", descr);
        let aud = try_get_token_field!(jwt_payload, "aud", descr);
        let email = try_get_token_field!(jwt_payload, "email", descr);
        let iat = try_get_token_field!(jwt_payload, "iat", |v| v.as_i64(), descr);
        let exp = try_get_token_field!(jwt_payload, "exp", |v| v.as_i64(), descr);
        let nonce = try_get_token_field!(jwt_payload, "nonce", descr);

        // Verify the token claims.
        check_token_field!(iss == bridge_data.origin, "iss", descr);
        check_token_field!(aud == bridge_data.client_id, "aud", descr);
        check_token_field!(nonce == bridge_data.nonce, "nonce", descr);

        let now = now_utc().to_timespec().sec;
        let exp = exp.checked_add(LEEWAY).unwrap_or(i64::min_value());
        let iat = iat.checked_sub(LEEWAY).unwrap_or(i64::max_value());
        check_token_field!(now < exp, "exp", descr);
        check_token_field!(iat <= now, "iat", descr);

        match bridge_data.link.rel {
            Relation::Portier => {
                // `email` should match the normalized email, as we sent it to the IdP.
                check_token_field!(email == data.email_addr.as_str(), "email", descr);
                // `email_original` should not be necessary for Broker -> IdP, but verify it any way.
                if let Some(email_original) =
                    jwt_payload.get("email_original").and_then(|v| v.as_str())
                {
                    check_token_field!(
                        email_original == data.email_addr.as_str(),
                        "email_original",
                        descr
                    );
                }
            }
            Relation::Google => {
                // Check `email` after additional Google-specific normalization.
                let email_addr: EmailAddress = match email.parse() {
                    Ok(email_addr) => email_addr,
                    Err(_) => {
                        return Err(BrokerError::ProviderInput(format!(
                            "failed to parse email in {}",
                            descr
                        )))
                    }
                };
                let google_email_addr = email_addr.normalize_google();
                let expected = data.email_addr.normalize_google();
                check_token_field!(google_email_addr == expected, "email", descr);
            }
        }

        // Everything is okay. Build a new identity token and send it to the relying party.
        complete_auth(&*ctx)
    });

    Box::new(f)
}

// Retrieve and verify the provider's configuration.
fn fetch_config(
    ctx_handle: &ContextHandle,
    bridge_data: &Rc<OidcBridgeData>,
) -> Box<dyn Future<Item = ProviderConfig, Error = BrokerError>> {
    let config_url = format!("{}/.well-known/openid-configuration", bridge_data.origin)
        .parse()
        .expect("could not build the OpenID Connect configuration URL");

    let ctx = ctx_handle.borrow();
    let bridge_data = Rc::clone(bridge_data);
    let f = fetch_json_url::<ProviderConfig>(
        &ctx.app,
        config_url,
        &CacheKey::OidcConfig {
            origin: bridge_data.origin.as_str(),
        },
    );

    let f = f.then(move |result| {
        let provider_config = result.map_err(|e| {
            BrokerError::Provider(format!(
                "could not fetch {}'s configuration: {}",
                bridge_data.origin, e
            ))
        })?;

        #[cfg(not(feature = "insecure"))]
        {
            if provider_config.authorization_endpoint.scheme() != "https" {
                return Err(BrokerError::Provider(format!(
                    "{}'s authorization_endpoint is not HTTPS",
                    bridge_data.origin
                )));
            }
            if provider_config.jwks_uri.scheme() != "https" {
                return Err(BrokerError::Provider(format!(
                    "{}'s jwks_uri is not HTTPS",
                    bridge_data.origin
                )));
            }
        }

        Ok(provider_config)
    });

    Box::new(f)
}
