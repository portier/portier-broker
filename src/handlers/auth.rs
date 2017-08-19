use bridges::{self, Provider};
use crypto;
use email_address::EmailAddress;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::json_response;
use http::{ContextHandle, HandlerResult};
use hyper::server::Response;
use std::rc::Rc;
use store_limits::addr_limiter;
use validation::{parse_redirect_uri};
use webfinger;


/// Request handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
pub fn discovery(ctx_handle: ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let obj = json!({
        "issuer": ctx.app.public_url,
        "authorization_endpoint": format!("{}/auth", ctx.app.public_url),
        "jwks_uri": format!("{}/keys.json", ctx.app.public_url),
        "scopes_supported": vec!["openid", "email"],
        "claims_supported": vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"],
        "response_types_supported": vec!["id_token"],
        "response_modes_supported": vec!["form_post"],
        "grant_types_supported": vec!["implicit"],
        "subject_types_supported": vec!["public"],
        "id_token_signing_alg_values_supported": vec!["RS256"],
    });
    Box::new(json_response(&obj, ctx.app.discovery_ttl))
}


/// Request handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
pub fn key_set(ctx_handle: ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let obj = json!({
        "keys": ctx.app.keys.iter()
            .map(|key| key.public_jwk())
            .collect::<Vec<_>>(),
    });
    Box::new(json_response(&obj, ctx.app.keys_ttl))
}


/// Request handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
pub fn auth(ctx_handle: ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    let redirect_uri = try_get_param!(ctx, "redirect_uri");
    let client_id = try_get_param!(ctx, "client_id");
    if try_get_param!(ctx, "response_mode", "fragment".to_string()) != "form_post" {
        return Box::new(future::err(BrokerError::Input(
            "unsupported response_mode, only form_post is supported".to_string())));
    }

    let redirect_uri = match parse_redirect_uri(&redirect_uri, "redirect_uri") {
        Ok(url) => url,
        Err(e) => return Box::new(future::err(e.into())),
    };

    if client_id != redirect_uri.origin().ascii_serialization() {
        return Box::new(future::err(BrokerError::Input(
            "the client_id must be the origin of the redirect_uri".to_owned())));
    }

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    ctx.redirect_uri = Some(redirect_uri.clone());

    if let Some(ref whitelist) = ctx.app.allowed_origins {
        if !whitelist.contains(&client_id) {
            return Box::new(future::err(BrokerError::Input(
                "the origin is not whitelisted".to_string())));
        }
    }

    let nonce = try_get_param!(ctx, "nonce");
    let login_hint = try_get_param!(ctx, "login_hint");
    if try_get_param!(ctx, "response_type") != "id_token" {
        return Box::new(future::err(BrokerError::Input(
            "unsupported response_type, only id_token is supported".to_string())));
    }

    let email_addr = match login_hint.parse::<EmailAddress>() {
        Ok(addr) => Rc::new(addr),
        Err(_) => return Box::new(future::err(BrokerError::Input(
            "login_hint is not a valid email address".to_string()))),
    };

    // Enforce ratelimit based on the login_hint
    match addr_limiter(&ctx.app.store, email_addr.as_str(), &ctx.app.limit_per_email) {
        Err(err) => return Box::new(future::err(err)),
        Ok(false) => return Box::new(future::err(BrokerError::RateLimited)),
        _ => {},
    }

    // Create the common session structure, but do not yet save the session
    ctx.session.id = crypto::session_id(&*email_addr, &client_id);
    ctx.session.set("email", email_addr.as_str().to_owned());
    ctx.session.set("nonce", nonce);
    ctx.session.set("redirect_uri", redirect_uri.into_string());

    // TODO: Start discovery timeout

    // Discover the authentication endpoints based on the email domain.
    let f = if let Some(mapped) = ctx.app.domain_overrides.get(email_addr.domain()) {
        Box::new(future::ok(vec![mapped.clone()]))
    } else {
        webfinger::query(&ctx.app, &email_addr)
    };

    let email_addr2 = email_addr.clone();
    let f = f.or_else(move |err| {
        info!("discovery failed for {}: {}", email_addr2, err);
        future::err(())
    });

    // Get a provider configuration for the first endpoint we support.
    let ctx_handle2 = ctx_handle.clone();
    let f = f.map(move |endpoints| {
        let ctx = ctx_handle2.borrow();
        endpoints.iter().filter_map(|endpoint| {
            match endpoint.scheme() {
                #[cfg(feature = "insecure")]
                bridges::PORTIER_INSECURE_IDP_SCHEME => {
                    // TODO: verify URI
                    Some(Rc::new(Provider::Portier {
                        origin: endpoint.origin().ascii_serialization()
                    }))
                },
                bridges::PORTIER_IDP_SCHEME => {
                    // TODO: verify URI
                    Some(Rc::new(Provider::Portier {
                        origin: endpoint.origin().ascii_serialization()
                    }))
                },
                bridges::GOOGLE_IDP_SCHEME => {
                    // TODO: verify URI
                    ctx.app.providers.get(endpoint).cloned()
                },
                _ => None,
            }
        }).next()
    });

    // Try to authenticate with this provider.
    let ctx_handle2 = ctx_handle.clone();
    let email_addr2 = email_addr.clone();
    let f = f.and_then(move |provider| -> Box<Future<Item=Response, Error=()>> {
        if let Some(provider) = provider {
            let f = Provider::delegate_request(&ctx_handle2, &email_addr2, &provider)
                .or_else(move |err| {
                    info!("error authenticating with {}: {}", provider, err);
                    future::err(())
                });
            Box::new(f)
        } else {
            Box::new(future::err(()))
        }
    });

    // Email loop authentication.
    let ctx_handle2 = ctx_handle.clone();
    let f = f.or_else(move |_| {
        bridges::email::request(&ctx_handle2, &email_addr)
    });

    Box::new(f)
}
