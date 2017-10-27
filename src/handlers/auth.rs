use bridges;
use email_address::EmailAddress;
use error::BrokerError;
use futures::future::{self, Future, Either};
use http::{ContextHandle, HandlerResult, json_response};
use std::rc::Rc;
use std::time::Duration;
use store_limits::addr_limiter;
use tokio_core::reactor::Timeout;
use validation::parse_redirect_uri;
use webfinger::{self, Link, Relation};


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

    let redirect_uri = try_get_input_param!(ctx, "redirect_uri");
    let client_id = try_get_input_param!(ctx, "client_id");
    if try_get_input_param!(ctx, "response_mode", "fragment".to_owned()) != "form_post" {
        return Box::new(future::err(BrokerError::Input(
            "unsupported response_mode, only form_post is supported".to_owned())));
    }

    let redirect_uri = match parse_redirect_uri(&redirect_uri, "redirect_uri") {
        Ok(url) => url,
        Err(e) => return Box::new(future::err(BrokerError::Input(format!("{}", e)))),
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
                "the origin is not whitelisted".to_owned())));
        }
    }

    let nonce = try_get_input_param!(ctx, "nonce");
    let login_hint = try_get_input_param!(ctx, "login_hint");
    if try_get_input_param!(ctx, "response_type") != "id_token" {
        return Box::new(future::err(BrokerError::Input(
            "unsupported response_type, only id_token is supported".to_owned())));
    }

    let email_addr = match login_hint.parse::<EmailAddress>() {
        Ok(addr) => Rc::new(addr),
        Err(_) => return Box::new(future::err(BrokerError::Input(
            "login_hint is not a valid email address".to_owned()))),
    };

    // Enforce ratelimit based on the login_hint.
    match addr_limiter(&ctx.app.store, email_addr.as_str(), &ctx.app.limit_per_email) {
        Err(err) => return Box::new(future::err(err)),
        Ok(false) => return Box::new(future::err(BrokerError::RateLimited)),
        _ => {},
    }

    // Create the session with common data, but do not yet save it.
    ctx.start_session(&client_id, (*email_addr).clone(), nonce);

    // Discover the authentication endpoints based on the email domain.
    let f = if let Some(mapped) = ctx.app.domain_overrides.get(email_addr.domain()) {
        Box::new(future::ok(mapped.clone()))
    } else {
        webfinger::query(&ctx.app, &email_addr)
    };

    // Try to authenticate with the first provider.
    // TODO: Queue discovery of links and process in order, with individual timeouts.
    let ctx_handle2 = Rc::clone(&ctx_handle);
    let email_addr2 = Rc::clone(&email_addr);
    let f = f.and_then(move |links| {
        match links.first() {
            // Portier and Google providers share an implementation
            Some(link @ &Link { rel: Relation::Portier, .. })
                | Some(link @ &Link { rel: Relation::Google, .. })
                => bridges::oidc::auth(&ctx_handle2, &email_addr2, link),
            _ => Box::new(future::err(BrokerError::ProviderCancelled)),
        }
    });

    // Apply a timeout to discovery.
    let ctx_handle2 = Rc::clone(&ctx_handle);
    let email_addr2 = Rc::clone(&email_addr);
    let f = Timeout::new(Duration::from_secs(5), &ctx.app.handle)
        .expect("failed to create discovery timeout")
        .select2(f)
        .then(move |result| {
            match result {
                // Timeout resolved first.
                Ok(Either::A((_, f))) => {
                    // Continue the discovery future in the background.
                    ctx_handle2.borrow().app.handle.spawn(
                        f.map(|_| ()).map_err(|e| { e.log(); () }));
                    Err(BrokerError::Provider(
                        format!("discovery timed out for {}", email_addr2)))
                },
                Err(Either::A((e, _))) => {
                    panic!("error in discovery timeout: {}", e)
                },
                // Discovery resolved first.
                Ok(Either::B((v, _))) => {
                    Ok(v)
                },
                Err(Either::B((e, _))) => {
                    Err(e)
                },
            }
        });

    // Fall back to email loop authentication.
    let ctx_handle2 = Rc::clone(&ctx_handle);
    let f = f.or_else(move |e| {
        e.log();
        match e {
            BrokerError::Provider(_)
                | BrokerError::ProviderCancelled
                => bridges::email::auth(&ctx_handle2, &email_addr),
            _ => Box::new(future::err(e))
        }
    });

    Box::new(f)
}
