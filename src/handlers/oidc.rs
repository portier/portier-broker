use email_bridge;
use email_address::EmailAddress;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::json_response;
use http::{ContextHandle, HandlerResult};
use hyper::{StatusCode};
use hyper::header::{ContentType, Location};
use hyper::server::Response;
use oidc_bridge;
use store_limits::addr_limiter;
use url::Url;
use validation::{valid_uri, only_origin, same_origin};


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

    let result = valid_uri(redirect_uri.as_str(), "redirect_uri")
        .and_then(|_| valid_uri(&client_id, "client_id"))
        .and_then(|_| same_origin(&client_id, redirect_uri.as_str()))
        .and_then(|_| only_origin(&client_id))
        .map_err(|err| err.into())
        .and_then(|_| {
            if let Some(ref whitelist) = ctx.app.allowed_origins {
                if !whitelist.contains(&client_id.to_string()) {
                    return Err(BrokerError::Input("the origin is not whitelisted".to_string()));
                }
            }
            Ok(())
        });
    if let Err(err) = result {
        return Box::new(future::err(err));
    }

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let redirect_uri: Url = redirect_uri.parse().expect("unable to parse redirect uri");
    ctx.redirect_uri = Some(redirect_uri.clone());

    let nonce = try_get_param!(ctx, "nonce");
    let login_hint = try_get_param!(ctx, "login_hint");
    if try_get_param!(ctx, "response_type") != "id_token" {
        return Box::new(future::err(BrokerError::Input(
            "unsupported response_type, only id_token is supported".to_string())));
    }

    let email_addr: EmailAddress = match login_hint.parse() {
        Ok(addr) => addr,
        Err(_) => return Box::new(future::err(BrokerError::Input(
            "login_hint is not a valid email address".to_string()))),
    };

    // Enforce ratelimit based on the login_hint
    match addr_limiter(&ctx.app.store, email_addr.as_str(), &ctx.app.limit_per_email) {
        Err(err) => return Box::new(future::err(err)),
        Ok(false) => return Box::new(future::err(BrokerError::RateLimited)),
        _ => {},
    }

    if ctx.app.providers.contains_key(email_addr.domain()) {
        // OIDC authentication. Redirect to the identity provider.
        let f = oidc_bridge::request(ctx.app.clone(), email_addr, &client_id, &nonce, &redirect_uri)
            .map(|auth_url| {
                Response::new()
                    .with_status(StatusCode::SeeOther)
                    .with_header(Location::new(auth_url.into_string()))
            });
        Box::new(f)

    } else {
        // Email loop authentication. Render a message and form.
        let ctx_handle = ctx_handle.clone();
        let f = email_bridge::request(ctx.app.clone(), &email_addr, &client_id, &nonce, &redirect_uri, ctx.catalog())
            .map(move |session_id| {
                let ctx = ctx_handle.borrow();
                let catalog = ctx.catalog();
                Response::new()
                    .with_header(ContentType::html())
                    .with_body(ctx.app.templates.confirm_email.render(&[
                        ("client_id", &client_id),
                        ("session_id", &session_id),
                        ("title", catalog.gettext("Confirm your address")),
                        ("explanation", catalog.gettext("We've sent you an email to confirm your address.")),
                        ("use", catalog.gettext("Use the link in that email to login to")),
                        ("alternate", catalog.gettext("Alternatively, enter the code from the email to continue in this browser tab:")),
                    ]))
            });
        Box::new(f)
    }
}
