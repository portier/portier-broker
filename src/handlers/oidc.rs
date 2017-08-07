use email_bridge;
use emailaddress::EmailAddress;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::json_response;
use http::{self, HandlerResult, ContextHandle};
use hyper::{Method, StatusCode};
use hyper::header::{ContentType, Location, AcceptLanguage};
use hyper::server::{Request, Response};
use oidc_bridge;
use store_limits::addr_limiter;
use url::Url;
use validation::{valid_uri, only_origin, same_origin};


/// Request handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
pub fn discovery(_: Request, shared_ctx: ContextHandle) -> HandlerResult {
    let ctx = shared_ctx.lock().expect("failed to lock request context");
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
    json_response(&obj, ctx.app.discovery_ttl).boxed()
}


/// Request handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
pub fn key_set(_: Request, shared_ctx: ContextHandle) -> HandlerResult {
    let ctx = shared_ctx.lock().expect("failed to lock request context");
    let obj = json!({
        "keys": ctx.app.keys.iter()
            .map(|key| key.public_jwk())
            .collect::<Vec<_>>(),
    });
    json_response(&obj, ctx.app.keys_ttl).boxed()
}


/// Request handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
pub fn auth(req: Request, shared_ctx: ContextHandle) -> HandlerResult {
    // Parse the Accept-Language header
    // TODO: Don't always have to do this, but can't carry Request
    let accept_languages = match req.headers().get::<AcceptLanguage>() {
        Some(&AcceptLanguage(ref list)) => list.clone(),
        None => vec![],
    };

    match *req.method() {
        Method::Get => future::ok(http::parse_query(&req)).boxed(),
        Method::Post => http::parse_form_encoded_body(req),
        _ => unreachable!(),
    }
        .and_then(move |mut params| {
            let client_id = try_get_param!(params, "client_id");
            let redirect_uri = try_get_param!(params, "redirect_uri");
            let nonce = try_get_param!(params, "nonce");
            let login_hint = try_get_param!(params, "login_hint");
            if try_get_param!(params, "response_type") != "id_token" {
                return future::err(BrokerError::Input("unsupported response_type, only id_token is supported".to_string()));
            }
            if try_get_param!(params, "response_mode", "fragment".to_string()) != "form_post" {
                return future::err(BrokerError::Input("unsupported response_mode, only form_post is supported".to_string()));
            }

            let result = valid_uri(&redirect_uri, "redirect_uri")
                .and_then(|_| valid_uri(&client_id, "client_id"))
                .and_then(|_| same_origin(&client_id, &redirect_uri))
                .and_then(|_| only_origin(&client_id))
                .map_err(|err| err.into())
                .and_then(|_| {
                    let redirect_uri = {
                        let mut ctx = shared_ctx.lock().expect("failed to lock request context");

                        if let Some(ref whitelist) = ctx.app.allowed_origins {
                            if !whitelist.contains(&client_id.to_string()) {
                                return Err(BrokerError::Input("the origin is not whitelisted".to_string()));
                            }
                        }

                        // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
                        // redirect_uri. In our case, this means we make redirect_uri available to error handling.
                        let redirect_uri: Url = redirect_uri.parse().expect("unable to parse redirect uri");
                        ctx.redirect_uri = Some(redirect_uri.clone());
                        redirect_uri
                    };

                    EmailAddress::new(&login_hint)
                        .map_err(|_| BrokerError::Input("login_hint is not a valid email address".to_string()))
                        .and_then(move |email_addr| {
                            Ok((shared_ctx, client_id, redirect_uri, nonce, login_hint, email_addr))
                        })
                });
            future::result(result)
        })
        .and_then(move |(shared_ctx, client_id, redirect_uri, nonce, login_hint, email_addr)| {
            let ctx = shared_ctx.lock().expect("failed to lock request context");

            // Enforce ratelimit based on the login_hint
            match addr_limiter(&ctx.app.store, &login_hint, &ctx.app.limit_per_email) {
                Err(err) => return future::err(err),
                Ok(false) => {
                    let res = Response::new()
                        .with_status(StatusCode::TooManyRequests)
                        .with_header(ContentType::plaintext())
                        .with_body("Rate limit exceeded. Please try again later.");
                    return future::ok(res)
                },
                _ => {},
            }

            future::result(
                if ctx.app.providers.contains_key(&email_addr.domain.to_lowercase()) {
                    // OIDC authentication. Redirect to the identity provider.
                    oidc_bridge::request(&ctx.app, &ctx.handle, &email_addr, &client_id, &nonce, &redirect_uri)
                        .map(|auth_url| {
                            Response::new()
                                .with_status(StatusCode::SeeOther)
                                .with_header(Location::new(auth_url.into_string()))
                        })

                } else {
                    // Determine the language catalog to use.
                    let mut catalog = &ctx.app.i18n.catalogs[0].1;
                    'outer: for accept_language in &accept_languages {
                        for &(ref lang_tag, ref lang_catalog) in &ctx.app.i18n.catalogs {
                            if lang_tag.matches(&accept_language.item) {
                                catalog = lang_catalog;
                                break 'outer;
                            }
                        }
                    }

                    // Email loop authentication. Render a message and form.
                    email_bridge::request(&ctx.app, &email_addr, &client_id, &nonce, &redirect_uri, catalog)
                        .map(|session_id| {
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
                        })
                }
            )
        })
        .boxed()
}
