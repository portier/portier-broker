use config::Config;
use email_bridge;
use emailaddress::EmailAddress;
use error::{BrokerError, BrokerResult};
use iron::{Handler, IronResult, Plugin, Request, Response, Url};
use iron::headers::{ContentType, Location, AcceptLanguage};
use iron::method::Method;
use iron::modifiers;
use iron::status;
use oidc_bridge;
use std::sync::Arc;
use super::{RedirectUri, handle_error, json_response};
use super::super::store_limits::addr_limiter;
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use validation::{valid_uri, only_origin, same_origin};

/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
broker_handler!(Discovery, |app, _req| {
    let obj = json!({
        "issuer": app.public_url,
        "authorization_endpoint": format!("{}/auth", app.public_url),
        "jwks_uri": format!("{}/keys.json", app.public_url),
        "scopes_supported": vec!["openid", "email"],
        "claims_supported": vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"],
        "response_types_supported": vec!["id_token"],
        "response_modes_supported": vec!["form_post"],
        "grant_types_supported": vec!["implicit"],
        "subject_types_supported": vec!["public"],
        "id_token_signing_alg_values_supported": vec!["RS256"],
    });
    json_response(&obj, app.discovery_ttl)
});


/// Iron handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
broker_handler!(KeySet, |app, _req| {
    let obj = json!({
        "keys": app.keys.iter()
            .map(|key| key.public_jwk())
            .collect::<Vec<_>>(),
    });
    json_response(&obj, app.keys_ttl)
});


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
broker_handler!(Auth, |app, req| {
    let params = match req.method {
        Method::Get => {
            req.compute::<UrlEncodedQuery>()
                .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
        },
        Method::Post => {
            req.compute::<UrlEncodedBody>()
                .map_err(|_| BrokerError::Input("no query string in POST data".to_string()))
        },
        _ => {
            panic!("Unsupported method: {}", req.method)
        }
    }?;

    let client_id = try_get_param!(params, "client_id");
    let redirect_uri = try_get_param!(params, "redirect_uri");

    valid_uri(redirect_uri, "redirect_uri")?;
    valid_uri(client_id, "client_id")?;
    same_origin(client_id, redirect_uri)?;
    only_origin(client_id)?;
    if let Some(ref whitelist) = app.allowed_origins {
        if !whitelist.contains(&client_id.to_string()) {
            return Err(BrokerError::Input("the origin is not whitelisted".to_string()));
        }
    }

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let parsed_redirect_uri = Url::parse(redirect_uri).expect("unable to parse redirect uri");
    req.extensions.insert::<RedirectUri>(parsed_redirect_uri.clone());

    // Check for all other necessary parameters
    if try_get_param!(params, "response_type") != "id_token" {
        return Err(BrokerError::Input("unsupported response_type, only id_token is supported".to_string()));
    }
    if try_get_param!(params, "response_mode", "fragment") != "form_post" {
        return Err(BrokerError::Input("unsupported response_mode, only form_post is supported".to_string()))
    }
    let nonce = try_get_param!(params, "nonce");
    let login_hint = try_get_param!(params, "login_hint");

    let email_addr = EmailAddress::new(login_hint)
        .map_err(|_| BrokerError::Input("login_hint is not a valid email address".to_string()))?;

    // Enforce ratelimit based on the login_hint
    if !addr_limiter(&app.store, &login_hint, &app.limit_per_email)? {
        return Ok(Response::with((
                    status::TooManyRequests,
                    modifiers::Header(ContentType::plaintext()),
                    "Rate limit exceeded. Please try again later.")));
    }

    if app.providers.contains_key(&email_addr.domain.to_lowercase()) {
        // OIDC authentication. Redirect to the identity provider.
        let auth_url = oidc_bridge::request(app, email_addr, client_id, nonce, &parsed_redirect_uri)?;
        Ok(Response::with((status::SeeOther, modifiers::Header(Location(auth_url.to_string())))))

    } else {
        // Determine the language catalog to use.
        let mut catalog = &app.i18n.catalogs[0].1;
        if let Some(accept) = req.headers.get::<AcceptLanguage>() {
            'outer: for accept_language in accept.iter() {
                for &(ref lang_tag, ref lang_catalog) in &app.i18n.catalogs {
                    if lang_tag.matches(&accept_language.item) {
                        catalog = lang_catalog;
                        break 'outer;
                    }
                }
            }
        }

        // Email loop authentication. Render a message and form.
        let session_id = email_bridge::request(app, email_addr, client_id, nonce, &parsed_redirect_uri, &catalog)?;

        Ok(Response::with((status::Ok,
                           modifiers::Header(ContentType::html()),
                           app.templates.confirm_email.render(&[
                               ("client_id", &client_id),
                               ("session_id", &session_id),
                               ("title", catalog.gettext("Confirm your address")),
                               ("explanation", catalog.gettext("We've sent you an email to confirm your address.")),
                               ("use", catalog.gettext("Use the link in that email to login to")),
                               ("alternate", catalog.gettext("Alternatively, enter the code from the email to continue in this browser tab:")),
                           ]))))
    }
});
