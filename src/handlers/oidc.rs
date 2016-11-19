use config::Config;
use email_bridge;
use emailaddress::EmailAddress;
use error::{BrokerError, BrokerResult};
use iron::{Handler, IronResult, Plugin, Request, Response, Url};
use iron::headers::{ContentType, Location};
use iron::method::Method;
use iron::modifiers;
use iron::status;
use oidc_bridge;
use serde_json::builder::{ArrayBuilder, ObjectBuilder};
use std::sync::Arc;
use super::{RedirectUri, handle_error, json_response};
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use validation::{valid_uri, only_origin, same_origin};


/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
broker_handler!(Discovery, |app, _req| {
    json_response(&ObjectBuilder::new()
        .insert("issuer", &app.public_url)
        .insert("authorization_endpoint",
                format!("{}/auth", app.public_url))
        .insert("jwks_uri", format!("{}/keys.json", app.public_url))
        .insert("scopes_supported", vec!["openid", "email"])
        .insert("claims_supported",
                vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
        .insert("response_types_supported", vec!["id_token"])
        .insert("response_modes_supported", vec!["form_post"])
        .insert("grant_types_supported", vec!["implicit"])
        .insert("subject_types_supported", vec!["public"])
        .insert("id_token_signing_alg_values_supported", vec!["RS256"])
        .build())
});


/// Iron handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
broker_handler!(KeySet, |app, _req| {
    let mut keys = ArrayBuilder::new();
    for key in &app.keys {
        keys = keys.push(key.public_jwk())
    }
    json_response(&ObjectBuilder::new()
                      .insert("keys", keys.build())
                      .build())
});


/// Iron handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
broker_handler!(Auth, |app, req| {
    let params = try!(
        match req.method {
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
        }
    );

    let client_id = try_get_param!(params, "client_id");
    let redirect_uri = try_get_param!(params, "redirect_uri");

    try!(valid_uri(redirect_uri));
    try!(valid_uri(client_id));
    try!(same_origin(client_id, redirect_uri));
    try!(only_origin(client_id));
    if let Some(ref whitelist) = app.allowed_origins {
        if !whitelist.contains(&client_id.to_string()) {
            return Err(BrokerError::Input("the origin is not whitelisted".to_string()));
        }
    }

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let parsed_redirect_uri = Url::parse(redirect_uri).unwrap();
    req.extensions.insert::<RedirectUri>(parsed_redirect_uri.clone());

    if try_get_param!(params, "response_type") != "id_token" {
        return Err(BrokerError::Input("unsupported response_type, only id_token is supported".to_string()));
    }
    if try_get_param!(params, "response_mode", "fragment") != "form_post" {
        return Err(BrokerError::Input("unsupported response_mode, only form_post is supported".to_string()))
    }
    let email_addr = try!(
        EmailAddress::new(try_get_param!(params, "login_hint"))
            .map_err(|_| BrokerError::Input("login_hint is not a valid email address".to_string()))
    );
    let nonce = try_get_param!(params, "nonce");
    if app.providers.contains_key(&email_addr.domain.to_lowercase()) {

        // OIDC authentication. Redirect to the identity provider.
        let auth_url = try!(oidc_bridge::request(app, email_addr, client_id, nonce, &parsed_redirect_uri));
        Ok(Response::with((status::SeeOther, modifiers::Header(Location(auth_url.to_string())))))

    } else {

        // Email loop authentication. Render a message and form.
        let session_id = try!(email_bridge::request(app, email_addr, client_id, nonce, &parsed_redirect_uri));
        Ok(Response::with((status::Ok,
                           modifiers::Header(ContentType::html()),
                           app.templates.confirm_email.render(&[
                               ("client_id", &client_id),
                               ("session_id", &session_id),
                           ]))))

    }
});
