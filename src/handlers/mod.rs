use config::Config;
use email;
use emailaddress::EmailAddress;
use error::{BrokerResult, BrokerError};
use hyper;
use iron::{IronError, IronResult, Plugin, Request, Response, Url};
use iron::headers::{ContentType, Location};
use iron::method::Method;
use iron::middleware::Handler;
use iron::modifiers;
use iron::status;
use iron::typemap;
use mustache;
use oidc;
use serde_json;
use serde_json::builder::{ArrayBuilder, ObjectBuilder};
use serde_json::value::Value;
use std::error::Error;
use std::sync::Arc;
use urlencoded::{UrlEncodedBody, UrlEncodedQuery};
use validation::{valid_uri, only_origin, same_origin};


/// Iron extension key we use to store the `redirect_uri`.
/// Once set, the error handler will return errors to the RP.
struct RedirectUri;
impl typemap::Key for RedirectUri { type Value = Url; }


/// Macro that creates Handler implementations that log the request,
/// and keep a reference to the Config.
macro_rules! broker_handler {
    ( $name:ident , | $app:ident, $req:ident | $body:block ) => {
        pub struct $name {
            pub app: Arc<Config>,
        }
        impl $name {
            pub fn new(app: &Arc<Config>) -> Self {
                $name { app: app.clone() }
            }
            fn handle_body($app: &Config, $req: &mut Request)
                -> BrokerResult<Response> $body
        }
        impl Handler for $name {
            fn handle(&self, req: &mut Request) -> IronResult<Response> {
                Self::handle_body(&self.app, req)
                    .or_else(|e| handle_error(&self.app, req, e))
            }
        }
    }
}


/// Macro used to extract a parameter from a QueryMap.
///
/// Will return from the caller with a `BrokerError` if
/// the parameter is missing and has no default.
///
/// ```
/// let foo = try_get_param!(params, "foo");
/// let foo = try_get_param!(params, "foo", "default");
/// ```
macro_rules! try_get_param {
    ( $input:expr , $param:tt ) => {
        try!($input.get($param)
                   .and_then(|list| list.into_iter().nth(0))
                   .map(|s| s.as_str())
                   .ok_or_else(|| BrokerError::Input(concat!("missing request parameter ", $param).to_string()))
        )
    };
    ( $input:expr , $param:tt, $default:tt ) => {
        $input.get($param)
              .and_then(|list| list.into_iter().nth(0))
              .map(|s| s.as_str())
              .unwrap_or($default)
    };
}


/// Helper function for returning a result to the Relying Party.
///
/// Takes an array of `(name, value)` parameter pairs to send to the relier and
/// embeds them in a form in `tmpl/forward.html`, from where it's POSTed to the
/// RP's `redirect_uri` as soon as the page has loaded.
///
/// The return value is a tuple of response modifiers.
fn return_to_relier(app: &Config, redirect_uri: &str, params: &[(&str, &str)])
    -> (hyper::status::StatusCode, modifiers::Header<ContentType>, String) {
    let data = mustache::MapBuilder::new()
        .insert_str("redirect_uri", redirect_uri)
        .insert_vec("params", |mut builder| {
            for &param in params {
                builder = builder.push_map(|builder| {
                    let (name, value) = param;
                    builder.insert_str("name", name).insert_str("value", value)
                });
            }
            builder
        })
        .build();
    (status::Ok,
     modifiers::Header(ContentType::html()),
     app.templates.forward.render_data(&data))
}


/// Handle an `BrokerError` and create an `IronResult`.
///
/// The `broker_handler!` macro calls this on error. We don't use a `From`
/// implementation, because this way we get app and request context, and we
/// don't necessarily have to pass the error on to Iron.
///
/// When we handle an error, we want to:
///
///  - Log internal errors and errors related to communcation with providers.
///  - Not log input errors, such as missing parameters.
///
///  - Hide the details of internal errors from the user.
///  - Show a description for input and provider errors.
///
///  - Return the error to the relier via redirect, as per the OAuth2 spec.
///  - Always show something to the user, even if we cannot redirect.
///
/// The large match-statement below handles all these scenario's properly,
/// and sets proper response codes for each category.
fn handle_error(app: &Config, req: &mut Request, err: BrokerError) -> IronResult<Response> {
    let redirect_uri = req.extensions.remove::<RedirectUri>().map(|url| url.to_string());
    match (err, redirect_uri) {
        (err @ BrokerError::Input(_), Some(redirect_uri)) => {
            Ok(Response::with(return_to_relier(app, &redirect_uri, &[
                ("error", "invalid_request"),
                ("error_description", err.description()),
            ])))
        },
        (err @ BrokerError::Input(_), None) => {
            Ok(Response::with((status::BadRequest,
                               modifiers::Header(ContentType::html()),
                               app.templates.error.render(&[
                                   ("error", err.description()),
                               ]))))
        },
        (err @ BrokerError::Provider(_), Some(redirect_uri)) => {
            let description = err.description().to_string();
            Err(IronError::new(err, return_to_relier(app, &redirect_uri, &[
                ("error", "temporarily_unavailable"),
                ("error_description", &description),
            ])))
        },
        (err @ BrokerError::Provider(_), None) => {
            let description = err.description().to_string();
            Err(IronError::new(err, (status::ServiceUnavailable,
                                     modifiers::Header(ContentType::html()),
                                     app.templates.error.render(&[
                                         ("error", &description),
                                     ]))))
        },
        (err, Some(redirect_uri)) => {
            Err(IronError::new(err, return_to_relier(app, &redirect_uri, &[
                ("error", "server_error"),
            ])))
        },
        (err, None) => {
            Err(IronError::new(err, (status::InternalServerError,
                                     modifiers::Header(ContentType::html()),
                                     app.templates.error.render(&[
                                         ("error", "internal server error"),
                                     ]))))
        },
    }
}


/// Helper function for returning an Iron response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
fn json_response(obj: &Value) -> BrokerResult<Response> {
    let content = serde_json::to_string(&obj).unwrap();
    Ok(Response::with((status::Ok,
                       modifiers::Header(ContentType::json()),
                       content)))
}


/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
broker_handler!(WelcomeHandler, |_app, _req| {
    json_response(&ObjectBuilder::new()
        .insert("ladaemon", "Welcome")
        .insert("version", env!("CARGO_PKG_VERSION"))
        .build())
});


/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
broker_handler!(OIDConfigHandler, |app, _req| {
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
broker_handler!(KeysHandler, |app, _req| {
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
broker_handler!(AuthHandler, |app, req| {
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
    if app.providers.contains_key(&email_addr.domain) {

        // OIDC authentication. Redirect to the identity provider.
        let auth_url = try!(oidc::request(app, email_addr, client_id, nonce, &parsed_redirect_uri));
        Ok(Response::with((status::SeeOther, modifiers::Header(Location(auth_url.to_string())))))

    } else {

        // Email loop authentication. Render a message and form.
        let session_id = try!(email::request(app, email_addr, client_id, nonce, &parsed_redirect_uri));
        Ok(Response::with((status::Ok,
                           modifiers::Header(ContentType::html()),
                           app.templates.confirm_email.render(&[
                               ("client_id", &client_id),
                               ("session_id", &session_id),
                           ]))))

    }
});


/// Iron handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
broker_handler!(ConfirmHandler, |app, req| {
    let params = try!(
        req.compute::<UrlEncodedQuery>()
            .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
    );

    let stored = try!(app.store.get_session("email", &try_get_param!(params, "session")));
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).unwrap());

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = try!(email::verify(app, &stored, code));
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
/// Verify the callback data and return the resulting token or error.
broker_handler!(CallbackHandler, |app, req| {
    let params = try!(
        req.compute::<UrlEncodedQuery>()
            .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))
    );

    let stored = try!(app.store.get_session("oidc", &try_get_param!(params, "state")));
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).unwrap());

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = try!(oidc::verify(app, &stored, code));
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});
