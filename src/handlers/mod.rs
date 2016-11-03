use config::Config;
use error::{BrokerResult, BrokerError};
use hyper;
use iron::{IronError, IronResult, Request, Response, Url};
use iron::headers::ContentType;
use iron::modifiers;
use iron::status;
use iron::typemap;
use mustache;
use serde_json;
use serde_json::value::Value;
use std::error::Error;


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


pub mod pages;
pub mod oidc;
pub mod oauth2;
pub mod email;
