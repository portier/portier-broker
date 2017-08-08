use config::Config;
use futures::future::{self, FutureResult};
use http::Context;
use hyper::header::{ContentType, CacheControl, CacheDirective};
use hyper::server::Response;
use mustache;
use serde_json::value::Value;
use serde_json;
use std::cell::Ref;


/// Macro used to extract a parameter from a `QueryMap`.
///
/// Will return from the caller with a `BrokerError` if
/// the parameter is missing and has no default.
///
/// ```
/// let foo = try_get_param!(params, "foo");
/// let foo = try_get_param!(params, "foo", "default");
/// ```
macro_rules! try_get_param {
    ( $params:expr , $key:tt ) => {
        match $params.remove($key) {
            Some(value) => value,
            None => return future::err(
                BrokerError::Input(concat!("missing request parameter ", $key).to_string())
            ),
        }
    };
    ( $params:expr , $key:tt, $default:expr ) => {
        $params.remove($key).unwrap_or($default)
    };
}


/// Helper function for returning a result to the Relying Party.
///
/// Takes an array of `(name, value)` parameter pairs to send to the relier and
/// embeds them in a form in `tmpl/forward.html`, from where it's POSTed to the
/// RP's `redirect_uri` as soon as the page has loaded.
///
/// The return value is a tuple of response modifiers.
pub fn return_to_relier<E>(app: &Config, ctx: &Ref<Context>, params: &[(&str, &str)]) -> FutureResult<Response, E> {
    let redirect_uri = ctx.redirect_uri.as_ref()
        .expect("return_to_relier called without redirect_uri set");

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

    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(app.templates.forward.render_data(&data));
    future::ok(res)
}


/// Helper function for returning a response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
pub fn json_response<E>(obj: &Value, max_age: u32) -> FutureResult<Response, E> {
    let body = serde_json::to_string(&obj).expect("unable to coerce JSON Value into string");
    let res = Response::new()
        .with_header(ContentType::json())
        .with_header(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MaxAge(max_age),
        ]))
        .with_body(body);
    future::ok(res)
}


pub mod pages;
pub mod oidc;
pub mod oauth2;
pub mod email;

