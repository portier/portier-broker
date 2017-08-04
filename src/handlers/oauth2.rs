use config::Config;
use error::{BrokerResult, BrokerError};
use handlers::{RedirectUri, handle_error, return_to_relier};
use iron::headers::ContentType;
use iron::method::Method;
use iron::middleware::Handler;
use iron::modifiers;
use iron::status;
use iron::{IronResult, Plugin, Request, Response, Url};
use oidc_bridge;
use std::sync::Arc;
use urlencoded::UrlEncodedBody;


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
///
/// For providers that don't support `response_type=form_post`, we capture the
/// fragment parameters in JavaScript and emulate the POST request.
///
/// Once we have a POST request, we can verify the callback data and return the
/// resulting token to the relying party, or error.
broker_handler!(Callback, |app, req| {
    match req.method {
        Method::Get => {
            Ok(Response::with((status::Ok,
                               modifiers::Header(ContentType::html()),
                               app.templates.fragment_callback.render(&[]))))
        },
        Method::Post => {
            let params = try!(req.compute::<UrlEncodedBody>()
                .map_err(|_| BrokerError::Input("no query string in POST data".to_string())));

            let stored = try!(app.store.get_session("oidc", try_get_param!(params, "state")));
            req.extensions.insert::<RedirectUri>(
                Url::parse(&stored["redirect"]).expect("redirect_uri missing from session")
            );

            let id_token = try_get_param!(params, "id_token");
            let (jwt, redirect_uri) = try!(oidc_bridge::verify(app, &stored, id_token));
            Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
        },
        _ => {
            panic!("Unsupported method: {}", req.method)
        }
    }
});
