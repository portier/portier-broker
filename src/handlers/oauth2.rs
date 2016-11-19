use config::Config;
use error::{BrokerResult, BrokerError};
use iron::{IronResult, Plugin, Request, Response, Url};
use iron::middleware::Handler;
use oidc_bridge;
use std::sync::Arc;
use super::{RedirectUri, handle_error, return_to_relier};
use urlencoded::UrlEncodedQuery;


/// Iron handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
/// Verify the callback data and return the resulting token or error.
broker_handler!(Callback, |app, req| {
    let params = req.compute::<UrlEncodedQuery>()
                    .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))?;

    let stored = app.store.get_session("oidc", &try_get_param!(params, "state"))?;
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).expect("unable to parse stored redirect uri"));

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = oidc_bridge::verify(app, &stored, code)?;
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});
