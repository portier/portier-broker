use config::Config;
use email_bridge;
use error::{BrokerResult, BrokerError};
use iron::{IronResult, Plugin, Request, Response, Url};
use iron::middleware::Handler;
use std::sync::Arc;
use super::{RedirectUri, handle_error, return_to_relier};
use urlencoded::UrlEncodedQuery;


/// Iron handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
broker_handler!(Confirmation, |app, req| {
    let params = req.compute::<UrlEncodedQuery>()
            .map_err(|_| BrokerError::Input("no query string in GET request".to_string()))?;

    let stored = app.store.get_session("email", &try_get_param!(params, "session"))?;
    req.extensions.insert::<RedirectUri>(Url::parse(&stored["redirect"]).expect("unable to parse stored redirect uri"));

    let code = try_get_param!(params, "code");
    let (jwt, redirect_uri) = email_bridge::verify(app, &stored, code)?;
    Ok(Response::with(return_to_relier(app, &redirect_uri, &[("id_token", &jwt)])))
});
