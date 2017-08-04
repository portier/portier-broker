use config::Config;
use error::BrokerError;
use futures::future::{self, Future, BoxFuture, FutureResult};
use futures::Stream;
use handlers::return_to_relier;
use hyper::{self, StatusCode, Error as HyperError};
use hyper::header::{ContentType};
use hyper::server::{Request, Response, Service as HyperService};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use tokio_core::reactor::Remote;
use url::{Url, form_urlencoded};


/// The default type of client we use for outgoing requests
// TODO: Use a HTTPS connector
pub type Client = hyper::Client<hyper::client::HttpConnector>;


/// HTTP request context
pub struct Context {
    /// The application configuration
    pub app: Arc<Config>,
    /// A Tokio reactor handle
    pub handle: Remote,
    /// Redirect URI of the relying party
    pub redirect_uri: Option<Url>,
}


/// Short-hand
pub type ContextHandle = Arc<Mutex<Context>>;
/// Result type of handlers
pub type HandlerResult = BoxFuture<Response, BrokerError>;
/// Handler function type.
pub type Handler = fn(Request, ContextHandle) -> HandlerResult;


// HTTP service
pub struct Service {
    /// The application configuration
    pub app: Arc<Config>,
    /// A Tokio reactor handle
    pub handle: Remote,
    /// The routing function
    pub route: fn(&Request) -> Handler,
}

impl HyperService for Service {
    type Request = Request;
    type Response = Response;
    type Error = HyperError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    // TODO Add headers
    fn call(&self, req: Request) -> Self::Future {
        info!("{} {}", req.method(), req.path());

        let ctx = Arc::new(Mutex::new(Context {
            app: self.app.clone(),
            handle: self.handle.clone(),
            redirect_uri: None,
        }));

        (self.route)(&req)(req, ctx.clone())
            .or_else(|err| handle_error(ctx, err))
            .boxed()
    }
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
fn handle_error(shared_ctx: ContextHandle, err: BrokerError) -> FutureResult<Response, HyperError> {
    let ctx = shared_ctx.lock().expect("failed to lock request context");
    match (err, ctx.redirect_uri.as_ref()) {
        (err @ BrokerError::Input(_), Some(_)) => {
            return_to_relier(&ctx, &[
                ("error", "invalid_request"),
                ("error_description", err.description()),
            ])
        },
        (err @ BrokerError::Input(_), None) => {
            let res = Response::new()
                .with_status(StatusCode::BadRequest)
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("error", err.description()),
                ]));
            future::ok(res)
        },
        (err @ BrokerError::Provider(_), Some(_)) => {
            error!("{}", err);
            return_to_relier(&ctx, &[
                ("error", "temporarily_unavailable"),
                ("error_description", &err.description().to_string()),
            ])
        },
        (err @ BrokerError::Provider(_), None) => {
            error!("{}", err);
            let res = Response::new()
                .with_status(StatusCode::ServiceUnavailable)
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("error", &err.description().to_string()),
                ]));
            future::ok(res)
        },
        (err, Some(_)) => {
            error!("{}", err);
            return_to_relier(&ctx, &[
                ("error", "server_error"),
            ])
        },
        (err, None) => {
            error!("{}", err);
            let res = Response::new()
                .with_status(StatusCode::InternalServerError)
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("error", "internal server error"),
                ]));
            future::ok(res)
        },
    }
}


/// Parse a form-encoded string into a `HashMap`.
pub fn parse_form_encoded(input: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (key, value) in form_urlencoded::parse(input) {
        map.insert(key.into_owned(), value.into_owned());
    }
    map
}


/// Parse the request query string into a `HashMap`.
pub fn parse_query(req: &Request) -> HashMap<String, String> {
    if let Some(query) = req.query() {
        parse_form_encoded(query.as_bytes())
    } else {
        HashMap::new()
    }
}


/// Parse the request form-encoded body into a `HashMap`.
pub fn parse_form_encoded_body(req: Request) -> BoxFuture<HashMap<String, String>, BrokerError> {
    req.body().concat2()
        .map_err(|err| err.into())
        .map(|chunk| parse_form_encoded(&chunk))
        .boxed()
}
