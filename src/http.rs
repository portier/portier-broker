use bridges::BridgeData;
use config::Config;
use crypto;
use email_address::EmailAddress;
use error::{BrokerError, BrokerResult};
use futures::future::{self, Future, FutureResult};
use futures::Stream;
use gettext::Catalog;
use hyper::{Body, Chunk, Error as HyperError, Method, StatusCode};
use hyper::header::{AcceptLanguage, ContentType, Location, StrictTransportSecurity, CacheControl, CacheDirective};
use hyper::server::{Request, Response, Service as HyperService};
use hyper_staticfile::Static;
use mustache;
use serde_helpers::UrlDef;
use serde_json as json;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::{fmt, io};
use url::{Url, form_urlencoded};


header! { (ContentSecurityPolicy, "Content-Security-Policy") => [String] }
header! { (XContentSecurityPolicy, "X-Content-Security-Policy") => [String] }
header! { (XContentTypeOptions, "X-Content-Type-Options") => [String] }
header! { (XXSSProtection, "X-XSS-Protection") => [String] }
header! { (XFrameOptions, "X-Frame-Options") => [String] }


/// A boxed future. Unlike the regular `BoxFuture`, this is not `Send`.
/// This means we also do not use the `boxed()` method.
pub type BoxFuture<T, E> = Box<Future<Item=T, Error=E>>;


/// Error type used within an `io::Error`, to indicate a size limit was exceeded.
#[derive(Debug)]
pub struct SizeLimitExceeded;
impl Error for SizeLimitExceeded {
    fn description(&self) -> &str {
        "size limit exceeded"
    }
}
impl fmt::Display for SizeLimitExceeded {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())
    }
}


/// A session as stored in Redis.
#[derive(Serialize,Deserialize)]
pub struct Session {
    pub data: SessionData,
    pub bridge_data: BridgeData,
}


/// Response modes we support.
#[derive(Clone,Copy,Serialize,Deserialize)]
pub enum ResponseMode {
    #[serde(rename = "fragment")]
    Fragment,
    #[serde(rename = "form_post")]
    FormPost,
}


/// Parameters used to return to the relying party
#[derive(Clone,Serialize,Deserialize)]
pub struct ReturnParams {
    #[serde(with = "UrlDef")]
    pub redirect_uri: Url,
    pub response_mode: ResponseMode,
    pub response_errors: bool,
    pub state: String,
}


/// Common session data.
#[derive(Serialize,Deserialize)]
pub struct SessionData {
    pub return_params: ReturnParams,
    pub email: String,
    #[serde(deserialize_with = "EmailAddress::deserialize_trusted")]
    pub email_addr: EmailAddress,
    pub nonce: String,
}


/// Context for a request
pub struct Context {
    /// The application configuration
    pub app: Rc<Config>,
    /// Request method
    pub method: Method,
    /// Request query string
    pub query: String,
    /// Request body
    pub body: Chunk,
    /// Session ID
    pub session_id: String,
    /// Session data (must be explicitely loaded)
    pub session_data: Option<SessionData>,
    /// Index into the config catalogs of the language to use
    pub catalog_idx: usize,
    /// Parameters used to return to the relying party
    pub return_params: Option<ReturnParams>,
}

impl Context {
    /// Get a reference to the language catalog to use
    pub fn catalog(&self) -> &Catalog {
        &self.app.i18n.catalogs[self.catalog_idx].1
    }

    /// Parse the query string into a `HashMap`.
    pub fn query_params(&self) -> HashMap<String, String> {
        parse_form_encoded(self.query.as_bytes())
    }

    /// Parse the form-encoded body into a `HashMap`.
    pub fn form_params(&self) -> HashMap<String, String> {
        parse_form_encoded(&self.body)
    }

    /// Start a session by filling out the common part.
    pub fn start_session(&mut self, client_id: &str, email: &str, email_addr: &EmailAddress, nonce: &str) {
        assert!(self.session_id.is_empty());
        assert!(self.session_data.is_none());
        let return_params = self.return_params.as_ref().expect("start_session called without return parameters");
        self.session_id = crypto::session_id(email_addr, client_id);
        self.session_data = Some(SessionData {
            return_params: return_params.clone(),
            email: email.to_owned(),
            email_addr: email_addr.clone(),
            nonce: nonce.to_owned(),
        });
    }

    /// Try to save the session with the given bridge data.
    ///
    /// Will return `false` if the session was not started, which will also happen if another
    /// provider has already claimed the session.
    pub fn save_session(&mut self, bridge_data: BridgeData) -> BrokerResult<bool> {
        let data = match self.session_data.take() {
            Some(data) => data,
            None => return Ok(false),
        };
        let data = json::to_string(&Session { data, bridge_data }).map_err(|e| BrokerError::Internal(
            format!("could not serialize session: {}", e)))?;
        self.app.store.store_session(&self.session_id, &data)?;
        Ok(true)
    }

    /// Load a session from storage.
    pub fn load_session(&mut self, id: &str) -> BrokerResult<BridgeData> {
        assert!(self.session_id.is_empty());
        assert!(self.session_data.is_none());
        assert!(self.return_params.is_none());
        let data = self.app.store.get_session(id)?;
        let (data, bridge_data) = match json::from_str(&data) {
            Ok(Session { data, bridge_data }) => (data, bridge_data),
            Err(e) => return Err(BrokerError::Internal(format!("could not deserialize session: {}", e))),
        };
        self.return_params = Some(data.return_params.clone());
        self.session_id = id.to_owned();
        self.session_data = Some(data);
        Ok(bridge_data)
    }
}


/// Short-hand
pub type ContextHandle = Rc<RefCell<Context>>;
/// Result type of handlers
pub type HandlerResult = BoxFuture<Response, BrokerError>;
/// Handler function type
pub type Handler = fn(&ContextHandle) -> HandlerResult;
/// Router function type
pub type Router = fn(&Request) -> Option<Handler>;


// HTTP service
pub struct Service {
    /// The application configuration
    app: Rc<Config>,
    /// The client address
    addr: SocketAddr,
    /// The routing function
    router: Router,
    /// The static file serving service
    static_: Static,
}

impl Service {
    pub fn new<P: Into<PathBuf>>(
        app: &Rc<Config>,
        addr: SocketAddr,
        router: Router,
        path: P
    ) -> Service {
        Service {
            app: Rc::clone(app),
            addr,
            router,
            static_: Static::new(path).with_cache_headers(app.static_ttl),
        }
    }
}

impl HyperService for Service {
    type Request = Request;
    type Response = Response;
    type Error = HyperError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Request) -> Self::Future {
        info!("{} - {} {}", self.addr, req.method(), req.path());

        // Match route or serve static files.
        let handler = match (self.router)(&req) {
            Some(handler) => handler,
            None => return self.static_.call(req),
        };

        // Read the request body.
        let (method, uri, _, headers, body) = req.deconstruct();
        let f = match method {
            Method::Post => read_body(body),
            _ => Box::new(future::ok(Chunk::from(vec![]))),
        };

        let app = Rc::clone(&self.app);
        let f = f.and_then(move |body| {
            // Determine the language catalog to use.
            let mut catalog_idx = 0;
            if let Some(&AcceptLanguage(ref list)) = headers.get() {
                for entry in list {
                    for (idx, &(ref tag, _)) in app.i18n.catalogs.iter().enumerate() {
                        if tag.matches(&entry.item) {
                            catalog_idx = idx;
                            break;
                        }
                    }
                }
            }

            // Create the request context.
            let ctx_handle = Rc::new(RefCell::new(Context {
                app,
                method,
                query: uri.query().unwrap_or("").to_owned(),
                body,
                session_id: String::default(),
                session_data: None,
                catalog_idx,
                return_params: None,
            }));

            // Call the route handler.
            let f = handler(&ctx_handle);

            // Handle errors.
            f.or_else(move |err| {
                let ctx = ctx_handle.borrow();
                Ok(handle_error(&*ctx, err))
            })
        });

        // Set common headers.
        let f = f.map(|mut res| {
            set_headers(&mut res);
            res
        });

        Box::new(f)
    }
}


/// Handle an `BrokerError` and create a response.
///
/// Our service calls this on error. We handle all these errors, and always
/// return a response.
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
/// The large match-statement below handles all these scenario's properly, and
/// sets proper response codes for each category.
fn handle_error(ctx: &Context, err: BrokerError) -> Response {
    let reference = err.log();

    // Check if we can redirect to the RP. We must have return parameters, and the RP must not have
    // opted out from receiving errors in the redirect response.
    let can_redirect = match ctx.return_params {
        Some(ReturnParams { response_errors: true, .. }) => true,
        _ => false,
    };

    let catalog = ctx.catalog();
    match (err, can_redirect) {
        // Redirects with description.
        (err @ BrokerError::Input(_), true)
            | (err @ BrokerError::Provider(_), true)
            | (err @ BrokerError::ProviderInput(_), true)
            => {
            return_to_relier(ctx, &[
                ("error", err.oauth_error_code()),
                ("error_description", err.description()),
            ])
        },
        // Friendly error pages for what we can't redirect.
        (err @ BrokerError::Input(_), false) => {
            Response::new()
                .with_status(err.http_status_code())
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("error", err.description()),
                    ("intro", catalog.gettext("The request is invalid, and could not be completed.")),
                    ("reason", catalog.gettext("Technical description")),
                    ("explanation", catalog.gettext("This indicates an issue with the site you're trying to login to. Contact the site administrator to get the issue resolved.")),
                ]))
        },
        (err @ BrokerError::Provider(_), false)
            | (err @ BrokerError::ProviderInput(_), false)
            => {
            Response::new()
                .with_status(err.http_status_code())
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("error", err.description()),
                    ("intro", catalog.gettext("Failed to connect with your email domain.")),
                    ("reason", catalog.gettext("Technical description")),
                    ("explanation", catalog.gettext("Contact the administrator of your email domain to get the issue resolved.")),
                ]))
        },
        // Friendly error pages for what we will never redirect.
        (err @ BrokerError::Internal(_), _) => {
            Response::new()
                .with_status(err.http_status_code())
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("ref", &reference.expect("internal error must have a reference")),
                    ("intro", catalog.gettext("Something went wrong, and we cannot complete your request at this time.")),
                    ("explanation", catalog.gettext("An internal error occurred, which has been logged with the below reference number.")),
                ]))
        },
        (err @ BrokerError::RateLimited, _) => {
            Response::new()
                .with_status(err.http_status_code())
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("intro", catalog.gettext("Too many login attempts.")),
                    ("explanation", catalog.gettext("We've received too many requests in a short amount of time. Please try again later.")),
                ]))
        },
        (err @ BrokerError::SessionExpired, _) => {
            Response::new()
                .with_status(err.http_status_code())
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.error.render(&[
                    ("intro", catalog.gettext("The session has expired.")),
                    ("explanation", catalog.gettext("Your login attempt may have taken too long, or you tried to follow an old link. Please try again.")),
                ]))
        },
        // Internal status that should never bubble this far
        (BrokerError::ProviderCancelled, _) => {
            unreachable!()
        },
    }
}


/// Mutate a response to set common headers.
fn set_headers(res: &mut Response) {
    let headers = res.headers_mut();

    // Specify a tight content security policy. We need to be able to POST
    // redirect anywhere, and run our own scripts.
    let csp = vec![
        "sandbox allow-scripts allow-forms",
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "form-action *",
    ].join("; ");

    headers.set(StrictTransportSecurity::excluding_subdomains(31_536_000u64));
    headers.set(ContentSecurityPolicy(csp.clone()));
    headers.set(XContentSecurityPolicy(csp));
    headers.set(XContentTypeOptions("nosniff".to_owned()));
    headers.set(XXSSProtection("1; mode=block".to_owned()));
    headers.set(XFrameOptions("DENY".to_owned()));

    // Default to disable caching completely.
    if !headers.has::<CacheControl>() {
        headers.set(CacheControl(vec![
            CacheDirective::NoCache,
            CacheDirective::NoStore,
        ]));
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


/// Read the request or response body up to a fixed size.
pub fn read_body(body: Body) -> BoxFuture<Chunk, HyperError> {
    Box::new(body.fold(Chunk::default(), |mut acc, chunk| {
        if acc.len() + chunk.len() > 8096 {
            Err(io::Error::new(io::ErrorKind::Other, SizeLimitExceeded))
        } else {
            acc.extend(chunk);
            Ok(acc)
        }
    }))
}


/// Helper function for returning a result to the Relying Party.
///
/// Takes an array of `(name, value)` parameter pairs and returns a response
/// that sends them to the RP's `redirect_uri`. The method used to return to
/// the RP depends on the `response_mode`.
pub fn return_to_relier(ctx: &Context, params: &[(&str, &str)]) -> Response {
    let &ReturnParams { ref redirect_uri, response_mode, .. } = ctx.return_params.as_ref()
        .expect("return_to_relier called without return parameters");

    match response_mode {
        // Add params as fragment parameters and redirect.
        ResponseMode::Fragment => {
            let mut redirect_uri = redirect_uri.clone();
            let fragment = redirect_uri.fragment().unwrap_or("").to_owned();
            let fragment = form_urlencoded::Serializer::for_suffix(fragment, 0)
                .extend_pairs(params)
                .finish();
            redirect_uri.set_fragment(Some(&fragment));

            Response::new()
                .with_status(StatusCode::SeeOther)
                .with_header(Location::new(redirect_uri.into_string()))
        },
        // Render a form that submits a POST request.
        ResponseMode::FormPost => {
            let data = mustache::MapBuilder::new()
                .insert_str("redirect_uri", redirect_uri.to_string())
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

            Response::new()
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.forward.render_data(&data))
        },
    }
}


/// Helper function for returning a response with JSON data.
///
/// Serializes the argument value to JSON and returns a HTTP 200 response
/// code with the serialized JSON as the body.
pub fn json_response<E>(obj: &json::Value, max_age: u32) -> FutureResult<Response, E> {
    let body = json::to_string(&obj).expect("unable to coerce JSON Value into string");
    let res = Response::new()
        .with_header(ContentType::json())
        .with_header(CacheControl(vec![
            CacheDirective::Public,
            CacheDirective::MaxAge(max_age),
        ]))
        .with_body(body);
    future::ok(res)
}


#[cfg(test)]
mod tests {
    use hyper::server::Response;
    use super::set_headers;

    #[test]
    fn sets_expected_headers() {
        let mut res = Response::new();
        set_headers(&mut res);

        let headers = res.headers();
        assert!(headers.get_raw("Strict-Transport-Security").is_some());
        assert!(headers.get_raw("Content-Security-Policy").is_some());
        assert!(headers.get_raw("X-Content-Security-Policy").is_some());
        assert!(headers.get_raw("X-Content-Type-Options").is_some());
        assert!(headers.get_raw("X-XSS-Protection").is_some());
        assert!(headers.get_raw("X-Frame-Options").is_some());
        assert!(headers.get_raw("Cache-Control").is_some());
    }
}
