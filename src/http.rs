use config::Config;
use error::{BrokerError, BrokerResult};
use futures::future::{self, Future, FutureResult};
use futures::Stream;
use gettext::Catalog;
use handlers::return_to_relier;
use hyper::{Method, Body, Chunk, StatusCode, Error as HyperError};
use hyper::header::{AcceptLanguage, ContentType, StrictTransportSecurity, CacheControl, CacheDirective};
use hyper::server::{Request, Response, Service as HyperService};
use hyper_staticfile::Static;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::ops::Index;
use std::path::PathBuf;
use std::rc::Rc;
use tokio_core::reactor::Handle;
use url::{Url, form_urlencoded};


header! { (ContentSecurityPolicy, "Content-Security-Policy") => [String] }
header! { (XContentSecurityPolicy, "X-Content-Security-Policy") => [String] }
header! { (XContentTypeOptions, "X-Content-Type-Options") => [String] }
header! { (XXSSProtection, "X-XSS-Protection") => [String] }
header! { (XFrameOptions, "X-Frame-Options") => [String] }


/// A boxed future. Unlike the regular `BoxFuture`, this is not `Send`.
/// This means we also do not use the `boxed()` method.
pub type BoxFuture<T, E> = Box<Future<Item=T, Error=E>>;


/// Generic session storage
#[derive(Default)]
pub struct Session {
    pub id: String,
    pub data: HashMap<String, String>,
}

impl Session {
    pub fn set(&mut self, key: &str, value: String) {
        self.data.insert(key.to_owned(), value);
    }
}

impl<'a> Index<&'a str> for Session {
    type Output = String;
    fn index(&self, index: &str) -> &String {
        &self.data[index]
    }
}


/// Context for a request
pub struct Context {
    /// The application configuration
    pub app: Rc<Config>,
    /// Request parameters, from the query or body
    pub params: HashMap<String, String>,
    /// Session data (must be explicitely loaded)
    pub session: Session,
    /// Index into the config catalogs of the language to use
    pub catalog_idx: usize,
    /// Redirect URI of the relying party
    pub redirect_uri: Option<Url>,
}

impl Context {
    /// Get a reference to the language catalog to use
    pub fn catalog(&self) -> &Catalog {
        &self.app.i18n.catalogs[self.catalog_idx].1
    }

    pub fn save_session(&self) -> BrokerResult<()> {
        debug_assert_ne!(&self.session.id, "");
        debug_assert!(self.session.data.contains_key("type"));
        let data = self.session.data.iter()
            .map(|(k, v)| -> (&str, &str) { (k, v) })
            .collect::<Vec<(&str, &str)>>();
        self.app.store.store_session(&self.session.id, &data)
    }

    pub fn load_session(&mut self, id: &str, type_value: &str) -> BrokerResult<()> {
        let data = self.app.store.get_session(id)?;
        if data["type"] != type_value {
            return Err(BrokerError::Input("invalid session".to_owned()));
        }
        self.session.id = id.to_owned();
        self.session.data = data;
        Ok(())
    }
}


/// Short-hand
pub type ContextHandle = Rc<RefCell<Context>>;
/// Result type of handlers
pub type HandlerResult = BoxFuture<Response, BrokerError>;
/// Handler function type
pub type Handler = fn(ContextHandle) -> HandlerResult;
/// Router function type
pub type Router = fn(&Request) -> Option<Handler>;


// HTTP service
pub struct Service {
    /// The application configuration
    app: Rc<Config>,
    /// The routing function
    router: Router,
    /// The static file serving service
    static_: Static,
}

impl Service {
    pub fn new<P: Into<PathBuf>>(handle: &Handle, app: &Rc<Config>, router: Router, path: P) -> Service {
        Service {
            app: app.clone(),
            router: router,
            static_: Static::new(handle, path).with_cache_headers(app.static_ttl),
        }
    }
}

impl HyperService for Service {
    type Request = Request;
    type Response = Response;
    type Error = HyperError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn call(&self, req: Request) -> Self::Future {
        info!("{} {}", req.method(), req.path());

        // Match route or serve static files.
        let handler = match (self.router)(&req) {
            Some(handler) => handler,
            None => return self.static_.call(req),
        };

        // Parse request parameters.
        let (method, uri, _, headers, body) = req.deconstruct();
        let f = match method {
            Method::Get => Box::new(future::ok(parse_query(uri.query()))),
            Method::Post => parse_form_encoded_body(body),
            _ => unreachable!(),
        };

        let app = self.app.clone();
        let f = f.and_then(move |params| {
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
                app: app,
                params: params,
                session: Session::default(),
                catalog_idx: catalog_idx,
                redirect_uri: None,
            }));

            // Call the route handler.
            let f = handler(ctx_handle.clone());

            // Handle errors.
            f.or_else(move |err| {
                let ctx = ctx_handle.borrow();
                handle_error(&*ctx, err)
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
fn handle_error(ctx: &Context, err: BrokerError) -> FutureResult<Response, HyperError> {
    match (err, ctx.redirect_uri.as_ref()) {
        (BrokerError::RateLimited, _) => {
            let res = Response::new()
                .with_status(StatusCode::TooManyRequests)
                .with_header(ContentType::plaintext())
                .with_body("Rate limit exceeded. Please try again later.");
            future::ok(res)
        },
        (err @ BrokerError::Input(_), Some(_)) => {
            return_to_relier(ctx, &[
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
            return_to_relier(ctx, &[
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
            return_to_relier(ctx, &[
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
    headers.set(XContentTypeOptions("nosniff".to_string()));
    headers.set(XXSSProtection("1; mode=block".to_string()));
    headers.set(XFrameOptions("DENY".to_string()));

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


/// Parse the request query string into a `HashMap`.
pub fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    if let Some(query) = query {
        parse_form_encoded(query.as_bytes())
    } else {
        HashMap::new()
    }
}


/// Read the request or response body up to a fixed size.
pub fn read_body(body: Body) -> BoxFuture<Chunk, HyperError> {
    Box::new(body.fold(Chunk::default(), |mut acc, chunk| {
        if acc.len() + chunk.len() > 8096 {
            // TODO: Is this the right thing to do?
            future::err(HyperError::TooLarge)
        } else {
            acc.extend(chunk);
            future::ok(acc)
        }
    }))
}


/// Parse the request form-encoded body into a `HashMap`.
pub fn parse_form_encoded_body(body: Body) -> BoxFuture<HashMap<String, String>, HyperError> {
    Box::new(read_body(body).map(|chunk| parse_form_encoded(&chunk)))
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
