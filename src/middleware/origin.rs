use hyper::status::StatusCode;
use iron::middleware::BeforeMiddleware;
use iron::modifiers;
use iron::{IronError, IronResult, Request};
use std::error::Error;
use std::fmt;
use url::Origin::{Opaque, Tuple};
use url;

/// Middleware that redirects requests to the broker's canonical public_url.
pub struct EnforceOrigin {
    origin: url::Origin,
}

impl EnforceOrigin {
    pub fn new(uri: &str) -> EnforceOrigin {
        let origin =
            url::Url::parse(uri).expect(format!("unable to parse uri: {}", uri).as_str()).origin();

        EnforceOrigin { origin: origin }
    }
}

// TODO: Extract the uri mutation into a standalone function?
// TODO: Supress error messages associated with failure here.
impl BeforeMiddleware for EnforceOrigin {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        let mut uri = req.url.clone().into_generic_url();

        // If the request and canonical origins match, everything is fine.
        if self.origin == uri.origin() {
            return Ok(());
        }

        // Otherwise, extract the configured, canonical origin...
        let (scheme, host, port) = match self.origin {
            Tuple(ref scheme, ref host, ref port) => (scheme, host, port),
            Opaque(_) => {
                return Err(IronError::new(OriginError::Opaque, StatusCode::InternalServerError))
            }
        };

        // ...mutate the request URI to point to the canonical origin...
        if uri.set_scheme(scheme).is_err() ||
           uri.set_host(Some(&format!("{}", host))).is_err() ||
           uri.set_port(Some(*port)).is_err() {
            return Err(IronError::new(OriginError::Mutation, StatusCode::InternalServerError));
        }

        // ...and redirect to it.
        let status = StatusCode::TemporaryRedirect;
        let location = modifiers::RedirectRaw(uri.to_string());

        Err(IronError::new(OriginError::Mismatch, (status, location)))
    }
}

#[derive(Debug)]
enum OriginError {
    Mismatch,
    Mutation,
    Opaque,
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            OriginError::Mismatch => write!(f, "origins did not match eachother"),
            OriginError::Mutation => write!(f, "unable to set new scheme, host, or port"),
            OriginError::Opaque => write!(f, "origin was opaque"),
        }
    }
}

impl Error for OriginError {
    fn description(&self) -> &str {
        match *self {
            OriginError::Mismatch => "origins did not match eachother",
            OriginError::Mutation => "unable to set new scheme, host, or port",
            OriginError::Opaque => "origin was opaque",
        }
    }
}
