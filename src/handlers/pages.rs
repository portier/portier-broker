use futures::future;
use http::{Service, ContextHandle, HandlerResult};
use hyper::{StatusCode};
use hyper::header::{ContentType, Location};
use hyper::server::{Request, Response};
use std::env;


/// Handler for the root path, redirects to the Portier homepage.
pub fn index(_: &Service, _: Request, _: ContextHandle) -> HandlerResult {
    let res = Response::new()
        .with_status(StatusCode::SeeOther)
        .with_header(Location::new("https://portier.github.io"));
    Box::new(future::ok(res))
}


/// Version information for the broker
pub fn version(_: &Service, _: Request, _: ContextHandle) -> HandlerResult {
    // TODO: Find a more robust way of detecting the git commit.
    // Maybe check/set it in build.rs? Fall back to HEROKU_SLUG_COMMIT?
    let version = env!("CARGO_PKG_VERSION");
    let sha = match env::var("HEROKU_SLUG_COMMIT") {
        Ok(sha) => sha,
        Err(_) => "unknown".to_string(),
    };
    let body = format!("Portier {} (git commit {})", version, sha);

    let res = Response::new()
        .with_header(ContentType::plaintext())
        .with_body(body);
    Box::new(future::ok(res))
}
