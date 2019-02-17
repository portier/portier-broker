use email_address::EmailAddress;
use futures::future;
use http::{ContextHandle, HandlerResult};
use hyper::header::{CacheControl, CacheDirective, ContentType};
use hyper::server::Response;

/// Request handler for the email normalization endpoint.
///
/// Performs normalization of email addresses, for clients that cannot implement all the necessary
/// parts of the relevant specifications. (Unicode, WHATWG, etc.)
pub fn normalize(ctx_handle: &ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let result = String::from_utf8_lossy(&ctx.body)
        .lines()
        .map(|s| {
            match s.parse::<EmailAddress>() {
                Ok(addr) => addr.to_string(),
                Err(_) => "".to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let res = Response::new()
        .with_header(ContentType::plaintext())
        .with_header(CacheControl(vec![
            CacheDirective::NoCache,
            CacheDirective::NoStore,
        ]))
        .with_body(result);
    Box::new(future::ok(res))
}
