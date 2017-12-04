use email_address::EmailAddress;
use error::BrokerError;
use futures::future;
use http::{ContextHandle, HandlerResult};
use hyper::header::{CacheControl, CacheDirective, ContentType};
use hyper::server::Response;

/// Request handler for the email normalization endpoint.
///
/// Performs normalization of email addresses, for clients that cannot implement all the necessary
/// parts of the relevant specifications. (Unicode, WHATWG, etc.)
pub fn normalize(ctx_handle: &ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    let input = try_get_input_param!(ctx, "email");
    let parsed = match input.parse::<EmailAddress>() {
        Ok(addr) => addr,
        Err(_) => return Box::new(future::err(BrokerError::Input(
            "not a valid email address".to_owned()))),
    };

    let res = Response::new()
        .with_header(ContentType::plaintext())
        .with_header(CacheControl(vec![
            CacheDirective::NoCache,
            CacheDirective::NoStore,
        ]))
        .with_body(parsed.to_string());
    Box::new(future::ok(res))
}
