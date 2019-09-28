use futures::future;
use http::{ContextHandle, HandlerResult};
use hyper::{header::ContentType, Response};

/// Request handler that transforms fragment and query parameters to POST parameters.
///
/// This is used by the OpenID Connect bridge to transform `response_mode=fragment` to `form_post`,
/// and by the email bridge to thwart virus scanners.
pub fn rewrite_to_post(ctx_handle: &ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(ctx.app.templates.rewrite_to_post.render(&[]));
    Box::new(future::ok(res))
}
