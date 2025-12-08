use crate::web::{Context, HandlerResult, html_response};

/// Request handler that transforms fragment and query parameters to POST parameters.
///
/// This is used by the OpenID Connect bridge to transform `response_mode=fragment` to `form_post`.
pub async fn rewrite_to_post(ctx: &mut Context) -> HandlerResult {
    Ok(html_response(ctx.app.templates.rewrite_to_post.render(&[])))
}
