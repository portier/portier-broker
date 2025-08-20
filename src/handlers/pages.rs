use std::{env, fmt::Write};

use headers::{ContentType, Header};
use http::StatusCode;
use hyper_staticfile::{AcceptEncoding, ResponseBuilder};

use crate::error::BrokerError;
use crate::utils::http::ResponseExt;
use crate::web::{data_response, empty_response, Context, HandlerResult, ResponseBody};

/// Handler for the root path, redirects to the Portier homepage.
pub async fn index(_ctx: &mut Context) -> HandlerResult {
    let mut res = empty_response(StatusCode::SEE_OTHER);
    res.header(
        hyper::header::LOCATION,
        "https://portier.github.io".to_owned(),
    );
    Ok(res)
}

/// Version information for the broker.
pub async fn version(_ctx: &mut Context) -> HandlerResult {
    // TODO: Find a more robust way of detecting the git commit.
    // Maybe check/set it in build.rs? Fall back to HEROKU_SLUG_COMMIT?
    let mut body = format!("Portier {}", env!("CARGO_PKG_VERSION"));
    if let Ok(commit) = env::var("HEROKU_SLUG_COMMIT") {
        write!(body, " (git commit {commit})").unwrap();
    }

    let mut res = data_response(body);
    res.typed_header(ContentType::text_utf8());
    Ok(res)
}

/// Metrics route. (Prometheus-compatible)
pub async fn metrics(_ctx: &mut Context) -> HandlerResult {
    let mut buffer = String::new();
    crate::metrics::write_metrics(&mut buffer).unwrap();

    let mut res = data_response(buffer);
    res.header(ContentType::name(), "text/plain; version=0.0.4");
    Ok(res)
}

/// Static serving of resources.
pub async fn static_(ctx: &mut Context) -> HandlerResult {
    let accept_encoding = ctx
        .headers
        .get(http::header::ACCEPT_ENCODING)
        .map_or(AcceptEncoding::none(), AcceptEncoding::from_header_value);
    let result = ctx
        .app
        .static_resolver
        .resolve_path(ctx.uri.path(), accept_encoding)
        .await
        .map_err(|e| BrokerError::Internal(format!("static serving failed: {e}")))?;
    let res = ResponseBuilder::new()
        .request_parts(&ctx.method, &ctx.uri, &ctx.headers)
        .cache_headers(Some(ctx.app.static_ttl.as_secs() as u32))
        .build(result)
        .expect("could not build static serving response");
    Ok(res.map(|body| ResponseBody::Static(Box::new(body))))
}
