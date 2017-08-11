use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{ContextHandle, HandlerResult};
use hyper::header::{ContentType};
use hyper::server::Response;
use oidc_bridge;


/// Request handler for OAuth callbacks with response mode 'fragment'
///
/// For providers that don't support `response_mode=form_post`, we capture the
/// fragment parameters in javascript and emulate the POST request.
pub fn fragment_callback(ctx_handle: ContextHandle) -> HandlerResult {
    let ctx = ctx_handle.borrow();

    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(ctx.app.templates.fragment_callback.render(&[]));
    Box::new(future::ok(res))
}


/// Request handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
///
/// We verify the callback data and return the resulting token to the relying
/// party, or error.
pub fn callback(ctx_handle: ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    let session_id = try_get_param!(ctx, "state");
    let stored = match ctx.app.store.get_session("email", &session_id) {
        Ok(stored) => stored,
        Err(err) => return Box::new(future::err(err)),
    };
    let redirect_uri = stored["redirect"].parse().expect("unable to parse stored redirect uri");
    ctx.redirect_uri = Some(redirect_uri);

    let id_token = try_get_param!(ctx, "id_token");
    let f = oidc_bridge::verify(ctx.app.clone(), stored, id_token);

    let ctx_handle = ctx_handle.clone();
    let f = f.and_then(move |jwt| {
        let ctx = ctx_handle.borrow();
        return_to_relier(&*ctx, &[("id_token", &jwt)])
    });

    Box::new(f)
}
