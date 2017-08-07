use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{self, HandlerResult, ContextHandle};
use hyper::{Method};
use hyper::header::{ContentType};
use hyper::server::{Request, Response};
use oidc_bridge;


/// Request handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
///
/// For providers that don't support `response_type=form_post`, we capture the
/// fragment parameters in javascript and emulate the POST request.
///
/// Once we have a POST request, we can verify the callback data and return the
/// resulting token to the relying party, or error.
pub fn callback(req: Request, shared_ctx: ContextHandle) -> HandlerResult {
    match *req.method() {
        Method::Get => {
            let ctx = shared_ctx.lock().expect("failed to lock request context");
            let res = Response::new()
                .with_header(ContentType::html())
                .with_body(ctx.app.templates.fragment_callback.render(&[]));
            future::ok(res).boxed()
        },
        Method::Post => {
            http::parse_form_encoded_body(req)
                .and_then(move |mut params| {
                    let state = try_get_param!(params, "state");
                    let id_token = try_get_param!(params, "id_token");

                    let result = {
                        let ctx = shared_ctx.lock().expect("failed to lock request context");
                        ctx.app.store.get_session("oidc", &state)
                    };

                    future::result(result.map(|stored| (shared_ctx, stored, id_token)))
                })
                .and_then(|(shared_ctx, stored, id_token)| {
                    let result = {
                        let mut ctx = shared_ctx.lock().expect("failed to lock request context");
                        ctx.redirect_uri = Some(stored["redirect"].parse().expect("redirect_uri missing from session"));

                        oidc_bridge::verify(&ctx.app, &ctx.handle, &stored, &id_token)
                    };

                    future::result(result.map(|jwt| (shared_ctx, jwt)))
                })
                .and_then(|(shared_ctx, jwt)| {
                    let ctx = shared_ctx.lock().expect("failed to lock request context");
                    return_to_relier(&ctx, &[("id_token", &jwt)])
                })
                .boxed()
        },
        _ => unreachable!(),
    }
}
