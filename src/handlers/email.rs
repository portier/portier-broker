#![allow(unknown_lints,needless_pass_by_value)]

use email_bridge;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{self, HandlerResult, ContextHandle};
use hyper::server::Request;


/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
pub fn confirmation(req: Request, shared_ctx: ContextHandle) -> HandlerResult {
    let mut params = http::parse_query(&req);

    future::ok(())
        .and_then(move |_| {
            let session_id = try_get_param!(params, "session");
            let code = try_get_param!(params, "code");

            let result = {
                let ctx = shared_ctx.lock().expect("failed to lock request context");
                ctx.app.store.get_session("email", &session_id)
            };

            future::result(result.map(|stored| (shared_ctx, stored, code)))
        })
        .and_then(|(shared_ctx, stored, code)| {
            let result = {
                let mut ctx = shared_ctx.lock().expect("failed to lock request context");
                ctx.redirect_uri = Some(stored["redirect"].parse().expect("unable to parse stored redirect uri"));

                email_bridge::verify(&ctx.app, &stored, &code)
            };

            future::result(result.map(|jwt| (shared_ctx, jwt)))
        })
        .and_then(|(shared_ctx, jwt)| {
            let ctx = shared_ctx.lock().expect("failed to lock request context");
            return_to_relier(&ctx, &[("id_token", &jwt)])
        })
        .boxed()
}
