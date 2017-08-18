#![allow(unknown_lints,needless_pass_by_value)]

use email_bridge;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{ContextHandle, HandlerResult};


/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
pub fn confirmation(ctx_handle: ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    let session_id = try_get_param!(ctx, "session");
    let stored = match ctx.app.store.get_session("email", &session_id) {
        Ok(stored) => stored,
        Err(err) => return Box::new(future::err(err)),
    };
    let redirect_uri = stored["redirect"].parse().expect("unable to parse stored redirect uri");
    ctx.redirect_uri = Some(redirect_uri);

    let code = try_get_param!(ctx, "code");
    let f = email_bridge::verify(ctx.app.clone(), &stored, &code);

    let ctx_handle = ctx_handle.clone();
    let f = f.and_then(move |jwt| {
        let ctx = ctx_handle.borrow();
        return_to_relier(&*ctx, &[("id_token", &jwt)])
    });

    Box::new(f)
}
