use bridges;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{ContextHandle, HandlerResult};


/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
pub fn confirmation(ctx_handle: ContextHandle) -> HandlerResult {
    let code = {
        let mut ctx = ctx_handle.borrow_mut();

        let session_id = try_get_param!(ctx, "session");
        if let Err(err) = ctx.load_session(&session_id, "email") {
            return Box::new(future::err(err));
        }

        let redirect_uri = ctx.session["redirect_uri"].parse().expect("unable to parse stored redirect uri");
        ctx.redirect_uri = Some(redirect_uri);

        try_get_param!(ctx, "code")
    };

    let f = bridges::email::verify(&ctx_handle, &code);

    let ctx_handle = ctx_handle.clone();
    let f = f.and_then(move |jwt| {
        let ctx = ctx_handle.borrow();
        return_to_relier(&*ctx, &[("id_token", &jwt)])
    });

    Box::new(f)
}
