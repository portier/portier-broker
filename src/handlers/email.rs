#![allow(unknown_lints,needless_pass_by_value)]

use email_bridge;
use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{self, Service, ContextHandle, HandlerResult};
use hyper::server::Request;


/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad.
/// Verify the code and return the resulting token or error to the RP.
pub fn confirmation(service: &Service, req: Request, shared_ctx: ContextHandle) -> HandlerResult {
    let mut params = http::parse_query(&req);

    let f = future::ok(());

    let app = service.app.clone();
    let f = f.and_then(move |_| {
        let session_id = try_get_param!(params, "session");
        let code = try_get_param!(params, "code");

        let result = app.store.get_session("email", &session_id);
        future::result(result.map(|stored| (app, stored, code)))
    });

    let ctx = shared_ctx.clone();
    let f = f.and_then(move |(app, stored, code)| {
        ctx.borrow_mut().redirect_uri = Some(
            stored["redirect"].parse().expect("unable to parse stored redirect uri"));

        email_bridge::verify(app.clone(), &stored, &code)
            .map(move |jwt| (app, ctx, jwt))
    });

    let f = f.and_then(|(app, ctx, jwt)| {
        let ctx = ctx.borrow();
        return_to_relier(&*app, &ctx, &[("id_token", &jwt)])
    });

    Box::new(f)
}
