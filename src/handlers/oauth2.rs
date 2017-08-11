use error::BrokerError;
use futures::future::{self, Future};
use handlers::return_to_relier;
use http::{self, Service, ContextHandle, HandlerResult};
use hyper::{Method};
use hyper::header::{ContentType};
use hyper::server::{Request, Response};
use oidc_bridge;


/// Request handler for OAuth callbacks
///
/// After the user allows or denies the Authentication Request with the famous
/// identity provider, they will be redirected back to the callback handler.
///
/// For providers that don't support `response_mode=form_post`, we capture the
/// fragment parameters in javascript and emulate the POST request.
///
/// Once we have a POST request, we can verify the callback data and return the
/// resulting token to the relying party, or error.
pub fn callback(service: &Service, req: Request, shared_ctx: ContextHandle) -> HandlerResult {
    match *req.method() {
        Method::Get => {
            let res = Response::new()
                .with_header(ContentType::html())
                .with_body(service.app.templates.fragment_callback.render(&[]));
            Box::new(future::ok(res))
        },
        Method::Post => {
            let f = http::parse_form_encoded_body(req.body());

            let app = service.app.clone();
            let f = f.and_then(move |mut params| {
                let state = try_get_param!(params, "state");
                let id_token = try_get_param!(params, "id_token");

                let result = app.store.get_session("oidc", &state);
                future::result(result.map(|stored| (app, stored, id_token)))
            });

            let ctx = shared_ctx.clone();
            let f = f.and_then(move |(app, stored, id_token)| {
                ctx.borrow_mut().redirect_uri = Some(
                    stored["redirect"].parse().expect("redirect_uri missing from session"));

                oidc_bridge::verify(app.clone(), stored, id_token)
                    .map(move |jwt| (app, ctx, jwt))
            });

            let f = f.and_then(|(app, ctx, jwt)| {
                let ctx = ctx.borrow();
                return_to_relier(&*app, &ctx, &[("id_token", &jwt)])
            });

            Box::new(f)
        },
        _ => unreachable!(),
    }
}
