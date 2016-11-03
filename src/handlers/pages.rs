use iron::{Handler, IronResult, Request, Response, status};
use iron::modifiers::RedirectRaw;

/// Handler for the root path, redirects to the Portier homepage.
pub struct Index;

impl Handler for Index {
    fn handle(&self, _req: &mut Request) -> IronResult<Response> {
        Ok(Response::with((status::SeeOther, RedirectRaw("https://portier.github.io".to_string()))))
    }
}
