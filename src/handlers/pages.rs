use iron::{Handler, IronResult, Request, Response, status};
use iron::headers::ContentType;
use iron::modifiers::{Header, RedirectRaw};
use std::env;

/// Handler for the root path, redirects to the Portier homepage.
pub struct Index;

impl Handler for Index {
    fn handle(&self, _req: &mut Request) -> IronResult<Response> {
        Ok(Response::with((status::SeeOther, RedirectRaw("https://portier.github.io".to_string()))))
    }
}

/// Version information for the broker
pub struct Version;

impl Handler for Version {
    fn handle(&self, _req: &mut Request) -> IronResult<Response> {
        // TODO: Find a more robust way of detecting the git commit.
        // Maybe check/set it in build.rs? Fall back to HEROKU_SLUG_COMMIT?
        let version = env!("CARGO_PKG_VERSION");
        let sha = match env::var("HEROKU_SLUG_COMMIT") {
            Ok(sha) => sha,
            Err(_) => "unknown".to_string(),
        };
        let body = format!("Portier {} (git commit {})", version, sha);

        Ok(Response::with((status::Ok, Header(ContentType::plaintext()), body)))
    }
}
