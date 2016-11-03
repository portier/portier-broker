use iron::middleware::BeforeMiddleware;
use iron::{IronResult, Request};

/// Middleware that logs each request.
pub struct LogRequest;
impl BeforeMiddleware for LogRequest {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        info!("{} {}", req.method, req.url);
        Ok(())
    }
}
