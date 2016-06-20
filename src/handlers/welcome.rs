use iron::middleware::Handler;
use iron::prelude::{IronResult, Request, Response};
use serde_json::builder::ObjectBuilder;
use AppConfig;
use super::json_response;

/// Iron handler for the root path, returns human-friendly message.
///
/// This is not actually used in the protocol.
pub struct Welcome { pub app: AppConfig }
impl Handler for Welcome {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("ladaemon", "Welcome")
            .insert("version", &self.app.version)
            .unwrap())
    }
}
