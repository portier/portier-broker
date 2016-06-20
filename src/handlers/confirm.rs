extern crate lettre;
extern crate rand;

use iron::middleware::Handler;
use iron::prelude::*;
use serde_json::builder::ObjectBuilder;
use redis::Commands;
use std::collections::HashMap;
use urlencoded::UrlEncodedQuery;
use AppConfig;
use super::{json_response, send_jwt_response};

/// Iron handler for one-time pad email loop confirmation.
///
/// Verifies the one-time pad as provided in the query string arguments against
/// the data saved in Redis. If the code matches, send an identity token to the
/// RP using `send_jwt_response()`. Otherwise, returns a JSON response with an
/// error message. TODO: the latter is obviously wrong.
pub struct Confirm { pub app: AppConfig }
impl Handler for Confirm {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let session = &params.get("session").unwrap()[0];
        let key = format!("session:{}", session);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.len() == 0 {
            let obj = ObjectBuilder::new().insert("error", "not found");
            return json_response(&obj.unwrap());
        }

        let req_code = &params.get("code").unwrap()[0];
        if req_code != stored.get("code").unwrap() {
            let mut obj = ObjectBuilder::new().insert("error", "code fail");
            obj = obj.insert("stored", stored);
            return json_response(&obj.unwrap());
        }

        let email = stored.get("email").unwrap();
        let client_id = stored.get("client_id").unwrap();
        let redirect = stored.get("redirect").unwrap();
        send_jwt_response(&self.app, email, client_id, redirect)

    }
}
