extern crate rand;

use emailaddress::EmailAddress;
use iron::middleware::Handler;
use iron::prelude::*;
use providers::gmail;
use providers::smtp;
use urlencoded::UrlEncodedBody;
use {AppConfig};

/// Iron handler for authentication requests from the RP.
///
/// Calls the `oauth_request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, sends an
/// email to the user with a randomly generated one-time pad. This code is
/// stored in Redis (with timeout) for later verification.
pub struct Auth { pub app: AppConfig }
impl Handler for Auth {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {
        let params = req.get_ref::<UrlEncodedBody>().unwrap();
        let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
        if self.app.providers.contains_key(&email_addr.domain) {
            gmail::authenticate(&self.app, params)
        } else {
            smtp::authenticate(&email_addr,
                               &self.app,
                               &params.get("client_id").unwrap()[0],
                               &params.get("redirect_url").unwrap()[0])
        }
    }
}
