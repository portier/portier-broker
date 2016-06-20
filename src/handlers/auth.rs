extern crate lettre;
extern crate rand;

use emailaddress::EmailAddress;
use iron::middleware::Handler;
use iron::prelude::*;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use serde_json::builder::ObjectBuilder;
use redis::{Commands, RedisResult};
use std::error::Error;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::UrlEncodedBody;
use {CODE_CHARS, AppConfig, oauth_request, session_id};
use super::json_response;

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
            return oauth_request(&self.app, &params);
        }

        // Generate a 6-character one-time pad.
        let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

        // Store data for this request in Redis, to reference when user uses
        // the generated link.
        let client_id = &params.get("client_id").unwrap()[0];
        let session = session_id(&email_addr, client_id);
        let key = format!("session:{}", session);
        let set_res: RedisResult<String> = self.app.store.hset_multiple(key.clone(), &[
            ("email", email_addr.to_string()),
            ("client_id", client_id.clone()),
            ("code", chars.clone()),
            ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
        ]);
        let exp_res: RedisResult<bool> = self.app.store.expire(key.clone(), self.app.expire_keys);

        // Generate the URL used to verify email address ownership.
        let href = format!("{}/confirm?session={}&code={}",
                           self.app.base_url,
                           utf8_percent_encode(&session, QUERY_ENCODE_SET),
                           utf8_percent_encode(&chars, QUERY_ENCODE_SET));

        // Generate a simple email and send it through the SMTP server running
        // on localhost. TODO: make the SMTP host configurable. Also, consider
        // using templates for the email message.
        let email = EmailBuilder::new()
            .to(email_addr.to_string().as_str())
            .from((self.app.sender.0.as_str(), self.app.sender.1.as_str()))
            .body(&format!("Enter your login code:\n\n{}\n\nOr click this link:\n\n{}",
                           chars, href))
            .subject(&format!("Code: {} - Finish logging in to {}", chars, client_id))
            .build().unwrap();
        let mut mailer = SmtpTransportBuilder::localhost().unwrap().build();
        let result = mailer.send(email);
        mailer.close();

        // TODO: for debugging, this part returns a JSON response with some
        // debugging stuff/diagnostics. Instead, it should return a form that
        // allows the user to enter the code they have received.
        let mut obj = ObjectBuilder::new();
        if !result.is_ok() {
            let error = result.unwrap_err();
            obj = obj.insert("error", error.to_string());
            obj = match error {
                lettre::transport::error::Error::IoError(inner) => {
                    obj.insert("cause", inner.description())
                }
                _ => obj,
            }
        }
        if !set_res.is_ok() {
            obj = obj.insert("hset_multiple", set_res.unwrap_err().to_string());
        }
        if !exp_res.is_ok() {
            obj = obj.insert("expire", exp_res.unwrap_err().to_string());
        }
        json_response(&obj.unwrap())

    }
}
