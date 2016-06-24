extern crate lettre;
extern crate rand;

use emailaddress::EmailAddress;
use iron::middleware::Handler;
use iron::prelude::*;
use redis::{Commands, RedisResult};
use self::lettre::email::EmailBuilder;
use self::lettre::transport::EmailTransport;
use self::lettre::transport::smtp::SmtpTransportBuilder;
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use super::{AppConfig, session_id, json_response, send_jwt_response};
use std::collections::HashMap;
use std::error::Error;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::{QueryMap, UrlEncodedQuery};


/// Characters eligible for inclusion in the email loop one-time pad.
///
/// Currently includes all numbers, lower- and upper-case ASCII letters,
/// except those that could potentially cause confusion when reading back.
/// (That is, '1', '5', '8', '0', 'b', 'i', 'l', 'o', 's', 'u', 'B', 'D', 'I'
/// and 'O'.)
const CODE_CHARS: &'static [char] = &[
    '2', '3', '4', '6', '7', '9', 'a', 'c', 'd', 'e', 'f', 'g', 'h', 'j', 'k',
    'm', 'n', 'p', 'q', 'r', 't', 'v', 'w', 'x', 'y', 'z', 'A', 'C', 'E', 'F',
    'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
    'X', 'Y', 'Z',
];


/// Helper method to provide authentication through an email loop.
///
/// If the email address' host does not support any native form of
/// authentication, create a randomly-generated one-time pad. Then, send
/// an email containing a link with the secret. Clicking the link will trigger
/// the `ConfirmHandler`, returning an authentication result to the RP.
pub fn request(app: &AppConfig, params: &QueryMap) -> Value {

    // Generate a 6-character one-time pad.
    let email_addr = EmailAddress::new(&params.get("login_hint").unwrap()[0]).unwrap();
    let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    let client_id = &params.get("client_id").unwrap()[0];
    let session = session_id(&email_addr, client_id);
    let key = format!("session:{}", session);
    let set_res: RedisResult<String> = app.store.hset_multiple(key.clone(), &[
        ("email", email_addr.to_string()),
        ("client_id", client_id.clone()),
        ("code", chars.clone()),
        ("redirect", params.get("redirect_uri").unwrap()[0].clone()),
    ]);
    let exp_res: RedisResult<bool> = app.store.expire(key.clone(), app.expire_keys);

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.base_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    // Generate a simple email and send it through the SMTP server running
    // on localhost. TODO: make the SMTP host configurable. Also, consider
    // using templates for the email message.
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((app.sender.0.as_str(), app.sender.1.as_str()))
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
    obj.unwrap()

}

/// Iron handler for one-time pad email loop confirmation.
///
/// Verifies the one-time pad as provided in the query string arguments against
/// the data saved in Redis. If the code matches, send an identity token to the
/// RP using `send_jwt_response()`. Otherwise, returns a JSON response with an
/// error message. TODO: the latter is obviously wrong.
pub struct ConfirmHandler { pub app: AppConfig }
impl Handler for ConfirmHandler {
    fn handle(&self, req: &mut Request) -> IronResult<Response> {

        let params = req.get_ref::<UrlEncodedQuery>().unwrap();
        let session = &params.get("session").unwrap()[0];
        let key = format!("session:{}", session);
        let stored: HashMap<String, String> = self.app.store.hgetall(key.clone()).unwrap();
        if stored.is_empty() {
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
