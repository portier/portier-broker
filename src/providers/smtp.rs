//! Authenticate users via an SMTP challenge

extern crate lettre;
extern crate rand;

use emailaddress::EmailAddress;
use handlers::json_response;
use iron::prelude::{IronResult, Response};
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use redis::{Commands, RedisResult};
use serde_json::builder::ObjectBuilder;
use std::error::Error;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use {AppConfig, session_id};


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


pub fn authenticate(email: &EmailAddress, app: &AppConfig, client_id: &String, redirect_uri: &String) -> IronResult<Response> {
    // Generate a 6-character one-time pad.
    let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    let session = session_id(&email, &client_id);
    let key = format!("session:{}", session);
    let set_res: RedisResult<String> = app.store.hset_multiple(key.clone(), &[
        ("email", email.to_string()),
        ("client_id", client_id.clone()),
        ("code", chars.clone()),
        ("redirect", redirect_uri.clone())
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
        .to(email.to_string().as_str())
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
    json_response(&obj.unwrap())
}
