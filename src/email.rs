extern crate lettre;
extern crate rand;

use emailaddress::EmailAddress;
use self::lettre::email::EmailBuilder;
use self::lettre::transport::EmailTransport;
use self::lettre::transport::smtp::SmtpTransportBuilder;
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use super::{AppConfig, create_jwt};
use super::crypto::session_id;
use std::error::Error;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};
use urlencoded::QueryMap;


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
    let nonce = &params.get("nonce").unwrap()[0];
    let session = session_id(&email_addr, client_id);
    let res = app.store.store_session(&session, &[
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("code", &chars),
        ("redirect", &params.get("redirect_uri").unwrap()[0]),
    ]);

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.base_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    // Generate a simple email and send it through the SMTP server running
    // on localhost. TODO: Use templates for the email message.
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((&*app.sender.address, &*app.sender.name))
        .body(&format!("Enter your login code:\n\n{}\n\nOr click this link:\n\n{}",
                       chars, href))
        .subject(&format!("Code: {} - Finish logging in to {}", chars, client_id))
        .build().unwrap();
    // TODO: Add support for authentication.
    let mut mailer = SmtpTransportBuilder::new(app.smtp.address.as_str()).unwrap().build();
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
    if !res.is_ok() {
        obj = obj.insert("store", res.unwrap_err());
    }
    obj.build()

}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks that the session exists and matches the one-time pad. If so,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(app: &AppConfig, session: &str, code: &str)
              -> Result<(String, String), String> {

    let res = app.store.get_session(&session);
    if res.is_err() {
        return Err(res.unwrap_err());
    }

    let stored = res.unwrap();
    if code != stored.get("code").unwrap() {
        return Err("incorrect code".to_string());
    }

    let email = stored.get("email").unwrap();
    let client_id = stored.get("client_id").unwrap();
    let nonce = stored.get("nonce").unwrap();
    let id_token = create_jwt(app, email, client_id, nonce);
    let redirect = stored.get("redirect").unwrap().to_string();
    Ok((id_token, redirect))

}
