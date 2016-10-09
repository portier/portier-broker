extern crate rand;

use emailaddress::EmailAddress;
use super::error::{BrokerError, BrokerResult};
use super::lettre::email::EmailBuilder;
use super::lettre::transport::EmailTransport;
use super::lettre::transport::smtp::SmtpTransportBuilder;
use super::{AppConfig, create_jwt};
use super::crypto::session_id;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


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
pub fn request(app: &AppConfig, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &str)
               -> BrokerResult<()> {

    let session = session_id(&email_addr, client_id);

    // Generate a 6-character one-time pad.
    let chars: String = (0..6).map(|_| CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]).collect();

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    try!(app.store.store_session(&session, &[
        ("type", "email"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("code", &chars),
        ("redirect", redirect_uri),
    ]));

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.base_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    // Generate a simple email and send it through the SMTP server.
    // We can unwrap here, because the possible errors cannot happen here.
    // TODO: Use templates for the email message.
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((&*app.sender.address, &*app.sender.name))
        .body(&format!("Enter your login code:\n\n{}\n\nOr click this link:\n\n{}",
                       chars, href))
        .subject(&format!("Code: {} - Finish logging in to {}", chars, client_id))
        .build().unwrap();
    // TODO: Add support for authentication.
    let mut mailer = try!(
        SmtpTransportBuilder::new(app.smtp.address.as_str())
    ).build();
    try!(mailer.send(email));
    mailer.close();
    Ok(())

}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks that the session exists and matches the one-time pad. If so,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(app: &AppConfig, session: &str, code: &str)
              -> BrokerResult<(String, String)> {

    let stored = try!(app.store.get_session(&session));
    if &stored["type"] != "email" {
        return Err(BrokerError::Custom("invalid session".to_string()));
    }
    if code != &stored["code"] {
        return Err(BrokerError::Custom("incorrect code".to_string()));
    }

    let email = &stored["email"];
    let client_id = &stored["client_id"];
    let nonce = &stored["nonce"];
    let id_token = create_jwt(app, email, client_id, nonce);
    let redirect = &stored["redirect"];
    Ok((id_token, redirect.to_string()))

}
