extern crate rand;

use emailaddress::EmailAddress;
use iron::Url;
use super::error::{BrokerError, BrokerResult};
use super::lettre::email::EmailBuilder;
use super::lettre::transport::EmailTransport;
use super::lettre::transport::smtp::SmtpTransportBuilder;
use super::{Config, create_jwt};
use super::crypto::session_id;
use std::collections::HashMap;
use std::error::Error;
use std::iter::Iterator;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// The z-base-32 character set, from which we select characters for the one-time pad.
const CODE_CHARS: &'static [u8] = b"13456789abcdefghijkmnopqrstuwxyz";


/// Helper method to provide authentication through an email loop.
///
/// If the email address' host does not support any native form of
/// authentication, create a randomly-generated one-time pad. Then, send
/// an email containing a link with the secret. Clicking the link will trigger
/// the `ConfirmHandler`, returning an authentication result to the RP.
///
/// Returns the session ID, so a form can be rendered as an alternative way
/// to confirm, without following the link.
pub fn request(app: &Config, email_addr: EmailAddress, client_id: &str, nonce: &str, redirect_uri: &Url)
               -> BrokerResult<String> {

    let session = session_id(&email_addr, client_id);

    // Generate a 12-character one-time pad.
    let chars = String::from_utf8((0..12).map(|_| {
        CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]
    }).collect()).unwrap();
    // For display, we split it in two groups of 6.
    let chars_fmt = [&chars[0..6], &chars[6..12]].join(" ");

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    app.store.store_session(&session, &[
        ("type", "email"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("code", &chars),
        ("redirect", &redirect_uri.to_string()),
    ])?;

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.public_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    let params = &[
        ("client_id", client_id),
        ("code", &chars_fmt),
        ("link", &href),
    ];
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((&*app.from_address, &*app.from_name))
        .alternative(&app.templates.email_html.render(params),
                     &app.templates.email_text.render(params))
        .subject(&format!("Finish logging in to {}", client_id))
        .build()
        .unwrap_or_else(|err| panic!("unhandled error building email: {}", err.description()));
    let mut builder = SmtpTransportBuilder::new(app.smtp_server.as_str())?;
    if let (&Some(ref username), &Some(ref password)) = (&app.smtp_username, &app.smtp_password) {
        builder = builder.credentials(username, password);
    }
    let mut mailer = builder.build();
    mailer.send(email)?;
    mailer.close();
    Ok(session)

}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks the one-time pad against the stored session data. If a match,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(app: &Config, stored: &HashMap<String, String>, code: &str)
              -> BrokerResult<(String, String)> {

    let trimmed = code.replace(|c: char| c.is_whitespace(), "").to_lowercase();
    if &trimmed != &stored["code"] {
        return Err(BrokerError::Input("incorrect code".to_string()));
    }

    let email = &stored["email"];
    let client_id = &stored["client_id"];
    let nonce = &stored["nonce"];
    let id_token = create_jwt(app, email, client_id, nonce);
    let redirect = &stored["redirect"];
    Ok((id_token, redirect.to_string()))

}
