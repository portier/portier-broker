use config::{Config};
use crypto;
use emailaddress::EmailAddress;
use error::BrokerError;
use futures::{Future, future};
use gettext::Catalog;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use rand;
use std::collections::HashMap;
use std::error::Error;
use std::iter::Iterator;
use std::rc::Rc;
use url::Url;
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
pub fn request(app: Rc<Config>, email_addr: &EmailAddress, client_id: &str, nonce: &str, redirect_uri: &Url, catalog: &Catalog)
               -> Box<Future<Item=String, Error=BrokerError>> {

    let session = crypto::session_id(email_addr, client_id);

    // Generate a 12-character one-time pad.
    let chars = String::from_utf8((0..12).map(|_| {
        CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]
    }).collect()).unwrap();
    // For display, we split it in two groups of 6.
    let chars_fmt = [&chars[0..6], &chars[6..12]].join(" ");

    // Store data for this request in Redis, to reference when user uses
    // the generated link.
    if let Err(err) = app.store.store_session(&session, &[
        ("type", "email"),
        ("email", &email_addr.to_string()),
        ("client_id", client_id),
        ("nonce", nonce),
        ("code", &chars),
        ("redirect", &redirect_uri.to_string()),
    ]) {
        return Box::new(future::err(err));
    }

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       app.public_url,
                       utf8_percent_encode(&session, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    let params = &[
        ("client_id", client_id),
        ("code", &chars_fmt),
        ("link", &href),
        ("title", catalog.gettext("Finish logging in to")),
        ("explanation", catalog.gettext("You received this email so that we may confirm your email address and finish your login to:")),
        ("click", catalog.gettext("Click here to login")),
        ("alternate", catalog.gettext("Alternatively, enter the following code on the login page:")),
    ];
    let email = EmailBuilder::new()
        .to(email_addr.to_string().as_str())
        .from((&*app.from_address, &*app.from_name))
        .alternative(&app.templates.email_html.render(params),
                     &app.templates.email_text.render(params))
        .subject(&[catalog.gettext("Finish logging in to"), client_id].join(" "))
        .build()
        .unwrap_or_else(|err| panic!("unhandled error building email: {}", err.description()));
    let mut builder = match SmtpTransportBuilder::new(app.smtp_server.as_str()) {
        Ok(builder) => builder,
        Err(err) => return Box::new(future::err(err.into())),
    };

    if let (&Some(ref username), &Some(ref password)) = (&app.smtp_username, &app.smtp_password) {
        builder = builder.credentials(username, password);
    }

    let mut mailer = builder.build();
    if let Err(err) = mailer.send(email) {
        Box::new(future::err(err.into()))
    } else {
        mailer.close();
        Box::new(future::ok(session))
    }
}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks the one-time pad against the stored session data. If a match,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(app: Rc<Config>, stored: &HashMap<String, String>, code: &str)
              -> Box<Future<Item=String, Error=BrokerError>> {

    let trimmed = code.replace(|c: char| c.is_whitespace(), "").to_lowercase();
    if trimmed != stored["code"] {
        return Box::new(future::err(BrokerError::Input("incorrect code".to_string())));
    }

    let email = &stored["email"];
    let client_id = &stored["client_id"];
    let nonce = &stored["nonce"];
    Box::new(future::ok(crypto::create_jwt(&*app, email, client_id, nonce)))
}
