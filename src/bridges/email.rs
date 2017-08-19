use crypto;
use email_address::EmailAddress;
use error::BrokerError;
use futures::{Future, future};
use http::{ContextHandle, HandlerResult};
use hyper::Response;
use hyper::header::ContentType;
use lettre::email::EmailBuilder;
use lettre::transport::EmailTransport;
use lettre::transport::smtp::SmtpTransportBuilder;
use rand;
use std::error::Error;
use std::iter::Iterator;
use std::rc::Rc;
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
pub fn request(ctx_handle: &ContextHandle, email_addr: &Rc<EmailAddress>)
    -> HandlerResult {

    let mut ctx = ctx_handle.borrow_mut();

    // Generate a 12-character one-time pad.
    let chars = String::from_utf8((0..12).map(|_| {
        CODE_CHARS[rand::random::<usize>() % CODE_CHARS.len()]
    }).collect()).unwrap();
    // For display, we split it in two groups of 6.
    let chars_fmt = [&chars[0..6], &chars[6..12]].join(" ");

    // Store the code in the session for use in the verify handler,
    // and set the session type.
    ctx.session.set("type", "email".to_owned());
    ctx.session.set("code", chars.clone());

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       ctx.app.public_url,
                       utf8_percent_encode(&ctx.session.id, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    let catalog = ctx.catalog();
    let origin = ctx.redirect_uri.as_ref()
        .expect("email::request called without redirect_uri set")
        .origin().unicode_serialization();
    let params = &[
        ("origin", origin.as_str()),
        ("code", &chars_fmt),
        ("link", &href),
        ("title", catalog.gettext("Finish logging in to")),
        ("explanation", catalog.gettext("You received this email so that we may confirm your email address and finish your login to:")),
        ("click", catalog.gettext("Click here to login")),
        ("alternate", catalog.gettext("Alternatively, enter the following code on the login page:")),
    ];
    let email = EmailBuilder::new()
        .to(email_addr.as_str())
        .from((&*ctx.app.from_address, &*ctx.app.from_name))
        .alternative(&ctx.app.templates.email_html.render(params),
                     &ctx.app.templates.email_text.render(params))
        .subject(&[catalog.gettext("Finish logging in to"), origin.as_str()].join(" "))
        .build()
        .unwrap_or_else(|err| panic!("unhandled error building email: {}", err.description()));
    let mut builder = match SmtpTransportBuilder::new(&ctx.app.smtp_server) {
        Ok(builder) => builder,
        Err(err) => return Box::new(future::err(err.into())),
    };

    if let (&Some(ref username), &Some(ref password)) = (&ctx.app.smtp_username, &ctx.app.smtp_password) {
        builder = builder.credentials(username, password);
    }

    // At this point, make sure we can save the session before we send mail.
    if let Err(err) = ctx.save_session() {
        return Box::new(future::err(err));
    }

    // Send the mail.
    let mut mailer = builder.build();
    if let Err(err) = mailer.send(email) {
        return Box::new(future::err(err.into()))
    }

    mailer.close();

    // Render a form for the user.
    let catalog = ctx.catalog();
    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(ctx.app.templates.confirm_email.render(&[
            ("origin", origin.as_str()),
            ("session_id", &ctx.session.id),
            ("title", catalog.gettext("Confirm your address")),
            ("explanation", catalog.gettext("We've sent you an email to confirm your address.")),
            ("use", catalog.gettext("Use the link in that email to login to")),
            ("alternate", catalog.gettext("Alternatively, enter the code from the email to continue in this browser tab:")),
        ]));
    Box::new(future::ok(res))
}

/// Helper function for verification of one-time pad sent through email.
///
/// Checks the one-time pad against the stored session data. If a match,
/// returns the Identity Token; otherwise, returns an error message.
pub fn verify(ctx_handle: &ContextHandle, code: &str)
              -> Box<Future<Item=String, Error=BrokerError>> {

    let ctx = ctx_handle.borrow();
    let redirect_uri = ctx.redirect_uri.as_ref()
        .expect("email::verify called without redirect_uri set");

    let trimmed = code.replace(|c: char| c.is_whitespace(), "").to_lowercase();
    if trimmed != ctx.session["code"] {
        return Box::new(future::err(BrokerError::Input("incorrect code".to_string())));
    }

    let email = EmailAddress::from_trusted(&ctx.session["email"]);
    let aud = redirect_uri.origin().ascii_serialization();
    let nonce = &ctx.session["nonce"];
    Box::new(future::ok(crypto::create_jwt(&*ctx.app, &email, &aud, nonce)))
}
