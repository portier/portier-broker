use bridges::{BridgeData, complete_auth};
use crypto::{random_zbase32};
use email_address::EmailAddress;
use error::BrokerError;
use futures::future;
use http::{ContextHandle, HandlerResult};
use hyper::Response;
use hyper::header::ContentType;
use lettre_email::EmailBuilder;
use lettre::EmailTransport;
use lettre::smtp::{ClientSecurity, SmtpTransportBuilder};
use lettre::smtp::authentication::Credentials;
use std::rc::Rc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};


/// Data we store in the session.
#[derive(Serialize,Deserialize)]
pub struct EmailBridgeData {
    pub code: String,
}


/// Provide authentication through an email loop.
///
/// If the email address' host does not support any native form of authentication, create a
/// randomly-generated one-time pad. Then, send an email containing a link with the secret.
/// Clicking the link will trigger the `confirmation` handler, returning an authentication result
/// to the relying party.
///
/// A form is rendered as an alternative way to confirm, without following the link. Submitting the
/// form results in the same callback as the email link.
pub fn auth(ctx_handle: &ContextHandle, email_addr: &Rc<EmailAddress>) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    // Generate a 12-character one-time pad.
    let chars = random_zbase32(12);
    // For display, we split it in two groups of 6.
    let chars_fmt = [&chars[0..6], &chars[6..12]].join(" ");

    // Generate the URL used to verify email address ownership.
    let href = format!("{}/confirm?session={}&code={}",
                       ctx.app.public_url,
                       utf8_percent_encode(&ctx.session_id, QUERY_ENCODE_SET),
                       utf8_percent_encode(&chars, QUERY_ENCODE_SET));

    let display_origin = ctx.redirect_uri.as_ref()
        .expect("email::request called without redirect_uri set")
        .origin().unicode_serialization();
    let email = {
        let catalog = ctx.catalog();
        let params = &[
            ("display_origin", display_origin.as_str()),
            ("code", &chars_fmt),
            ("link", &href),
            ("title", catalog.gettext("Finish logging in to")),
            ("explanation", catalog.gettext("You received this email so that we may confirm your email address and finish your login to:")),
            ("click", catalog.gettext("Click here to login")),
            ("alternate", catalog.gettext("Alternatively, enter the following code on the login page:")),
        ];
        EmailBuilder::new()
            .to(email_addr.as_str())
            .from((&*ctx.app.from_address, &*ctx.app.from_name))
            .alternative(ctx.app.templates.email_html.render(params),
                         ctx.app.templates.email_text.render(params))
            .subject([catalog.gettext("Finish logging in to"), display_origin.as_str()].join(" "))
            .build()
            .unwrap_or_else(|err| panic!("unhandled error building email: {}", err))
    };
    // TODO: Configurable security.
    let mut builder = match SmtpTransportBuilder::new(&ctx.app.smtp_server, ClientSecurity::Opportunistic) {
        Ok(builder) => builder,
        Err(err) => return Box::new(future::err(BrokerError::Internal(
            format!("could not create the smtp transport: {}", err)))),
    };

    if let (&Some(ref username), &Some(ref password)) = (&ctx.app.smtp_username, &ctx.app.smtp_password) {
        builder = builder.credentials(Credentials::new(username.to_owned(), password.to_owned()));
    }

    // Store the code in the session for use in the verify handler. We should never fail to claim
    // the session, because we only get here after all other options have failed.
    match ctx.save_session(BridgeData::Email(EmailBridgeData {
        code: chars.clone(),
    })) {
        Ok(true) => {},
        Ok(false) => return Box::new(future::err(BrokerError::Internal(
            "email fallback failed to claim session".to_owned()))),
        Err(e) => return Box::new(future::err(e)),
    }

    // Send the mail.
    let mut mailer = builder.build();
    if let Err(err) = mailer.send(&email) {
        return Box::new(future::err(BrokerError::Internal(
            format!("could not send mail: {}", err))))
    }

    mailer.close();

    // Render a form for the user.
    let catalog = ctx.catalog();
    let res = Response::new()
        .with_header(ContentType::html())
        .with_body(ctx.app.templates.confirm_email.render(&[
            ("display_origin", display_origin.as_str()),
            ("session_id", &ctx.session_id),
            ("title", catalog.gettext("Confirm your address")),
            ("explanation", catalog.gettext("We've sent you an email to confirm your address.")),
            ("use", catalog.gettext("Use the link in that email to login to")),
            ("alternate", catalog.gettext("Alternatively, enter the code from the email to continue in this browser tab:")),
        ]));
    Box::new(future::ok(res))
}


/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad. Verifies the code and
/// returns the resulting token to the relying party.
pub fn confirmation(ctx_handle: &ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();

    let session_id = try_get_provider_param!(ctx, "session");
    let bridge_data = match ctx.load_session(&session_id) {
        Ok(BridgeData::Email(bridge_data)) => Rc::new(bridge_data),
        Ok(_) => return Box::new(future::err(BrokerError::ProviderInput("invalid session".to_owned()))),
        Err(e) => return Box::new(future::err(e)),
    };

    let code = try_get_provider_param!(ctx, "code")
        .replace(|c: char| c.is_whitespace(), "").to_lowercase();
    if code != bridge_data.code {
        return Box::new(future::err(BrokerError::ProviderInput("incorrect code".to_owned())));
    }

    Box::new(future::result(complete_auth(&*ctx)))
}
