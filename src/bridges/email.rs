use bridges::{complete_auth, BridgeData};
use config::Config;
use crypto::random_zbase32;
use email_address::EmailAddress;
use error::BrokerError;
use futures::future;
use http::{ContextHandle, HandlerResult};
use hyper::header::ContentType;
use hyper::Response;
use lettre::smtp::authentication::Credentials;
use lettre::smtp::client::net::ClientTlsParameters;
use lettre::smtp::{ClientSecurity, SmtpClient, SmtpTransport};
use lettre::Transport;
use lettre_email::EmailBuilder;
use native_tls::TlsConnector;
use std::rc::Rc;
use url::percent_encoding::{utf8_percent_encode, QUERY_ENCODE_SET};

/// Data we store in the session.
#[derive(Serialize, Deserialize)]
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
    let href = format!(
        "{}/confirm?session={}&code={}",
        ctx.app.public_url,
        utf8_percent_encode(&ctx.session_id, QUERY_ENCODE_SET),
        utf8_percent_encode(&chars, QUERY_ENCODE_SET)
    );

    let display_origin = ctx
        .return_params
        .as_ref()
        .expect("email::request called without redirect_uri set")
        .redirect_uri
        .origin()
        .unicode_serialization();
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
            .alternative(
                ctx.app.templates.email_html.render(params),
                ctx.app.templates.email_text.render(params),
            )
            .subject(
                [
                    catalog.gettext("Finish logging in to"),
                    display_origin.as_str(),
                ]
                .join(" "),
            )
            .build()
            .unwrap_or_else(|err| panic!("unhandled error building email: {}", err))
    };

    // Store the code in the session for use in the verify handler. We should never fail to claim
    // the session, because we only get here after all other options have failed.
    match ctx.save_session(BridgeData::Email(EmailBridgeData {
        code: chars.clone(),
    })) {
        Ok(true) => {}
        Ok(false) => {
            return Box::new(future::err(BrokerError::Internal(
                "email fallback failed to claim session".to_owned(),
            )))
        }
        Err(e) => return Box::new(future::err(e)),
    }

    // Send the mail.
    let mut mailer = match build_transport(&ctx.app) {
        Ok(mailer) => mailer,
        Err(reason) => return Box::new(future::err(BrokerError::Internal(reason))),
    };
    if let Err(err) = mailer.send(email.into()) {
        return Box::new(future::err(BrokerError::Internal(format!(
            "could not send mail: {}",
            err
        ))));
    }
    mailer.close();

    // Render a form for the user.
    let catalog = ctx.catalog();
    let res =
        Response::new()
            .with_header(ContentType::html())
            .with_body(ctx.app.templates.confirm_email.render(&[
            ("display_origin", display_origin.as_str()),
            ("session_id", &ctx.session_id),
            ("title", catalog.gettext("Confirm your address")),
            (
                "explanation",
                catalog.gettext("We've sent you an email to confirm your address."),
            ),
            (
                "use",
                catalog.gettext("Use the link in that email to login to"),
            ),
            (
                "alternate",
                catalog.gettext(
                    "Alternatively, enter the code from the email to continue in this browser tab:",
                ),
            ),
        ]));
    Box::new(future::ok(res))
}

/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad. Verifies the code and
/// returns the resulting token to the relying party.
pub fn confirmation(ctx_handle: &ContextHandle) -> HandlerResult {
    let mut ctx = ctx_handle.borrow_mut();
    let mut params = ctx.form_params();

    let session_id = try_get_provider_param!(params, "session");
    let bridge_data = match ctx.load_session(&session_id) {
        Ok(BridgeData::Email(bridge_data)) => Rc::new(bridge_data),
        Ok(_) => {
            return Box::new(future::err(BrokerError::ProviderInput(
                "invalid session".to_owned(),
            )))
        }
        Err(e) => return Box::new(future::err(e)),
    };

    let code = try_get_provider_param!(params, "code")
        .replace(|c: char| c.is_whitespace(), "")
        .to_lowercase();
    if code != bridge_data.code {
        return Box::new(future::err(BrokerError::ProviderInput(
            "incorrect code".to_owned(),
        )));
    }

    Box::new(future::result(complete_auth(&*ctx)))
}

/// Build the SMTP transport from config.
fn build_transport(app: &Config) -> Result<SmtpTransport, String> {
    // Extract domain, and build an address with a default port.
    // Split the same way `to_socket_addrs` does.
    let parts = app.smtp_server.rsplitn(2, ':').collect::<Vec<_>>();
    let (domain, addr) = if parts.len() == 2 {
        (parts[1].to_owned(), app.smtp_server.to_owned())
    } else {
        (parts[0].to_owned(), format!("{}:25", app.smtp_server))
    };

    // TODO: Configurable security.
    let tls_connector =
        TlsConnector::new().map_err(|e| format!("could not initialize tls: {}", e))?;
    let security = ClientSecurity::Opportunistic(ClientTlsParameters::new(domain, tls_connector));
    let mut client = SmtpClient::new(&addr, security)
        .map_err(|e| format!("could not create the smtp transport: {}", e))?;
    if let (&Some(ref username), &Some(ref password)) = (&app.smtp_username, &app.smtp_password) {
        client = client.credentials(Credentials::new(username.to_owned(), password.to_owned()));
    }
    Ok(client.transport())
}
