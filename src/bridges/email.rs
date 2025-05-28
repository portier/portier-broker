use crate::agents::mailer::SendMail;
use crate::bridges::{complete_auth, AuthContext, BridgeData};
use crate::config::Config;
use crate::crypto::random_zbase32;
use crate::error::BrokerError;
use crate::metrics;
use crate::web::{html_response, json_response, Context, HandlerResult, Response};
use gettext::Catalog;
use http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Data we store in the session.
#[derive(Clone, Serialize, Deserialize)]
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
pub async fn auth(mut ctx: AuthContext) -> HandlerResult {
    // Generate a 12-character one-time pad.
    let code = random_zbase32(12, &ctx.app.rng).await;
    // For display, we split it in two groups of 6.
    let code_fmt = [&code[0..6], &code[6..12]].join(" ");

    let display_origin = ctx.display_origin();

    let catalog = ctx.catalog();
    let subject = format!(
        "{} {}",
        catalog.gettext("Finish logging in to"),
        display_origin
    );
    let params = &[
        ("display_origin", display_origin.as_str()),
        ("code", &code_fmt),
        ("title", catalog.gettext("Finish logging in to")),
        ("explanation", catalog.gettext("You received this email so that we may confirm your email address and finish your login to:")),
        ("instruction", catalog.gettext("Enter the following code on the login page:")),
    ];
    let html_body = ctx.app.templates.email_html.render(params);
    let text_body = ctx.app.templates.email_text.render(params);

    // Store the code in the session for use in the verify handler. We should never fail to claim
    // the session, because we only get here after all other options have failed.
    if !ctx
        .save_session(BridgeData::Email(EmailBridgeData { code }))
        .await?
    {
        return Err(BrokerError::Internal(
            "email fallback failed to claim session".to_owned(),
        ));
    }

    // Increment the counter only after the session was claimed.
    if !ctx.app.uncounted_emails.contains(&ctx.email_addr) {
        metrics::AUTH_EMAIL_REQUESTS.inc();
    }

    // Send the mail.
    let ok = ctx
        .app
        .mailer
        .send(SendMail {
            to: ctx.email_addr.clone(),
            subject,
            html_body,
            text_body,
        })
        .await;
    if !ok {
        return Err(BrokerError::Internal("Failed to send mail".to_owned()));
    }

    // Render a form for the user.
    if ctx.want_json {
        Ok(json_response(&json!({
            "result": "verification_code_sent",
            "session": &ctx.session_id,
        })))
    } else {
        Ok(render_form(
            &ctx.app,
            ctx.catalog(),
            &ctx.session_id,
            &display_origin,
            None,
        ))
    }
}

/// Request handler for one-time pad email loop confirmation.
///
/// Retrieves the session based session ID and the expected one-time pad. Verifies the code and
/// returns the resulting token to the relying party.
pub async fn confirmation(ctx: &mut Context) -> HandlerResult {
    let mut params = ctx.form_params();
    let session_id = try_get_provider_param!(params, "session");
    let code = try_get_provider_param!(params, "code")
        .replace(char::is_whitespace, "")
        .to_lowercase();

    let (data, BridgeData::Email(bridge_data)) = ctx.load_session(&session_id).await? else {
        return Err(BrokerError::ProviderInput("invalid session".to_owned()));
    };

    if code != bridge_data.code {
        metrics::AUTH_EMAIL_CODE_INCORRECT.inc();
        let mut res = if ctx.want_json {
            json_response(&json!({
                "result": "incorrect_code",
            }))
        } else {
            render_form(
                &ctx.app,
                ctx.catalog(),
                &ctx.session_id,
                &ctx.display_origin(),
                Some("The code you entered was incorrect."),
            )
        };
        *res.status_mut() = StatusCode::FORBIDDEN;
        return Ok(res);
    }

    if !ctx.app.uncounted_emails.contains(&data.email_addr) {
        metrics::AUTH_EMAIL_COMPLETED.inc();
    }

    complete_auth(ctx, data).await
}

fn render_form(
    app: &Config,
    catalog: &Catalog,
    session_id: &str,
    display_origin: &str,
    error: Option<&str>,
) -> Response {
    html_response(app.templates.confirm_email.render(&[
        ("display_origin", display_origin),
        ("session_id", session_id),
        ("title", catalog.gettext("Confirm your address")),
        (
            "explanation",
            catalog.gettext("We've sent you an email to confirm your address."),
        ),
        (
            "instruction",
            catalog.gettext("Enter the code from the email to finish your login to"),
        ),
        (
            "error",
            error.map(|msg| catalog.gettext(msg)).unwrap_or_default(),
        ),
    ]))
}
