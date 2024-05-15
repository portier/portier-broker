use std::convert::TryInto;

use crate::email_address::EmailAddress;
use crate::utils::agent::Message;

#[cfg(feature = "lettre")]
use ::lettre::message::{
    header::{HeaderName, HeaderValue},
    Mailbox, Message as LettreMessage, MultiPart,
};

/// Message requesting a mail be sent.
///
/// Handlers should also time the request using `metrics::AUTH_EMAIL_SEND_DURATION`, measuring the
/// narrowest possible section of code that makes the external call.
pub struct SendMail {
    pub to: EmailAddress,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}
impl Message for SendMail {
    type Reply = bool;
}

#[cfg(feature = "lettre")]
impl SendMail {
    /// Convert the message to a Lettre `Message`.
    pub fn into_lettre_message(
        self,
        from_address: &EmailAddress,
        from_name: &str,
    ) -> LettreMessage {
        let mut msg = LettreMessage::builder()
            .from(
                (from_name, from_address.as_str())
                    .try_into()
                    .expect("Could not build mail From header"),
            )
            .to(Mailbox::new(
                None,
                self.to
                    .as_str()
                    .parse()
                    .expect("Could not build mail To header"),
            ))
            .subject(self.subject)
            .multipart(MultiPart::alternative_plain_html(
                self.text_body,
                self.html_body,
            ))
            .expect("Could not build mail");

        // Add a List-Id header to prevent autoresponders.
        msg.headers_mut().insert_raw(HeaderValue::new(
            HeaderName::new_from_ascii_str("List-Id"),
            format!("Authentication <auth.{}>", from_address.domain()),
        ));

        msg
    }
}

#[cfg(feature = "lettre_smtp")]
pub mod lettre_smtp;
#[cfg(feature = "lettre_smtp")]
pub use self::lettre_smtp::SmtpMailer;

#[cfg(feature = "lettre_sendmail")]
pub mod lettre_sendmail;
#[cfg(feature = "lettre_sendmail")]
pub use self::lettre_sendmail::SendmailMailer;

#[cfg(feature = "postmark")]
pub mod postmark;
#[cfg(feature = "postmark")]
pub use self::postmark::PostmarkMailer;

#[cfg(feature = "mailgun")]
pub mod mailgun;
#[cfg(feature = "mailgun")]
pub use self::mailgun::MailgunMailer;

#[cfg(feature = "sendgrid")]
pub mod sendgrid;
#[cfg(feature = "sendgrid")]
pub use self::sendgrid::SendgridMailer;
