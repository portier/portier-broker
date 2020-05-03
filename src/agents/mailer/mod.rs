use crate::email_address::EmailAddress;
use crate::utils::agent::Message;

#[cfg(feature = "lettre_email")]
use ::{lettre::SendableEmail, lettre_email::EmailBuilder};

/// Message requesting a mail be sent.
pub struct SendMail {
    pub to: EmailAddress,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}
impl Message for SendMail {
    type Reply = bool;
}

#[cfg(feature = "lettre_email")]
impl SendMail {
    /// Convert the message to a lettre `SendableEmail`.
    pub fn into_lettre_email(self, from_address: &EmailAddress, from_name: &str) -> SendableEmail {
        EmailBuilder::new()
            .from((from_address.as_str(), from_name))
            .to(self.to.into_string())
            .subject(self.subject)
            .alternative(self.html_body, self.text_body)
            .build()
            .expect("Could not build mail")
            .into()
    }
}

#[cfg(feature = "lettre_smtp")]
pub mod lettre_smtp;
#[cfg(feature = "lettre_smtp")]
pub use self::lettre_smtp::SmtpMailer;
