use crate::agents::*;
use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use lettre::{SendmailTransport, Transport};

/// Mailer agent that uses `lettre` and sendmail.
pub struct SendmailMailer {
    transport: SendmailTransport,
    from_address: EmailAddress,
    from_name: String,
}

impl SendmailMailer {
    pub fn new(sendmail_command: String, from_address: EmailAddress, from_name: String) -> Self {
        SendmailMailer {
            transport: SendmailTransport::new_with_command(sendmail_command),
            from_address,
            from_name,
        }
    }
}

impl Agent for SendmailMailer {}

impl Handler<SendMail> for SendmailMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let mail = message.into_lettre_email(&self.from_address, &self.from_name);
        match self.transport.send(mail) {
            Ok(()) => {
                cx.reply(true);
            }
            Err(err) => {
                log::error!("Could not send mail: {}", err);
                cx.reply(false);
            }
        }
    }
}
