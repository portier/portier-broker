use std::time::Duration;

use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use crate::{agents::*, metrics};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{SmtpTransport, Transport};

/// Mailer agent that uses `lettre` and SMTP.
pub struct SmtpMailer {
    transport: SmtpTransport,
    from_address: EmailAddress,
    from_name: String,
}

impl SmtpMailer {
    pub fn new(
        server: &str,
        credentials: Option<(String, String)>,
        from_address: EmailAddress,
        from_name: String,
        timeout: Duration,
    ) -> Self {
        // Extract domain, and build an address with a default port.
        // Split the same way `to_socket_addrs` does.
        let parts = server.rsplitn(2, ':').collect::<Vec<_>>();
        let (domain, port) = if parts.len() == 2 {
            (
                parts[1].to_owned(),
                parts[0].parse().expect("Invalid SMTP port"),
            )
        } else {
            (parts[0].to_owned(), 25)
        };

        // TODO: Configurable security.
        let tls_parameters =
            TlsParameters::new(domain.clone()).expect("Could not initialize TLS for SMTP client");
        let mut builder = SmtpTransport::builder_dangerous(&domain)
            .port(port)
            .tls(Tls::Opportunistic(tls_parameters))
            .timeout(Some(timeout));
        if let Some((username, password)) = credentials {
            builder = builder.credentials(Credentials::new(username, password));
        }

        SmtpMailer {
            transport: builder.build(),
            from_address,
            from_name,
        }
    }
}

impl Agent for SmtpMailer {}

impl Handler<SendMail> for SmtpMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let mail = message.into_lettre_message(&self.from_address, &self.from_name);

        let send_timer = metrics::AUTH_EMAIL_SEND_DURATION.start_timer();
        let res = self.transport.send(&mail);
        send_timer.observe_duration();

        match res {
            Ok(result) => {
                if result.is_positive() {
                    cx.reply(true);
                } else {
                    log::error!(
                        "SMTP server rejected a mail: {} {}",
                        result.code(),
                        result.first_line().unwrap_or("")
                    );
                    cx.reply(false);
                }
            }
            Err(err) => {
                log::error!("Could not send mail: {}", err);
                cx.reply(false);
            }
        }
    }
}
