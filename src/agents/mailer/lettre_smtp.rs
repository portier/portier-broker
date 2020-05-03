use crate::agents::*;
use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use lettre::{
    smtp::authentication::Credentials, ClientSecurity, ClientTlsParameters, SmtpClient,
    SmtpTransport, Transport,
};
use native_tls::TlsConnector;

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
    ) -> Self {
        // Extract domain, and build an address with a default port.
        // Split the same way `to_socket_addrs` does.
        let parts = server.rsplitn(2, ':').collect::<Vec<_>>();
        let (domain, addr) = if parts.len() == 2 {
            (parts[1].to_owned(), server.to_owned())
        } else {
            (parts[0].to_owned(), format!("{}:25", server))
        };

        // TODO: Configurable security.
        let tls_connector = TlsConnector::new().expect("Could not initialize TLS for SMTP client");
        let security =
            ClientSecurity::Opportunistic(ClientTlsParameters::new(domain, tls_connector));
        let mut client =
            SmtpClient::new(&addr, security).expect("Could not create the SMTP client");
        if let Some((username, password)) = credentials {
            client = client.credentials(Credentials::new(username, password));
        }

        SmtpMailer {
            transport: client.transport(),
            from_address,
            from_name,
        }
    }
}

impl Agent for SmtpMailer {}

impl Handler<SendMail> for SmtpMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let mail = message.into_lettre_email(&self.from_address, &self.from_name);
        match self.transport.send(mail) {
            Ok(result) => {
                if result.is_positive() {
                    cx.reply(true);
                } else {
                    log::error!(
                        "SMTP server rejected a mail: {} {}",
                        result.code,
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
