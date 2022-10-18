use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use crate::{agents::*, metrics};
use http::Request;
use hyper::Body;
use url::form_urlencoded;

/// Mailer agent that uses the Mailgun API.
pub struct MailgunMailer {
    fetcher: Addr<FetchAgent>,
    token: String,
    api: String,
    domain: String,
    from: String,
}

impl MailgunMailer {
    pub fn new(
        fetcher: Addr<FetchAgent>,
        token: String,
        api: String,
        domain: String,
        from_address: &EmailAddress,
        from_name: &str,
    ) -> Self {
        MailgunMailer {
            fetcher,
            token,
            api,
            domain,
            from: format!("{} <{}>", from_name, from_address),
        }
    }
}

impl Agent for MailgunMailer {}

impl Handler<SendMail> for MailgunMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("from", &self.from)
            .append_pair("to", message.to.as_ref())
            .append_pair("subject", &message.subject)
            .append_pair("html", &message.html_body)
            .append_pair("text", &message.text_body)
            .finish();

        let mut auth = String::from("Basic ");
        base64::encode_config_buf(format!("api:{}", &self.token), base64::STANDARD, &mut auth);

        let request = Request::post(format!("{}/{}/messages", &self.api, &self.domain))
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Authorization", auth)
            .body(Body::from(body))
            .expect("Could not build Mailgun request");

        let future = self.fetcher.send(FetchUrl {
            request,
            metric: &*metrics::AUTH_EMAIL_SEND_DURATION,
        });
        cx.reply_later(async move {
            match future.await {
                Ok(_) => true,
                Err(err) => {
                    log::error!("Mailgun request failed: {}", err);
                    false
                }
            }
        });
    }
}
