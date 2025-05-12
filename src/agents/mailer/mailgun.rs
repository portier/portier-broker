use std::time::Duration;

use base64::prelude::*;
use http::HeaderValue;
use reqwest::{Method, Request};
use url::{form_urlencoded, Url};

use crate::{agents::*, email_address::EmailAddress, metrics, utils::agent::*};

const JSON_MIME: HeaderValue = HeaderValue::from_static("application/json");
const URLENCODED_MIME: HeaderValue = HeaderValue::from_static("application/x-www-form-urlencoded");

/// Mailer agent that uses the Mailgun API.
pub struct MailgunMailer {
    fetcher: Addr<FetchAgent>,
    auth: HeaderValue,
    messages_api: Url,
    from: String,
    list_id: String,
    timeout: Duration,
}

impl MailgunMailer {
    pub fn new(
        fetcher: Addr<FetchAgent>,
        token: &str,
        api: &str,
        domain: &str,
        from_address: &EmailAddress,
        from_name: &str,
        timeout: Duration,
    ) -> Self {
        let messages_api = format!("{api}/{domain}/messages")
            .parse()
            .expect("Could not format Mailgun messages endpoint URL");

        let mut auth = String::from("Basic ");
        BASE64_STANDARD.encode_string(format!("api:{token}"), &mut auth);
        let auth = HeaderValue::from_str(&auth).expect("Invalid Mailgun token");

        MailgunMailer {
            fetcher,
            auth,
            messages_api,
            from: format!("{from_name} <{from_address}>"),
            list_id: format!("Authentication <auth.{}>", from_address.domain()),
            timeout,
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
            .append_pair("h:X-Auto-Response-Suppress", "All")
            .append_pair("h:List-Id", &self.list_id)
            .finish();

        let mut request = Request::new(Method::POST, self.messages_api.clone());
        request.headers_mut().append("Accept", JSON_MIME);
        request
            .headers_mut()
            .append("Content-Type", URLENCODED_MIME);
        request
            .headers_mut()
            .append("Authorization", self.auth.clone());
        *request.body_mut() = Some(body.into());
        *request.timeout_mut() = Some(self.timeout);

        let future = self.fetcher.send(FetchUrl {
            request,
            metric: Some(&metrics::AUTH_EMAIL_SEND_DURATION),
        });
        cx.reply_later(async move {
            match future.await {
                Ok(_) => true,
                Err(err) => {
                    log::error!("Mailgun request failed: {err}");
                    false
                }
            }
        });
    }
}
