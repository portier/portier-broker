use std::time::Duration;

use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use crate::{agents::*, metrics};
use http::HeaderValue;
use reqwest::{Method, Request};
use serde_json::json;
use url::Url;

static JSON_MIME: HeaderValue = HeaderValue::from_static("application/json");

/// Mailer agent that uses the Sendgrid API.
pub struct SendgridMailer {
    fetcher: Addr<FetchAgent>,
    auth: HeaderValue,
    api: Url,
    from: serde_json::Value,
    headers: serde_json::Value,
    timeout: Duration,
}

impl SendgridMailer {
    pub fn new(
        fetcher: Addr<FetchAgent>,
        token: &str,
        api: Url,
        from_address: &EmailAddress,
        from_name: &str,
        timeout: Duration,
    ) -> Self {
        SendgridMailer {
            fetcher,
            auth: HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("Invalid Sendgrid token"),
            api,
            from: json!({ "name": from_name, "email": from_address }),
            headers: json!({
                "List-Id": format!("Authentication <auth.{}>", from_address.domain()),
            }),
            timeout,
        }
    }
}

impl Agent for SendgridMailer {}

impl Handler<SendMail> for SendgridMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let body = serde_json::to_vec(&json!({
            "from": &self.from,
            "personalizations": [ { "to": [ { "email": message.to } ] } ],
            "subject": message.subject,
            "content": [
                {
                    "type": "text/plain",
                    "value": message.text_body,
                },
                {
                    "type": "text/html",
                    "value": message.html_body,
                },
            ],
            "headers": &self.headers,
        }))
        .expect("Could not build Sendgrid request JSON body");

        let mut request = Request::new(Method::POST, self.api.clone());
        request
            .headers_mut()
            .append("Content-Type", JSON_MIME.clone());
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
                    log::error!("Sendgrid request failed: {}", err);
                    false
                }
            }
        });
    }
}
