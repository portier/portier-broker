use std::time::Duration;

use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use crate::{agents::*, metrics};
use http::HeaderValue;
use reqwest::{Method, Request};
use serde::Deserialize;
use serde_json::json;
use url::Url;

static JSON_MIME: HeaderValue = HeaderValue::from_static("application/json");

#[derive(Deserialize)]
struct PostmarkResponse {
    #[serde(rename = "ErrorCode")]
    error_code: u16,
}

/// Mailer agent that uses the Postmark API.
pub struct PostmarkMailer {
    fetcher: Addr<FetchAgent>,
    token: HeaderValue,
    api: Url,
    from: String,
    headers: serde_json::Value,
    timeout: Duration,
}

impl PostmarkMailer {
    pub fn new(
        fetcher: Addr<FetchAgent>,
        token: &str,
        api: Url,
        from_address: &EmailAddress,
        from_name: &str,
        timeout: Duration,
    ) -> Self {
        PostmarkMailer {
            fetcher,
            token: HeaderValue::from_str(token).expect("Invalid Postmark token"),
            api,
            from: format!("{from_name} <{from_address}>"),
            headers: json!([
                {
                    "Name": "List-Id",
                    "Value": format!("Authentication <auth.{}>", from_address.domain()),
                },
            ]),
            timeout,
        }
    }
}

impl Agent for PostmarkMailer {}

impl Handler<SendMail> for PostmarkMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        let body = serde_json::to_vec(&json!({
            "From": &self.from,
            "To": message.to,
            "Subject": message.subject,
            "HtmlBody": message.html_body,
            "TextBody": message.text_body,
            "Headers": &self.headers,
        }))
        .expect("Could not build Postmark request JSON body");

        let mut request = Request::new(Method::POST, self.api.clone());
        request.headers_mut().append("Accept", JSON_MIME.clone());
        request
            .headers_mut()
            .append("Content-Type", JSON_MIME.clone());
        request
            .headers_mut()
            .append("X-Postmark-Server-Token", self.token.clone());
        *request.body_mut() = Some(body.into());
        *request.timeout_mut() = Some(self.timeout);

        let future = self.fetcher.send(FetchUrl {
            request,
            metric: Some(&metrics::AUTH_EMAIL_SEND_DURATION),
        });
        cx.reply_later(async move {
            let data = match future.await {
                Ok(result) => result.data,
                Err(err) => {
                    log::error!("Postmark request failed: {}", err);
                    return false;
                }
            };
            let response: PostmarkResponse = match serde_json::from_str(&data) {
                Ok(response) => response,
                Err(err) => {
                    log::error!("Could not parse Postmark response: {}", err);
                    return false;
                }
            };
            if response.error_code == 0 {
                true
            } else {
                log::error!("Postmark returned error code {}", response.error_code);
                false
            }
        });
    }
}
