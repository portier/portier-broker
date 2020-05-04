use crate::agents::*;
use crate::email_address::EmailAddress;
use crate::utils::agent::*;
use http::Request;
use hyper::Body;
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
struct PostmarkResponse {
    #[serde(rename = "ErrorCode")]
    error_code: u16,
}

/// Mailer agent that uses the Postmark API.
pub struct PostmarkMailer {
    fetcher: Addr<FetchAgent>,
    token: String,
    from: String,
}

impl PostmarkMailer {
    pub fn new(
        fetcher: Addr<FetchAgent>,
        token: String,
        from_address: &EmailAddress,
        from_name: &str,
    ) -> Self {
        PostmarkMailer {
            fetcher,
            token,
            from: format!("{} <{}>", from_name, from_address),
        }
    }
}

impl Agent for PostmarkMailer {}

impl Handler<SendMail> for PostmarkMailer {
    fn handle(&mut self, message: SendMail, cx: Context<Self, SendMail>) {
        // If using the test token, print the email text body to stderr.
        // This is here for our test suite, but maybe useful in general.
        let is_test_request = self.token == "POSTMARK_API_TEST";

        let body = serde_json::to_vec(&json!({
            "From": &self.from,
            "To": message.to,
            "Subject": message.subject,
            "HtmlBody": message.html_body,
            "TextBody": message.text_body,
        }))
        .expect("Could not build Postmark request JSON body");

        let request = Request::post("https://api.postmarkapp.com/email")
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("X-Postmark-Server-Token", &self.token)
            .body(Body::from(body))
            .expect("Could not build Postmark request");

        let future = self.fetcher.send(FetchUrl { request });
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
                if is_test_request {
                    eprintln!("-----BEGIN EMAIL TEXT BODY-----");
                    eprintln!("{}", message.text_body);
                    eprintln!("-----END EMAIL TEXT BODY-----");
                }
                true
            } else {
                log::error!("Postmark returned error code {}", response.error_code);
                false
            }
        });
    }
}
