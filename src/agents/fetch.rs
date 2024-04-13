use crate::agents::store::FetchUrlCached;
use crate::metrics::Histogram;
use crate::utils::agent::{Agent, Context, Handler, Message};
use headers::{CacheControl, HeaderMapExt};
use http::StatusCode;
use reqwest::{Client, Method, Request};
use std::time::Duration;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("invalid UTF-8 in HTTP response body: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("unexpected HTTP status code {status}, response: {data}")]
    BadStatus { status: StatusCode, data: String },
}

/// The result of fetching a URL.
pub struct FetchUrlResult {
    /// Data from the response.
    pub data: String,
    /// Public caching age from  `Cache-Control` header, or 0.
    pub max_age: Duration,
}

/// Message containing an HTTP request to make.
pub struct FetchUrl {
    /// The request to make.
    pub request: Request,
    /// Latency metric to use.
    pub metric: Option<&'static Histogram>,
}
impl Message for FetchUrl {
    type Reply = Result<FetchUrlResult, FetchError>;
}
impl FetchUrl {
    /// Create a simple GET request message.
    pub fn get(url: Url, metric: Option<&'static Histogram>) -> Self {
        let request = Request::new(Method::GET, url);
        FetchUrl { request, metric }
    }
}
impl From<FetchUrlCached> for FetchUrl {
    fn from(value: FetchUrlCached) -> Self {
        let mut message = FetchUrl::get(value.url, value.metric);
        *message.request.timeout_mut() = Some(value.timeout);
        message
    }
}

/// Agent that fetches URLs.
pub struct FetchAgent {
    client: Client,
}

impl FetchAgent {
    pub fn new() -> Self {
        FetchAgent {
            client: Client::builder()
                .user_agent(format!("portier.io/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("Failed to initialize HTTP client"),
        }
    }
}

impl Agent for FetchAgent {}

impl Handler<FetchUrl> for FetchAgent {
    fn handle(&mut self, message: FetchUrl, cx: Context<Self, FetchUrl>) {
        let timer = message.metric.map(Histogram::start_timer);
        let future = self.client.execute(message.request);
        cx.reply_later(async {
            let res = future.await?;
            let status = res.status();

            // Grab the max-age directive from the Cache-Control header.
            let max_age = res
                .headers()
                .typed_get()
                .and_then(|header: CacheControl| header.max_age())
                .unwrap_or_else(|| Duration::from_secs(0));

            let data = res.text().await?;
            if !status.is_success() {
                let data = data.escape_default().take(200).collect();
                return Err(FetchError::BadStatus { status, data });
            }

            if let Some(timer) = timer {
                timer.observe_duration();
            }

            Ok(FetchUrlResult { data, max_age })
        });
    }
}
