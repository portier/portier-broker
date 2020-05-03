use crate::utils::agent::{Agent, Context, Handler, Message};
use crate::utils::BoxError;
use crate::web::read_body;
use err_derive::Error;
use headers::{CacheControl, HeaderMapExt};
use http::{HeaderValue, Request, StatusCode};
use hyper::client::{Client, HttpConnector};
use hyper::Body;
use hyper_tls::HttpsConnector;
use std::time::Duration;
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(display = "HTTP request failed: {}", _0)]
    Hyper(#[error(source)] hyper::Error),
    #[error(display = "unexpected HTTP status code: {}", _0)]
    BadStatus(StatusCode),
    #[error(display = "could not read HTTP response body: {}", _0)]
    Read(BoxError),
    #[error(display = "invalid UTF-8 in HTTP response body: {}", _0)]
    Utf8(#[error(source)] std::string::FromUtf8Error),
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
    pub request: Request<Body>,
}
impl Message for FetchUrl {
    type Reply = Result<FetchUrlResult, FetchError>;
}
impl FetchUrl {
    /// Create a simple GET request message.
    pub fn get(url: &Url) -> Self {
        let hyper_uri: hyper::Uri = url
            .as_str()
            .parse()
            .expect("could not convert Url to Hyper Url");
        let request = Request::get(hyper_uri)
            .body(Body::empty())
            .expect("could not build GET request");
        FetchUrl { request }
    }
}

/// Agent that fetches URLs.
pub struct FetchAgent {
    client: Client<HttpsConnector<HttpConnector>>,
    user_agent: HeaderValue,
}

impl FetchAgent {
    pub fn new() -> Self {
        FetchAgent {
            client: Client::builder().build(HttpsConnector::new()),
            user_agent: HeaderValue::from_str(&format!("portier.io/{}", env!("CARGO_PKG_VERSION")))
                .expect("Could not prepare User-Agent header"),
        }
    }
}

impl Agent for FetchAgent {}

impl Handler<FetchUrl> for FetchAgent {
    fn handle(&mut self, mut message: FetchUrl, cx: Context<Self, FetchUrl>) {
        message
            .request
            .headers_mut()
            .insert("User-Agent", self.user_agent.clone());

        let future = self.client.request(message.request);
        cx.reply_later(async {
            let res = future.await?;
            if !res.status().is_success() {
                return Err(FetchError::BadStatus(res.status()));
            }

            // Grab the max-age directive from the Cache-Control header.
            let max_age = res
                .headers()
                .typed_get()
                .and_then(|header: CacheControl| header.max_age())
                .unwrap_or_else(|| Duration::from_secs(0));

            let chunk = read_body(res.into_body()).await.map_err(FetchError::Read)?;
            let data = String::from_utf8(chunk.to_vec())?;
            Ok(FetchUrlResult { data, max_age })
        });
    }
}
