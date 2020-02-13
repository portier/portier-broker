use crate::utils::agent::{Agent, Handler, Message, ReplySender};
use crate::utils::BoxError;
use crate::web::read_body;
use err_derive::Error;
use headers::{CacheControl, HeaderMapExt};
use http::StatusCode;
use hyper::client::{Client, HttpConnector};
use hyper_tls::HttpsConnector;
use std::time::Duration;
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error(display = "HTTP request failed: {}", _0)]
    Hyper(#[error(source)] hyper::Error),
    #[error(display = "unexpected HTTP status code: {}", _0)]
    NotOK(StatusCode),
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

/// Message requesting a URL be fetched.
pub struct FetchUrl {
    /// The URL to fetch.
    pub url: Url,
}

impl Message for FetchUrl {
    type Reply = Result<FetchUrlResult, FetchError>;
}

/// Agent that fetches URLs.
pub struct FetchAgent {
    client: Client<HttpsConnector<HttpConnector>>,
}

impl FetchAgent {
    pub fn new() -> Self {
        let connector = HttpsConnector::new();
        let client = Client::builder().build(connector);
        FetchAgent { client }
    }
}

impl Agent for FetchAgent {}

impl Handler<FetchUrl> for FetchAgent {
    fn handle(&mut self, message: FetchUrl, reply: ReplySender<FetchUrl>) {
        let FetchUrl { url } = message;
        let hyper_url = url
            .as_str()
            .parse()
            .expect("failed to convert Url to Hyper Url");
        let future = self.client.get(hyper_url);
        reply.later(move || async {
            let res = future.await?;
            if res.status() != StatusCode::OK {
                return Err(FetchError::NotOK(res.status()));
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
