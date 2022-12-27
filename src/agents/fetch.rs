use crate::utils::agent::{Agent, Context, Handler, Message};
use crate::utils::BoxError;
use crate::web::read_body;
use headers::{CacheControl, HeaderMapExt};
use http::{HeaderValue, Request, StatusCode};
use hyper::client::{Client, HttpConnector};
use hyper::Body;
use prometheus::Histogram;
use std::time::Duration;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("HTTP request failed: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("unexpected HTTP status code: {0}")]
    BadStatus(StatusCode),
    #[error("could not read HTTP response body: {0}")]
    Read(BoxError),
    #[error("invalid UTF-8 in HTTP response body: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
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
    /// Latency metric to use.
    pub metric: &'static Histogram,
}
impl Message for FetchUrl {
    type Reply = Result<FetchUrlResult, FetchError>;
}
impl FetchUrl {
    /// Create a simple GET request message.
    pub fn get(url: &Url, metric: &'static Histogram) -> Self {
        let hyper_uri: hyper::Uri = url
            .as_str()
            .parse()
            .expect("could not convert Url to Hyper Url");
        let request = Request::get(hyper_uri)
            .body(Body::empty())
            .expect("could not build GET request");
        FetchUrl { request, metric }
    }
}

/// Agent that fetches URLs.
pub struct FetchAgent {
    #[cfg(feature = "rustls")]
    client: Client<hyper_rustls::HttpsConnector<HttpConnector>>,
    #[cfg(feature = "native-tls")]
    client: Client<hyper_tls::HttpsConnector<HttpConnector>>,
    user_agent: HeaderValue,
}

impl FetchAgent {
    pub fn new() -> Self {
        #[cfg(feature = "rustls")]
        let connector = {
            let connector = hyper_rustls::HttpsConnectorBuilder::new().with_native_roots();

            #[cfg(feature = "insecure")]
            let connector = connector.https_or_http();
            #[cfg(not(feature = "insecure"))]
            let connector = connector.https_only();

            connector.enable_http1().enable_http2().build()
        };

        #[cfg(feature = "native-tls")]
        let connector = {
            let mut connector = hyper_tls::HttpsConnector::new();
            connector.https_only(cfg!(not(feature = "insecure")));
            connector
        };

        FetchAgent {
            client: Client::builder().build(connector),
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

        let timer = message.metric.start_timer();
        let future = self.client.request(message.request);
        cx.reply_later(async {
            let mut res = future.await?;
            if !res.status().is_success() {
                return Err(FetchError::BadStatus(res.status()));
            }

            let chunk = read_body(res.body_mut()).await.map_err(FetchError::Read)?;
            timer.observe_duration();

            let data = String::from_utf8(chunk.to_vec())?;

            // Grab the max-age directive from the Cache-Control header.
            let max_age = res
                .headers()
                .typed_get()
                .and_then(|header: CacheControl| header.max_age())
                .unwrap_or_else(|| Duration::from_secs(0));

            Ok(FetchUrlResult { data, max_age })
        });
    }
}
