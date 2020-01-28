use headers::{Header, HeaderMapExt};
use http::header::{HeaderName, HeaderValue};
use http::Response;
use std::convert::TryFrom;
use std::fmt::Debug;

pub trait ResponseExt {
    fn header<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: Debug,
        <HeaderValue as TryFrom<V>>::Error: Debug;

    fn typed_header(&mut self, header: impl Header) -> &mut Self;
}

impl<B> ResponseExt for Response<B> {
    fn header<K, V>(&mut self, key: K, value: V) -> &mut Self
    where
        HeaderName: TryFrom<K>,
        HeaderValue: TryFrom<V>,
        <HeaderName as TryFrom<K>>::Error: Debug,
        <HeaderValue as TryFrom<V>>::Error: Debug,
    {
        self.headers_mut().insert(
            HeaderName::try_from(key).expect("header name must be valid"),
            HeaderValue::try_from(value).expect("header value must be valid"),
        );
        self
    }

    fn typed_header(&mut self, header: impl Header) -> &mut Self {
        self.headers_mut().typed_insert(header);
        self
    }
}
