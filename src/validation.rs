use thiserror::Error;
use url::{self, Url};

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("the URL is not http(s): {0}")]
    NotHttps(String),
    #[error("the URL could not be parsed: {0}")]
    InvalidUrl(#[from] url::ParseError),
    #[error("the URL must not contain a username or password: {0}")]
    UserinfoPresent(Url),
    #[error("parsing and re-serializing the URL changed its representation (check for unnecessary information like default ports): {0}")]
    InconsistentSerialization(Url),
    #[error("the URL contains an invalid port: {0}")]
    InvalidPort(Url),
}

/// Test that a `redirect_uri` is valid. Returns the parsed `Url` if successful.
pub fn parse_redirect_uri(input: &str, param: &str) -> Result<Url, ValidationError> {
    if !input.starts_with("http://") && !input.starts_with("https://") {
        return Err(ValidationError::NotHttps(param.to_owned()));
    }

    let url = Url::parse(input)?;
    if url.username() != "" || url.password().is_some() {
        return Err(ValidationError::UserinfoPresent(url));
    }
    if url.port() == Some(0) {
        return Err(ValidationError::InvalidPort(url));
    }

    // Make sure the input origin matches the serialized origin.
    let origin = url.origin().ascii_serialization();
    if !input.starts_with(&origin) {
        return Err(ValidationError::InconsistentSerialization(url));
    }
    match input.as_bytes().get(origin.len()) {
        Some(&b'/') | None => {}
        _ => return Err(ValidationError::InconsistentSerialization(url)),
    }

    Ok(url)
}

/// Test that a OpenID Connect endpoint is valid.
///
/// This method is more tolerant than `parse_redirect_uri`, because we're in control of all
/// validation on the identity provider side. Note that this method also assumes the scheme was
/// already checked.
///
/// Returns the origin if successful.
pub fn parse_oidc_href(input: &Url) -> Option<String> {
    if input.port() == Some(0) {
        return None;
    }

    // Simple check to see if it's just an origin.
    // The input should be the same, with only a trailing slash.
    let origin = input.origin().ascii_serialization();
    if input.as_str().len() != origin.len() + 1 {
        return None;
    }

    Some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_redirect_uris() {
        for uri in &[
            // HTTP
            "http://example.com",
            "http://localhost",
            "http://127.0.0.1",
            // HTTPS
            "https://example.com",
            "https://localhost",
            "https://127.0.0.1",
            // Non-default ports
            "http://example.com:8080",
            "http://127.0.0.1:8080",
            "http://example.com:443",
            "https://example.com:80",
            // Paths, query strings, and fragments
            "http://example.com:8080/path?foo=bar#baz",
            "http://example.com:8080/?foo=bar#baz",
            "http://example.com:8080/#baz",
            "http://example.com:8080/path#baz",
            "http://example.com:8080/path?foo=bar",
        ] {
            if let Err(err) = parse_redirect_uri(uri, "input") {
                panic!("unexpectedly rejected uri: {uri}. Reported: {err}");
            }
        }
    }

    #[test]
    fn invalid_redirect_uris() {
        for uri in &[
            // Incomplete strings
            "",
            "/",
            "/index.html",
            // Other or missing schemes
            "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==",
            "ws://example.com",
            "//example.com",
            // Opaque data
            "http:example.com",
            // Redundant default ports
            "http://example.com:80",
            "https://example.com:443",
            // Userinfo
            "http://user:pass@example.com",
            "http://user@example.com",
            "http://@example.com",
            // Missing host
            "http://",
            "http:///path",
            "http://:8080",
            "http://:8080/path",
            // Invalid ports
            "http://example.com:0",
            "http://example.com:65536",
            // Invalid IPv6 literals
            "http://::1",
            "http://::1:8080",
            // Weird strings
            "http://example.com:8080:8080",
            "http://:8080:8080",
            "http://»",
        ] {
            assert!(
                parse_redirect_uri(uri, "input").is_err(),
                "did not reject uri: {uri}"
            );
        }
    }

    #[test]
    fn valid_oidc_endpoints() {
        for uri in &[
            // HTTP
            "http://example.com",
            "http://localhost",
            "http://127.0.0.1",
            // HTTPS
            "https://example.com",
            "https://localhost",
            "https://127.0.0.1",
            // Odd notations
            "http:example.com",
            "http://@example.com",
            // Redundant default ports
            "http://example.com:80",
            "https://example.com:443",
            // Non-default ports
            "http://example.com:8080",
            "http://127.0.0.1:8080",
            "http://example.com:443",
            "https://example.com:80",
        ] {
            let uri = uri.parse().expect("could not parse a test uri");
            assert!(
                parse_oidc_href(&uri).is_some(),
                "unexpectedly rejected uri: {uri}"
            );
        }
    }

    #[test]
    fn invalid_oidc_endpoints() {
        for uri in &[
            // Userinfo
            "http://user:pass@example.com",
            "http://user@example.com",
            // Paths, query strings, and fragments
            "http://example.com:8080/path?foo=bar#baz",
            "http://example.com:8080/?foo=bar#baz",
            "http://example.com:8080/#baz",
            "http://example.com:8080/path#baz",
            "http://example.com:8080/path?foo=bar",
            // Invalid ports
            "http://example.com:0",
        ] {
            println!("{uri}");
            let uri = uri.parse().expect("could not parse a test uri");
            assert!(parse_oidc_href(&uri).is_none(), "did not reject uri: {uri}");
        }
    }
}
