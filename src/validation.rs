use std::error::Error;
use std::fmt;
use url::{self, Url};

// -- Errors --

/// Union type for errors encountered during validation
#[derive(Debug)]
pub enum ValidationError {
    Parse(url::ParseError),
    MismatchedOrigin,
    NotBareOrigin,
    BadScheme(String),
    UserinfoPresent,
    InconsistentSerialization,
    BadPort,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ValidationError::Parse(ref err) => err.fmt(f),
            ValidationError::MismatchedOrigin => write!(f, "origins did not match"),
            ValidationError::NotBareOrigin => write!(f, "uri was not a bare origin"),
            ValidationError::BadScheme(ref param) => write!(f, "{} scheme was not http(s)", param),
            ValidationError::UserinfoPresent => write!(f, "a username or password was specified in the uri"),
            ValidationError::InconsistentSerialization => write!(f, "parsing and re-serializing the uri changed its representation, check for unnecessary information like default ports"),
            ValidationError::BadPort => write!(f, "invalid port specified"),
        }
    }
}

impl Error for ValidationError {
    fn description(&self) -> &str {
        match *self {
            ValidationError::Parse(ref err) => err.description(),
            ValidationError::MismatchedOrigin => "origins did not match",
            ValidationError::NotBareOrigin => "uri was not a bare origin",
            ValidationError::BadScheme(_) => "scheme was not http(s)",
            ValidationError::UserinfoPresent => "a username or password was specified in the uri",
            ValidationError::InconsistentSerialization => "parsing and re-serializing the uri changed its representation, check for unnecessary information like default ports",
            ValidationError::BadPort => "invalid port specified",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            ValidationError::Parse(ref err) => Some(err),
            ValidationError::MismatchedOrigin
                | ValidationError::NotBareOrigin
                | ValidationError::BadScheme(_)
                | ValidationError::UserinfoPresent
                | ValidationError::InconsistentSerialization
                | ValidationError::BadPort
                => None,
        }
    }
}

impl From<url::ParseError> for ValidationError {
    fn from(err: url::ParseError) -> ValidationError {
        ValidationError::Parse(err)
    }
}

// -- Validation Functions --

/// Test that a URI is valid and conforms to our expetations.
pub fn valid_uri(raw_uri: &str, param: &str) -> Result<(), ValidationError> {
    let uri = Url::parse(raw_uri)?;

    if !raw_uri.starts_with("http://") && !raw_uri.starts_with("https://") {
        return Err(ValidationError::BadScheme(param.to_string()))
    }

    if uri.username() != "" || uri.password().is_some() {
        return Err(ValidationError::UserinfoPresent)
    }

    if let Some(port) = uri.port() {
        if port == 0 {
            return Err(ValidationError::BadPort)
        }
    }

    if uri.as_str() != raw_uri && uri.origin().ascii_serialization() != raw_uri {
        return Err(ValidationError::InconsistentSerialization)
    }

    Ok(())
}

/// Test that a URI is is valid and only has a scheme, host, and port.
pub fn only_origin(raw_uri: &str) -> Result<(), ValidationError> {
    let uri = Url::parse(raw_uri)?;

    if uri.origin().ascii_serialization() != raw_uri {
        return Err(ValidationError::NotBareOrigin)
    }

    Ok(())
}

/// Test that two URIs fall within the same origin.
pub fn same_origin(raw_a: &str, raw_b: &str) -> Result<(), ValidationError> {
    let a = Url::parse(raw_a)?;
    let b = Url::parse(raw_b)?;

    if a.origin() != b.origin() {
        return Err(ValidationError::MismatchedOrigin)
    }

    Ok(())
}

// -- Unit Tests --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_uris() {
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
            if let Err(err) = valid_uri(uri, "input") {
                panic!(format!("unexpectedly rejected uri: {}. Reported: {}", uri, err))
            }
        }
    }

    #[test]
    fn rejects_invalid_uris() {
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
            if valid_uri(uri, "input").is_ok() {
                panic!(format!("did not reject uri: {}", uri))
            }
        }
    }

    #[test]
    fn accepts_valid_origins() {
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
        ] {
            if let Err(err) = only_origin(uri) {
                panic!(format!("unexpectedly rejected: {}: {}", uri, err))
            }
        }
    }

    #[test]
    fn rejects_invalid_origins() {
        for uri in &[
            // Opaque Data
            "data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==",
            "http:example.com",

            // Default ports
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

            // Invalid IPv6 literals
            "http://::1",
            "http://::1:8080",

            // Weird strings
            "http://example.com:8080:8080",
            "http://:8080:8080",

            // Paths, query strings, and fragments
            "http://example.com:8080/",
            "http://example.com:8080/path?foo=bar#baz",
            "http://example.com:8080/?foo=bar#baz",
            "http://example.com:8080/#baz",
            "http://example.com:8080/path#baz",
            "http://example.com:8080/path?foo=bar",
        ] {
            if only_origin(uri).is_ok() {
                panic!(format!("unexpectedly accepted: {}", uri))
            }
        }
    }

    #[test]
    fn accepts_same_origin() {
        for &(a, b) in &[
            ("http://example.com", "http://example.com"),
            ("http://example.com:80", "http://example.com"),
            ("https://example.com:443", "https://example.com"),
            ("http://example.com/foo", "http://example.com"),
            ("http://user:pass@example.com", "http://example.com"),
        ] {
            if same_origin(a, b).is_err() != same_origin(b, a).is_err() {
                panic!(format!("same_origin() was not symmetric for: {}, {}", a, b))
            }

            if let Err(err) = same_origin(a, b) {
                panic!(format!("unexpectedly rejected: {}, {}: {}", a, b, err))
            }
        }
    }

    #[test]
    fn rejects_different_origin() {
        for &(a, b) in &[
            ("http://example.com`", "http://example.com"),
            ("http://example.com.evil.com", "http://example.com"),
            ("http://example.com@evil.com", "http://example.com"),
            ("https://example.com", "http://example.com"),
            ("http://example.com:8080", "http://example.com"),
        ] {
            if same_origin(a, b).is_err() != same_origin(b, a).is_err() {
                panic!(format!("same_origin() was not symmetric for: {}, {}", a, b))
            }

            if same_origin(a, b).is_ok() {
                panic!(format!("unexpectedly accepted: {}, {}", a, b))
            }
        }
    }
}
