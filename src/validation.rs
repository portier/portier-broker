use std::error::Error;
use std::fmt;
use url::{self, Url};


#[derive(Debug)]
pub enum ValidationError {
    Parse(url::ParseError),
    BadScheme(String),
    UserinfoPresent(String),
    InconsistentSerialization(String),
    BadPort(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ValidationError::Parse(ref err) => {
                err.fmt(f)
            },
            ValidationError::BadScheme(ref param) => {
                write!(f, "the {} scheme was not http(s)", param)
            },
            ValidationError::UserinfoPresent(ref param) => {
                write!(f, "the {} must not contain username or password", param)
            },
            ValidationError::InconsistentSerialization(ref param) => {
                write!(f, "parsing and re-serializing the {} changed its representation, check for unnecessary information like default ports", param)
            },
            ValidationError::BadPort(ref param) => {
                write!(f, "the {} contains an invalid port", param)
            },
        }
    }
}

impl Error for ValidationError {
    fn description(&self) -> &str {
        match *self {
            ValidationError::Parse(ref err) => err.description(),
            ValidationError::BadScheme(_) => "scheme was not http(s)",
            ValidationError::UserinfoPresent(_) => "must not contain a username or password",
            ValidationError::InconsistentSerialization(_) => "parsing and re-serializing changed its representation, check for unnecessary information like default ports",
            ValidationError::BadPort(_) => "contains an invalid port",
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            ValidationError::Parse(ref err) => Some(err),
            ValidationError::BadScheme(_)
                | ValidationError::UserinfoPresent(_)
                | ValidationError::InconsistentSerialization(_)
                | ValidationError::BadPort(_)
                => None,
        }
    }
}

impl From<url::ParseError> for ValidationError {
    fn from(err: url::ParseError) -> ValidationError {
        ValidationError::Parse(err)
    }
}


/// Test that a `redirect_uri` is valid. Returns the parsed `Url` if successful.
pub fn parse_redirect_uri(input: &str, param: &str) -> Result<Url, ValidationError> {
    if !input.starts_with("http://") && !input.starts_with("https://") {
        return Err(ValidationError::BadScheme(param.to_owned()));
    }

    let url = Url::parse(input)?;
    if url.username() != "" || url.password().is_some() {
        return Err(ValidationError::UserinfoPresent(param.to_owned()));
    }
    if url.port() == Some(0) {
        return Err(ValidationError::BadPort(param.to_owned()));
    }

    // Make sure the input origin matches the serialized origin.
    let origin = url.origin().ascii_serialization();
    if !input.starts_with(&origin) {
        return Err(ValidationError::InconsistentSerialization(param.to_owned()));
    }
    match input.as_bytes().get(origin.len()) {
        Some(&b'/') | None => {},
        _ => return Err(ValidationError::InconsistentSerialization(param.to_owned())),
    }

    Ok(url)
}


/// Test that a OpenID Connect endpoint is valid.
///
/// This method is more tolerant than `parse_redirect_uri`, because we're in control of all
/// validation on the IdP side. Note that this method also assumes the scheme was already checked.
///
/// Returns the origin if successful.
pub fn parse_oidc_endpoint(input: &Url) -> Option<String> {
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
                panic!(format!("unexpectedly rejected uri: {}. Reported: {}", uri, err))
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
            if parse_redirect_uri(uri, "input").is_ok() {
                panic!(format!("did not reject uri: {}", uri))
            }
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
            if parse_oidc_endpoint(&uri).is_none() {
                panic!(format!("unexpectedly rejected uri: {}", uri))
            }
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
            println!("{}", uri);
            let uri = uri.parse().expect("could not parse a test uri");
            if parse_oidc_endpoint(&uri).is_some() {
                panic!(format!("did not reject uri: {}", uri))
            }
        }
    }
}
