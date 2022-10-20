use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::hash::{Hash, Hasher};
use thiserror::Error;

fn is_invalid_domain_char(c: char) -> bool {
    matches::matches!(
        c,
        '\0' | '\t' | '\n' | '\r' | ' ' | '#' | '%' | '/' | ':' | '?' | '@' | '[' | '\\' | ']'
    )
}

#[derive(Debug, Error)]
pub enum ParseEmailError {
    #[error("email address contains invalid characters")]
    InvalidChars,
    #[error("missing '@' separator in email address")]
    NoSeparator,
    #[error("local part of an email address cannot be empty")]
    EmptyLocal,
    #[error("local part of the email address is too long")]
    LocalPartTooLong,
    #[error("invalid international domain name in email address")]
    InvalidIdna(idna::Errors),
    #[error("domain part of an email address cannot be empty")]
    EmptyDomain,
    #[error("email address contains invalid characters in the domain part")]
    InvalidDomainChars,
    #[error("domain part of the email address is too long")]
    DomainTooLong,
    #[error("domain part of the email address contains a component that is too long")]
    DomainComponentTooLong,
    #[error("email address domain part cannot be a raw IP address")]
    RawAddrNotAllowed,
}

impl From<email_address::Error> for ParseEmailError {
    fn from(err: email_address::Error) -> Self {
        use email_address::Error as Raw;
        match err {
            Raw::InvalidCharacter => Self::InvalidChars,
            Raw::MissingSeparator => Self::NoSeparator,
            Raw::LocalPartEmpty => Self::EmptyLocal,
            Raw::LocalPartTooLong => Self::LocalPartTooLong,
            Raw::DomainEmpty => Self::EmptyDomain,
            Raw::DomainTooLong => Self::DomainTooLong,
            Raw::SubDomainTooLong => Self::DomainComponentTooLong,
            // It appears these are never produced.
            Raw::DomainTooFew
            | Raw::DomainInvalidSeparator
            | Raw::UnbalancedQuotes
            | Raw::InvalidComment
            | Raw::InvalidIPAddress => unreachable!(),
        }
    }
}

#[derive(Clone)]
pub struct EmailAddress {
    serialization: String,
    local_end: usize,
}

impl PartialEq for EmailAddress {
    fn eq(&self, other: &Self) -> bool {
        self.serialization == other.serialization
    }
}

impl Eq for EmailAddress {}

impl Hash for EmailAddress {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.serialization.hash(state);
    }
}

impl std::str::FromStr for EmailAddress {
    type Err = ParseEmailError;

    /// Parse and normalize an email address.
    /// <https://github.com/portier/portier.github.io/blob/main/specs/Email-Normalization.md>
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let local_end = input.rfind('@').ok_or(ParseEmailError::NoSeparator)?;
        // Transform the local part to lowercase.
        let local = input[..local_end].to_lowercase();
        // Normalize international domain names.
        let domain =
            idna::domain_to_ascii(&input[local_end + 1..]).map_err(ParseEmailError::InvalidIdna)?;
        // Reject IP addresses.
        if domain.parse::<std::net::Ipv4Addr>().is_ok() {
            return Err(ParseEmailError::RawAddrNotAllowed);
        }
        // The email_address crate doesn't validate the domain per WHATWG, but
        // our normalization spec requires it.
        if domain.find(is_invalid_domain_char).is_some() {
            return Err(ParseEmailError::InvalidDomainChars);
        }
        // Perform remaining validation using the email_address crate. This
        // ensures we don't encounter any unexpected errors when sending mail
        // using Lettre.
        let result = EmailAddress::from_parts(&local, &domain);
        email_address::EmailAddress::from_str(&result.serialization)?;
        Ok(result)
    }
}

impl AsRef<str> for EmailAddress {
    /// Return the serialization of this email address.
    fn as_ref(&self) -> &str {
        &self.serialization
    }
}

impl EmailAddress {
    /// Create an email address from local and domain parts.
    fn from_parts(local: &str, domain: &str) -> EmailAddress {
        EmailAddress {
            serialization: format!("{}@{}", local, domain),
            local_end: local.len(),
        }
    }

    /// Return the serialization.
    pub fn as_str(&self) -> &str {
        &self.serialization
    }

    /// Consume and return the serialization.
    #[allow(dead_code)]
    pub fn into_string(self) -> String {
        self.serialization
    }

    /// Return the normalized local part.
    pub fn local(&self) -> &str {
        &self.serialization[..self.local_end]
    }

    /// Return the ASCII normalized domain.
    pub fn domain(&self) -> &str {
        &self.serialization[self.local_end + 1..]
    }

    /// Return the normalized local and domain parts as a tuple.
    pub fn parts(&self) -> (&str, &str) {
        (self.local(), self.domain())
    }

    /// Normalize a Google email address.
    ///
    /// This method can also be used to normalize G Suite addresses.
    pub fn normalize_google(&self) -> EmailAddress {
        let (local, domain) = self.parts();

        // Normalize googlemail.com to gmail.com
        let domain = match domain {
            "googlemail.com" => "gmail.com",
            domain => domain,
        };

        // Trim plus addresses
        let local = match self.local().find('+') {
            Some(pos) => &local[..pos],
            None => local,
        };

        // Ignore dots
        let local = local.replace('.', "");

        EmailAddress::from_parts(&local, domain)
    }
}

/// Display the serialization of this email address.
impl Display for EmailAddress {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Display::fmt(&self.serialization, formatter)
    }
}

/// Debug the serialization of this email address.
impl Debug for EmailAddress {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Debug::fmt(&self.serialization, formatter)
    }
}

serde_from_str!(EmailAddress);
serde_display!(EmailAddress);

#[cfg(test)]
mod tests {
    use super::EmailAddress;

    #[test]
    fn test_valid() {
        fn parse(input: &str, output: &str) {
            assert_eq!(
                input.parse::<EmailAddress>().unwrap(),
                output.parse::<EmailAddress>().unwrap()
            );
        }
        parse("example.foo+bar@example.com", "example.foo+bar@example.com");
        parse("EXAMPLE.FOO+BAR@EXAMPLE.COM", "example.foo+bar@example.com");
        parse("BJÖRN@göteborg.test", "björn@xn--gteborg-90a.test");
        parse("İⅢ@İⅢ.example", "i̇ⅲ@xn--iiii-qwc.example");
        parse("\"ex@mple\"@example.com", "\"ex@mple\"@example.com");
    }

    #[test]
    fn test_invalid() {
        fn parse(input: &str) {
            assert!(input.parse::<EmailAddress>().is_err());
        }
        parse("foo");
        parse("foo@");
        parse("@foo.example");
        parse("foo@127.0.0.1");
        parse("foo@[::1]");
    }

    #[test]
    fn test_google() {
        fn parse(input: &str, output: &str) {
            assert_eq!(
                input.parse::<EmailAddress>().unwrap().normalize_google(),
                output.parse::<EmailAddress>().unwrap()
            );
        }
        parse("example@gmail.com", "example@gmail.com");
        parse("example@googlemail.com", "example@gmail.com");
        parse("example.foo@gmail.com", "examplefoo@gmail.com");
        parse("example+bar@gmail.com", "example@gmail.com");
        parse("example.foo+bar@googlemail.com", "examplefoo@gmail.com");
        parse("EXAMPLE@GOOGLEMAIL.COM", "example@gmail.com");
        parse("EXAMPLE.FOO+BAR@GOOGLEMAIL.COM", "examplefoo@gmail.com");
    }
}
