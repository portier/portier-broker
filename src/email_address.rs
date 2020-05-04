use crate::utils::TLDS;
use err_derive::Error;
use matches::matches;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::str::FromStr;

fn is_invalid_domain_char(c: char) -> bool {
    matches!(
        c,
        '\0' | '\t' | '\n' | '\r' | ' ' | '#' | '%' | '/' | ':' | '?' | '@' | '[' | '\\' | ']'
    )
}

#[derive(Debug, Error)]
pub enum ParseEmailError {
    #[error(display = "missing '@' separator in email address")]
    NoSeparator,
    #[error(display = "local part of an email address cannot be empty")]
    EmptyLocal,
    #[error(display = "invalid international domain name in email address")]
    InvalidIdna(#[error(from)] idna::Errors),
    #[error(display = "domain part of an email address cannot be empty")]
    EmptyDomain,
    #[error(display = "email address contains invalid characters in the domain part")]
    InvalidDomainChars,
    #[error(display = "email address domain part is not in a public top-level domain")]
    InvalidTld,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EmailAddress {
    serialization: String,
    local_end: usize,
}

impl FromStr for EmailAddress {
    type Err = ParseEmailError;

    /// Parse and normalize an email address.
    /// <https://github.com/portier/portier.github.io/blob/master/specs/Email-Normalization.md>
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let local_end = input.rfind('@').ok_or(ParseEmailError::NoSeparator)?;
        // Transform the local part to lowercase
        let local = input[..local_end].to_lowercase();
        if local == "" {
            return Err(ParseEmailError::EmptyLocal);
        }
        // Verify and normalize the domain
        let domain = idna::domain_to_ascii(&input[local_end + 1..])?;
        if domain == "" {
            return Err(ParseEmailError::EmptyDomain);
        }
        if domain.find(is_invalid_domain_char).is_some() {
            return Err(ParseEmailError::InvalidDomainChars);
        }
        // Verify the domain has a valid TLD.
        let tld_start = domain.rfind('.').map_or(0, |v| v + 1);
        if !TLDS.contains(&domain[tld_start..]) {
            return Err(ParseEmailError::InvalidTld);
        }
        Ok(EmailAddress::from_parts(&local, &domain))
    }
}

impl AsRef<str> for EmailAddress {
    /// Return the serialization of this email address.
    fn as_ref(&self) -> &str {
        &self.serialization
    }
}

impl EmailAddress {
    /// Create an email address from trusted local and domain parts.
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
        let local = local.replace(".", "");

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

serde_string!(EmailAddress);

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
        parse("BJÖRN@göteborg.se", "björn@xn--gteborg-90a.se");
        parse("İⅢ@İⅢ.ninja", "i̇ⅲ@xn--iiii-qwc.ninja");
        parse("\"ex@mple\"@example.com", "\"ex@mple\"@example.com");
        parse("test@example.موقع", "test@example.xn--4gbrim");
        parse("test@uk", "test@uk");
    }

    #[test]
    fn test_invalid() {
        fn parse(input: &str) {
            assert!(input.parse::<EmailAddress>().is_err());
        }
        parse("foo");
        parse("foo@");
        parse("@foo.com");
        parse("foo@127.0.0.1");
        parse("foo@[::1]");
        parse("foo@bla.test");
        parse("foo@bla.example");
        parse("foo@bla.invalid");
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
