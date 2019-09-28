use idna;
use serde::{Deserialize, Deserializer};
use serde::{Serialize, Serializer};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Clone, PartialEq, Eq)]
pub struct EmailAddress {
    serialization: String,
    local_end: usize,
}

impl FromStr for EmailAddress {
    type Err = ();

    /// Parse and normalize an email address.
    /// https://github.com/portier/portier.github.io/blob/master/specs/Email-Normalization.md
    fn from_str(input: &str) -> Result<EmailAddress, ()> {
        let local_end = input.rfind('@').ok_or(())?;
        // Transform the local part to lowercase
        let local = input[..local_end].to_lowercase();
        if local == "" {
            return Err(());
        }
        // Verify and normalize the domain
        let domain = idna::domain_to_ascii(&input[local_end + 1..]).map_err(|_| ())?;
        if domain == "" {
            return Err(());
        }
        if domain
            .find(|c| {
                matches!(
                    c,
                    '\0' | '\t'
                        | '\n'
                        | '\r'
                        | ' '
                        | '#'
                        | '%'
                        | '/'
                        | ':'
                        | '?'
                        | '@'
                        | '['
                        | '\\'
                        | ']'
                )
            })
            .is_some()
        {
            return Err(());
        }
        if domain.parse::<Ipv4Addr>().is_ok() {
            return Err(());
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

impl Serialize for EmailAddress {
    /// Serialize this email address as a string.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_str().serialize(serializer)
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

    /// Create an EmailAddress from trusted input.
    ///
    /// The input is the already serialized form, preferably extracted from an
    /// EmailAddress parsed earlier.
    pub fn from_trusted(input: &str) -> EmailAddress {
        EmailAddress {
            serialization: input.to_owned(),
            local_end: input.rfind('@').expect("no @ found in input"),
        }
    }

    /// Deserialize implementation for trusted input.
    ///
    /// Because this assumes input is valid, it must be explicitely selected using
    /// `#[serde(deserialize_with = "EmailAddress::deserialize_trusted")]`
    pub fn deserialize_trusted<'de, D>(deserializer: D) -> Result<EmailAddress, D::Error>
    where
        D: Deserializer<'de>,
    {
        <&str>::deserialize(deserializer).map(|s| EmailAddress::from_trusted(s))
    }

    /// Return the serialization.
    pub fn as_str(&self) -> &str {
        &self.serialization
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

#[cfg(test)]
mod tests {
    use super::EmailAddress;

    #[test]
    fn test_valid() {
        fn parse(input: &str, output: &str) {
            assert_eq!(
                input.parse::<EmailAddress>().unwrap(),
                EmailAddress::from_trusted(output)
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
                EmailAddress::from_trusted(output)
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
