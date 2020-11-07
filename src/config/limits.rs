use crate::email_address::EmailAddress;
use serde::de::{Deserialize, Deserializer, Error as DeError};
use std::{net::IpAddr, num::ParseIntError, str::FromStr, time::Duration};
use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum LimitConfigError {
    #[error("rate limit must contain a '/' fraction separator")]
    NoSeparator,
    #[error("rate limit window is missing a time unit")]
    NoWindowUnit,
    #[error("rate limit window has an invalid unit: {0}")]
    InvalidUnit(String),
    #[error("could not parse rate limit count as integer: {0}")]
    InvalidCount(ParseIntError),
    #[error("rate limit contains an invalid keyword: {0}")]
    InvalidKeyword(String),
}

/// Configuration for a type of rate limiting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(clippy::struct_excessive_bools)]
pub struct LimitConfig {
    /// ID of the limit. Currently matches config index.
    pub id: usize,
    /// Whether to include the email address in the key.
    pub with_email_addr: bool,
    /// Whether to include the email domain in the key.
    pub with_email_domain: bool,
    /// Whether to include the RP origin in the key.
    pub with_origin: bool,
    /// Whether to include the user IP in the key.
    pub with_ip: bool,
    /// Whether to extend the time window on new hits.
    pub extend_window: bool,
    /// Whether to decrement the limit for completed requests.
    pub decr_complete: bool,
    /// Maximum request count within the window before we refuse.
    pub max_count: usize,
    /// Timespan of the entire window, in seconds.
    pub window: Duration,
}

impl FromStr for LimitConfig {
    type Err = LimitConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut iter = value.rsplit(':');

        let rate = iter.next().unwrap();
        let rate_sep = rate.find('/').ok_or(LimitConfigError::NoSeparator)?;
        let max_count = rate[..rate_sep]
            .parse()
            .map_err(LimitConfigError::InvalidCount)?;
        let window_str = &rate[(rate_sep + 1)..];

        let window_split = window_str
            .find(|c: char| !c.is_digit(10))
            .ok_or(LimitConfigError::NoWindowUnit)?;
        let mut window = if window_split == 0 {
            1
        } else {
            window_str[..window_split].parse().unwrap()
        };

        match &window_str[window_split..] {
            "s" | "sec" | "secs" | "second" | "seconds" => {}
            "m" | "min" | "mins" | "minute" | "minutes" => window *= 60,
            "h" | "hour" | "hours" => window *= 3600,
            "d" | "day" | "days" => window *= 86400,
            unit => {
                return Err(LimitConfigError::InvalidUnit(unit.to_owned()));
            }
        }

        let mut config = LimitConfig {
            id: 0,
            with_email_addr: false,
            with_email_domain: false,
            with_origin: false,
            with_ip: false,
            extend_window: false,
            decr_complete: false,
            max_count,
            window: Duration::from_secs(window),
        };

        for keyword in iter {
            match keyword {
                "ip" => config.with_ip = true,
                "email" => config.with_email_addr = true,
                "domain" => config.with_email_domain = true,
                "origin" => config.with_origin = true,
                "extend_window" => config.extend_window = true,
                "decr_complete" => config.decr_complete = true,
                _ => {
                    return Err(LimitConfigError::InvalidKeyword(keyword.to_owned()));
                }
            }
        }

        Ok(config)
    }
}

serde_from_str!(LimitConfig);

/// Input values for limit operations.
pub struct LimitInput {
    /// The email address of the user.
    pub email_addr: EmailAddress,
    /// The origin of the relying party.
    pub origin: String,
    /// The IP address of the user agent.
    pub ip: IpAddr,
}

impl LimitInput {
    /// Build a string key for these values and the given config.
    ///
    /// The prefix can be used to add additional namespacing to the key, for usage with Redis for
    /// example. The separator is added between each element of the key.
    pub fn build_key(&self, config: &LimitConfig, prefix: &str, sep: &str) -> String {
        let mut result = format!("{}{}", prefix, config.id);
        if config.with_ip {
            result.push_str(sep);
            result.push_str(&format!("{}", self.ip));
        }
        if config.with_email_addr {
            result.push_str(sep);
            result.push_str(self.email_addr.as_str());
        }
        if config.with_email_domain {
            result.push_str(sep);
            result.push_str(self.email_addr.domain());
        }
        if config.with_origin {
            result.push_str(sep);
            result.push_str(&self.origin);
        }
        result
    }
}

/// Wrapper structure to deserialize the old `limit_per_email` field.
#[derive(Clone)]
pub struct LegacyLimitPerEmail(pub LimitConfig);

impl<'de> Deserialize<'de> for LegacyLimitPerEmail {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let input = format!("email:{}", String::deserialize(deserializer)?);
        Ok(Self(input.parse().map_err(DeError::custom)?))
    }
}

#[cfg(test)]
mod tests {
    use super::LimitConfig;
    use std::time::Duration;

    #[test]
    fn test_parse() {
        assert_eq!(
            "10/s".parse(),
            Ok(LimitConfig {
                max_count: 10,
                window: Duration::from_secs(1),
                ..Default::default()
            })
        );
        assert_eq!(
            "email:decr_complete:11/2min".parse(),
            Ok(LimitConfig {
                with_email_addr: true,
                decr_complete: true,
                max_count: 11,
                window: Duration::from_secs(120),
                ..Default::default()
            })
        );
        assert_eq!(
            "domain:30/h".parse(),
            Ok(LimitConfig {
                with_email_domain: true,
                max_count: 30,
                window: Duration::from_secs(3600),
                ..Default::default()
            })
        );
        assert_eq!(
            "origin:200/day".parse(),
            Ok(LimitConfig {
                with_origin: true,
                max_count: 200,
                window: Duration::from_secs(86400),
                ..Default::default()
            })
        );
        assert_eq!(
            "ip:extend_window:5/second".parse(),
            Ok(LimitConfig {
                with_ip: true,
                extend_window: true,
                max_count: 5,
                window: Duration::from_secs(1),
                ..Default::default()
            })
        );
    }
}
