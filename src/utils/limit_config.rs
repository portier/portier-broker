use err_derive::Error;
use std::fmt::{Display, Error as FmtError, Formatter};
use std::num::ParseIntError;
use std::str::FromStr;

// TODO: Support more units, and an integer amount in the denominator.

#[derive(Debug, Error)]
pub enum LimitConfigError {
    #[error(display = "rate limit must contain a '/' fraction separator")]
    NoSeparator,
    #[error(display = "could not parse rate limit numerator as integer: {}", _0)]
    InvalidNumerator(#[error(source)] ParseIntError),
    #[error(display = "rate limit denominator uses an unrecognized unit")]
    InvalidDenominator,
}

/// Configuration for a type of rate limiting.
#[derive(Clone, Copy, Debug)]
pub struct LimitConfig {
    /// Maximum request count within the window before we refuse.
    pub max_count: usize,
    /// Timespan of the entire window, in seconds.
    pub duration: usize,
}

impl LimitConfig {
    /// Create a limit config from a max count per minute.
    pub fn per_minute(max_count: usize) -> Self {
        LimitConfig {
            max_count,
            duration: 60,
        }
    }
}

impl Display for LimitConfig {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match self.duration {
            60 => write!(f, "{}/min", self.max_count),
            _ => unimplemented!(),
        }
    }
}

impl FromStr for LimitConfig {
    type Err = LimitConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let idx = value.find('/').ok_or(LimitConfigError::NoSeparator)?;
        let (max_count, unit) = value.split_at(idx);
        let config = LimitConfig {
            max_count: max_count.parse()?,
            duration: match unit {
                "/min" | "/minute" => 60,
                _ => return Err(LimitConfigError::InvalidDenominator),
            },
        };
        Ok(config)
    }
}

serde_string!(LimitConfig);
