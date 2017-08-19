use std::error::Error;
use std::fmt;


/// Union of all possible runtime error types.
#[derive(Debug)]
pub enum BrokerError {
    /// User input error, which results in 400
    Input(String),
    /// Identity provider error, which results in 503 or email loop fallback
    Provider(String),
    /// Internal errors, which result in 500
    Internal(String),
    /// User was rate limited, results in 413
    RateLimited,
}

pub type BrokerResult<T> = Result<T, BrokerError>;

impl Error for BrokerError {
    fn description(&self) -> &str {
        match *self {
            BrokerError::Input(ref description)
                | BrokerError::Provider(ref description)
                | BrokerError::Internal(ref description)
                => description,
            BrokerError::RateLimited => "rate limited",
        }
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}
