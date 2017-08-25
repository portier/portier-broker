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
    /// Result status used by bridges to cancel a request
    ProviderCancelled,
}

impl BrokerError {
    /// Log this error at the appropriate log level.
    pub fn log(&self) {
        match *self {
            BrokerError::Input(ref description) => debug!("{}", description),
            BrokerError::Provider(ref description) => info!("{}", description),
            BrokerError::Internal(ref description) => error!("{}", description),
            // Silent errors
            BrokerError::RateLimited
                | BrokerError::ProviderCancelled
                => {},
        }
    }
}

impl Error for BrokerError {
    fn description(&self) -> &str {
        match *self {
            BrokerError::Input(ref description)
                | BrokerError::Provider(ref description)
                | BrokerError::Internal(ref description)
                => description,
            BrokerError::RateLimited
                | BrokerError::ProviderCancelled
                => unreachable!(),
        }
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}


/// Result type with `BrokerError` for errors.
pub type BrokerResult<T> = Result<T, BrokerError>;
