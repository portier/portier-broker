use std::fmt;
use std::convert::From;
use std::error::Error;
use super::redis::RedisError;


#[derive(Debug)]
pub enum BrokerError {
    Custom(String),
    Redis(RedisError),
}

pub type BrokerResult<T> = Result<T, BrokerError>;

impl Error for BrokerError {
    fn description(&self) -> &str {
        if let BrokerError::Custom(ref description) = *self {
            description
        } else {
            self.cause().unwrap().description()
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            BrokerError::Custom(_) => None,
            _ => Some(self)
        }
    }
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<RedisError> for BrokerError {
    fn from(err: RedisError) -> BrokerError {
        BrokerError::Redis(err)
    }
}

impl From<BrokerError> for String {
    fn from(err: BrokerError) -> String {
        err.description().to_string()
    }
}
