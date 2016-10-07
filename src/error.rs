use std::fmt;
use std::convert::From;
use std::error::Error;
use std::io::Error as IoError;
use super::hyper::Error as HttpError;
use super::redis::RedisError;
use super::iron::IronError;
use super::iron::status;


/// Union of all possible runtime error types.
#[derive(Debug)]
pub enum BrokerError {
    Custom(String),
    Io(IoError),
    Redis(RedisError),
    Http(HttpError),
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

impl From<BrokerError> for String {
    fn from(err: BrokerError) -> String {
        err.description().to_string()
    }
}

// TODO: Add a category for user errors, and return such errors to the RP.
impl From<BrokerError> for IronError {
    fn from(err: BrokerError) -> IronError {
        IronError::new(err, status::ServiceUnavailable)
    }
}


// Conversion from other error types.
macro_rules! from_error {
    ( $orig:ty, $enum_type:ident ) => {
        impl From<$orig> for BrokerError {
            fn from(err: $orig) -> BrokerError {
                BrokerError::$enum_type(err)
            }
        }
    }
}

from_error!(IoError, Io);
from_error!(HttpError, Http);
from_error!(RedisError, Redis);
