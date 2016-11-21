use emailaddress;
use std::fmt;
use std::convert::From;
use std::error::Error;
use std::io::Error as IoError;
use super::hyper::Error as HttpError;
use super::redis::RedisError;
use super::lettre::transport::smtp::error::Error as MailError;
use validation::ValidationError;


/// Union of all possible runtime error types.
#[derive(Debug)]
pub enum BrokerError {
    // User input error, which results in 400
    Input(String),
    // Identity provider error, which we report in the RP redirect
    Provider(String),
    // Internal errors, which we hide from the user
    Custom(String),
    Io(IoError),
    Redis(RedisError),
    Http(HttpError),
    Mail(MailError),
}

pub type BrokerResult<T> = Result<T, BrokerError>;

impl Error for BrokerError {
    fn description(&self) -> &str {
        match *self {
            BrokerError::Input(ref description) |
            BrokerError::Provider(ref description) |
            BrokerError::Custom(ref description) => description,
            BrokerError::Io(ref err) => err.description(),
            BrokerError::Redis(ref err) => err.description(),
            BrokerError::Http(ref err) => err.description(),
            BrokerError::Mail(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            BrokerError::Input(_) |
            BrokerError::Provider(_) |
            BrokerError::Custom(_) => None,
            BrokerError::Io(ref e) => Some(e),
            BrokerError::Redis(ref e) => Some(e),
            BrokerError::Http(ref e) => Some(e),
            BrokerError::Mail(ref e) => Some(e),
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

impl From<ValidationError> for BrokerError {
    fn from(err: ValidationError) -> BrokerError {
        BrokerError::Input(err.description().to_string())
    }
}

impl From<emailaddress::AddrError> for BrokerError {
    fn from(err: emailaddress::AddrError) -> BrokerError {
        BrokerError::Custom(format!("unable to parse email address: {}", err.description()).to_string())
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
from_error!(MailError, Mail);
