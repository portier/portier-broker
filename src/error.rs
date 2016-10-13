use std::fmt;
use std::convert::From;
use std::error::Error;
use std::io::Error as IoError;
use super::hyper::Error as HttpError;
use super::redis::RedisError;
use super::lettre::transport::error::Error as MailError;
use super::iron::IronError;
use super::iron::modifiers;
use super::iron::status;
use super::iron::headers::ContentType;
use super::serde_json;
use super::serde_json::builder::ObjectBuilder;


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
            _ => self.cause().unwrap().description(),
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

impl From<BrokerError> for IronError {
    fn from(err: BrokerError) -> IronError {
        match err {
            BrokerError::Input(_) => {
                let obj = ObjectBuilder::new()
                    .insert("error", err.description())
                    .build();
                let content = serde_json::to_string(&obj).unwrap();
                let content_type = modifiers::Header(ContentType::json());
                IronError::new(err, (status::BadRequest, content_type, content))
            }
            BrokerError::Provider(_) => {
                // TODO: Redirect to RP with the error description
                IronError::new(err, status::ServiceUnavailable)
            }
            _ => IronError::new(err, status::InternalServerError),
        }
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
