use serde;
use serde::de::Deserialize;
use serde_json;
use serde_json::de::from_reader;
use serde_json::value::Value;
use std;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use super::{crypto, store};


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    De(serde_json::error::Error),
    Store(&'static str),
}

macro_rules! from_error {
    ( $orig:ty, $enum_type:ident ) => {
        impl From<$orig> for Error {
            fn from(err: $orig) -> Error {
                Error::$enum_type(err)
            }
        }
    }
}

from_error!(std::io::Error, Io);
from_error!(serde_json::error::Error, De);
from_error!(&'static str, Store);


/// Takes a JSON object containing "id" and "file" properties, and attempts
/// to instantiate the `NamedKey` object matching the property values.
impl Deserialize for crypto::NamedKey {
    fn deserialize<D>(de: &mut D) -> Result<crypto::NamedKey, D::Error>
                      where D: serde::Deserializer {
        let value: Value = try!(serde::Deserialize::deserialize(de));
        let id = value.find("id").unwrap().as_str().unwrap();
        let file_name = value.find("file").unwrap().as_str().unwrap();
        let res = crypto::NamedKey::from_file(id, file_name);
        res.or_else(|err| Err(serde::de::Error::custom(err)))
    }
}


impl Deserialize for store::Store {
    fn deserialize<D>(de: &mut D) -> Result<store::Store, D::Error>
                      where D: serde::Deserializer {
        let value: Value = try!(serde::Deserialize::deserialize(de));
        let url = value.find("redis_url").unwrap().as_str().unwrap();
        let expire_sessions = value.find("expire_sessions").unwrap().as_u64().unwrap() as usize;
        let expire_cache = value.find("expire_cache").unwrap().as_u64().unwrap() as usize;
        let res = store::Store::new(url, expire_sessions, expire_cache);
        res.or_else(|err| Err(serde::de::Error::custom(err)))
    }
}


/// Represents an email address.
#[derive(Clone, Deserialize)]
pub struct Smtp {
    pub address: String
}


/// Represents an email address.
#[derive(Clone, Deserialize)]
pub struct Email {
    pub address: String,
    pub name: String,
}


/// Represents an OpenID Connect provider.
#[derive(Clone, Deserialize)]
pub struct Provider {
    pub discovery: String,
    pub client_id: String,
    pub secret: String,
    pub issuer: String,
}


/// Holds runtime configuration data for this daemon instance.
#[derive(Clone, Deserialize)]
pub struct AppConfig {
    pub base_url: String, // Origin of this instance, used for constructing URLs
    pub keys: Vec<crypto::NamedKey>, // Signing keys
    pub store: store::Store, // Redis Client
    pub smtp: Smtp, // SMTP client
    pub sender: Email, // From address for email
    pub token_validity: usize, // JWT validity duration, in seconds
    pub providers: HashMap<String, Provider>, // Mapping of Domain -> OIDC Provider
}

/// Implementation with single method to read configuration from JSON.
impl AppConfig {
    pub fn from_json_file(file_name: &str) -> Result<AppConfig, Error> {
        let file = try!(File::open(file_name));
        Ok(try!(from_reader(BufReader::new(file))))
    }
}
