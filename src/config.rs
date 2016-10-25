extern crate serde;
extern crate serde_json;
extern crate toml;

use serde::de::Deserialize;
use serde_json::value::Value;
use std;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use super::{crypto, store, mustache};

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum ConfigError {
    Custom(String),
    Io(std::io::Error),
    De(serde_json::error::Error),
    Store(&'static str),
}

macro_rules! from_error {
    ( $orig:ty, $enum_type:ident ) => {
        impl From<$orig> for ConfigError {
            fn from(err: $orig) -> ConfigError {
                ConfigError::$enum_type(err)
            }
        }
    }
}

from_error!(std::io::Error, Io);
from_error!(serde_json::error::Error, De);
from_error!(&'static str, Store);


/// Instantiate a `NamedKey` object from a value with a `file` property.
impl Deserialize for crypto::NamedKey {
    fn deserialize<D>(de: &mut D) -> Result<crypto::NamedKey, D::Error>
                      where D: serde::Deserializer {
        let value: Value = try!(serde::Deserialize::deserialize(de));
        let file_name = value.find("file").unwrap().as_str().unwrap();
        let res = crypto::NamedKey::from_file(file_name);
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
        let max_response_size = value.find("max_response_size").unwrap().as_u64().unwrap();
        let res = store::Store::new(url, expire_sessions, expire_cache, max_response_size);
        res.or_else(|err| Err(serde::de::Error::custom(err)))
    }
}


// Newtype so we can implement helpers for templates.
#[derive(Clone)]
pub struct Template(mustache::Template);


impl Template {
    pub fn render(&self, params: &[(&str, &str)]) -> String {
        let mut builder = mustache::MapBuilder::new();
        for &param in params {
            let (ref key, ref value) = param;
            builder = builder.insert_str(key, value);
        }
        self.render_data(&builder.build())
    }

    pub fn render_data(&self, data: &mustache::Data) -> String {
        let mut out: Vec<u8> = Vec::new();
        self.0.render_data(&mut out, data);
        String::from_utf8(out).unwrap()
    }
}


// Contains all templates we use in compiled form.
pub struct Templates {
    /// Page displayed when the confirmation email was sent.
    pub confirm_email: Template,
    /// HTML formatted email containing the one-type pad.
    pub email_html: Template,
    /// Plain text email containing the one-type pad.
    pub email_text: Template,
    /// The error page template.
    pub error: Template,
    /// A dummy form used to redirect back to the RP with a POST request.
    pub forward: Template,
}


impl Templates {
    fn compile_template(path: &str) -> Template {
        Template(mustache::compile_path(path).unwrap())
    }
}

impl Default for Templates {
    fn default() -> Templates {
        Templates {
            confirm_email: Self::compile_template("tmpl/confirm_email.mustache"),
            email_html: Self::compile_template("tmpl/email_html.mustache"),
            email_text: Self::compile_template("tmpl/email_text.mustache"),
            error: Self::compile_template("tmpl/error.mustache"),
            forward: Self::compile_template("tmpl/forward.mustache"),
        }
    }
}


/// Implementation with single method to read configuration from JSON.
impl Config {
    /// Read a TOML configuration file.
    pub fn from_toml_file(file_name: &str) -> Result<Config, ConfigError> {
        let mut file = try!(File::open(file_name));
        let mut file_contents = String::new();
        try!(file.read_to_string(&mut file_contents));
        let app: Config = toml::decode_str(&file_contents).unwrap();

        // Additional validations.
        if app.smtp.username.is_none() != app.smtp.password.is_none() {
            return Err(ConfigError::Custom(
                "only one of smtp username and password specified; provide both or neither".to_string()
            ));
        }

        Ok(app)
    }
}
