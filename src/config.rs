extern crate serde;
extern crate serde_json;
extern crate toml;

use std;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;

use super::{crypto, store, mustache};

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum ConfigError {
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
#[derive(Clone)]
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


pub struct Provider {
    pub client_id: String,
    pub secret: String,
    pub discovery_url: String,
    pub issuer_domain: String,
}


pub struct Config {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: String,
    pub token_ttl: u16,
    pub keys: Vec<crypto::NamedKey>,
    pub store: store::Store,
    pub from_name: String,
    pub from_address: String,
    pub smtp_server: String,
    pub providers: HashMap<String, Provider>,
    pub templates: Templates,
}


/// Implementation with single method to read configuration from JSON.
impl Config {
    /// Read a TOML configuration file.
    pub fn from_toml_file(file_name: &str) -> Result<Config, ConfigError> {
        let mut file = try!(File::open(file_name));
        let mut file_contents = String::new();
        try!(file.read_to_string(&mut file_contents));

        let toml_config: TomlConfig = toml::decode_str(&file_contents)
            .expect("unable to parse config file");

        let mut keys: Vec<crypto::NamedKey> = Vec::new();
        for path in toml_config.crypto.keyfiles.iter() {
            keys.push(try!(crypto::NamedKey::from_file(path)));
        }

        let store = try!(store::Store::new(
            &toml_config.redis.url,
            toml_config.redis.session_ttl as usize,
            toml_config.redis.cache_ttl as usize,
            toml_config.redis.cache_max_doc_size as u64
        ));

        let mut providers: HashMap<String, Provider> = HashMap::new();
        for (domain, settings) in toml_config.providers.iter() {
            let provider = Provider {
                client_id: settings.client_id.clone(),
                secret: settings.secret.clone(),
                discovery_url: settings.discovery_url.clone(),
                issuer_domain: settings.issuer_domain.clone(),
            };

            providers.insert(domain.to_string(), provider);
        }


        Ok(Config {
            listen_ip: toml_config.server.listen_ip,
            listen_port: toml_config.server.listen_port,
            public_url: toml_config.server.public_url,
            token_ttl: toml_config.crypto.token_ttl,
            keys: keys,
            store: store,
            from_name: toml_config.smtp.from_name,
            from_address: toml_config.smtp.from_address,
            smtp_server: toml_config.smtp.server,
            providers: providers,
            templates: Templates::default(),
        })
    }
}
