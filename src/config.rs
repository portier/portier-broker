extern crate serde;
extern crate serde_json;
extern crate toml;

use std;
use std::collections::HashMap;
use std::env;
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


pub struct Builder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub token_ttl: u16,
    pub keyfiles: Vec<String>,
    pub redis_url: Option<String>,
    pub redis_session_ttl: u16,
    pub redis_cache_ttl: u16,
    pub redis_cache_max_doc_size: u16,
    pub from_name: String,
    pub from_address: Option<String>,
    pub smtp_server: Option<String>,
    pub providers: HashMap<String, ProviderBuilder>,
}


pub struct ProviderBuilder {
    pub client_id: Option<String>,
    pub secret: Option<String>,
    pub discovery_url: Option<String>,
    pub issuer_domain: Option<String>,
}


impl ProviderBuilder {
    pub fn new() -> ProviderBuilder {
        ProviderBuilder {
            client_id: None,
            secret: None,
            discovery_url: None,
            issuer_domain: None,
        }
    }

    pub fn done(self) -> Option<Provider> {
        match (self.client_id, self.secret, self.discovery_url, self.issuer_domain) {
            (Some(id), Some(secret), Some(url), Some(iss)) => {
                Some(Provider {
                    client_id: id,
                    secret: secret,
                    discovery_url: url,
                    issuer_domain: iss,
                })
            }
            _ => None
        }
    }
}


impl Builder {
    pub fn new() -> Builder {
        Builder {
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 3333,
            public_url: None,
            token_ttl: 600,
            keyfiles: Vec::new(),
            redis_url: None,
            redis_session_ttl: 900,
            redis_cache_ttl: 3600,
            redis_cache_max_doc_size: 8096,
            from_name: "Portier".to_string(),
            from_address: None,
            smtp_server: None,
            providers: HashMap::new(),
        }
    }

    pub fn update_from_file(&mut self, path: &String) -> &mut Builder {
        let mut file = File::open(path).unwrap();
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents).unwrap();

        let toml_config: TomlConfig = toml::decode_str(&file_contents)
            .expect("unable to parse config file");

        if let Some(table) = toml_config.server {
            if let Some(val) = table.listen_ip {
                self.listen_ip = val;
            }

            if let Some(val) = table.listen_port {
                self.listen_port = val;
            }

            self.public_url = table.public_url.or(self.public_url.clone());
        }

        if let Some(table) = toml_config.crypto {
            if let Some(val) = table.token_ttl {
                self.token_ttl = val;
            }

            if let Some(val) = table.keyfiles {
                for path in val.iter() {
                    self.keyfiles.push(path.clone());
                }
            }
        }

        if let Some(table) = toml_config.redis {
            self.redis_url = table.url.or(self.redis_url.clone());

            if let Some(val) = table.session_ttl {
                self.redis_session_ttl = val;
            }

            if let Some(val) = table.cache_ttl {
                self.redis_cache_ttl = val;
            }

            if let Some(val) = table.cache_max_doc_size {
                self.redis_cache_max_doc_size = val;
            }
        }

        if let Some(table) = toml_config.smtp {
            self.smtp_server = table.server;

            self.from_address = table.from_address;

            if let Some(val) = table.from_name {
                self.from_name = val;
            }
        }

        if let Some(table) = toml_config.providers {
            for (domain, values) in table {
                if values.client_id.is_some() {
                    let provider = self.providers.entry(domain.clone())
                        .or_insert_with(|| ProviderBuilder::new());

                    provider.client_id = values.client_id;
                }

                if values.secret.is_some() {
                    let provider = self.providers.entry(domain.clone())
                        .or_insert_with(|| ProviderBuilder::new());

                    provider.secret = values.secret;
                }

                if values.discovery_url.is_some() {
                    let provider = self.providers.entry(domain.clone())
                        .or_insert_with(|| ProviderBuilder::new());

                    provider.discovery_url = values.discovery_url;
                }

                if values.issuer_domain.is_some() {
                    let provider = self.providers.entry(domain.clone())
                        .or_insert_with(|| ProviderBuilder::new());

                    provider.issuer_domain = values.issuer_domain;
                }
            }
        }

        self
    }

    pub fn update_from_common_env(&mut self) -> &mut Builder {
        if let Some(port) = env::var("PORT").ok().and_then(|s| s.parse().ok()) {
            self.listen_ip = "0.0.0.0".to_string();
            self.listen_port = port;
        }

        if let Ok(val) = env::var("HEROKU_APP_NAME") {
            self.public_url = Some(format!("https://{}.herokuapp.com", val));
        }

        for var in ["REDISTOGO_URL", "REDISGREEN_URL", "REDISCLOUD_URL", "REDIS_URL", "OPENREDIS_URL"].iter() {
            if let Ok(val) = env::var(var) {
                self.redis_url = Some(val);
                break;
            }
        }

        self
    }

    pub fn update_from_broker_env(&mut self) -> &mut Builder {
        let env_config = EnvConfig::from_env();

        // TODO: This is ripe for a macro...

        if let Some(val) = env_config.broker_ip {
            self.listen_ip = val
        }

        if let Some(val) = env_config.broker_port {
            self.listen_port = val;
        }

        if let Some(val) = env_config.broker_public_url {
            self.public_url = Some(val);
        }

        if let Some(val) = env_config.broker_token_ttl {
            self.token_ttl = val;
        }

        if let Some(val) = env_config.broker_keyfiles {
            // Should this append instead of replacing?
            // Append seems more convenient, but everything else replaces.
            self.keyfiles = val;
        }

        if let Some(val) = env_config.broker_redis_url {
            self.redis_url = Some(val);
        }

        if let Some(val) = env_config.broker_session_ttl {
            self.redis_session_ttl = val;
        }

        if let Some(val) = env_config.broker_cache_ttl {
            self.redis_cache_ttl = val;
        }

        if let Some(val) = env_config.broker_cache_max_doc_size {
            self.redis_cache_max_doc_size = val;
        }

        if let Some(val) = env_config.broker_from_name {
            self.from_name = val;
        }

        if let Some(val) = env_config.broker_from_address {
            self.from_address = Some(val);
        }

        if let Some(val) = env_config.broker_smtp_server {
            self.smtp_server = Some(val);
        }

        if let Some(val) = env_config.broker_gmail_secret {
            let provider = self.providers.entry("gmail.com".to_string())
                .or_insert_with(|| ProviderBuilder::new());

            provider.secret = Some(val);
        }

        if let Some(val) = env_config.broker_gmail_client {
            let provider = self.providers.entry("gmail.com".to_string())
                .or_insert_with(|| ProviderBuilder::new());

            provider.client_id = Some(val);
        }

        if let Some(val) = env_config.broker_gmail_discovery {
            let provider = self.providers.entry("gmail.com".to_string())
                .or_insert_with(|| ProviderBuilder::new());

            provider.discovery_url = Some(val);
        }

        if let Some(val) = env_config.broker_gmail_issuer {
            let provider = self.providers.entry("gmail.com".to_string())
                .or_insert_with(|| ProviderBuilder::new());

            provider.issuer_domain = Some(val);
        }

        self
    }

    pub fn done(self) -> Config {
        let keys = self.keyfiles.iter().filter_map(|path| {
            crypto::NamedKey::from_file(&path).ok()
        }).collect();

        let store = store::Store::new(
            &self.redis_url.unwrap(),
            self.redis_cache_ttl as usize,
            self.redis_session_ttl as usize,
            self.redis_cache_max_doc_size as u64,
        ).unwrap();

        let mut providers = HashMap::new();
        for (domain, builder) in self.providers {
            if let Some(provider) = builder.done() {
                providers.insert(domain.clone(), provider);
            }
        }

        Config {
            listen_ip: self.listen_ip,
            listen_port: self.listen_port,
            public_url: self.public_url.unwrap(),
            token_ttl: self.token_ttl,
            keys: keys,
            store: store,
            from_name: self.from_name,
            from_address: self.from_address.unwrap(),
            smtp_server: self.smtp_server.unwrap(),
            providers: providers,
            templates: Templates::default(),
        }
    }
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
