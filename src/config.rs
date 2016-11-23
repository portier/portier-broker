extern crate serde;
extern crate toml;

use std;
use std::collections::HashMap;
use std::env;
use std::fmt::{self, Display};
use std::error::Error;
use std::fs::File;
use std::io::Read;

use super::{crypto, store, mustache};
use super::store_limits::Ratelimit;

include!(concat!(env!("OUT_DIR"), "/serde_types.rs"));


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum ConfigError {
    Custom(String),
    Io(std::io::Error),
    Store(&'static str),
}

impl Error for ConfigError {
    fn description(&self) -> &str {
        match *self {
            ConfigError::Io(ref err) => err.description(),
            ConfigError::Custom(ref string) => string,
            ConfigError::Store(static_str) => static_str,
        }
    }
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self{
            ConfigError::Io(ref err) => write!(f, "IO error: {}", err),
            ConfigError::Custom(ref string) => write!(f, "Configuration error: {}", string),
            ConfigError::Store(static_str) => write!(f, "Store error: {}", static_str),
        }
    }
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

from_error!(String, Custom);
from_error!(std::io::Error, Io);
from_error!(&'static str, Store);


// Newtype so we can implement helpers for templates.
#[derive(Clone)]
pub struct Template(mustache::Template);


impl Template {
    pub fn render(&self, params: &[(&str, &str)]) -> String {
        let mut builder = mustache::MapBuilder::new();
        for &param in params {
            let (key, value) = param;
            builder = builder.insert_str(key, value);
        }
        self.render_data(&builder.build())
    }

    pub fn render_data(&self, data: &mustache::Data) -> String {
        let mut out: Vec<u8> = Vec::new();
        self.0.render_data(&mut out, data);
        String::from_utf8(out).expect("unable to render template as string")
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
        Template(mustache::compile_path(path)
                 .expect(&format!("unable to compile template at: {}", path)))
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
    pub allowed_origins: Option<Vec<String>>,
    pub token_ttl: u16,
    pub keys: Vec<crypto::NamedKey>,
    pub store: store::Store,
    pub from_name: String,
    pub from_address: String,
    pub smtp_server: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub limit_per_email: Ratelimit,
    pub providers: HashMap<String, Provider>,
    pub templates: Templates,
}


#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub allowed_origins: Option<Vec<String>>,
    pub token_ttl: u16,
    pub keyfiles: Vec<String>,
    pub keytext: Option<String>,
    pub redis_url: Option<String>,
    pub redis_session_ttl: u16,
    pub redis_cache_ttl: u16,
    pub redis_cache_max_doc_size: u16,
    pub from_name: String,
    pub from_address: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub limit_per_email: String,
    pub providers: HashMap<String, ProviderBuilder>,
}


#[derive(Clone, Debug, Default)]
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

    pub fn new_gmail() -> ProviderBuilder {
        ProviderBuilder {
            client_id: None,
            secret: None,
            discovery_url: Some("https://accounts.google.com/.well-known/openid-configuration".to_string()),
            issuer_domain: Some("accounts.google.com".to_string()),
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


impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            listen_ip: "127.0.0.1".to_string(),
            listen_port: 3333,
            public_url: None,
            allowed_origins: None,
            token_ttl: 600,
            keyfiles: Vec::new(),
            keytext: None,
            redis_url: None,
            redis_session_ttl: 900,
            redis_cache_ttl: 3600,
            redis_cache_max_doc_size: 8096,
            from_name: "Portier".to_string(),
            from_address: None,
            smtp_username: None,
            smtp_password: None,
            smtp_server: None,
            limit_per_email: "5/min".to_string(),
            providers: HashMap::new(),
        }
    }

    pub fn update_from_file(&mut self, path: &str) -> Result<&mut ConfigBuilder, ConfigError> {
        let mut file = File::open(path)?;
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents)?;
        let toml_config: TomlConfig =
            toml::decode_str(&file_contents).ok_or("unable to parse config file")?;

        if let Some(table) = toml_config.server {
            if let Some(val) = table.listen_ip { self.listen_ip = val; }
            if let Some(val) = table.listen_port { self.listen_port = val; }
            self.public_url = table.public_url.or(self.public_url.clone());
            if let Some(val) = table.allowed_origins { self.allowed_origins = Some(val) };
        }

        if let Some(table) = toml_config.crypto {
            if let Some(val) = table.token_ttl { self.token_ttl = val; }
            if let Some(val) = table.keyfiles {
                self.keyfiles.append(&mut val.clone());
            }
            self.keytext = table.keytext.or(self.keytext.clone());
        }

        if let Some(table) = toml_config.redis {
            self.redis_url = table.url.or(self.redis_url.clone());
            if let Some(val) = table.session_ttl { self.redis_session_ttl = val; }
            if let Some(val) = table.cache_ttl { self.redis_cache_ttl = val; }
            if let Some(val) = table.cache_max_doc_size { self.redis_cache_max_doc_size = val; }
        }

        if let Some(table) = toml_config.smtp {
            self.smtp_server = table.server;
            self.from_address = table.from_address;
            self.smtp_username = table.username.or(self.smtp_username.clone());
            self.smtp_password = table.password.or(self.smtp_password.clone());
            if let Some(val) = table.from_name { self.from_name = val; }
        }

        if let Some(table) = toml_config.limit {
            if let Some(val) = table.per_email { self.limit_per_email = val; }
        }

        if let Some(table) = toml_config.providers {
            for (domain, values) in table {
                let provider = self.providers.entry(domain.clone())
                    .or_insert(match domain.as_str() {
                        "gmail.com" => ProviderBuilder::new_gmail(),
                        _ => ProviderBuilder::new(),
                    });

                if values.client_id.is_some() { provider.client_id = values.client_id; }
                if values.secret.is_some() { provider.secret = values.secret; }
                if values.discovery_url.is_some() { provider.discovery_url = values.discovery_url; }
                if values.issuer_domain.is_some() { provider.issuer_domain = values.issuer_domain; }
            }
        }

        Ok(self)
    }

    pub fn update_from_common_env(&mut self) -> &mut ConfigBuilder {
        if let Some(port) = env::var("PORT").ok().and_then(|s| s.parse().ok()) {
            // If $PORT is set, also bind to 0.0.0.0. Common PaaS convention.
            self.listen_ip = "0.0.0.0".to_string();
            self.listen_port = port;
        }

        if let Ok(val) = env::var("HEROKU_APP_NAME") {
            self.public_url = Some(format!("https://{}.herokuapp.com", val));
        }

        for var in &["REDISTOGO_URL", "REDISGREEN_URL", "REDISCLOUD_URL", "REDIS_URL", "OPENREDIS_URL"] {
            if let Ok(val) = env::var(var) {
                self.redis_url = Some(val);
                break;
            }
        }

        self
    }

    pub fn update_from_broker_env(&mut self) -> &mut ConfigBuilder {
        let env_config = EnvConfig::from_env();

        if let Some(val) = env_config.broker_ip { self.listen_ip = val }
        if let Some(val) = env_config.broker_port { self.listen_port = val; }
        if let Some(val) = env_config.broker_public_url { self.public_url = Some(val); }
        if let Some(val) = env_config.broker_allowed_origins { self.allowed_origins = Some(val); }

        if let Some(val) = env_config.broker_token_ttl { self.token_ttl = val; }
        if let Some(val) = env_config.broker_keyfiles { self.keyfiles = val; }
        if let Some(val) = env_config.broker_keytext { self.keytext = Some(val); }

        if let Some(val) = env_config.broker_redis_url { self.redis_url = Some(val); }
        if let Some(val) = env_config.broker_session_ttl { self.redis_session_ttl = val; }
        if let Some(val) = env_config.broker_cache_ttl { self.redis_cache_ttl = val; }
        if let Some(val) = env_config.broker_cache_max_doc_size { self.redis_cache_max_doc_size = val; }

        if let Some(val) = env_config.broker_from_name { self.from_name = val; }
        if let Some(val) = env_config.broker_from_address { self.from_address = Some(val); }
        if let Some(val) = env_config.broker_smtp_server { self.smtp_server = Some(val); }
        if let Some(val) = env_config.broker_smtp_username { self.smtp_username = Some(val); }
        if let Some(val) = env_config.broker_smtp_password { self.smtp_password = Some(val); }

        if let Some(val) = env_config.broker_limit_per_email { self.limit_per_email = val; }

        // New scope to avoid mutably borrowing `self` twice
        {
            let mut gmail_provider = self.providers.entry("gmail.com".to_string())
                .or_insert_with(ProviderBuilder::new_gmail);

            if let Some(val) = env_config.broker_gmail_secret { gmail_provider.secret = Some(val); }
            if let Some(val) = env_config.broker_gmail_client { gmail_provider.client_id = Some(val); }
            if let Some(val) = env_config.broker_gmail_discovery { gmail_provider.discovery_url = Some(val); }
            if let Some(val) = env_config.broker_gmail_issuer { gmail_provider.issuer_domain = Some(val); }
        }

        self
    }

    pub fn done(self) -> Result<Config, ConfigError> {
        // Additional validations
        if self.smtp_username.is_none() != self.smtp_password.is_none() {
            return Err(ConfigError::Custom(
                "only one of smtp username and password specified; provide both or neither".to_string()
            ));
        }

        // Child structs
        let mut keys: Vec<crypto::NamedKey> = self.keyfiles.iter().filter_map(|path| {
            crypto::NamedKey::from_file(path).ok()
        }).collect();

        if let Some(keytext) = self.keytext {
            if let Ok(pkey) = crypto::NamedKey::from_pem_str(&keytext) {
                keys.push(pkey)
            }
        }

        let store = store::Store::new(
            &self.redis_url.expect("no redis url configured"),
            self.redis_cache_ttl as usize,
            self.redis_session_ttl as usize,
            self.redis_cache_max_doc_size as u64,
        ).expect("unable to instantiate new redis store");

        let idx = self.limit_per_email.find('/')
            .expect("unable to parse limit.per_email format");
        let (count, unit) = self.limit_per_email.split_at(idx);
        let ratelimit = Ratelimit {
            count: count.parse().expect("unable to parse limit count"),
            duration: match unit {
                "/min" | "/minute" => 60,
                _ => return Err(From::from("unrecognized limit duration")),
            }
        };

        let mut providers = HashMap::new();
        for (domain, builder) in self.providers {
            if let Some(provider) = builder.done() {
                providers.insert(domain.clone(), provider);
            }
        }

        Ok(Config {
            listen_ip: self.listen_ip,
            listen_port: self.listen_port,
            public_url: self.public_url.expect("no public url configured"),
            allowed_origins: self.allowed_origins,
            token_ttl: self.token_ttl,
            keys: keys,
            store: store,
            from_name: self.from_name,
            from_address: self.from_address.expect("no smtp from address configured"),
            smtp_server: self.smtp_server.expect("no smtp outserver address configured"),
            smtp_username: self.smtp_username,
            smtp_password: self.smtp_password,
            limit_per_email: ratelimit,
            providers: providers,
            templates: Templates::default(),
        })
    }
}


impl EnvConfig {
    /// Manually deserialize from environment variables
    ///
    /// Redundant once [Envy](https://crates.io/crates/envy) supports Serde 0.8
    pub fn from_env() -> EnvConfig {
        EnvConfig {
            broker_ip: env::var("BROKER_IP").ok(),
            broker_port: env::var("BROKER_PORT").ok().and_then(|x| x.parse().ok()),
            broker_public_url: env::var("BROKER_PUBLIC_URL").ok(),
            broker_allowed_origins: env::var("BROKER_ALLOWED_ORIGINS").ok().map(|x| x.split(',').map(|x| x.to_string()).collect()),

            broker_token_ttl: env::var("BROKER_TOKEN_TTL").ok().and_then(|x| x.parse().ok()),
            broker_keyfiles: env::var("BROKER_KEYFILES").ok().map(|x| x.split(',').map(|x| x.to_string()).collect()),
            broker_keytext: env::var("BROKER_KEYTEXT").ok().and_then(|x| x.parse().ok()),

            broker_redis_url: env::var("BROKER_REDIS_URL").ok(),
            broker_session_ttl: env::var("BROKER_SESSION_TTL").ok().and_then(|x| x.parse().ok()),
            broker_cache_ttl: env::var("BROKER_CACHE_TTL").ok().and_then(|x| x.parse().ok()),
            broker_cache_max_doc_size: env::var("BROKER_CACHE_MAX_DOC_SIZE").ok().and_then(|x| x.parse().ok()),

            broker_from_name: env::var("BROKER_FROM_NAME").ok(),
            broker_from_address: env::var("BROKER_FROM_ADDRESS").ok(),
            broker_smtp_server: env::var("BROKER_SMTP_SERVER").ok(),
            broker_smtp_username: env::var("BROKER_SMTP_USERNAME").ok(),
            broker_smtp_password: env::var("BROKER_SMTP_PASSWORD").ok(),

            broker_limit_per_email: env::var("BROKER_LIMIT_PER_EMAIL").ok(),

            broker_gmail_client: env::var("BROKER_GMAIL_CLIENT").ok(),
            broker_gmail_secret: env::var("BROKER_GMAIL_SECRET").ok(),
            broker_gmail_discovery: env::var("BROKER_GMAIL_DISCOVERY").ok(),
            broker_gmail_issuer: env::var("BROKER_GMAIL_ISSUER").ok(),
        }
    }
}
