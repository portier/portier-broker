mod env;
mod i18n;
mod limits;
mod templates;
mod toml;

pub use limits::LimitConfig;

use self::env::EnvConfig;
use self::i18n::I18n;
use self::templates::Templates;
use self::toml::TomlConfig;
use crate::agents::{
    self, FetchAgent, KeyManagerSender, ManualKeys, ManualKeysError, RotatingKeys, StoreSender,
};
use crate::bridges::oidc::GOOGLE_IDP_ORIGIN;
use crate::crypto::SigningAlgorithm;
use crate::utils::agent::Agent;
use crate::webfinger::{Link, ParseLinkError, Relation};
use err_derive::Error;
use ring::rand::{SecureRandom, SystemRandom};
use std::{
    collections::HashMap, env::var as env_var, io::Error as IoError, path::PathBuf, sync::Arc,
    time::Duration,
};

/// Union of all possible error types seen while parsing.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(display = "configuration error: {}", _0)]
    Custom(#[error(from)] &'static str),
    #[error(display = "IO error: {}", _0)]
    Io(#[error(source)] IoError),
    #[error(display = "TOML error: {}", _0)]
    Toml(#[error(source)] ::toml::de::Error),
    #[error(display = "keys configuration error: {}", _0)]
    ManualKeys(#[error(source)] ManualKeysError),
    #[error(display = "domain override configuration error: {}", _0)]
    DomainOverride(#[error(source)] ParseLinkError),
}

pub type ConfigRc = Arc<Config>;

pub struct Config {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: String,
    pub allowed_origins: Option<Vec<String>>,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,

    pub key_manager: Box<dyn KeyManagerSender>,
    pub signing_algs: Vec<SigningAlgorithm>,

    pub store: Arc<dyn StoreSender>,

    pub from_name: String,
    pub from_address: String,
    pub smtp_server: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,

    pub res_dir: PathBuf,
    pub templates: Templates,
    pub i18n: I18n,
    pub rng: Arc<dyn SecureRandom + Send + Sync>,
}

pub struct ConfigBuilder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub allowed_origins: Option<Vec<String>>,
    pub data_dir: String,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,
    pub session_ttl: Duration,
    pub cache_ttl: Duration,

    pub keyfiles: Vec<String>,
    pub keytext: Option<String>,
    pub signing_algs: Vec<SigningAlgorithm>,
    pub generate_rsa_command: Vec<String>,

    pub redis_url: Option<String>,
    pub sqlite_db: Option<String>,
    pub memory_storage: bool,

    pub from_name: String,
    pub from_address: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,

    pub limit_per_email: LimitConfig,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,
}

impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            listen_ip: "127.0.0.1".to_owned(),
            listen_port: 3333,
            public_url: None,
            allowed_origins: None,
            data_dir: String::new(),

            static_ttl: Duration::from_secs(604_800),
            discovery_ttl: Duration::from_secs(604_800),
            keys_ttl: Duration::from_secs(86_400),
            token_ttl: Duration::from_secs(600),
            session_ttl: Duration::from_secs(900),
            cache_ttl: Duration::from_secs(3600),

            keyfiles: Vec::new(),
            keytext: None,
            signing_algs: vec![SigningAlgorithm::Rs256],
            generate_rsa_command: vec![],

            redis_url: None,
            sqlite_db: None,
            memory_storage: false,

            from_name: "Portier".to_owned(),
            from_address: None,
            smtp_username: None,
            smtp_password: None,
            smtp_server: None,

            limit_per_email: LimitConfig::per_minute(5),

            google_client_id: None,
            domain_overrides: HashMap::new(),
        }
    }

    pub fn update_from_file(&mut self, path: &str) -> &mut ConfigBuilder {
        TomlConfig::parse_and_apply(path, self);
        self
    }

    pub fn update_from_common_env(&mut self) -> &mut ConfigBuilder {
        if let Some(port) = env_var("PORT").ok().and_then(|s| s.parse().ok()) {
            // If $PORT is set, also bind to 0.0.0.0. Common PaaS convention.
            self.listen_ip = "0.0.0.0".to_owned();
            self.listen_port = port;
        }

        if let Ok(val) = env_var("HEROKU_APP_NAME") {
            self.public_url = Some(format!("https://{}.herokuapp.com", val));
        }

        for var in &[
            "REDISTOGO_URL",
            "REDISGREEN_URL",
            "REDISCLOUD_URL",
            "REDIS_URL",
            "OPENREDIS_URL",
        ] {
            if let Ok(val) = env_var(var) {
                self.redis_url = Some(val);
                break;
            }
        }

        let sendgrid_creds = (env_var("SENDGRID_USERNAME"), env_var("SENDGRID_PASSWORD"));
        if let (Ok(smtp_username), Ok(smtp_password)) = sendgrid_creds {
            self.smtp_username = Some(smtp_username);
            self.smtp_password = Some(smtp_password);
            self.smtp_server = Some("smtp.sendgrid.net:587".to_string());
        }

        self
    }

    pub fn update_from_broker_env(&mut self) -> &mut ConfigBuilder {
        EnvConfig::parse_and_apply(self);
        self
    }

    pub async fn done(self) -> Result<Config, ConfigError> {
        // Additional validations
        if self.smtp_username.is_none() != self.smtp_password.is_none() {
            return Err(
                "only one of smtp username and password specified; provide both or neither".into(),
            );
        }

        // Create the secure random number generate.
        // Per SystemRandom docs, call `fill` once here to prepare the generator.
        let rng: Arc<dyn SecureRandom + Send + Sync> = tokio::task::spawn_blocking(|| {
            let rng = SystemRandom::new();
            let mut dummy = [0u8; 16];
            rng.fill(&mut dummy)
                .expect("secure random number generator failed to initialize");
            Arc::new(rng)
        })
        .await
        .unwrap();

        // Child structs
        let fetcher = FetchAgent::new().start();
        let store: Arc<dyn StoreSender> =
            match (self.redis_url, self.sqlite_db, self.memory_storage) {
                #[cfg(feature = "redis")]
                (Some(redis_url), None, false) => {
                    let addr = agents::RedisStore::new(
                        redis_url,
                        self.session_ttl,
                        self.cache_ttl,
                        self.limit_per_email,
                        fetcher,
                    )
                    .await
                    .expect("unable to instantiate new Redis store")
                    .start();
                    Arc::new(addr)
                }
                #[cfg(not(feature = "redis"))]
                (Some(_), None, false) => {
                    panic!("Redis storage requested, but this build does not support it.")
                }

                #[cfg(feature = "rusqlite")]
                (None, Some(sqlite_db), false) => {
                    let addr = agents::RusqliteStore::new(
                        sqlite_db,
                        self.session_ttl,
                        self.cache_ttl,
                        self.limit_per_email,
                        fetcher,
                    )
                    .await
                    .expect("unable to instantiate new SQLite store")
                    .start();
                    Arc::new(addr)
                }
                #[cfg(not(feature = "rusqlite"))]
                (None, Some(_), false) => {
                    panic!("SQLite storage requested, but this build does not support it.")
                }

                (None, None, true) => {
                    let addr = agents::MemoryStore::new(
                        self.session_ttl,
                        self.cache_ttl,
                        self.limit_per_email,
                        fetcher,
                    )
                    .start();
                    Arc::new(addr)
                }

                (None, None, false) => {
                    panic!("Must specify one of redis_url, sqlite_db or memory_storage")
                }

                _ => panic!("Can only specify one of redis_url, sqlite_db or memory_storage"),
            };

        let key_manager: Box<dyn KeyManagerSender> =
            if !self.keyfiles.is_empty() || self.keytext.is_some() {
                let key_manager =
                    ManualKeys::new(self.keyfiles, self.keytext, &self.signing_algs, rng.clone())?
                        .start();
                Box::new(key_manager)
            } else {
                if self.signing_algs.contains(&SigningAlgorithm::Rs256)
                    && self.generate_rsa_command.is_empty()
                {
                    return Err("generate_rsa_command is required for rotating RSA keys".into());
                }
                let key_manager = RotatingKeys::new(
                    store.clone(),
                    self.keys_ttl,
                    &self.signing_algs,
                    self.generate_rsa_command,
                    rng.clone(),
                )
                .start();
                key_manager
                    .send(crate::agents::key_manager::rotating::Init)
                    .await;
                Box::new(key_manager)
            };

        // Configure default domain overrides for hosted Google
        let mut domain_overrides = HashMap::new();
        if self.google_client_id.is_some() {
            let links = vec![Link {
                rel: Relation::Google,
                href: GOOGLE_IDP_ORIGIN
                    .parse()
                    .expect("failed to parse the Google URL"),
            }];
            domain_overrides.insert("gmail.com".to_owned(), links.clone());
            domain_overrides.insert("googlemail.com".to_owned(), links);
        }

        for (domain, links) in self.domain_overrides {
            domain_overrides.insert(domain, links);
        }

        let templates = Templates::new(&self.data_dir);
        let i18n = I18n::new(&self.data_dir);
        let mut res_dir: PathBuf = self.data_dir.into();
        res_dir.push("res");

        Ok(Config {
            listen_ip: self.listen_ip,
            listen_port: self.listen_port,
            public_url: self.public_url.expect("no public url configured"),
            allowed_origins: self.allowed_origins,

            static_ttl: self.static_ttl,
            discovery_ttl: self.discovery_ttl,
            keys_ttl: self.keys_ttl,
            token_ttl: self.token_ttl,

            key_manager,
            signing_algs: self.signing_algs,

            store,

            from_name: self.from_name,
            from_address: self.from_address.expect("no smtp from address configured"),
            smtp_server: self
                .smtp_server
                .expect("no smtp outserver address configured"),
            smtp_username: self.smtp_username,
            smtp_password: self.smtp_password,

            google_client_id: self.google_client_id,
            domain_overrides,

            res_dir,
            templates,
            i18n,
            rng,
        })
    }
}
