mod env;
mod i18n;
mod limits;
mod templates;
mod toml;

pub use limits::{LegacyLimitPerEmail, LimitConfig, LimitInput};

use self::env::EnvConfig;
use self::i18n::I18n;
use self::templates::Templates;
use self::toml::TomlConfig;
use crate::agents::{
    self, FetchAgent, KeyManagerSender, ManualKeys, ManualKeysError, RotatingKeys, SendMail,
    StoreSender,
};
use crate::bridges::oidc::GOOGLE_IDP_ORIGIN;
use crate::crypto::SigningAlgorithm;
use crate::email_address::EmailAddress;
use crate::utils::{
    agent::{spawn_agent, Addr, Sender},
    SecureRandom,
};
use crate::webfinger::{Link, ParseLinkError, Relation};
use err_derive::Error;
use ipnetwork::IpNetwork;
use std::{
    borrow::ToOwned,
    collections::HashMap,
    env::var as env_var,
    io::Error as IoError,
    path::{Path, PathBuf},
    sync::Arc,
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
    pub trusted_proxies: Vec<IpNetwork>,
    pub allowed_origins: Option<Vec<String>>,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,

    pub key_manager: Box<dyn KeyManagerSender>,
    pub signing_algs: Vec<SigningAlgorithm>,

    pub store: Arc<dyn StoreSender>,
    pub mailer: Box<dyn Sender<SendMail>>,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,

    pub res_dir: PathBuf,
    pub templates: Templates,
    pub i18n: I18n,
    pub rng: SecureRandom,
}

/// Parameters for `StoreConfig::spawn_store`.
struct StoreParams {
    session_ttl: Duration,
    cache_ttl: Duration,
    limit_configs: Vec<LimitConfig>,
    fetcher: Addr<FetchAgent>,
    #[allow(dead_code)]
    rng: SecureRandom,
}

/// Store configuration is first translated into this intermediate enum.
enum StoreConfig {
    #[cfg(feature = "redis")]
    Redis(String),
    #[cfg(feature = "rusqlite")]
    Rusqlite(PathBuf),
    Memory,
}

impl StoreConfig {
    fn from_options(
        redis_url: Option<String>,
        sqlite_db: Option<PathBuf>,
        memory_storage: bool,
    ) -> Result<Self, ConfigError> {
        match (redis_url, sqlite_db, memory_storage) {
            #[cfg(feature = "redis")]
            (Some(redis_url), None, false) => Ok(StoreConfig::Redis(redis_url)),
            #[cfg(not(feature = "redis"))]
            (Some(_), None, false) => {
                Err("Redis storage requested, but this build does not support it.".into())
            }

            #[cfg(feature = "rusqlite")]
            (None, Some(sqlite_db), false) => Ok(StoreConfig::Rusqlite(sqlite_db)),
            #[cfg(not(feature = "rusqlite"))]
            (None, Some(_), false) => {
                Err("SQLite storage requested, but this build does not support it.".into())
            }

            (None, None, true) => Ok(StoreConfig::Memory),

            (None, None, false) => {
                Err("Must specify one of redis_url, sqlite_db or memory_storage".into())
            }

            _ => Err("Can only specify one of redis_url, sqlite_db or memory_storage".into()),
        }
    }

    async fn spawn_store(self, params: StoreParams) -> Arc<dyn StoreSender> {
        match self {
            #[cfg(feature = "redis")]
            StoreConfig::Redis(redis_url) => {
                let store = agents::RedisStore::new(
                    redis_url,
                    params.session_ttl,
                    params.cache_ttl,
                    params.limit_configs,
                    params.fetcher,
                    params.rng,
                )
                .await
                .expect("unable to initialize Redis store");
                Arc::new(spawn_agent(store).await)
            }
            #[cfg(feature = "rusqlite")]
            StoreConfig::Rusqlite(sqlite_db) => {
                let store = agents::RusqliteStore::new(
                    sqlite_db,
                    params.session_ttl,
                    params.cache_ttl,
                    params.limit_configs,
                    params.fetcher,
                )
                .await
                .expect("unable to initialize SQLite store");
                Arc::new(spawn_agent(store).await)
            }
            StoreConfig::Memory => {
                let store = agents::MemoryStore::new(
                    params.session_ttl,
                    params.cache_ttl,
                    params.limit_configs,
                    params.fetcher,
                );
                Arc::new(spawn_agent(store).await)
            }
        }
    }
}

/// Parameters for `MailerConfig::spawn_mailer`.
struct MailerParams {
    #[allow(unused)]
    fetcher: Addr<FetchAgent>,
    #[allow(unused)]
    from_address: EmailAddress,
    #[allow(unused)]
    from_name: String,
}

/// Mailer configuration is first translated into this intermediate enum.
enum MailerConfig {
    #[cfg(feature = "lettre_smtp")]
    LettreSmtp {
        server: String,
        credentials: Option<(String, String)>,
    },
    #[cfg(feature = "lettre_sendmail")]
    LettreSendmail { command: String },
    #[cfg(feature = "postmark")]
    Postmark { token: String, api: String },
}

impl MailerConfig {
    fn from_options(
        smtp_server: Option<String>,
        #[allow(unused)] smtp_username: Option<String>,
        #[allow(unused)] smtp_password: Option<String>,
        sendmail_command: Option<String>,
        postmark_token: Option<String>,
        postmark_api: String,
    ) -> Result<Self, ConfigError> {
        match (smtp_server, sendmail_command, postmark_token) {
            #[cfg(feature = "lettre_smtp")]
            (Some(server), None, None) => {
                let credentials = match (smtp_username, smtp_password) {
                    (Some(username), Some(password)) => Some((username, password)),
                    (None, None) => None,
                    _ => return Err(
                        "only one of SMTP username and password specified; provide both or neither"
                            .into(),
                    ),
                };
                Ok(MailerConfig::LettreSmtp {
                    server,
                    credentials,
                })
            }
            #[cfg(not(feature = "lettre_smtp"))]
            (Some(_), None, None) => {
                Err("SMTP mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "lettre_sendmail")]
            (None, Some(command), None) => Ok(MailerConfig::LettreSendmail { command }),
            #[cfg(not(feature = "lettre_sendmail"))]
            (None, Some(_), None) => {
                Err("sendmail mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "postmark")]
            (None, None, Some(token)) => Ok(MailerConfig::Postmark { token, api: postmark_api }),
            #[cfg(not(feature = "postmark"))]
            (None, None, Some(_)) => {
                Err("Postmark mailer requested, but this build does not support it.".into())
            }

            (None, None, None) => {
                Err("Must specify one of smtp_server, sendmail_command or postmark_token".into())
            }

            _ => Err(
                "Can only specify one of smtp_server, sendmail_command or postmark_token".into(),
            ),
        }
    }

    async fn spawn_mailer(
        self,
        #[allow(unused)] params: MailerParams,
    ) -> Box<dyn Sender<SendMail>> {
        match self {
            #[cfg(feature = "lettre_smtp")]
            MailerConfig::LettreSmtp {
                server,
                credentials,
            } => {
                let mailer = agents::SmtpMailer::new(
                    &server,
                    credentials,
                    params.from_address,
                    params.from_name,
                );
                Box::new(spawn_agent(mailer).await)
            }
            #[cfg(feature = "lettre_sendmail")]
            MailerConfig::LettreSendmail { command } => {
                let mailer =
                    agents::SendmailMailer::new(command, params.from_address, params.from_name);
                Box::new(spawn_agent(mailer).await)
            }
            #[cfg(feature = "postmark")]
            MailerConfig::Postmark { token, api } => {
                let mailer = agents::PostmarkMailer::new(
                    params.fetcher,
                    token,
                    api,
                    &params.from_address,
                    &params.from_name,
                );
                Box::new(spawn_agent(mailer).await)
            }
        }
    }
}

pub struct ConfigBuilder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub trusted_proxies: Vec<IpNetwork>,
    pub allowed_origins: Option<Vec<String>>,
    pub data_dir: String,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,
    pub session_ttl: Duration,
    pub cache_ttl: Duration,

    pub keyfiles: Vec<PathBuf>,
    pub keytext: Option<String>,
    pub signing_algs: Vec<SigningAlgorithm>,
    pub generate_rsa_command: Vec<String>,

    pub redis_url: Option<String>,
    pub sqlite_db: Option<PathBuf>,
    pub memory_storage: bool,

    pub from_name: String,
    pub from_address: Option<String>,

    pub smtp_server: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,

    pub sendmail_command: Option<String>,

    pub postmark_token: Option<String>,
    pub postmark_api: String,

    pub limits: Vec<LimitConfig>,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,
}

impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            listen_ip: "127.0.0.1".to_owned(),
            listen_port: 3333,
            public_url: None,
            trusted_proxies: ["127.0.0.0/8", "::1"]
                .iter()
                .map(|v| v.parse().unwrap())
                .collect(),
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
            generate_rsa_command: "openssl genrsa 2048"
                .split_whitespace()
                .map(ToOwned::to_owned)
                .collect(),

            redis_url: None,
            sqlite_db: None,
            memory_storage: false,

            from_name: "Portier".to_owned(),
            from_address: None,

            smtp_username: None,
            smtp_password: None,
            smtp_server: None,

            sendmail_command: None,

            postmark_token: None,
            postmark_api: "https://api.postmarkapp.com/email".to_owned(),

            limits: [
                "ip:50/s",
                "ip:extend_window:100/5s",
                "ip:email:30/h",
                "ip:email:decr_complete:5/15m",
                "ip:email:origin:decr_complete:2/15m",
            ]
            .iter()
            .map(|value| value.parse().unwrap())
            .collect::<Vec<_>>(),

            google_client_id: None,
            domain_overrides: HashMap::new(),
        }
    }

    pub fn update_from_file(&mut self, path: &Path) -> &mut ConfigBuilder {
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

    pub async fn done(mut self) -> Result<Config, ConfigError> {
        let store_config =
            StoreConfig::from_options(self.redis_url, self.sqlite_db, self.memory_storage)?;
        let mailer_config = MailerConfig::from_options(
            self.smtp_server,
            self.smtp_username,
            self.smtp_password,
            self.sendmail_command,
            self.postmark_token,
            self.postmark_api,
        )?;

        // Assign IDs to limit configs.
        for (idx, limit) in self.limits.iter_mut().enumerate() {
            limit.id = idx;
        }

        // Child structs
        let rng = SecureRandom::new().await;
        let fetcher = spawn_agent(FetchAgent::new()).await;
        let store = store_config
            .spawn_store(StoreParams {
                session_ttl: self.session_ttl,
                cache_ttl: self.cache_ttl,
                limit_configs: self.limits,
                fetcher: fetcher.clone(),
                rng: rng.clone(),
            })
            .await;
        let key_manager: Box<dyn KeyManagerSender> =
            if !self.keyfiles.is_empty() || self.keytext.is_some() {
                let key_manager = ManualKeys::new(
                    &self.keyfiles,
                    self.keytext,
                    &self.signing_algs,
                    rng.clone(),
                )?;
                Box::new(spawn_agent(key_manager).await)
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
                );
                Box::new(spawn_agent(key_manager).await)
            };
        let mailer = mailer_config
            .spawn_mailer(MailerParams {
                fetcher,
                from_address: self
                    .from_address
                    .expect("No mail 'From' address configured")
                    .parse()
                    .expect("Invalid mail 'From' address configured"),
                from_name: self.from_name,
            })
            .await;

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
            trusted_proxies: self.trusted_proxies,
            allowed_origins: self.allowed_origins,

            static_ttl: self.static_ttl,
            discovery_ttl: self.discovery_ttl,
            keys_ttl: self.keys_ttl,
            token_ttl: self.token_ttl,

            key_manager,
            signing_algs: self.signing_algs,

            store,
            mailer,

            google_client_id: self.google_client_id,
            domain_overrides,

            res_dir,
            templates,
            i18n,
            rng,
        })
    }

    pub async fn into_store(self) -> Result<Arc<dyn StoreSender>, ConfigError> {
        let store_config =
            StoreConfig::from_options(self.redis_url, self.sqlite_db, self.memory_storage)?;
        let store = store_config
            .spawn_store(StoreParams {
                session_ttl: self.session_ttl,
                cache_ttl: self.cache_ttl,
                limit_configs: self.limits,
                fetcher: spawn_agent(FetchAgent::new()).await,
                rng: SecureRandom::new().await,
            })
            .await;
        Ok(store)
    }
}
