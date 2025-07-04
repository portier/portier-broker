mod env;
mod i18n;
mod limits;
mod string_list;
mod templates;
mod toml;

pub use limits::*;
pub use string_list::*;
use url::Url;

use std::{
    borrow::ToOwned,
    collections::{HashMap, HashSet},
    env::var as env_var,
    io::Error as IoError,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use hyper_staticfile::Resolver;
use ipnetwork::IpNetwork;
use thiserror::Error;

use crate::agents::{
    self, FetchAgent, KeyManagerSender, ManualKeys, ManualKeysError, RotatingKeys, SendMail,
    StoreSender,
};
use crate::bridges::oidc::GOOGLE_IDP_ORIGIN;
use crate::crypto::SigningAlgorithm;
use crate::email_address::EmailAddress;
use crate::utils::{
    agent::{spawn_agent, Addr, Sender},
    DomainValidator, SecureRandom,
};
use crate::webfinger::{Link, ParseLinkError, Relation};

use self::env::EnvConfig;
use self::i18n::I18n;
use self::templates::Templates;
use self::toml::TomlConfig;

/// Union of all possible error types seen while parsing.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration error: {0}")]
    Custom(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] IoError),
    #[error("TOML error: {0}")]
    Toml(#[from] ::toml::de::Error),
    #[error("keys configuration error: {0}")]
    ManualKeys(#[from] ManualKeysError),
    #[error("domain override configuration error: {0}")]
    DomainOverride(#[from] ParseLinkError),
}

impl From<&'static str> for ConfigError {
    fn from(msg: &'static str) -> ConfigError {
        ConfigError::Custom(msg)
    }
}

pub type ConfigRc = Arc<Config>;

pub struct Config {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: String,
    pub trusted_proxies: Vec<IpNetwork>,
    pub allowed_origins: Option<Vec<String>>,
    pub cors_ttl: Duration,
    pub csp: Option<String>,
    pub domain_validator: DomainValidator,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,

    pub webfinger_timeout: Duration,
    pub oidc_config_timeout: Duration,
    pub oidc_jwks_timeout: Duration,
    pub discovery_timeout: Duration,

    pub key_manager: Box<dyn KeyManagerSender>,
    pub signing_algs: Vec<SigningAlgorithm>,

    pub store: Arc<dyn StoreSender>,
    pub mailer: Box<dyn Sender<SendMail>>,
    pub device_cookie_ttl: Option<u32>,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,
    pub uncounted_emails: HashSet<EmailAddress>,

    pub static_resolver: Resolver,
    pub templates: Templates,
    pub i18n: I18n,
    pub rng: SecureRandom,
}

/// Parameters for `StoreConfig::spawn_store`.
struct StoreParams {
    session_ttl: Duration,
    auth_code_ttl: Duration,
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
                    params.auth_code_ttl,
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
                    params.auth_code_ttl,
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
                    params.auth_code_ttl,
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
    #[allow(unused)]
    timeout: Duration,
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
    Postmark { token: String, api: Url },
    #[cfg(feature = "mailgun")]
    Mailgun {
        token: String,
        api: String,
        domain: String,
    },
    #[cfg(feature = "sendgrid")]
    Sendgrid { token: String, api: Url },
}

impl MailerConfig {
    // TODO: Clippy is complaining and it is right, this is running a little out of hand.
    // Especially the match statement has become difficult to follow.
    #[allow(clippy::too_many_arguments)]
    fn from_options(
        smtp_server: Option<String>,
        #[allow(unused)] smtp_username: Option<String>,
        #[allow(unused)] smtp_password: Option<String>,
        sendmail_command: Option<String>,
        postmark_token: Option<String>,
        postmark_api: Url,
        mailgun_api: String,
        mailgun_token: Option<String>,
        mailgun_domain: Option<String>,
        sendgrid_token: Option<String>,
        sendgrid_api: Url,
    ) -> Result<Self, ConfigError> {
        match (smtp_server, sendmail_command, postmark_token, mailgun_token, mailgun_domain, sendgrid_token) {
            #[cfg(feature = "lettre_smtp")]
            (Some(server), None, None, None, None, None) => {
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
            (Some(_), None, None, None, None, None) => {
                Err("SMTP mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "lettre_sendmail")]
            (None, Some(command), None, None, None, None) => Ok(MailerConfig::LettreSendmail { command }),
            #[cfg(not(feature = "lettre_sendmail"))]
            (None, Some(_), None, None, None, None) => {
                Err("sendmail mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "postmark")]
            (None, None, Some(token), None, None, None) => Ok(MailerConfig::Postmark {
                token,
                api: postmark_api,
            }),
            #[cfg(not(feature = "postmark"))]
            (None, None, Some(_), None, None, None) => {
                Err("Postmark mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "mailgun")]
            (None, None, None, Some(token), Some(domain), None) => Ok(MailerConfig::Mailgun {
                token,
                api: mailgun_api,
                domain,
            }),
            #[cfg(not(feature = "mailgun"))]
            (None, None, None, Some(_), Some(_), None) => {
                Err("Mailgun mailer requested, but this build does not support it.".into())
            }

            #[cfg(feature = "sendgrid")]
            (None, None, None, None, None, Some(token)) => Ok(MailerConfig::Sendgrid {
                token,
                api: sendgrid_api,
            }),
            #[cfg(not(feature = "sendgrid"))]
            (None, None, None, None, None, Some(_)) => {
                Err("Sendgrid mailer requested, but this build does not support it.".into())
            }

            (None, None, None, None, None, None) => {
                Err("Must specify one of smtp_server, sendmail_command, postmark_token, sendgrid_token, or mailgun_token and mailgun_domain".into())
            }

            _ => Err(
                "Can only specify one of smtp_server, sendmail_command, postmark_token, sendgrid_token, or mailgun_token".into(),
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
                    params.timeout,
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
            MailerConfig::Postmark { ref token, api } => {
                let mailer = agents::PostmarkMailer::new(
                    params.fetcher,
                    token,
                    api,
                    &params.from_address,
                    &params.from_name,
                    params.timeout,
                );
                Box::new(spawn_agent(mailer).await)
            }
            #[cfg(feature = "mailgun")]
            MailerConfig::Mailgun {
                ref token,
                ref api,
                ref domain,
            } => {
                let mailer = agents::MailgunMailer::new(
                    params.fetcher,
                    token,
                    api,
                    domain,
                    &params.from_address,
                    &params.from_name,
                    params.timeout,
                );
                Box::new(spawn_agent(mailer).await)
            }
            #[cfg(feature = "sendgrid")]
            MailerConfig::Sendgrid { ref token, api } => {
                let mailer = agents::SendgridMailer::new(
                    params.fetcher,
                    token,
                    api,
                    &params.from_address,
                    &params.from_name,
                    params.timeout,
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
    pub cors_ttl: Duration,
    pub csp: Option<String>,
    pub domain_validator: DomainValidator,
    pub data_dir: String,

    pub static_ttl: Duration,
    pub discovery_ttl: Duration,
    pub keys_ttl: Duration,
    pub token_ttl: Duration,
    pub session_ttl: Duration,
    pub auth_code_ttl: Duration,
    pub cache_ttl: Duration,

    pub send_email_timeout: Duration,
    pub webfinger_timeout: Duration,
    pub oidc_config_timeout: Duration,
    pub oidc_jwks_timeout: Duration,
    pub discovery_timeout: Duration,

    pub keyfiles: Vec<PathBuf>,
    pub keytext: Option<String>,
    pub signing_algs: Vec<SigningAlgorithm>,
    pub rsa_modulus_bits: usize,
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
    pub postmark_api: Url,

    pub mailgun_token: Option<String>,
    pub mailgun_api: String,
    pub mailgun_domain: Option<String>,

    pub sendgrid_token: Option<String>,
    pub sendgrid_api: Url,

    pub device_cookie_ttl: Option<u32>,

    pub limits: Vec<LimitConfig>,

    pub google_client_id: Option<String>,
    pub domain_overrides: HashMap<String, Vec<Link>>,
    pub uncounted_emails: HashSet<EmailAddress>,
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
            cors_ttl: Duration::ZERO,
            csp: None,
            domain_validator: DomainValidator::new(),
            data_dir: String::new(),

            static_ttl: Duration::from_secs(604_800),
            discovery_ttl: Duration::from_secs(604_800),
            keys_ttl: Duration::from_secs(86_400),
            token_ttl: Duration::from_secs(600),
            session_ttl: Duration::from_secs(900),
            auth_code_ttl: Duration::from_secs(600),
            cache_ttl: Duration::from_secs(3600),

            send_email_timeout: Duration::from_secs(5),
            webfinger_timeout: Duration::from_secs(5),
            oidc_config_timeout: Duration::from_secs(5),
            oidc_jwks_timeout: Duration::from_secs(5),
            discovery_timeout: Duration::from_secs(5),

            keyfiles: Vec::new(),
            keytext: None,
            signing_algs: vec![SigningAlgorithm::Rs256],
            rsa_modulus_bits: 2048,
            generate_rsa_command: vec![],

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
            postmark_api: "https://api.postmarkapp.com/email".parse().unwrap(),

            mailgun_token: None,
            mailgun_api: "https://api.mailgun.net/v3".to_owned(),
            mailgun_domain: None,

            sendgrid_token: None,
            sendgrid_api: "https://api.sendgrid.com/v3/mail/send".parse().unwrap(),

            device_cookie_ttl: Some(0),

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
            uncounted_emails: HashSet::new(),
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
            self.public_url = Some(format!("https://{val}.herokuapp.com"));
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

    pub fn is_keyed_manually(&self) -> bool {
        !self.keyfiles.is_empty() || self.keytext.is_some()
    }

    pub async fn done(mut self) -> Result<Config, ConfigError> {
        let is_keyed_manually = self.is_keyed_manually();
        let store_config =
            StoreConfig::from_options(self.redis_url, self.sqlite_db, self.memory_storage)?;
        let mailer_config = MailerConfig::from_options(
            self.smtp_server,
            self.smtp_username,
            self.smtp_password,
            self.sendmail_command,
            self.postmark_token,
            self.postmark_api,
            self.mailgun_api,
            self.mailgun_token,
            self.mailgun_domain,
            self.sendgrid_token,
            self.sendgrid_api,
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
                auth_code_ttl: self.auth_code_ttl,
                cache_ttl: self.cache_ttl,
                limit_configs: self.limits,
                fetcher: fetcher.clone(),
                rng: rng.clone(),
            })
            .await;
        let key_manager: Box<dyn KeyManagerSender> = if is_keyed_manually {
            let key_manager = ManualKeys::new(
                &self.keyfiles,
                self.keytext,
                &self.signing_algs,
                rng.clone(),
            )?;
            Box::new(spawn_agent(key_manager).await)
        } else {
            let key_manager = RotatingKeys::new(
                store.clone(),
                self.keys_ttl,
                &self.signing_algs,
                self.rsa_modulus_bits,
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
                timeout: self.send_email_timeout,
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
            cors_ttl: self.cors_ttl,
            csp: self.csp,
            domain_validator: self.domain_validator,

            static_ttl: self.static_ttl,
            discovery_ttl: self.discovery_ttl,
            keys_ttl: self.keys_ttl,
            token_ttl: self.token_ttl,

            webfinger_timeout: self.webfinger_timeout,
            oidc_config_timeout: self.oidc_config_timeout,
            oidc_jwks_timeout: self.oidc_jwks_timeout,
            discovery_timeout: self.discovery_timeout,

            key_manager,
            signing_algs: self.signing_algs,

            store,
            mailer,
            device_cookie_ttl: self.device_cookie_ttl,

            google_client_id: self.google_client_id,
            domain_overrides,
            uncounted_emails: self.uncounted_emails,

            static_resolver: Resolver::new(res_dir),
            templates,
            i18n,
            rng,
        })
    }

    pub async fn into_store(self) -> Result<Arc<dyn StoreSender>, ConfigError> {
        let store_config =
            StoreConfig::from_options(self.redis_url, self.sqlite_db, self.memory_storage)?;
        let fetcher = spawn_agent(FetchAgent::new()).await;
        let rng = SecureRandom::new().await;
        let store = store_config
            .spawn_store(StoreParams {
                session_ttl: self.session_ttl,
                auth_code_ttl: self.auth_code_ttl,
                cache_ttl: self.cache_ttl,
                limit_configs: self.limits,
                fetcher,
                rng,
            })
            .await;
        Ok(store)
    }
}
