use crate::bridges::oidc::GOOGLE_IDP_ORIGIN;
use crate::crypto::{self, SigningAlgorithm};
use crate::store;
use crate::store_limits::Ratelimit;
use crate::webfinger::{Link, LinkDef, Relation};
use gettext::Catalog;
use hyper_tls::HttpsConnector;
use log::warn;
use ring::rand::{SecureRandom, SystemRandom};
use serde_derive::Deserialize;
use std::{
    collections::HashMap,
    env,
    error::Error,
    fmt::{self, Display},
    fs::File,
    io::{Error as IoError, Read},
    sync::Arc,
};

/// The type of HTTP client we use, with TLS enabled.
pub type HttpClient = hyper::Client<HttpsConnector<hyper::client::HttpConnector>>;

/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum ConfigError {
    Custom(String),
    Io(IoError),
    Toml(toml::de::Error),
    Store(&'static str),
}

impl Error for ConfigError {}

impl Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ConfigError::Custom(ref string) => write!(f, "Configuration error: {}", string),
            ConfigError::Io(ref err) => write!(f, "IO error: {}", err),
            ConfigError::Toml(ref err) => write!(f, "TOML error: {}", err),
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
    };
}

from_error!(String, Custom);
from_error!(IoError, Io);
from_error!(toml::de::Error, Toml);
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
        self.0
            .render_data(&mut out, data)
            .expect("unable to render template");
        String::from_utf8(out).expect("unable to render template as string")
    }
}

// Contains all templates we use in compiled form.
pub struct Templates {
    /// Page displayed when the confirmation email was sent.
    pub confirm_email: Template,
    /// Page displayed when the login_hint is missing.
    pub login_hint: Template,
    /// HTML formatted email containing the one-type pad.
    pub email_html: Template,
    /// Plain text email containing the one-type pad.
    pub email_text: Template,
    /// The error page template.
    pub error: Template,
    /// A dummy form used to redirect back to the RP with a POST request.
    pub forward: Template,
    /// A dummy form used to capture query and fragment parameters.
    pub rewrite_to_post: Template,
}

impl Templates {
    fn compile_template(path: &str) -> Template {
        Template(
            mustache::compile_path(path)
                .unwrap_or_else(|err| panic!("unable to compile template '{}': {:?}", path, err)),
        )
    }
}

impl Default for Templates {
    fn default() -> Templates {
        Templates {
            confirm_email: Self::compile_template("tmpl/confirm_email.mustache"),
            email_html: Self::compile_template("tmpl/email_html.mustache"),
            email_text: Self::compile_template("tmpl/email_text.mustache"),
            login_hint: Self::compile_template("tmpl/login_hint.mustache"),
            error: Self::compile_template("tmpl/error.mustache"),
            forward: Self::compile_template("tmpl/forward.mustache"),
            rewrite_to_post: Self::compile_template("tmpl/rewrite_to_post.mustache"),
        }
    }
}

// Contains all gettext catalogs we use in compiled form.
pub struct I18n {
    pub catalogs: Vec<(&'static str, Catalog)>,
}

const SUPPORTED_LANGUAGES: &[&str] = &["en", "de", "nl"];

impl Default for I18n {
    fn default() -> I18n {
        I18n {
            catalogs: SUPPORTED_LANGUAGES
                .iter()
                .map(|lang| {
                    let file = File::open(format!("lang/{}.mo", lang))
                        .expect("could not open catalog file");
                    let catalog = Catalog::parse(file).expect("could not parse catalog file");
                    (*lang, catalog)
                })
                .collect(),
        }
    }
}

pub struct GoogleConfig {
    pub client_id: String,
}

pub type ConfigRc = Arc<Config>;

pub struct Config {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: String,
    pub allowed_origins: Option<Vec<String>>,
    pub static_ttl: u32,
    pub discovery_ttl: u64,
    pub keys_ttl: u64,
    pub token_ttl: u16,
    pub keys: Vec<crypto::NamedKeyPair>,
    pub signing_algs: Vec<SigningAlgorithm>,
    pub store: store::Store,
    pub http_client: HttpClient,
    pub from_name: String,
    pub from_address: String,
    pub smtp_server: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub limit_per_email: Ratelimit,
    pub domain_overrides: HashMap<String, Vec<Link>>,
    pub google: Option<GoogleConfig>,
    pub templates: Templates,
    pub i18n: I18n,
    pub rng: SystemRandom,
}

pub struct ConfigBuilder {
    pub listen_ip: String,
    pub listen_port: u16,
    pub public_url: Option<String>,
    pub allowed_origins: Option<Vec<String>>,
    pub static_ttl: u32,
    pub discovery_ttl: u64,
    pub keys_ttl: u64,
    pub token_ttl: u16,
    pub keyfiles: Vec<String>,
    pub keytext: Option<String>,
    pub redis_url: Option<String>,
    pub redis_session_ttl: u16,
    pub redis_cache_ttl: u16,
    pub from_name: String,
    pub from_address: Option<String>,
    pub smtp_server: Option<String>,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,
    pub limit_per_email: String,
    pub domain_overrides: HashMap<String, Vec<Link>>,
    pub google: Option<GoogleConfig>,
}

impl ConfigBuilder {
    pub fn new() -> ConfigBuilder {
        ConfigBuilder {
            listen_ip: "127.0.0.1".to_owned(),
            listen_port: 3333,
            public_url: None,
            allowed_origins: None,
            static_ttl: 604_800,
            discovery_ttl: 604_800,
            keys_ttl: 86_400,
            token_ttl: 600,
            keyfiles: Vec::new(),
            keytext: None,
            redis_url: None,
            redis_session_ttl: 900,
            redis_cache_ttl: 3600,
            from_name: "Portier".to_owned(),
            from_address: None,
            smtp_username: None,
            smtp_password: None,
            smtp_server: None,
            limit_per_email: "5/min".to_owned(),
            domain_overrides: HashMap::new(),
            google: None,
        }
    }

    pub fn update_from_file(&mut self, path: &str) -> Result<&mut ConfigBuilder, ConfigError> {
        let mut file = File::open(path)?;
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents)?;
        let toml_config: TomlConfig = toml::from_str(&file_contents)?;

        if let Some(table) = toml_config.server {
            if let Some(val) = table.listen_ip {
                self.listen_ip = val;
            }
            if let Some(val) = table.listen_port {
                self.listen_port = val;
            }
            self.public_url = table.public_url.or_else(|| self.public_url.clone());
            if let Some(val) = table.allowed_origins {
                self.allowed_origins = Some(val)
            };
        }

        if let Some(table) = toml_config.headers {
            if let Some(val) = table.static_ttl {
                self.static_ttl = val;
            }
            if let Some(val) = table.discovery_ttl {
                self.discovery_ttl = val;
            }
            if let Some(val) = table.keys_ttl {
                self.keys_ttl = val;
            }
        }

        if let Some(table) = toml_config.crypto {
            if let Some(val) = table.token_ttl {
                self.token_ttl = val;
            }
            if let Some(mut val) = table.keyfiles {
                self.keyfiles.append(&mut val);
            }
            self.keytext = table.keytext.or_else(|| self.keytext.clone());
        }

        if let Some(table) = toml_config.redis {
            self.redis_url = table.url.or_else(|| self.redis_url.clone());
            if let Some(val) = table.session_ttl {
                self.redis_session_ttl = val;
            }
            if let Some(val) = table.cache_ttl {
                self.redis_cache_ttl = val;
            }
        }

        if let Some(table) = toml_config.smtp {
            self.smtp_server = table.server;
            self.from_address = table.from_address;
            self.smtp_username = table.username.or_else(|| self.smtp_username.clone());
            self.smtp_password = table.password.or_else(|| self.smtp_password.clone());
            if let Some(val) = table.from_name {
                self.from_name = val;
            }
        }

        if let Some(table) = toml_config.limit {
            if let Some(val) = table.per_email {
                self.limit_per_email = val;
            }
        }

        if let Some(table) = toml_config.domain_overrides {
            for (domain, links) in table {
                let links = links
                    .iter()
                    .map(Link::from_de_link)
                    .collect::<Result<_, _>>()?;
                self.domain_overrides.insert(domain, links);
            }
        }

        if let Some(table) = toml_config.google {
            self.google = Some(GoogleConfig {
                client_id: table.client_id,
            });
        }

        Ok(self)
    }

    pub fn update_from_common_env(&mut self) -> &mut ConfigBuilder {
        if let Some(port) = env::var("PORT").ok().and_then(|s| s.parse().ok()) {
            // If $PORT is set, also bind to 0.0.0.0. Common PaaS convention.
            self.listen_ip = "0.0.0.0".to_owned();
            self.listen_port = port;
        }

        if let Ok(val) = env::var("HEROKU_APP_NAME") {
            self.public_url = Some(format!("https://{}.herokuapp.com", val));
        }

        for var in &[
            "REDISTOGO_URL",
            "REDISGREEN_URL",
            "REDISCLOUD_URL",
            "REDIS_URL",
            "OPENREDIS_URL",
        ] {
            if let Ok(val) = env::var(var) {
                self.redis_url = Some(val);
                break;
            }
        }

        let sendgrid_creds = (env::var("SENDGRID_USERNAME"), env::var("SENDGRID_PASSWORD"));
        if let (Ok(smtp_username), Ok(smtp_password)) = sendgrid_creds {
            self.smtp_username = Some(smtp_username);
            self.smtp_password = Some(smtp_password);
            self.smtp_server = Some("smtp.sendgrid.net:587".to_string());
        }

        self
    }

    pub fn update_from_broker_env(&mut self) -> &mut ConfigBuilder {
        let env_config: EnvConfig = envy::prefixed("BROKER_")
            .from_env()
            .expect("could not parse environment variables");

        if let Some(val) = env_config.ip {
            self.listen_ip = val
        }
        if let Some(val) = env_config.port {
            self.listen_port = val;
        }
        if let Some(val) = env_config.public_url {
            self.public_url = Some(val);
        }
        if let Some(val) = env_config.allowed_origins {
            self.allowed_origins = Some(val);
        }

        if let Some(val) = env_config.static_ttl {
            self.static_ttl = val;
        }
        if let Some(val) = env_config.discovery_ttl {
            self.discovery_ttl = val;
        }
        if let Some(val) = env_config.keys_ttl {
            self.keys_ttl = val;
        }

        if let Some(val) = env_config.token_ttl {
            self.token_ttl = val;
        }
        if let Some(val) = env_config.keyfiles {
            self.keyfiles = val;
        }
        if let Some(val) = env_config.keytext {
            self.keytext = Some(val);
        }

        if let Some(val) = env_config.redis_url {
            self.redis_url = Some(val);
        }
        if let Some(val) = env_config.session_ttl {
            self.redis_session_ttl = val;
        }
        if let Some(val) = env_config.cache_ttl {
            self.redis_cache_ttl = val;
        }

        if let Some(val) = env_config.from_name {
            self.from_name = val;
        }
        if let Some(val) = env_config.from_address {
            self.from_address = Some(val);
        }
        if let Some(val) = env_config.smtp_server {
            self.smtp_server = Some(val);
        }
        if let Some(val) = env_config.smtp_username {
            self.smtp_username = Some(val);
        }
        if let Some(val) = env_config.smtp_password {
            self.smtp_password = Some(val);
        }

        if let Some(val) = env_config.limit_per_email {
            self.limit_per_email = val;
        }

        if let Some(client_id) = env_config.google_client_id {
            self.google = Some(GoogleConfig { client_id });
        }

        self
    }

    pub async fn done(self) -> Result<Config, ConfigError> {
        // Additional validations
        if self.smtp_username.is_none() != self.smtp_password.is_none() {
            return Err(ConfigError::Custom(
                "only one of smtp username and password specified; provide both or neither"
                    .to_owned(),
            ));
        }

        // Create the secure random number generate.
        // Per SystemRandom docs, call `fill` once here to prepare the generator.
        let rng = SystemRandom::new();
        let mut dummy = [0u8; 16];
        rng.fill(&mut dummy)
            .expect("secure random number generator failed to initialize");

        // Child structs
        let mut keys: Vec<crypto::NamedKeyPair> = self
            .keyfiles
            .iter()
            .filter_map(|path| match crypto::NamedKeyPair::from_pem_file(path) {
                Ok(keys) => {
                    if keys.is_empty() {
                        warn!("No key pairs found in: {}", path);
                        None
                    } else {
                        Some(keys)
                    }
                }
                Err(_) => {
                    warn!("Could not parse key pair in: {}", path);
                    None
                }
            })
            .flatten()
            .collect();

        if let Some(keytext) = self.keytext {
            if let Ok(mut env_keys) = crypto::NamedKeyPair::from_pem(&mut keytext.as_bytes()) {
                if env_keys.is_empty() {
                    warn!("No key pairs found in environment");
                } else {
                    keys.append(&mut env_keys);
                }
            } else {
                warn!("Could not parse key pair from environment");
            }
        }

        // We prefer EdDSA, but list it last, in case a client treats the order as preference.
        let mut signing_algs = vec![];
        if crypto::find_key_pair(&keys, SigningAlgorithm::Rs256).is_ok() {
            signing_algs.push(SigningAlgorithm::Rs256);
        }
        if crypto::find_key_pair(&keys, SigningAlgorithm::EdDsa).is_ok() {
            signing_algs.push(SigningAlgorithm::EdDsa);
        }

        let store = store::Store::new(
            self.redis_url.expect("no redis url configured"),
            self.redis_session_ttl as usize,
            self.redis_cache_ttl as usize,
        )
        .await
        .expect("unable to instantiate new redis store");

        let http_connector = HttpsConnector::new();
        let http_client = hyper::Client::builder().build(http_connector);

        let idx = self
            .limit_per_email
            .find('/')
            .expect("unable to parse limit.per_email format");
        let (count, unit) = self.limit_per_email.split_at(idx);
        let ratelimit = Ratelimit {
            count: count.parse().expect("unable to parse limit count"),
            duration: match unit {
                "/min" | "/minute" => 60,
                _ => return Err(From::from("unrecognized limit duration")),
            },
        };

        // Configure default domain overrides for hosted Google
        let mut domain_overrides = HashMap::new();
        if self.google.is_some() {
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

        Ok(Config {
            listen_ip: self.listen_ip,
            listen_port: self.listen_port,
            public_url: self.public_url.expect("no public url configured"),
            allowed_origins: self.allowed_origins,
            static_ttl: self.static_ttl,
            discovery_ttl: self.discovery_ttl,
            keys_ttl: self.keys_ttl,
            token_ttl: self.token_ttl,
            keys,
            signing_algs,
            store,
            http_client,
            from_name: self.from_name,
            from_address: self.from_address.expect("no smtp from address configured"),
            smtp_server: self
                .smtp_server
                .expect("no smtp outserver address configured"),
            smtp_username: self.smtp_username,
            smtp_password: self.smtp_password,
            limit_per_email: ratelimit,
            domain_overrides,
            google: self.google,
            templates: Templates::default(),
            i18n: I18n::default(),
            rng,
        })
    }
}

/// Intermediate structure for deserializing TOML files
#[derive(Clone, Debug, Deserialize)]
struct TomlConfig {
    server: Option<TomlServerTable>,
    headers: Option<TomlHeadersTable>,
    crypto: Option<TomlCryptoTable>,
    redis: Option<TomlRedisTable>,
    smtp: Option<TomlSmtpTable>,
    limit: Option<TomlLimitTable>,
    domain_overrides: Option<HashMap<String, Vec<LinkDef>>>,
    google: Option<TomlGoogleTable>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlServerTable {
    listen_ip: Option<String>,
    listen_port: Option<u16>,
    public_url: Option<String>,
    allowed_origins: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlHeadersTable {
    static_ttl: Option<u32>,
    discovery_ttl: Option<u64>,
    keys_ttl: Option<u64>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlCryptoTable {
    token_ttl: Option<u16>,
    keyfiles: Option<Vec<String>>,
    keytext: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlRedisTable {
    url: Option<String>,
    session_ttl: Option<u16>,
    cache_ttl: Option<u16>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlSmtpTable {
    from_name: Option<String>,
    from_address: Option<String>,
    server: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlLimitTable {
    per_email: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct TomlGoogleTable {
    client_id: String,
}

/// Intermediate structure for deserializing environment variables
///
/// Environment variable `BROKER_FOO_BAR` deserializes in to struct member `foo_bar`. These vars
/// have high precendence and must be prefixed to avoid collisions.
#[derive(Clone, Debug, Deserialize)]
struct EnvConfig {
    ip: Option<String>,
    port: Option<u16>,
    public_url: Option<String>,
    allowed_origins: Option<Vec<String>>,
    static_ttl: Option<u32>,
    discovery_ttl: Option<u64>,
    keys_ttl: Option<u64>,
    token_ttl: Option<u16>,
    keyfiles: Option<Vec<String>>,
    keytext: Option<String>,
    redis_url: Option<String>,
    session_ttl: Option<u16>,
    cache_ttl: Option<u16>,
    from_name: Option<String>,
    from_address: Option<String>,
    smtp_server: Option<String>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    limit_per_email: Option<String>,
    google_client_id: Option<String>,
}
