use super::{ConfigBuilder, LimitConfig};
use crate::crypto::SigningAlgorithm;
use crate::webfinger::Link;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Intermediate structure for deserializing TOML files
#[derive(Deserialize)]
pub struct TomlConfig {
    listen_ip: Option<String>,
    listen_port: Option<u16>,
    public_url: Option<String>,
    allowed_origins: Option<Vec<String>>,
    data_dir: Option<String>,

    static_ttl: Option<u64>,
    discovery_ttl: Option<u64>,
    keys_ttl: Option<u64>,
    token_ttl: Option<u64>,
    session_ttl: Option<u64>,
    cache_ttl: Option<u64>,

    keyfiles: Option<Vec<PathBuf>>,
    keytext: Option<String>,
    signing_algs: Option<Vec<SigningAlgorithm>>,
    generate_rsa_command: Option<Vec<String>>,

    redis_url: Option<String>,
    sqlite_db: Option<PathBuf>,
    memory_storage: Option<bool>,

    from_name: Option<String>,
    from_address: Option<String>,

    smtp_server: Option<String>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,

    sendmail_command: Option<String>,

    limit_per_email: Option<LimitConfig>,

    google_client_id: Option<String>,
    domain_overrides: Option<HashMap<String, Vec<Link>>>,

    // Deprecated.
    server: Option<TomlServerTable>,
    headers: Option<TomlHeadersTable>,
    crypto: Option<TomlCryptoTable>,
    redis: Option<TomlRedisTable>,
    smtp: Option<TomlSmtpTable>,
    limit: Option<TomlLimitTable>,
    google: Option<TomlGoogleTable>,
}

#[derive(Deserialize)]
struct TomlServerTable {
    listen_ip: Option<String>,
    listen_port: Option<u16>,
    public_url: Option<String>,
    allowed_origins: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TomlHeadersTable {
    static_ttl: Option<u64>,
    discovery_ttl: Option<u64>,
    keys_ttl: Option<u64>,
}

#[derive(Deserialize)]
struct TomlCryptoTable {
    token_ttl: Option<u64>,
    keyfiles: Option<Vec<PathBuf>>,
    keytext: Option<String>,
}

#[derive(Deserialize)]
struct TomlRedisTable {
    url: Option<String>,
    session_ttl: Option<u64>,
    cache_ttl: Option<u64>,
}

#[derive(Deserialize)]
struct TomlSmtpTable {
    from_name: Option<String>,
    from_address: Option<String>,
    server: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct TomlLimitTable {
    per_email: Option<LimitConfig>,
}

#[derive(Deserialize)]
struct TomlGoogleTable {
    client_id: Option<String>,
}

impl TomlConfig {
    pub fn parse_and_apply(path: &Path, builder: &mut ConfigBuilder) {
        let parsed = Self::parse(path);
        Self::apply(parsed, builder);
    }

    fn warn_table(table: &str) {
        log::warn!(
            "TOML '{}' section is deprecated. See {} on how to update your config.",
            table,
            "https://github.com/portier/portier-broker/releases/tag/v0.3.0"
        );
    }

    #[allow(clippy::cognitive_complexity)]
    fn parse(path: &Path) -> TomlConfig {
        let data = fs::read(path).expect("Could not read config file");
        let mut parsed: TomlConfig =
            toml::from_slice(&data).expect("Could not parse TOML in config file");

        if let Some(ref table) = parsed.server {
            Self::warn_table("server");
            if parsed.listen_ip.is_none() {
                parsed.listen_ip = table.listen_ip.clone();
            }
            if parsed.listen_port.is_none() {
                parsed.listen_port = table.listen_port;
            }
            if parsed.public_url.is_none() {
                parsed.public_url = table.public_url.clone();
            }
            if parsed.allowed_origins.is_none() {
                parsed.allowed_origins = table.allowed_origins.clone();
            }
        }

        if let Some(ref table) = parsed.headers {
            Self::warn_table("headers");
            if parsed.static_ttl.is_none() {
                parsed.static_ttl = table.static_ttl;
            }
            if parsed.discovery_ttl.is_none() {
                parsed.discovery_ttl = table.discovery_ttl;
            }
            if parsed.keys_ttl.is_none() {
                parsed.keys_ttl = table.keys_ttl;
            }
        }

        if let Some(ref table) = parsed.crypto {
            Self::warn_table("crypto");
            if parsed.token_ttl.is_none() {
                parsed.token_ttl = table.token_ttl;
            }
            if parsed.keyfiles.is_none() {
                parsed.keyfiles = table.keyfiles.clone();
            }
            if parsed.keytext.is_none() {
                parsed.keytext = table.keytext.clone();
            }
        }

        if let Some(ref table) = parsed.redis {
            Self::warn_table("redis");
            if parsed.redis_url.is_none() {
                parsed.redis_url = table.url.clone();
            }
            if parsed.session_ttl.is_none() {
                parsed.session_ttl = table.session_ttl;
            }
            if parsed.cache_ttl.is_none() {
                parsed.cache_ttl = table.cache_ttl;
            }
        }

        if let Some(ref table) = parsed.smtp {
            Self::warn_table("smtp");
            if parsed.from_name.is_none() {
                parsed.from_name = table.from_name.clone();
            }
            if parsed.from_address.is_none() {
                parsed.from_address = table.from_address.clone();
            }
            if parsed.smtp_server.is_none() {
                parsed.smtp_server = table.server.clone();
            }
            if parsed.smtp_username.is_none() {
                parsed.smtp_username = table.username.clone();
            }
            if parsed.smtp_password.is_none() {
                parsed.smtp_password = table.password.clone();
            }
        }

        if let Some(ref table) = parsed.limit {
            Self::warn_table("limit");
            if parsed.limit_per_email.is_none() {
                parsed.limit_per_email = table.per_email;
            }
        }

        if let Some(ref table) = parsed.google {
            Self::warn_table("google");
            if parsed.google_client_id.is_none() {
                parsed.google_client_id = table.client_id.clone();
            }
        }

        parsed
    }

    #[allow(clippy::cognitive_complexity)]
    fn apply(parsed: TomlConfig, builder: &mut ConfigBuilder) {
        if let Some(val) = parsed.listen_ip {
            builder.listen_ip = val;
        }
        if let Some(val) = parsed.listen_port {
            builder.listen_port = val;
        }
        if let Some(val) = parsed.public_url {
            builder.public_url = Some(val);
        }
        if let Some(val) = parsed.allowed_origins {
            builder.allowed_origins = Some(val)
        };
        if let Some(val) = parsed.data_dir {
            builder.data_dir = val;
        }

        if let Some(val) = parsed.static_ttl {
            builder.static_ttl = Duration::from_secs(val);
        }
        if let Some(val) = parsed.discovery_ttl {
            builder.discovery_ttl = Duration::from_secs(val);
        }
        if let Some(val) = parsed.keys_ttl {
            builder.keys_ttl = Duration::from_secs(val);
        }
        if let Some(val) = parsed.token_ttl {
            builder.token_ttl = Duration::from_secs(val);
        }
        if let Some(val) = parsed.session_ttl {
            builder.session_ttl = Duration::from_secs(val);
        }
        if let Some(val) = parsed.cache_ttl {
            builder.cache_ttl = Duration::from_secs(val);
        }

        if let Some(mut val) = parsed.keyfiles {
            builder.keyfiles.append(&mut val);
        }
        if let Some(val) = parsed.keytext {
            builder.keytext = Some(val);
        }
        if let Some(val) = parsed.signing_algs {
            builder.signing_algs = val;
        }
        if let Some(val) = parsed.generate_rsa_command {
            builder.generate_rsa_command = val;
        }

        if let Some(val) = parsed.redis_url {
            builder.redis_url = Some(val);
        }
        if let Some(val) = parsed.sqlite_db {
            builder.sqlite_db = Some(val);
        }
        if let Some(val) = parsed.memory_storage {
            builder.memory_storage = val;
        }

        if let Some(val) = parsed.from_name {
            builder.from_name = val;
        }
        if let Some(val) = parsed.from_address {
            builder.from_address = Some(val);
        }

        if let Some(val) = parsed.smtp_server {
            builder.smtp_server = Some(val);
        }
        if let Some(val) = parsed.smtp_username {
            builder.smtp_username = Some(val);
        }
        if let Some(val) = parsed.smtp_password {
            builder.smtp_password = Some(val);
        }

        if let Some(val) = parsed.sendmail_command {
            builder.sendmail_command = Some(val);
        }

        if let Some(val) = parsed.limit_per_email {
            builder.limit_per_email = val;
        }

        if let Some(val) = parsed.google_client_id {
            builder.google_client_id = Some(val);
        }
        if let Some(val) = parsed.domain_overrides {
            for (domain, links) in val {
                builder.domain_overrides.insert(domain, links);
            }
        }
    }
}
