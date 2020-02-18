use super::{ConfigBuilder, LimitConfig};
use crate::crypto::SigningAlgorithm;
use serde_derive::Deserialize;
use std::time::Duration;

/// Intermediate structure for deserializing environment variables
///
/// Environment variable `BROKER_FOO_BAR` deserializes in to struct member `foo_bar`. These vars
/// have high precendence and must be prefixed to avoid collisions.
#[derive(Deserialize)]
pub struct EnvConfig {
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

    keyfiles: Option<Vec<String>>,
    keytext: Option<String>,
    signing_algs: Option<Vec<SigningAlgorithm>>,
    generate_rsa_command: Option<String>,

    redis_url: Option<String>,
    sqlite_db: Option<String>,
    memory_storage: Option<bool>,

    from_name: Option<String>,
    from_address: Option<String>,
    smtp_server: Option<String>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,

    limit_per_email: Option<LimitConfig>,

    google_client_id: Option<String>,

    // Deprecated
    ip: Option<String>,
    port: Option<u16>,
}

impl EnvConfig {
    pub fn parse_and_apply(builder: &mut ConfigBuilder) {
        let parsed = Self::parse();
        Self::apply(parsed, builder);
    }

    fn parse() -> EnvConfig {
        let mut parsed: EnvConfig = envy::prefixed("BROKER_")
            .from_env()
            .expect("Could not parse environment variables");

        if let Some(ref ip) = parsed.ip {
            log::warn!("BROKER_IP is deprecated. Please use BROKER_LISTEN_IP instead.");
            if parsed.listen_ip.is_none() {
                parsed.listen_ip = Some(ip.clone());
            }
        }

        if let Some(port) = parsed.port {
            log::warn!("BROKER_PORT is deprecated. Please use BROKER_LISTEN_PORT instead.");
            if parsed.listen_port.is_none() {
                parsed.listen_port = Some(port);
            }
        }

        parsed
    }

    #[allow(clippy::cognitive_complexity)]
    fn apply(parsed: EnvConfig, builder: &mut ConfigBuilder) {
        if let Some(val) = parsed.listen_ip {
            builder.listen_ip = val
        }
        if let Some(val) = parsed.listen_port {
            builder.listen_port = val;
        }
        if let Some(val) = parsed.public_url {
            builder.public_url = Some(val);
        }
        if let Some(val) = parsed.allowed_origins {
            builder.allowed_origins = Some(val);
        }
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

        if let Some(val) = parsed.keyfiles {
            builder.keyfiles = val;
        }
        if let Some(val) = parsed.keytext {
            builder.keytext = Some(val);
        }
        if let Some(val) = parsed.signing_algs {
            builder.signing_algs = val;
        }
        if let Some(val) = parsed.generate_rsa_command {
            builder.generate_rsa_command =
                val.split_whitespace().map(|arg| arg.to_owned()).collect();
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

        if let Some(val) = parsed.limit_per_email {
            builder.limit_per_email = val;
        }

        if let Some(val) = parsed.google_client_id {
            builder.google_client_id = Some(val);
        }
    }
}
