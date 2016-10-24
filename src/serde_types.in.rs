// Included by src/config.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


/// Intermediate structure for deserializing TOML files
#[derive(Clone,Debug,Deserialize)]
struct TomlConfig {
    server: Option<TomlServerTable>,
    crypto: Option<TomlCryptoTable>,
    redis: Option<TomlRedisTable>,
    smtp: Option<TomlSmtpTable>,
    providers: Option<HashMap<String, TomlProviderTable>>,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlServerTable {
    listen_ip: Option<String>,
    listen_port: Option<u16>,
    public_url: Option<String>,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlCryptoTable {
    token_ttl: Option<u16>,
    keyfiles: Option<Vec<String>>,
}

#[derive(Clone,Debug,Deserialize)]
struct TomlRedisTable {
    url: Option<String>,
    session_ttl: Option<u16>,
    cache_ttl: Option<u16>,
    cache_max_doc_size: Option<u16>,
}

#[derive(Clone,Debug,Deserialize)]
struct TomlSmtpTable {
    from_name: Option<String>,
    from_address: Option<String>,
    server: Option<String>,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlProviderTable {
    client_id: Option<String>,
    secret: Option<String>,
    discovery_url: Option<String>,
    issuer_domain: Option<String>,
}

/// Intermediate structure for deserializing environment variables
#[derive(Clone,Debug,Deserialize)]
struct EnvConfig {
    broker_ip: Option<String>,
    broker_port: Option<u16>,
    broker_public_url: Option<String>,
    broker_token_ttl: Option<u16>,
    broker_keyfiles: Option<Vec<String>>,
    broker_redis_url: Option<String>,
    broker_session_ttl: Option<u16>,
    broker_cache_ttl: Option<u16>,
    broker_cache_max_doc_size: Option<u16>,
    broker_from_name: Option<String>,
    broker_from_address: Option<String>,
    broker_smtp_server: Option<String>,
    broker_gmail_client: Option<String>,
    broker_gmail_secret: Option<String>,
    broker_gmail_discovery: Option<String>,
    broker_gmail_issuer: Option<String>,
}

impl EnvConfig {
    // TODO: Just use https://crates.io/crates/envy once it supports Serde 0.8
    pub fn from_env() -> EnvConfig {
        EnvConfig {
            broker_ip: env::var("BROKER_IP").ok(),

            broker_port: env::var("BROKER_PORT")
                .ok().and_then(|x| x.parse().ok()),

            broker_public_url: env::var("BROKER_PUBLIC_URL").ok(),

            broker_token_ttl: env::var("BROKER_TOKEN_TTL")
                .ok().and_then(|x| x.parse().ok()),

            broker_keyfiles: env::var("BROKER_KEYFILES")
                .ok().map(|x| x.split(',').map(|x| x.to_string()).collect()),

            broker_redis_url: env::var("BROKER_REDIS_URL").ok(),

            broker_session_ttl: env::var("BROKER_SESSION_TTL")
                .ok().and_then(|x| x.parse().ok()),

            broker_cache_ttl: env::var("BROKER_CACHE_TTL")
                .ok().and_then(|x| x.parse().ok()),

            broker_cache_max_doc_size: env::var("BROKER_CACHE_MAX_DOC_SIZE")
                .ok().and_then(|x| x.parse().ok()),

            broker_from_name: env::var("BROKER_FROM_NAME").ok(),

            broker_from_address: env::var("BROKER_FROM_ADDRESS").ok(),

            broker_smtp_server: env::var("BROKER_SMTP_SERVER").ok(),

            broker_gmail_client: env::var("BROKER_GMAIL_CLIENT").ok(),

            broker_gmail_secret: env::var("BROKER_GMAIL_SECRET").ok(),

            broker_gmail_discovery: env::var("BROKER_GMAIL_DISCOVERY").ok(),

            broker_gmail_issuer: env::var("BROKER_GMAIL_ISSUER").ok(),
        }
    }
}
