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
    username: Option<String>,
    password: Option<String>,
}

#[derive(Clone,Debug,Deserialize)]
struct TomlProviderTable {
    client_id: Option<String>,
    secret: Option<String>,
    discovery_url: Option<String>,
    issuer_domain: Option<String>,
}


/// Intermediate structure for deserializing environment variables
///
/// Environment variable `FOO_BAR` deserializes in to struct member `foo_bar`.
/// These vars have high precendence and must be prefixed to avoid collisions.
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
    broker_smtp_username: Option<String>,
    broker_smtp_password: Option<String>,
    broker_gmail_client: Option<String>,
    broker_gmail_secret: Option<String>,
    broker_gmail_discovery: Option<String>,
    broker_gmail_issuer: Option<String>,
}
