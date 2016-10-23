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
