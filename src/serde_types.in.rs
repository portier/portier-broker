// Included by src/config.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


#[derive(Clone,Debug,Deserialize)]
struct TomlConfig {
    server: TomlServerTable,
    crypto: TomlCryptoTable,
    redis: TomlRedisTable,
    smtp: TomlSmtpTable,
    providers: HashMap<String, TomlProviderTable>,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlServerTable {
    listen_ip: String,
    listen_port: u16,
    public_url: String,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlCryptoTable {
    token_ttl: u16,
    keyfiles: Vec<String>,
}

#[derive(Clone,Debug,Deserialize)]
struct TomlRedisTable {
    url: String,
    session_ttl: u16,
    cache_ttl: u16,
    cache_max_doc_size: u16,
}

#[derive(Clone,Debug,Deserialize)]
struct TomlSmtpTable {
    from_name: String,
    from_address: String,
    server: String,
}


#[derive(Clone,Debug,Deserialize)]
struct TomlProviderTable {
    client_id: String,
    secret: String,
    discovery_url: String,
    issuer_domain: String,
}
