// Included by src/config.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


/// Contains the SMTP server connection settings.
#[derive(Deserialize)]
pub struct Smtp {
    pub address: String,
    pub username: Option<String>,
    pub password: Option<String>,
}


/// Represents an email address.
#[derive(Deserialize)]
pub struct Email {
    pub address: String,
    pub name: String,
}


/// Represents an OpenID Connect provider.
#[derive(Deserialize)]
pub struct Provider {
    pub discovery: String,
    pub client_id: String,
    pub secret: String,
    pub issuer: String,
}


/// Holds runtime configuration data for this daemon instance.
#[derive(Deserialize)]
pub struct AppConfig {
    /// Address to listen on
    pub listen_ip: String,
    /// Port to listen on
    pub listen_port: u16,
    /// Origin of this instance, used for constructing URLs
    pub base_url: String,
    /// Signing keys
    pub keys: Vec<crypto::NamedKey>,
    /// Redis Client
    pub store: store::Store,
    /// SMTP client
    pub smtp: Smtp,
    /// From address for email
    pub sender: Email,
    /// JWT validity duration, in seconds
    pub token_validity: usize,
    /// Mapping of Domain -> OIDC Provider
    pub providers: HashMap<String, Provider>,
    /// Template files
    #[serde(skip_deserializing)]
    pub templates: Templates,
}
