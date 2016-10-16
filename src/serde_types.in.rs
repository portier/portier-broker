// Included by src/config.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


/// Represents an email address.
#[derive(Clone, Deserialize)]
pub struct Smtp {
    pub address: String
}


/// Represents an email address.
#[derive(Clone, Deserialize)]
pub struct Email {
    pub address: String,
    pub name: String,
}


/// Represents an OpenID Connect provider.
#[derive(Clone, Deserialize)]
pub struct Provider {
    pub discovery: String,
    pub client_id: String,
    pub secret: String,
    pub issuer: String,
}


/// Holds runtime configuration data for this daemon instance.
#[derive(Clone, Deserialize)]
pub struct AppConfig {
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
}
