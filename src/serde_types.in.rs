// Included by src/config.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


// Newtype so we can implement Deserialize for templates.
#[derive(Clone)]
pub struct Template(mustache::Template);


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


// Contains all templates we use in compiled form.
#[derive(Clone)]
pub struct Templates {
    /// Page displayed when the confirmation email was sent.
    pub confirm_email: Template,
    /// HTML formatted email containing the one-type pad.
    pub email_html: Template,
    /// Plain text email containing the one-type pad.
    pub email_text: Template,
    /// The error page template.
    pub error: Template,
    /// A dummy form used to redirect back to the RP with a POST request.
    pub forward: Template,
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
    /// Template files
    #[serde(skip_deserializing)]
    pub templates: Templates,
}
