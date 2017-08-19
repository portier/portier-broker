pub mod email;
pub mod oidc;


use email_address::EmailAddress;
use http::{ContextHandle, HandlerResult};
use std::fmt::{Display, Formatter, Error as FmtError};
use std::rc::Rc;
use std::str::FromStr;


/// The Portier scheme used to identify a regular Portier identity provider.
pub const PORTIER_IDP_SCHEME: &'static str = "https";
/// The Portier endpoint for the Google provider.
pub const GOOGLE_IDP_ENDPOINT: &'static str = "https+io.portier.idp.google://accounts.google.com";
/// The origin of the Google identity provider.
pub const GOOGLE_IDP_ORIGIN: &'static str = "https://accounts.google.com";

/// Testing scheme for a Portier provider without TLS.
#[cfg(feature = "insecure")]
pub const PORTIER_INSECURE_IDP_SCHEME: &'static str = "http";


/// Simple enum for the kind of provider.
///
/// Used for the `provider_kind` session field in the OpenID Connect bridge.
pub enum ProviderKind {
    Portier,
    Google,
}

impl ProviderKind {
    /// Return a string identifier for this provider kind.
    pub fn as_str(&self) -> &'static str {
        match *self {
            ProviderKind::Portier => "portier",
            ProviderKind::Google => "google",
        }
    }
}

impl FromStr for ProviderKind {
    type Err = ();

    /// Parse a string identifier back into a `ProviderKind`.
    fn from_str(s: &str) -> Result<ProviderKind, ()> {
        match s {
            "portier" => Ok(ProviderKind::Portier),
            "google" => Ok(ProviderKind::Google),
            _ => Err(()),
        }
    }
}


/// Internal structure to represent a provider.
pub enum Provider {
    Portier {
        origin: String,
    },
    Google {
        client_id: String,
    },
}

impl Provider {
    /// Send a request for the given provider to the correct function.
    pub fn delegate_request(ctx_handle: &ContextHandle, email_addr: &Rc<EmailAddress>, provider: &Rc<Provider>) -> HandlerResult {
        match **provider {
            Provider::Portier { .. } | Provider::Google { .. } => {
                Box::new(oidc::request(ctx_handle, email_addr, provider))
            },
        }
    }

    /// Get a `ProviderKind` for this provider.
    pub fn kind(&self) -> ProviderKind {
        match *self {
            Provider::Portier { .. } => ProviderKind::Portier,
            Provider::Google { .. } => ProviderKind::Google,
        }
    }
}

impl Display for Provider {
    fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
        match *self {
            Provider::Portier { ref origin } => f.write_str(origin),
            Provider::Google { .. } => f.write_str(GOOGLE_IDP_ENDPOINT),
        }
    }
}
