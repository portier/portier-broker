use iron::middleware::Handler;
use iron::prelude::{IronResult, Request, Response};
use serde_json::builder::ObjectBuilder;
use AppConfig;
use super::json_response;

/// Iron handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `base_url` configuration value.
pub struct OIDCConfig { pub app: AppConfig }
impl Handler for OIDCConfig {
    fn handle(&self, _: &mut Request) -> IronResult<Response> {
        json_response(&ObjectBuilder::new()
            .insert("issuer", &self.app.base_url)
            .insert("authorization_endpoint",
                    format!("{}/auth", self.app.base_url))
            .insert("jwks_uri", format!("{}/keys.json", self.app.base_url))
            .insert("scopes_supported", vec!["openid", "email"])
            .insert("claims_supported",
                    vec!["aud", "email", "email_verified", "exp", "iat", "iss", "sub"])
            .insert("response_types_supported", vec!["id_token"])
            .insert("response_modes_supported", vec!["form_post"])
            .insert("grant_types_supported", vec!["implicit"])
            .insert("subject_types_supported", vec!["public"])
            .insert("id_token_signing_alg_values_supported", vec!["RS256"])
            .unwrap())
    }
}
