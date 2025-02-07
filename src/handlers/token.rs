use serde_json::json;

use crate::{
    agents::ConsumeAuthCode,
    crypto::create_jwt,
    error::BrokerError,
    validation::parse_redirect_uri,
    web::{json_response, Context, HandlerResult},
};

pub async fn token(ctx: &mut Context) -> HandlerResult {
    // Per OAuth2, an Accept header is not necessary, but this is a server-to-server request that
    // should always return a JSON response.
    ctx.get_mut_req().want_json = true;

    let mut params = ctx.form_params();

    if try_get_provider_param!(params, "grant_type") != "authorization_code" {
        return Err(BrokerError::ProviderInput(
            "invalid grant_type, must be authorization_code".to_owned(),
        ));
    }

    let code = try_get_provider_param!(params, "code");
    let redirect_uri = try_get_provider_param!(params, "redirect_uri");

    // Even though we compare to the original below, parse again, because the client may use a
    // serialization different from us.
    let redirect_uri = parse_redirect_uri(&redirect_uri, "redirect_uri")
        .map_err(|e| BrokerError::ProviderInput(format!("{e}")))?;

    let data = ctx
        .app
        .store
        .send(ConsumeAuthCode { code })
        .await
        .map_err(|e| {
            BrokerError::Internal(format!("could not lookup the authorization code: {e}"))
        })?
        .ok_or_else(|| BrokerError::SpecificInput {
            error: "invalid_grant".to_owned(),
            error_description: "invalid authorization code".to_owned(),
        })?;

    if data.return_params.redirect_uri != redirect_uri {
        return Err(BrokerError::ProviderInput(
            "redirect_uri does not match the original from the authorization request".to_owned(),
        ));
    }

    let jwt = create_jwt(
        &ctx.app,
        &data.email,
        &data.email_addr,
        &redirect_uri.origin().ascii_serialization(),
        data.nonce.as_deref(),
        data.signing_alg,
    )
    .await
    .map_err(|err| BrokerError::Internal(format!("Could not create a JWT: {err:?}")))?;

    Ok(json_response(&json!({
        "access_token": "UNUSED",
        "token_type": "bearer",
        "id_token": &jwt,
    })))
}
