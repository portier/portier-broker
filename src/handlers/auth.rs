use crate::bridges;
use crate::email_address::EmailAddress;
use crate::error::BrokerError;
use crate::store_limits::addr_limiter;
use crate::validation::parse_redirect_uri;
use crate::web::{html_response, json_response, Context, HandlerResult, ReturnParams};
use crate::webfinger::{self, Link, Relation};
use futures_util::future::{self, Either};
use http::Method;
use log::info;
use mustache;
use serde_json::{from_value, json, Value};
use std::time::Duration;

/// Request handler to return the OpenID Discovery document.
///
/// Most of this is hard-coded for now, although the URLs are constructed by
/// using the base URL as configured in the `public_url` configuration value.
pub async fn discovery(ctx: &mut Context) -> HandlerResult {
    let obj = json!({
        "issuer": ctx.app.public_url,
        "authorization_endpoint": format!("{}/auth", ctx.app.public_url),
        "jwks_uri": format!("{}/keys.json", ctx.app.public_url),
        "scopes_supported": vec!["openid", "email"],
        "claims_supported": vec!["iss", "aud", "exp", "iat", "email"],
        "response_types_supported": vec!["id_token"],
        "response_modes_supported": vec!["form_post", "fragment"],
        "grant_types_supported": vec!["implicit"],
        "subject_types_supported": vec!["public"],
        "id_token_signing_alg_values_supported": vec!["RS256"],
    });
    Ok(json_response(&obj, ctx.app.discovery_ttl))
}

/// Request handler for the JSON Web Key Set document.
///
/// Respond with the JWK key set containing all of the configured keys.
///
/// Relying Parties will need to fetch this data to be able to verify identity
/// tokens issued by this daemon instance.
pub async fn key_set(ctx: &mut Context) -> HandlerResult {
    let obj = json!({
        "keys": ctx.app.keys.iter()
            .map(|key| key.public_jwk())
            .collect::<Vec<_>>(),
    });
    Ok(json_response(&obj, ctx.app.keys_ttl))
}

/// Request handler for authentication requests from the RP.
///
/// Calls the `oidc::request()` function if the provided email address's
/// domain matches one of the configured famous providers. Otherwise, calls the
/// `email::request()` function to allow authentication through the email loop.
pub async fn auth(ctx: &mut Context) -> HandlerResult {
    let mut params = match ctx.method {
        Method::GET => ctx.query_params(),
        Method::POST => ctx.form_params(),
        _ => unreachable!(),
    };

    let original_params = params.clone();

    let redirect_uri = try_get_input_param!(params, "redirect_uri");
    let client_id = try_get_input_param!(params, "client_id");
    let response_mode = try_get_input_param!(params, "response_mode", "fragment".to_owned());
    let response_errors = try_get_input_param!(params, "response_errors", "true".to_owned());
    let state = try_get_input_param!(params, "state", "".to_owned());

    let redirect_uri = parse_redirect_uri(&redirect_uri, "redirect_uri")
        .map_err(|e| BrokerError::Input(format!("{}", e)))?;

    if client_id != redirect_uri.origin().ascii_serialization() {
        return Err(BrokerError::Input(
            "the client_id must be the origin of the redirect_uri".to_owned(),
        ));
    }

    // Parse response_mode by wrapping it a JSON Value.
    // This has minimal overhead, and saves us a separate implementation.
    let response_mode = from_value(Value::String(response_mode)).map_err(|_| {
        BrokerError::Input("unsupported response_mode, must be fragment or form_post".to_owned())
    })?;

    let response_errors = response_errors
        .parse::<bool>()
        .map_err(|_| BrokerError::Input("response_errors must be true or false".to_owned()))?;

    // Per the OAuth2 spec, we may redirect to the RP once we have validated client_id and
    // redirect_uri. In our case, this means we make redirect_uri available to error handling.
    let redirect_uri_ = redirect_uri.clone();
    ctx.return_params = Some(ReturnParams {
        redirect_uri,
        response_mode,
        response_errors,
        state,
    });

    if let Some(ref whitelist) = ctx.app.allowed_origins {
        if !whitelist.contains(&client_id) {
            return Err(BrokerError::Input(
                "the origin is not whitelisted".to_owned(),
            ));
        }
    }

    let nonce = try_get_input_param!(params, "nonce");
    if try_get_input_param!(params, "response_type") != "id_token" {
        return Err(BrokerError::Input(
            "unsupported response_type, only id_token is supported".to_owned(),
        ));
    }

    let login_hint = try_get_input_param!(params, "login_hint", "".to_string());
    if login_hint == "" {
        let display_origin = redirect_uri_.origin().unicode_serialization();

        let catalog = ctx.catalog();
        let data = mustache::MapBuilder::new()
            // TODO: catalog/localization?
            .insert_str("display_origin", display_origin)
            .insert_str("title", catalog.gettext("Finish logging in to"))
            .insert_str(
                "explanation",
                catalog.gettext("Login with your email address."),
            )
            .insert_str(
                "use",
                catalog.gettext("Please specify the email you wish to use to login with"),
            )
            .insert_vec("params", |mut builder| {
                for param in &original_params {
                    builder = builder.push_map(|builder| {
                        let (name, value) = param;
                        builder.insert_str("name", name).insert_str("value", value)
                    });
                }
                builder
            })
            .build();

        return Ok(html_response(
            ctx.app.templates.login_hint.render_data(&data),
        ));
    }

    // Verify and normalize the email.
    let email_addr = login_hint
        .parse::<EmailAddress>()
        .map_err(|_| BrokerError::Input("login_hint is not a valid email address".to_owned()))?;

    // Enforce ratelimit based on the normalized email.
    if !addr_limiter(
        &ctx.app.store,
        email_addr.as_str(),
        &ctx.app.limit_per_email,
    )? {
        return Err(BrokerError::RateLimited);
    }

    // Create the session with common data, but do not yet save it.
    ctx.start_session(&client_id, &login_hint, &email_addr, &nonce);

    // Discover the authentication endpoints based on the email domain.
    let discovery_future = async {
        let links = webfinger::query(&ctx.app, &email_addr).await?;

        // Try to authenticate with the first provider.
        // TODO: Queue discovery of links and process in order, with individual timeouts.
        match links.first() {
            // Portier and Google providers share an implementation
            Some(
                link @ &Link {
                    rel: Relation::Portier,
                    ..
                },
            )
            | Some(
                link @ &Link {
                    rel: Relation::Google,
                    ..
                },
            ) => bridges::oidc::auth(ctx, &email_addr, link).await,
            _ => Err(BrokerError::ProviderCancelled),
        }
    };

    // Apply a timeout to discovery.
    match future::select(
        tokio::time::delay_for(Duration::from_secs(5)),
        Box::pin(discovery_future),
    )
    .await
    {
        Either::Left((_, _f)) => {
            // Timeout causes fall back to email loop auth.
            info!("discovery timed out for {}", email_addr);

            // TODO: We used to (before async) continue discovery in the background, using shared
            // access to Context through RefCell. We could bring that back by decoupling auth
            // mechanisms from Context.
            //
            // (The original idea was also for auth mechanisms to have a 'commit' action, to
            // indicate a side-effect is about the happen. From this side, it'd effectively abort
            // the timeout and bubble all errors. An intermediate AuthContext could provide this.)
            /*
            tokio::spawn(async {
                if let Err(e) = f.await {
                    e.log();
                }
            });
            */
        }
        Either::Right((Ok(v), _)) => {
            // Discovery succeeded, simply return the response.
            return Ok(v);
        }
        Either::Right((Err(e @ BrokerError::Provider(_)), _))
        | Either::Right((Err(e @ BrokerError::ProviderCancelled), _)) => {
            // Provider errors cause fallback to email loop auth.
            e.log();
        }
        Either::Right((Err(e), _)) => {
            // Other errors during discovery are bubbled.
            return Err(e);
        }
    }

    // Fall back to email loop auth.
    bridges::email::auth(ctx, &email_addr).await
}
