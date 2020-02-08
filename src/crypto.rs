use crate::bridges::oidc::ProviderKey;
use crate::config::Config;
use crate::email_address::EmailAddress;
use crate::keys::SignError;
use crate::utils::base64url;
use ring::{
    digest,
    error::Unspecified,
    rand::SecureRandom,
    signature::{self, UnparsedPublicKey},
};
use serde_json as json;
use serde_json::json;
use std::fmt;
use std::iter::Iterator;
use std::time::{SystemTime, UNIX_EPOCH};

type RsaPublicKey = signature::RsaPublicKeyComponents<Vec<u8>>;

/// Token signing algorithms we support.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SigningAlgorithm {
    EdDsa,
    Rs256,
}

impl SigningAlgorithm {
    /// Get the JWA string representation.
    pub fn as_str(self) -> &'static str {
        use SigningAlgorithm::*;
        match self {
            EdDsa => "EdDSA",
            Rs256 => "RS256",
        }
    }

    /// Format a list of algorithms for display.
    pub fn format_list(list: &[Self]) -> String {
        list.iter()
            .map(|alg| alg.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for SigningAlgorithm {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<SigningAlgorithm, &'static str> {
        use SigningAlgorithm::*;
        match s {
            "EdDSA" => Ok(EdDsa),
            "RS256" => Ok(Rs256),
            _ => Err("unsupported value"),
        }
    }
}

serde_string!(SigningAlgorithm);

/// The types of public keys we support.
pub enum SupportedPublicKey {
    Ed25519(UnparsedPublicKey<Vec<u8>>),
    Rsa(RsaPublicKey),
}

impl SupportedPublicKey {
    /// Verify a message signature.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Unspecified> {
        use SupportedPublicKey::*;
        match self {
            Ed25519(ref inner) => inner.verify(message, signature),
            Rsa(ref inner) => {
                inner.verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
            }
        }
    }
}

/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
pub fn session_id(email: &EmailAddress, client_id: &str, rng: &dyn SecureRandom) -> String {
    let mut rand_bytes = [0u8; 16];
    rng.fill(&mut rand_bytes)
        .expect("secure random number generator failed");

    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(email.as_str().as_bytes());
    ctx.update(client_id.as_bytes());
    ctx.update(&rand_bytes);
    base64url::encode(&ctx.finish())
}

/// Helper function to create a secure nonce.
pub fn nonce(rng: &dyn SecureRandom) -> String {
    let mut rand_bytes = [0u8; 16];
    rng.fill(&mut rand_bytes)
        .expect("secure random number generator failed");

    base64url::encode(&rand_bytes)
}

/// Helper function to create a random string consisting of
/// characters from the z-base-32 set.
pub fn random_zbase32(len: usize, rng: &dyn SecureRandom) -> String {
    const CHARSET: &[u8] = b"13456789abcdefghijkmnopqrstuwxyz";

    let mut rand_bytes = vec![0u8; len];
    rng.fill(&mut rand_bytes)
        .expect("secure random number generator failed");

    String::from_utf8(
        rand_bytes
            .into_iter()
            .map(|v| CHARSET[v as usize % CHARSET.len()])
            .collect(),
    )
    .expect("failed to build one-time pad")
}

/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(key_set: &[ProviderKey], kid: &str) -> Result<SupportedPublicKey, ()> {
    let matching: Vec<&ProviderKey> = key_set
        .iter()
        .filter(|key| key.use_ == "sig" && key.kid == kid)
        .collect();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }
    let key = matching.first().expect("expected one key");

    // Then, use the data to build a public key object for verification.
    match (key.alg.as_str(), key.crv.as_str()) {
        ("EdDSA", "Ed25519") => {
            let x = base64url::decode(&key.x).map_err(|_| ())?;
            let key = UnparsedPublicKey::new(&signature::ED25519, x);
            Ok(SupportedPublicKey::Ed25519(key))
        }
        ("RS256", _) => {
            let n = base64url::decode(&key.n).map_err(|_| ())?;
            let e = base64url::decode(&key.e).map_err(|_| ())?;
            let key = RsaPublicKey { n, e };
            Ok(SupportedPublicKey::Rsa(key))
        }
        _ => Err(()),
    }
}

/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(
    jws: &str,
    key_set: &[ProviderKey],
    signing_alg: SigningAlgorithm,
) -> Result<json::Value, ()> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let decoded = parts
        .iter()
        .map(|s| base64url::decode(s))
        .collect::<Result<Vec<_>, _>>()?;
    let jwt_header: json::Value = json::from_slice(&decoded[0]).map_err(|_| ())?;
    let kid = jwt_header.get("kid").and_then(|v| v.as_str()).ok_or(())?;
    let pub_key = jwk_key_set_find(key_set, kid)?;

    // Make sure the key matches the algorithm originally selected.
    match (signing_alg, &pub_key) {
        (SigningAlgorithm::EdDsa, &SupportedPublicKey::Ed25519(_))
        | (SigningAlgorithm::Rs256, &SupportedPublicKey::Rsa(_)) => {}
        _ => return Err(()),
    }

    // Verify the identity token's signature.
    let message_len = parts[0].len() + parts[1].len() + 1;
    pub_key
        .verify(jws[..message_len].as_bytes(), &decoded[2])
        .map_err(|_| ())?;

    // Return the payload.
    Ok(json::from_slice(&decoded[1]).map_err(|_| ())?)
}

/// Helper method to create a JWT for a given email address and audience.
///
/// Builds the JSON payload, then signs it using the last key provided in
/// the configuration object.
pub fn create_jwt(
    app: &Config,
    email: &str,
    email_addr: &EmailAddress,
    aud: &str,
    nonce: &str,
    signing_alg: SigningAlgorithm,
) -> Result<String, SignError> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    let payload = json!({
        "aud": aud,
        "email": email_addr.as_str(),
        "email_verified": true,
        "email_original": email,
        "exp": (now + app.token_ttl).as_secs(),
        "iat": now.as_secs(),
        "iss": &app.public_url,
        "sub": email_addr.as_str(),
        "nonce": nonce,
    });
    app.key_manager.sign_jws(&payload, signing_alg, &app.rng)
}
