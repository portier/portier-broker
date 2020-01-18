use crate::bridges::oidc::ProviderKey;
use crate::config::Config;
use crate::email_address::EmailAddress;
use ring::{
    digest,
    error::{KeyRejected, Unspecified},
    io::Positive,
    rand::SecureRandom,
    signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair},
};
use serde_derive::{Deserialize, Serialize};
use serde_json as json;
use serde_json::json;
use std::fmt;
use std::fs::File;
use std::io::Error as IoError;
use std::iter::Iterator;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

type RsaPublicKey = signature::RsaPublicKeyComponents<Vec<u8>>;

/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum CryptoError {
    Custom(&'static str),
    Io(IoError),
    KeyRejected(KeyRejected),
    UnsupportedAlgorithm,
    Unspecified,
}

impl From<&'static str> for CryptoError {
    fn from(err: &'static str) -> CryptoError {
        CryptoError::Custom(err)
    }
}

impl From<IoError> for CryptoError {
    fn from(err: IoError) -> CryptoError {
        CryptoError::Io(err)
    }
}

impl From<KeyRejected> for CryptoError {
    fn from(err: KeyRejected) -> CryptoError {
        CryptoError::KeyRejected(err)
    }
}

impl From<Unspecified> for CryptoError {
    fn from(_: Unspecified) -> CryptoError {
        CryptoError::Unspecified
    }
}

/// Token signing algorithms we support.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    #[serde(rename = "EdDSA")]
    EdDsa,
    #[serde(rename = "RS256")]
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

/// The types of key pairs we support.
pub enum SupportedKeyPair {
    Ed25519(Ed25519KeyPair),
    Rsa(RsaKeyPair),
}

impl SupportedKeyPair {
    /// Whether this is an Ed25519 key pair.
    pub fn is_ed25519(&self) -> bool {
        match self {
            SupportedKeyPair::Ed25519(_) => true,
            _ => false,
        }
    }

    /// Whether this is an RSA key pair.
    pub fn is_rsa(&self) -> bool {
        match self {
            SupportedKeyPair::Rsa(_) => true,
            _ => false,
        }
    }

    /// Generate an ID for the key by hashing the public components.
    ///
    /// Note that this hash is not a standard format, but that's okay, because it's only used as
    /// a simple identifier in JWKs.
    pub fn generate_id(&self) -> String {
        use SupportedKeyPair::*;
        match self {
            Ed25519(inner) => {
                let mut ctx = digest::Context::new(&digest::SHA256);
                ctx.update(b"ed25519.");
                ctx.update(inner.public_key().as_ref());
                base64url_encode(&ctx.finish())
            }
            Rsa(inner) => {
                let public = inner.public_key();
                let (n, e) = (public.modulus(), public.exponent());
                let mut ctx = digest::Context::new(&digest::SHA256);
                ctx.update(b"rsa.");
                ctx.update(e.big_endian_without_leading_zero());
                ctx.update(b".");
                ctx.update(n.big_endian_without_leading_zero());
                base64url_encode(&ctx.finish())
            }
        }
    }
}

/// A named key pair, for use in JWS signing.
pub struct NamedKeyPair {
    pub id: String,
    pub key_pair: SupportedKeyPair,
}

impl NamedKeyPair {
    /// Read key pairs from a PEM file.
    pub fn from_pem_file(filename: impl AsRef<Path>) -> Result<Vec<NamedKeyPair>, ()> {
        let file = File::open(filename).map_err(|_| ())?;
        NamedKeyPair::from_pem(&mut std::io::BufReader::new(file))
    }

    /// Read key pairs from PEM data.
    pub fn from_pem(pem: &mut dyn std::io::BufRead) -> Result<Vec<NamedKeyPair>, ()> {
        let key_pairs = crate::pemfile::parse_key_pairs(pem).map_err(|_| ())?;
        Ok(key_pairs
            .into_iter()
            .map(NamedKeyPair::from_key_pair)
            .collect())
    }

    /// Creates a NamedKeyPair from an key pair object.
    pub fn from_key_pair(key_pair: SupportedKeyPair) -> NamedKeyPair {
        let id = key_pair.generate_id();
        NamedKeyPair { id, key_pair }
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &json::Value, rng: &dyn SecureRandom) -> String {
        use SupportedKeyPair::*;
        let header = match self.key_pair {
            Ed25519(_) => json!({
                "kid": &self.id,
                "alg": "EdDSA",
            }),
            Rsa(_) => json!({
                "kid": &self.id,
                "alg": "RS256",
            }),
        }
        .to_string();

        let payload = payload.to_string();
        let mut input = Vec::<u8>::new();
        input.extend(base64url_encode(&header).into_bytes());
        input.push(b'.');
        input.extend(base64url_encode(&payload).into_bytes());

        let sig = match self.key_pair {
            Ed25519(ref inner) => {
                let sig = inner.sign(&input);
                base64url_encode(&sig)
            }
            Rsa(ref inner) => {
                let mut sig = vec![0; inner.public_modulus_len()];
                inner
                    .sign(&signature::RSA_PKCS1_SHA256, rng, &input, &mut sig)
                    .expect("failed to sign jwt");
                base64url_encode(&sig)
            }
        };

        input.push(b'.');
        input.extend(sig.into_bytes());
        String::from_utf8(input).expect("unable to coerce jwt into string")
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> json::Value {
        fn json_big_num(v: Positive) -> String {
            base64url_encode(v.big_endian_without_leading_zero())
        }

        use SupportedKeyPair::*;
        match self.key_pair {
            Ed25519(ref inner) => {
                let public = inner.public_key();
                json!({
                    "kty": "OKP",
                    "alg": "EdDSA",
                    "crv": "Ed25519",
                    "use": "sig",
                    "kid": &self.id,
                    "x": base64url_encode(&public),
                })
            }
            Rsa(ref inner) => {
                let public = inner.public_key();
                let (n, e) = (public.modulus(), public.exponent());
                json!({
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "kid": &self.id,
                    "n": json_big_num(n),
                    "e": json_big_num(e),
                })
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
    base64url_encode(&ctx.finish())
}

/// Helper function to create a secure nonce.
pub fn nonce(rng: &dyn SecureRandom) -> String {
    let mut rand_bytes = [0u8; 16];
    rng.fill(&mut rand_bytes)
        .expect("secure random number generator failed");

    base64url_encode(&rand_bytes)
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
pub fn jwk_key_set_find(key_set: &[ProviderKey], kid: &str) -> Result<RsaPublicKey, ()> {
    let matching: Vec<&ProviderKey> = key_set
        .iter()
        .filter(|key| key.use_ == "sig" && key.kid == kid)
        .collect();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let key = matching.first().expect("expected one key");
    let n = base64url_decode(&key.n).map_err(|_| ())?;
    let e = base64url_decode(&key.e).map_err(|_| ())?;
    Ok(RsaPublicKey { n, e })
}

/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(jws: &str, key_set: &[ProviderKey]) -> Result<json::Value, ()> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let decoded = parts
        .iter()
        .map(|s| base64url_decode(s))
        .collect::<Result<Vec<_>, _>>()?;
    let jwt_header: json::Value = json::from_slice(&decoded[0]).map_err(|_| ())?;
    let kid = jwt_header.get("kid").and_then(|v| v.as_str()).ok_or(())?;
    let pub_key = jwk_key_set_find(key_set, kid)?;

    // Verify the identity token's signature.
    let message_len = parts[0].len() + parts[1].len() + 1;
    pub_key
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            jws[..message_len].as_bytes(),
            &decoded[2],
        )
        .map_err(|_| ())?;

    // Return the payload.
    Ok(json::from_slice(&decoded[1]).map_err(|_| ())?)
}

/// Find the key pair for the selected signing algorithm.
pub fn find_key_pair(
    keys: &[NamedKeyPair],
    signing_alg: SigningAlgorithm,
) -> Result<&NamedKeyPair, CryptoError> {
    use SigningAlgorithm::*;
    match signing_alg {
        EdDsa => keys.iter().rfind(|k| k.key_pair.is_ed25519()),
        Rs256 => keys.iter().rfind(|k| k.key_pair.is_rsa()),
    }
    .ok_or(CryptoError::UnsupportedAlgorithm)
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
) -> Result<String, CryptoError> {
    let key_pair = find_key_pair(&app.keys, signing_alg)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let payload = json!({
        "aud": aud,
        "email": email_addr.as_str(),
        "email_verified": true,
        "email_original": email,
        "exp": now + u64::from(app.token_ttl),
        "iat": now,
        "iss": &app.public_url,
        "sub": email_addr.as_str(),
        "nonce": nonce,
    });
    Ok(key_pair.sign_jws(&payload, &app.rng))
}

#[inline]
fn base64url_encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

#[inline]
fn base64url_decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, ()> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD).map_err(|_| ())
}
