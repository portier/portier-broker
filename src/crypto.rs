use crate::bridges::oidc::ProviderKey;
use crate::config::Config;
use crate::email_address::EmailAddress;
use ring::{
    digest,
    error::{KeyRejected, Unspecified},
    io::Positive,
    rand::SecureRandom,
    signature::{self, KeyPair, RsaKeyPair},
};
use serde_json as json;
use serde_json::json;
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

/// A named key pair, for use in JWS signing.
pub struct NamedKey {
    id: String,
    key_pair: RsaKeyPair,
}

impl NamedKey {
    /// Creates a NamedKey by reading a `file` path and generating an `id`.
    pub fn from_pem_file(filename: impl AsRef<Path>) -> Result<Vec<NamedKey>, ()> {
        let file = File::open(filename).map_err(|_| ())?;
        NamedKey::from_pem(&mut std::io::BufReader::new(file))
    }

    /// Creates a NamedKey from a PEM-encoded str.
    pub fn from_pem(pem: &mut dyn std::io::BufRead) -> Result<Vec<NamedKey>, ()> {
        let key_pairs = crate::pemfile::parse_key_pairs(pem).map_err(|_| ())?;
        Ok(key_pairs.into_iter().map(NamedKey::from_key_pair).collect())
    }

    /// Creates a NamedKey from an RsaKeyPair.
    pub fn from_key_pair(key_pair: RsaKeyPair) -> NamedKey {
        let id = {
            let public = key_pair.public_key();
            let (n, e) = (public.modulus(), public.exponent());
            let mut ctx = digest::Context::new(&digest::SHA256);
            ctx.update(e.big_endian_without_leading_zero());
            ctx.update(b".");
            ctx.update(n.big_endian_without_leading_zero());
            base64url_encode(&ctx.finish())
        };
        NamedKey { id, key_pair }
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &json::Value, rng: &dyn SecureRandom) -> String {
        let header = json!({
            "kid": &self.id,
            "alg": "RS256",
        })
        .to_string();

        let payload = payload.to_string();
        let mut input = Vec::<u8>::new();
        input.extend(base64url_encode(&header).into_bytes());
        input.push(b'.');
        input.extend(base64url_encode(&payload).into_bytes());

        let mut sig = vec![0; self.key_pair.public_modulus_len()];
        self.key_pair
            .sign(&signature::RSA_PKCS1_SHA256, rng, &input, &mut sig)
            .expect("failed to sign jwt");

        input.push(b'.');
        input.extend(base64url_encode(&sig).into_bytes());
        String::from_utf8(input).expect("unable to coerce jwt into string")
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> json::Value {
        fn json_big_num(v: Positive) -> String {
            base64url_encode(v.big_endian_without_leading_zero())
        }

        let public = self.key_pair.public_key();
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
) -> String {
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
    let key = app.keys.last().expect("unable to locate signing key");
    key.sign_jws(&payload, &app.rng)
}

#[inline]
fn base64url_encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

#[inline]
fn base64url_decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, ()> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD).map_err(|_| ())
}
