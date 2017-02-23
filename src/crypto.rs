extern crate ring;
extern crate rustc_serialize;
extern crate pem;
extern crate untrusted;

use emailaddress::EmailAddress;
use self::ring::signature::{self, RSAPublicKey, RSAKeyPair};
use self::ring::{rand, digest};
use self::rustc_serialize::base64::{self, FromBase64, ToBase64};
use serde_json::de::from_slice;
use serde_json::value::Value;
use std;
use std::error::Error;
use std::fmt::{self, Display};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum CryptoError {
    Custom(&'static str),
    Io(std::io::Error),
}

impl From<&'static str> for CryptoError {
    fn from(err: &'static str) -> CryptoError {
        CryptoError::Custom(err)
    }
}

impl From<std::io::Error> for CryptoError {
    fn from(err: std::io::Error) -> CryptoError {
        CryptoError::Io(err)
    }
}

impl Error for CryptoError {
    fn description(&self) -> &str {
        match *self {
            CryptoError::Custom(string) => string,
            CryptoError::Io(ref err) => err.description(),
        }
    }

    fn cause(&self) -> Option<&Error> {
        match *self {
            CryptoError::Custom(_) => None,
            CryptoError::Io(ref err) => Some(err),
        }
    }
}

impl Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CryptoError::Custom(string) => write!(f, "Crypto error: {}", string),
            CryptoError::Io(ref err) => write!(f, "IO error: {}", err),
        }
    }
}


/// A named key pair, for use in JWS signing.
pub struct NamedKey {
    id: String,
    key: Arc<RSAKeyPair>,
}


impl NamedKey {
    /// Creates a `NamedKey` from an `id` and  `key` private key.
    pub fn new(id: String, key: RSAKeyPair) -> NamedKey {
        NamedKey { id: id, key: Arc::new(key) }
    }

    /// Creates a `NamedKey` by reading a `file` path and generating an ID.
    pub fn from_file(filename: &str) -> Result<NamedKey, CryptoError> {
        let mut file = File::open(filename)?;
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents)?;
        NamedKey::from_pem_str(&file_contents)
    }

    /// Creates a `NamedKey` from the PEM `input` and generates an ID.
    pub fn from_pem_str(input: &str) -> Result<NamedKey, CryptoError> {
        let pem = pem::parse(input).map_err(|_| {
            CryptoError::Custom("invalid pem format")
        })?;
        if pem.tag != "RSA PRIVATE KEY" {
            return Err(CryptoError::Custom("pem file is not a private key"));
        }
        NamedKey::from_der_bytes(&pem.contents)
    }

    /// Creates a `NamedKey` from the DER `input` and generates an ID.
    pub fn from_der_bytes(input: &[u8]) -> Result<NamedKey, CryptoError> {
        let key = RSAKeyPair::from_der(untrusted::Input::from(input)).map_err(|_| {
            CryptoError::Custom("failed to parse pem contents")
        })?;
        let id = digest::digest(&digest::SHA256, input).as_ref().to_base64(base64::URL_SAFE);
        Ok(NamedKey::new(id, key))
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &Value) -> String {
        let header = json!({
            "kid": &self.id,
            "alg": "RS256",
        }).to_string();

        let payload = payload.to_string();
        let mut input = Vec::<u8>::new();
        input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
        input.push(b'.');
        input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());

        let mut signer = signature::RSASigningState::new(self.key.clone())
            .expect("unable to create jwt signer");
        let rng = rand::SystemRandom::new();
        let mut sig = vec![0; signer.key_pair().public_key().modulus_len()];
        signer.sign(&signature::RSA_PKCS1_SHA256, &rng, &input, &mut sig)
            .expect("unable to create jwt signature");

        input.push(b'.');
        input.extend(sig.to_base64(base64::URL_SAFE).into_bytes());
        String::from_utf8(input).expect("unable to coerce jwt into string")
    }

    /// Return JSON representation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> Value {
        let pub_key = self.key.public_key();

        let mut n: Vec<u8> = vec![0; pub_key.modulus_len()];
        pub_key.export_modulus(&mut n)
            .expect("could not export public modulus");

        let mut e: Vec<u8> = vec![0; pub_key.exponent_len()];
        pub_key.export_exponent(&mut e)
            .expect("could not export public modulus");

        json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": &self.id,
            "n": n.to_base64(base64::URL_SAFE),
            "e": e.to_base64(base64::URL_SAFE),
        })
    }
}


/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
pub fn session_id(email: &EmailAddress, client_id: &str) -> String {
    let mut rand_bytes: [u8; 16] = [0; 16];
    rand::SystemRandom::new().fill(&mut rand_bytes)
        .expect("unable to generate random bytes");

    let mut hasher = digest::Context::new(&digest::SHA256);
    hasher.update(email.to_string().as_bytes());
    hasher.update(client_id.as_bytes());
    hasher.update(&rand_bytes);
    hasher.finish().as_ref().to_base64(base64::URL_SAFE)
}


/// Create a unique nonce of 16-bytes encoded as base64.
pub fn nonce() -> String {
    let mut rand_bytes: [u8; 16] = [0; 16];
    rand::SystemRandom::new().fill(&mut rand_bytes)
        .expect("unable to generate random bytes");
    rand_bytes.to_base64(base64::URL_SAFE)
}


/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(set: &Value, kid: &str) -> Result<RSAPublicKey, ()> {
    let key_objs = set.get("keys").and_then(|v| v.as_array()).ok_or(())?;
    let matching = key_objs.iter()
        .filter(|key_obj| {
            key_obj.get("kid").and_then(|v| v.as_str()) == Some(kid) &&
            key_obj.get("use").and_then(|v| v.as_str()) == Some("sig")
        })
        .collect::<Vec<&Value>>();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let n = matching[0].get("n").and_then(|v| v.as_str()).ok_or(())
                .and_then(|data| data.from_base64().map_err(|_| ()))?;
    let e = matching[0].get("e").and_then(|v| v.as_str()).ok_or(())
                .and_then(|data| data.from_base64().map_err(|_| ()))?;
    RSAPublicKey::from_be_bytes(untrusted::Input::from(&n),
        untrusted::Input::from(&e)).map_err(|_| ())
}


/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(jws: &str, key_set: &Value) -> Result<Value, CryptoError> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CryptoError::Custom("invalid jwt format"));
    }
    let decoded = parts.iter().map(|s| s.from_base64())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CryptoError::Custom("invalid base64 data in jwt"))?;
    let jwt_header: Value = from_slice(&decoded[0])
        .map_err(|_| CryptoError::Custom("invalid json in jwt header"))?;
    let kid = jwt_header.get("kid").and_then(|v| v.as_str())
        .ok_or(CryptoError::Custom("kid missing from jwt header"))?;
    // FIXME: error handling in jwk_key_set_find
    let pub_key = jwk_key_set_find(key_set, kid)
        .map_err(|_| CryptoError::Custom("could not find key mentioned in jwt header"))?;

    // Verify the identity token's signature.
    let message_len = parts[0].len() + parts[1].len() + 1;
    pub_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256,
                   untrusted::Input::from(jws[..message_len].as_bytes()),
                   untrusted::Input::from(&decoded[2])).map_err(|_| {
        CryptoError::Custom("invalid jwt signature")
    })?;

    Ok(from_slice(&decoded[1])
        .map_err(|_| CryptoError::Custom("invalid json in jwt payload"))?)
}
