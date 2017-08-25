use base64;
use bridges::oidc::ProviderKey;
use config::Config;
use email_address::EmailAddress;
use openssl::bn::{BigNum, BigNumRef};
use openssl::error::ErrorStack as SslErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use rand::{OsRng, Rng};
use serde_json as json;
use std::fs::File;
use std::io::{Read, Error as IoError};
use time::now_utc;


/// Union of all possible error types seen while parsing.
#[derive(Debug)]
pub enum CryptoError {
    Custom(&'static str),
    Io(IoError),
    Ssl(SslErrorStack),
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

impl From<SslErrorStack> for CryptoError {
    fn from(err: SslErrorStack) -> CryptoError {
        CryptoError::Ssl(err)
    }
}


/// A named key pair, for use in JWS signing.
pub struct NamedKey {
    id: String,
    key: PKey,
}


impl NamedKey {
    /// Creates a NamedKey by reading a `file` path and generating an `id`.
    pub fn from_file(filename: &str) -> Result<NamedKey, CryptoError> {
        let mut file = File::open(filename)?;
        let mut file_contents = String::new();
        file.read_to_string(&mut file_contents)?;

        NamedKey::from_pem_str(&file_contents)
    }

    /// Creates a NamedKey from a PEM-encoded str.
    pub fn from_pem_str(pem: &str) -> Result<NamedKey, CryptoError> {
        let rsa = Rsa::private_key_from_pem(pem.as_bytes())?;

        NamedKey::from_rsa(rsa)
    }

    /// Creates a NamedKey from an Rsa
    pub fn from_rsa(rsa: Rsa) -> Result<NamedKey, CryptoError> {
        let id = {
            let e = rsa.e().ok_or(CryptoError::Custom("unable to retrieve key's e value"))?;
            let n = rsa.n().ok_or(CryptoError::Custom("unable to retrieve key's n value"))?;
            let mut hasher = Hasher::new(MessageDigest::sha256())?;
            let hash = hasher.update(&e.to_vec())
                .and_then(|_| hasher.update(b"."))
                .and_then(|_| hasher.update(&n.to_vec()))
                .and_then(|_| hasher.finish2())?;
            base64url_encode(&hash)
        };
        let key = PKey::from_rsa(rsa)?;
        Ok(NamedKey { id, key })
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &json::Value) -> String {
        let header = json!({
            "kid": &self.id,
            "alg": "RS256",
        }).to_string();

        let payload = payload.to_string();
        let mut input = Vec::<u8>::new();
        input.extend(base64url_encode(&header).into_bytes());
        input.push(b'.');
        input.extend(base64url_encode(&payload).into_bytes());

        let mut signer = Signer::new(MessageDigest::sha256(), &self.key)
            .expect("could not initialize signer");
        let sig = signer.update(&input)
            .and_then(|_| signer.finish())
            .expect("failed to sign jwt");

        input.push(b'.');
        input.extend(base64url_encode(&sig).into_bytes());
        String::from_utf8(input).expect("unable to coerce jwt into string")
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> json::Value {
        fn json_big_num(n: &BigNumRef) -> String {
            base64url_encode(&n.to_vec())
        }

        let rsa = self.key.rsa().expect("unable to retrieve rsa key");
        let n = rsa.n().expect("unable to retrieve key's n value");
        let e = rsa.e().expect("unable to retrieve key's e value");
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
pub fn session_id(email: &EmailAddress, client_id: &str) -> String {
    let mut rng = OsRng::new().expect("unable to create rng");
    let rand_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

    let mut hasher = Hasher::new(MessageDigest::sha256())
        .expect("couldn't initialize SHA256 hasher");
    let hash = hasher.update(email.as_str().as_bytes())
        .and_then(|_| hasher.update(client_id.as_bytes()))
        .and_then(|_| hasher.update(&rand_bytes))
        .and_then(|_| hasher.finish2())
        .expect("session hashing failed");
    base64url_encode(&hash)
}


pub fn nonce() -> String {
    let mut rng = OsRng::new().expect("unable to create rng");
    let rand_bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    base64url_encode(&rand_bytes)
}


/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(key_set: &[ProviderKey], kid: &str) -> Result<PKey, ()> {
    let matching: Vec<&ProviderKey> = key_set.iter()
        .filter(|key| key.use_ == "sig" && key.kid == kid)
        .collect();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let key = matching.first().expect("expected one key");
    let n = base64url_decode(&key.n).and_then(|data| BigNum::from_slice(&data).map_err(|_| ()))?;
    let e = base64url_decode(&key.e).and_then(|data| BigNum::from_slice(&data).map_err(|_| ()))?;
    let rsa = Rsa::from_public_components(n, e).map_err(|_| ())?;
    Ok(PKey::from_rsa(rsa).map_err(|_| ())?)
}


/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(jws: &str, key_set: &[ProviderKey]) -> Result<json::Value, ()> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(());
    }
    let decoded = parts.iter().map(|s| base64url_decode(s))
        .collect::<Result<Vec<_>, _>>()?;
    let jwt_header: json::Value = json::from_slice(&decoded[0]).map_err(|_| ())?;
    let kid = jwt_header.get("kid").and_then(|v| v.as_str()).ok_or(())?;
    let pub_key = jwk_key_set_find(key_set, kid)?;

    // Verify the identity token's signature.
    let message_len = parts[0].len() + parts[1].len() + 1;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pub_key).map_err(|_| ())?;
    verifier.update(jws[..message_len].as_bytes())
        .and_then(|_| verifier.finish(&decoded[2]))
        .map_err(|_| ())
        .and_then(|ok| {
            if ok {
                Ok(json::from_slice(&decoded[1]).map_err(|_| ())?)
            } else {
                Err(())
            }
        })
}

/// Helper method to create a JWT for a given email address and audience.
///
/// Builds the JSON payload, then signs it using the last key provided in
/// the configuration object.
pub fn create_jwt(app: &Config, email: &EmailAddress, aud: &str, nonce: &str) -> String {
    let now = now_utc().to_timespec().sec;
    let payload = json!({
        "aud": aud,
        "email": email.as_str(),
        "email_verified": email.as_str(),
        "exp": now + app.token_ttl as i64,
        "iat": now,
        "iss": &app.public_url,
        "sub": email.as_str(),
        "nonce": nonce,
    });
    let key = app.keys.last().expect("unable to locate signing key");
    key.sign_jws(&payload)
}


#[inline]
fn base64url_encode<T: ?Sized + AsRef<[u8]>>(data: &T) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

#[inline]
fn base64url_decode<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<Vec<u8>, ()> {
    base64::decode_config(data, base64::URL_SAFE_NO_PAD).map_err(|_| ())
}
