mod manual_keys;
mod rotating_keys;

pub use manual_keys::*;
pub use rotating_keys::*;

use crate::crypto::SigningAlgorithm;
use crate::utils::base64url;
use err_derive::Error;
use ring::{
    digest,
    io::Positive,
    rand::SecureRandom,
    signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair},
};
use serde_json as json;
use serde_json::json;

#[derive(Debug, Error)]
pub enum SignError {
    #[error(display = "unsupported signing algorithm {}", _0)]
    UnsupportedAlgorithm(SigningAlgorithm),
    #[error(display = "unspecified signing error")]
    Unspecified,
}

impl From<ring::error::Unspecified> for SignError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

/// Trait implemented by key management strategies.
pub trait KeyManager: Send + Sync {
    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    fn sign_jws(
        &self,
        payload: &json::Value,
        signing_alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> Result<String, SignError>;

    /// Get a list of JWKs containing public keys.
    fn public_jwks(&self) -> Vec<json::Value>;
}

/// A named key pair, for use in JWS signing.
pub struct NamedKeyPair<T: KeyPairExt> {
    pub kid: String,
    pub key_pair: T,
}

impl<T: KeyPairExt> NamedKeyPair<T> {
    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    fn sign_jws(&self, payload: &json::Value, rng: &dyn SecureRandom) -> Result<String, SignError> {
        self.key_pair.sign_jws(&self.kid, payload, rng)
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    fn public_jwk(&self) -> json::Value {
        self.key_pair.public_jwk(&self.kid)
    }
}

impl<T: KeyPairExt> From<T> for NamedKeyPair<T> {
    fn from(key_pair: T) -> Self {
        let kid = key_pair.generate_kid();
        Self { kid, key_pair }
    }
}

/// Additional KeyPair methods we implement for key pair types we support.
pub trait KeyPairExt {
    /// Generate an ID for the key by hashing the public components.
    ///
    /// Note that this hash is not a standard format, but that's okay, because it's only used as
    /// a simple identifier in JWKs.
    fn generate_kid(&self) -> String;

    /// Get the signing algorithm for this key type.
    fn signing_alg(&self) -> SigningAlgorithm;

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    fn sign_jws(
        &self,
        kid: &str,
        payload: &json::Value,
        rng: &dyn SecureRandom,
    ) -> Result<String, SignError>;

    /// Return JSON represenation of the public key for use in JWK key sets.
    fn public_jwk(&self, kid: &str) -> json::Value;
}

impl KeyPairExt for Ed25519KeyPair {
    fn generate_kid(&self) -> String {
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"ed25519.");
        ctx.update(self.public_key().as_ref());
        base64url::encode(&ctx.finish())
    }

    fn signing_alg(&self) -> SigningAlgorithm {
        SigningAlgorithm::EdDsa
    }

    fn sign_jws(
        &self,
        kid: &str,
        payload: &json::Value,
        _rng: &dyn SecureRandom,
    ) -> Result<String, SignError> {
        let header = json!({ "kid": kid, "alg": "EdDSA" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        // TODO: Maybe treat this as blocking?
        let sig = self.sign(data.as_bytes());
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        Ok(data)
    }

    fn public_jwk(&self, kid: &str) -> json::Value {
        let public = self.public_key();
        json!({
            "kty": "OKP",
            "alg": "EdDSA",
            "crv": "Ed25519",
            "use": "sig",
            "kid": &kid,
            "x": base64url::encode(&public),
        })
    }
}

impl KeyPairExt for RsaKeyPair {
    fn generate_kid(&self) -> String {
        let public = self.public_key();
        let (n, e) = (public.modulus(), public.exponent());
        let mut ctx = digest::Context::new(&digest::SHA256);
        ctx.update(b"rsa.");
        ctx.update(e.big_endian_without_leading_zero());
        ctx.update(b".");
        ctx.update(n.big_endian_without_leading_zero());
        base64url::encode(&ctx.finish())
    }

    fn signing_alg(&self) -> SigningAlgorithm {
        SigningAlgorithm::Rs256
    }

    fn sign_jws(
        &self,
        kid: &str,
        payload: &json::Value,
        rng: &dyn SecureRandom,
    ) -> Result<String, SignError> {
        let header = json!({ "kid": kid, "alg": "RS256" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        let mut sig = vec![0; self.public_modulus_len()];
        // TODO: RNG is blocking
        self.sign(&signature::RSA_PKCS1_SHA256, rng, data.as_bytes(), &mut sig)?;
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        Ok(data)
    }

    fn public_jwk(&self, kid: &str) -> json::Value {
        fn json_big_num(v: Positive) -> String {
            base64url::encode(v.big_endian_without_leading_zero())
        }

        let public = self.public_key();
        let (n, e) = (public.modulus(), public.exponent());
        json!({
            "kty": "RSA",
            "alg": "RS256",
            "use": "sig",
            "kid": &kid,
            "n": json_big_num(n),
            "e": json_big_num(e),
        })
    }
}
