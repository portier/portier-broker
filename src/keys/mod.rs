mod manual_keys;
mod rotating_keys;

pub use manual_keys::*;
pub use rotating_keys::*;

use crate::base64url;
use crate::crypto::SigningAlgorithm;
use crate::pemfile::ParsedKeyPair;
use ring::{
    digest,
    io::Positive,
    rand::SecureRandom,
    signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair},
};
use serde_json as json;
use serde_json::json;

/// Trait implemented by key management strategies.
pub trait KeyManager: Send + Sync {
    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    fn sign_jws(
        &self,
        payload: &json::Value,
        signing_alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> String;

    /// Get a list of JWKs containing public keys.
    fn public_jwks(&self) -> Vec<json::Value>;

    /// Get a list of supported signing algorithms.
    fn signing_algs(&self) -> Vec<SigningAlgorithm>;
}

/// A named key pair, for use in JWS signing.
pub struct NamedKeyPair<T: KeyPairExt> {
    pub kid: String,
    pub key_pair: T,
}

impl<T: KeyPairExt> NamedKeyPair<T> {
    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    fn sign_jws(&self, payload: &json::Value, rng: &dyn SecureRandom) -> String {
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
    fn sign_jws(&self, kid: &str, payload: &json::Value, rng: &dyn SecureRandom) -> String;

    /// Return JSON represenation of the public key for use in JWK key sets.
    fn public_jwk(&self, kid: &str) -> json::Value;
}

/// Additional KeyPair conversion from ParsedKeyPair.
///
/// This is separate from KeyPairExt in order to allow trait objects of KeyPairExt.
pub trait TryFromParsedKeyPair: Sized {
    /// Convert a ParsedKeyPair if it is of the correct type.
    fn try_from_parsed_key_pair(parsed: ParsedKeyPair) -> Option<Self>;
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

    fn sign_jws(&self, kid: &str, payload: &json::Value, _rng: &dyn SecureRandom) -> String {
        let header = json!({ "kid": kid, "alg": "EdDSA" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        let sig = self.sign(data.as_bytes());
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        data
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

impl TryFromParsedKeyPair for Ed25519KeyPair {
    fn try_from_parsed_key_pair(parsed: ParsedKeyPair) -> Option<Self> {
        match parsed {
            ParsedKeyPair::Ed25519(inner) => Some(inner),
            _ => None,
        }
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

    fn sign_jws(&self, kid: &str, payload: &json::Value, rng: &dyn SecureRandom) -> String {
        let header = json!({ "kid": kid, "alg": "RS256" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        let mut sig = vec![0; self.public_modulus_len()];
        self.sign(&signature::RSA_PKCS1_SHA256, rng, data.as_bytes(), &mut sig)
            .expect("failed to sign JWT using RSA");
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        data
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

impl TryFromParsedKeyPair for RsaKeyPair {
    fn try_from_parsed_key_pair(parsed: ParsedKeyPair) -> Option<Self> {
        match parsed {
            ParsedKeyPair::Rsa(inner) => Some(inner),
            _ => None,
        }
    }
}
