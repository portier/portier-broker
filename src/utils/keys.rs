use crate::crypto::SigningAlgorithm;
use crate::utils::{
    base64url,
    pem::{self, ParsedKeyPair},
    SecureRandom,
};
use ring::{
    digest,
    io::Positive,
    signature::{self, Ed25519KeyPair, KeyPair, RsaKeyPair},
};
use serde_json::{json, Value as JsonValue};
use std::ffi::OsString;
use std::process::{Command, Stdio};
use thiserror::Error;

#[cfg(feature = "rsa")]
use rsa::pkcs8::EncodePrivateKey;

#[derive(Debug, Error)]
pub enum SignError {
    #[error("unsupported signing algorithm {0}")]
    UnsupportedAlgorithm(SigningAlgorithm),
    #[error("unspecified signing error")]
    Unspecified,
}

impl From<ring::error::Unspecified> for SignError {
    fn from(_: ring::error::Unspecified) -> Self {
        Self::Unspecified
    }
}

/// A named key pair, for use in JWS signing.
pub struct NamedKeyPair<T: KeyPairExt> {
    pub kid: String,
    pub key_pair: T,
}

impl<T: KeyPairExt> NamedKeyPair<T> {
    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &JsonValue, rng: &SecureRandom) -> Result<String, SignError> {
        self.key_pair.sign_jws(&self.kid, payload, rng)
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> JsonValue {
        self.key_pair.public_jwk(&self.kid)
    }
}

impl<T: KeyPairExt> From<T> for NamedKeyPair<T> {
    fn from(key_pair: T) -> Self {
        let kid = key_pair.generate_kid();
        Self { kid, key_pair }
    }
}

/// Additional `KeyPair` methods we implement for key pair types we support.
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
        payload: &JsonValue,
        rng: &SecureRandom,
    ) -> Result<String, SignError>;

    /// Return JSON represenation of the public key for use in JWK key sets.
    fn public_jwk(&self, kid: &str) -> JsonValue;
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
        payload: &JsonValue,
        _rng: &SecureRandom,
    ) -> Result<String, SignError> {
        let header = json!({ "kid": kid, "alg": "EdDSA" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        let sig = self.sign(data.as_bytes());
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        Ok(data)
    }

    fn public_jwk(&self, kid: &str) -> JsonValue {
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
        payload: &JsonValue,
        rng: &SecureRandom,
    ) -> Result<String, SignError> {
        let header = json!({ "kid": kid, "alg": "RS256" }).to_string();
        let mut data = String::new();
        data.push_str(&base64url::encode(&header));
        data.push('.');
        data.push_str(&base64url::encode(&payload.to_string()));
        let mut sig = vec![0; self.public_modulus_len()];
        self.sign(
            &signature::RSA_PKCS1_SHA256,
            &rng.generator,
            data.as_bytes(),
            &mut sig,
        )?;
        data.push('.');
        data.push_str(&base64url::encode(&sig));
        Ok(data)
    }

    fn public_jwk(&self, kid: &str) -> JsonValue {
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

/// Trait for key pair types we can generate.
pub trait GeneratedKeyPair: KeyPairExt + Sized {
    /// Configuration required for generating a key pair.
    type Config;

    /// Generate a new key pair.
    ///
    /// If this fails, we panic, because it may happen at an arbitrary moment at run-time.
    fn generate(config: Self::Config) -> String;

    /// Convert a `ParsedKeyPair`, if it is of the correct type.
    fn from_parsed(parsed: ParsedKeyPair) -> Option<Self>;
}

impl GeneratedKeyPair for Ed25519KeyPair {
    type Config = SecureRandom;

    fn generate(config: Self::Config) -> String {
        let doc =
            Self::generate_pkcs8(&config.generator).expect("could not generate Ed25519 key pair");
        pem::encode(doc.as_ref(), pem::PKCS8)
    }

    fn from_parsed(parsed: ParsedKeyPair) -> Option<Self> {
        #[allow(clippy::match_wildcard_for_single_variants)]
        match parsed {
            ParsedKeyPair::Ed25519(inner) => Some(inner),
            _ => None,
        }
    }
}

pub struct GenerateRsaConfig {
    pub rng: SecureRandom,
    pub modulus_bits: usize,
    pub command: Vec<String>,
}

impl GeneratedKeyPair for RsaKeyPair {
    type Config = GenerateRsaConfig;

    fn generate(mut config: GenerateRsaConfig) -> String {
        #[cfg(feature = "rsa")]
        if config.command.is_empty() {
            let der = rsa::RsaPrivateKey::new(&mut config.rng, config.modulus_bits)
                .expect("Failed to generate RSA key")
                .to_pkcs8_der()
                .expect("Failed to serialize generated RSA key as PKCS8");
            return pem::encode(der.as_bytes(), pem::PKCS8);
        }

        let mut args: Vec<OsString> = config.command.iter().map(Into::into).collect();
        let program = args.remove(0);
        let output = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .output()
            .expect("Failed to run command to generate RSA key");
        assert!(
            output.status.success(),
            "Command to generate RSA key failed with status {}",
            output.status
        );
        String::from_utf8(output.stdout).expect("Generated RSA is not UTF-8")
    }

    fn from_parsed(parsed: ParsedKeyPair) -> Option<Self> {
        #[allow(clippy::match_wildcard_for_single_variants)]
        match parsed {
            ParsedKeyPair::Rsa(inner) => Some(inner),
            _ => None,
        }
    }
}
