use crate::crypto::SigningAlgorithm;
use crate::keys::{KeyManager, NamedKeyPair};
use crate::pemfile::{self, ParsedKeyPair};
use log::{info, warn};
use ring::{
    rand::SecureRandom,
    signature::{Ed25519KeyPair, RsaKeyPair},
};
use serde_json as json;
use std::fs::File;

/// KeyManager where the use provided keys to us manually.
pub struct ManualKeys {
    ed25519_keys: Vec<NamedKeyPair<Ed25519KeyPair>>,
    rsa_keys: Vec<NamedKeyPair<RsaKeyPair>>,
}

impl ManualKeys {
    pub fn new(keyfiles: Vec<String>, keytext: Option<String>) -> Self {
        info!("Using manual key management");
        let mut parsed = vec![];
        for keyfile in &keyfiles {
            let file = match File::open(keyfile) {
                Ok(file) => file,
                Err(err) => {
                    warn!("Ignoring keyfile '{}', could not open: {:?}", keyfile, err);
                    continue;
                }
            };

            let mut key_pairs = match pemfile::parse_key_pairs(&mut std::io::BufReader::new(file)) {
                Ok(key_pairs) => key_pairs,
                Err(err) => {
                    warn!("Ignoring keyfile '{}', could not read: {:?}", keyfile, err);
                    continue;
                }
            };

            if key_pairs.is_empty() {
                warn!("Ignoring keyfile '{}', no PEM in content", keyfile);
            } else {
                parsed.append(&mut key_pairs);
            }
        }
        if let Some(keytext) = keytext {
            let mut key_pairs =
                pemfile::parse_key_pairs(&mut keytext.as_bytes()).expect("could not parse keytext");
            if key_pairs.is_empty() {
                panic!("no PEM found in keytext");
            } else {
                parsed.append(&mut key_pairs);
            }
        }
        if parsed.is_empty() {
            panic!("no keys found in keyfiles or keytext");
        }

        let mut ed25519_keys = vec![];
        let mut rsa_keys = vec![];
        for key_pair in parsed {
            match key_pair {
                ParsedKeyPair::Ed25519(key_pair) => ed25519_keys.push(key_pair.into()),
                ParsedKeyPair::Rsa(key_pair) => rsa_keys.push(key_pair.into()),
            }
        }
        info!(
            "Found keys: {} Ed25519 key(s), {} RSA key(s)",
            ed25519_keys.len(),
            rsa_keys.len()
        );

        Self {
            ed25519_keys,
            rsa_keys,
        }
    }
}

impl KeyManager for ManualKeys {
    fn sign_jws(
        &self,
        payload: &json::Value,
        signing_alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> String {
        match signing_alg {
            SigningAlgorithm::EdDsa => self
                .ed25519_keys
                .last()
                .expect("no keys found for EdDSA")
                .sign_jws(payload, rng),
            SigningAlgorithm::Rs256 => self
                .rsa_keys
                .last()
                .expect("no keys found for RS256")
                .sign_jws(payload, rng),
        }
    }

    /// Get a list of JWKs containing public keys.
    fn public_jwks(&self) -> Vec<json::Value> {
        let ed25519_jwks = self.ed25519_keys.iter().map(NamedKeyPair::public_jwk);
        let rsa_jwks = self.rsa_keys.iter().map(NamedKeyPair::public_jwk);
        ed25519_jwks.chain(rsa_jwks).collect()
    }

    /// Get a list of supported signing algorithms.
    fn signing_algs(&self) -> Vec<SigningAlgorithm> {
        // We prefer EdDSA, but list RSA first, in case a client treats the order as preference.
        let mut list = vec![];
        if !self.rsa_keys.is_empty() {
            list.push(SigningAlgorithm::Rs256);
        }
        if !self.ed25519_keys.is_empty() {
            list.push(SigningAlgorithm::EdDsa);
        }
        list
    }
}
