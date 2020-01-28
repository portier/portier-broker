use crate::crypto::SigningAlgorithm;
use crate::keys::{KeyManager, NamedKeyPair, SignError};
use crate::utils::pem::{self, ParsedKeyPair};
use err_derive::Error;
use log::{info, warn};
use ring::{
    rand::SecureRandom,
    signature::{Ed25519KeyPair, RsaKeyPair},
};
use serde_json as json;
use tokio::fs::File;
use tokio::io::BufReader;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(display = "could not parse keytext: {}", _0)]
    InvalidKeytext(#[error(source)] pem::ParseError),
    #[error(display = "no PEM data found in keytext")]
    EmptyKeytext,
    #[error(display = "no {} keys found in keyfiles or keytext", signing_alg)]
    MissingKeys { signing_alg: SigningAlgorithm },
}

/// KeyManager where the use provided keys to us manually.
pub struct ManualKeys {
    ed25519_keys: Vec<NamedKeyPair<Ed25519KeyPair>>,
    rsa_keys: Vec<NamedKeyPair<RsaKeyPair>>,
}

impl ManualKeys {
    pub async fn new(
        keyfiles: Vec<String>,
        keytext: Option<String>,
        signing_algs: &[SigningAlgorithm],
    ) -> Result<Self, ConfigError> {
        info!(
            "Using manual key management with algorithms: {}",
            SigningAlgorithm::format_list(signing_algs)
        );
        let mut parsed = vec![];
        for keyfile in &keyfiles {
            let file = match File::open(keyfile).await {
                Ok(file) => file,
                Err(err) => {
                    warn!("Ignoring keyfile '{}', could not open: {}", keyfile, err);
                    continue;
                }
            };

            let key_pairs = match pem::parse_key_pairs(BufReader::new(file)).await {
                Ok(key_pairs) => key_pairs,
                Err(err) => {
                    warn!("Ignoring keyfile '{}', could not parse: {}", keyfile, err);
                    continue;
                }
            };

            if key_pairs.is_empty() {
                warn!("Ignoring keyfile '{}', no PEM data found", keyfile);
                continue;
            }

            let orig_len = key_pairs.len();
            let mut key_pairs = key_pairs
                .into_iter()
                .filter(|key_pair| signing_algs.contains(&key_pair.signing_alg()))
                .collect::<Vec<_>>();
            if key_pairs.len() != orig_len {
                warn!(
                    "Ignoring {} (of {}) key(s) in '{}' for disabled signing algorithms",
                    orig_len - key_pairs.len(),
                    orig_len,
                    keyfile
                );
            }

            parsed.append(&mut key_pairs);
        }
        if let Some(keytext) = keytext {
            let mut key_pairs = pem::parse_key_pairs(keytext.as_bytes()).await?;
            if key_pairs.is_empty() {
                return Err(ConfigError::EmptyKeytext);
            } else {
                parsed.append(&mut key_pairs);
            }
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

        for signing_alg in signing_algs {
            if match signing_alg {
                SigningAlgorithm::EdDsa => ed25519_keys.is_empty(),
                SigningAlgorithm::Rs256 => rsa_keys.is_empty(),
            } {
                return Err(ConfigError::MissingKeys {
                    signing_alg: *signing_alg,
                });
            }
        }

        Ok(Self {
            ed25519_keys,
            rsa_keys,
        })
    }
}

impl KeyManager for ManualKeys {
    fn sign_jws(
        &self,
        payload: &json::Value,
        signing_alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> Result<String, SignError> {
        match signing_alg {
            SigningAlgorithm::EdDsa => self
                .ed25519_keys
                .last()
                .ok_or_else(|| SignError::UnsupportedAlgorithm(signing_alg))?
                .sign_jws(payload, rng),
            SigningAlgorithm::Rs256 => self
                .rsa_keys
                .last()
                .ok_or_else(|| SignError::UnsupportedAlgorithm(signing_alg))?
                .sign_jws(payload, rng),
        }
    }

    /// Get a list of JWKs containing public keys.
    fn public_jwks(&self) -> Vec<json::Value> {
        let ed25519_jwks = self.ed25519_keys.iter().map(NamedKeyPair::public_jwk);
        let rsa_jwks = self.rsa_keys.iter().map(NamedKeyPair::public_jwk);
        ed25519_jwks.chain(rsa_jwks).collect()
    }
}
