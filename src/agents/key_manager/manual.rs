use crate::agents::*;
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::*,
    keys::{NamedKeyPair, SignError},
    pem::{self, ParsedKeyPair},
    SecureRandom,
};
use err_derive::Error;
use log::{info, warn};
use ring::signature::{Ed25519KeyPair, RsaKeyPair};
use std::fs::File;
use std::io::BufReader;

#[derive(Debug, Error)]
pub enum ManualKeysError {
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
    rng: SecureRandom,
}

impl ManualKeys {
    pub fn new(
        keyfiles: Vec<String>,
        keytext: Option<String>,
        signing_algs: &[SigningAlgorithm],
        rng: SecureRandom,
    ) -> Result<Self, ManualKeysError> {
        info!(
            "Using manual key management with algorithms: {}",
            SigningAlgorithm::format_list(signing_algs)
        );
        let mut parsed = vec![];
        for keyfile in &keyfiles {
            let file = match File::open(keyfile) {
                Ok(file) => file,
                Err(err) => {
                    warn!("Ignoring keyfile '{}', could not open: {}", keyfile, err);
                    continue;
                }
            };

            let key_pairs = match pem::parse_key_pairs(BufReader::new(file)) {
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
            let mut key_pairs = pem::parse_key_pairs(keytext.as_bytes())?;
            if key_pairs.is_empty() {
                return Err(ManualKeysError::EmptyKeytext);
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
                return Err(ManualKeysError::MissingKeys {
                    signing_alg: *signing_alg,
                });
            }
        }

        Ok(Self {
            ed25519_keys,
            rsa_keys,
            rng,
        })
    }
}

impl Agent for ManualKeys {}

impl Handler<SignJws> for ManualKeys {
    fn handle(&mut self, message: SignJws, cx: Context<Self, SignJws>) {
        let maybe_jws = match message.signing_alg {
            SigningAlgorithm::EdDsa => self
                .ed25519_keys
                .last()
                .map(|key| key.sign_jws(&message.payload, &self.rng)),
            SigningAlgorithm::Rs256 => self
                .rsa_keys
                .last()
                .map(|key| key.sign_jws(&message.payload, &self.rng)),
        };
        cx.reply(
            maybe_jws.unwrap_or_else(|| Err(SignError::UnsupportedAlgorithm(message.signing_alg))),
        );
    }
}

impl Handler<GetPublicJwks> for ManualKeys {
    fn handle(&mut self, _message: GetPublicJwks, cx: Context<Self, GetPublicJwks>) {
        let ed25519_jwks = self.ed25519_keys.iter().map(NamedKeyPair::public_jwk);
        let rsa_jwks = self.rsa_keys.iter().map(NamedKeyPair::public_jwk);
        cx.reply(ed25519_jwks.chain(rsa_jwks).collect())
    }
}

impl KeyManagerSender for Addr<ManualKeys> {}
