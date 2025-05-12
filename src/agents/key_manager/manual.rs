use crate::agents::*;
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::*,
    keys::{NamedKeyPair, SignError},
    pem::{self, ParsedKeyPair},
    SecureRandom,
};
use aws_lc_rs::signature::{Ed25519KeyPair, RsaKeyPair};
use log::{info, warn};
use std::fs::File;
use std::io::{BufReader, Error as IoError};
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManualKeysError {
    #[error("could not read keyfile '{file}': {err}")]
    IoError { file: PathBuf, err: IoError },
    #[error("no {} keys found in keyfiles or keytext", signing_alg)]
    MissingKeys { signing_alg: SigningAlgorithm },
}

/// A `KeyManager` where the use provided keys to us manually.
pub struct ManualKeys {
    ed25519_keys: Vec<NamedKeyPair<Ed25519KeyPair>>,
    rsa_keys: Vec<NamedKeyPair<RsaKeyPair>>,
    rng: SecureRandom,
}

impl ManualKeys {
    pub fn new(
        keyfiles: &[PathBuf],
        keytext: Option<String>,
        signing_algs: &[SigningAlgorithm],
        rng: SecureRandom,
    ) -> Result<Self, ManualKeysError> {
        info!(
            "Using manual key management with algorithms: {}",
            SigningAlgorithm::format_list(signing_algs)
        );

        let mut parsed = vec![];
        for keyfile in keyfiles {
            let file = match File::open(keyfile) {
                Ok(file) => file,
                Err(err) => {
                    warn!("{}: ignoring, could not open: {}", keyfile.display(), err);
                    continue;
                }
            };
            let entries = pem::parse_key_pairs(BufReader::new(file)).map_err(|err| {
                let file = keyfile.clone();
                ManualKeysError::IoError { file, err }
            })?;
            let source = format!("{}", keyfile.display());
            parsed.push((source, entries));
        }
        if let Some(keytext) = keytext {
            let entries = pem::parse_key_pairs(keytext.as_bytes()).unwrap();
            let source = "<keytext>".to_owned();
            parsed.push((source, entries));
        }

        let mut ed25519_keys = vec![];
        let mut rsa_keys = vec![];
        for (source, entries) in parsed {
            if entries.is_empty() {
                warn!("{source}: ignoring, no PEM sections found");
            }

            for (idx, result) in entries.into_iter().enumerate() {
                let idx = idx + 1;
                let entry = match result {
                    Ok(entry) => entry,
                    Err(err) => {
                        warn!("{source} #{idx}: ignoring, {err}");
                        continue;
                    }
                };

                let alg = entry.key_pair.signing_alg();
                if !signing_algs.contains(&alg) {
                    warn!("{source} #{idx}: ignoring, disabled signing algorithm");
                    continue;
                }

                match entry.key_pair {
                    ParsedKeyPair::Ed25519(key_pair) => ed25519_keys.push(key_pair.into()),
                    ParsedKeyPair::Rsa(key_pair) => rsa_keys.push(key_pair.into()),
                }

                let fp = entry.raw.fingerprint();
                info!("{source} #{idx}: found {alg} key, fingerprint: {fp}");
            }
        }

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
        cx.reply(maybe_jws.unwrap_or(Err(SignError::UnsupportedAlgorithm(message.signing_alg))));
    }
}

impl Handler<GetPublicJwks> for ManualKeys {
    fn handle(&mut self, _message: GetPublicJwks, cx: Context<Self, GetPublicJwks>) {
        let ed25519_jwks = self.ed25519_keys.iter().map(NamedKeyPair::public_jwk);
        let rsa_jwks = self.rsa_keys.iter().map(NamedKeyPair::public_jwk);
        cx.reply(GetPublicJwksReply {
            jwks: ed25519_jwks.chain(rsa_jwks).collect(),
            expires: None,
        });
    }
}

impl KeyManagerSender for Addr<ManualKeys> {}
