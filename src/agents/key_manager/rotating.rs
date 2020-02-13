use crate::agents::*;
use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::*,
    keys::{KeyPairExt, NamedKeyPair, SignError},
    pem::{self, ParsedKeyPair},
    BoxFuture,
};
use err_derive::Error;
use log::{info, warn};
use ring::{
    rand::SecureRandom,
    signature::{Ed25519KeyPair, RsaKeyPair},
};
use serde_json as json;
use std::ffi::OsString;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::mem;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};
use tokio::fs::{self, File};
use tokio::io::BufReader;
use tokio::process::Command;
use tokio::task;

#[derive(Debug, Error)]
pub enum RotatingKeysError {
    #[error(display = "could not open '{}': {}", path, error)]
    Open {
        path: String,
        #[error(source, nofrom)]
        error: IoError,
    },
    #[error(display = "could not create directory '{}': {}", path, error)]
    Mkdir {
        path: String,
        #[error(source, nofrom)]
        error: IoError,
    },
    #[error(
        display = "could not determine last modification time of '{}': {}",
        path,
        error
    )]
    StatMtime {
        path: String,
        #[error(source, nofrom)]
        error: IoError,
    },
    #[error(display = "could not parse file '{}': {}", path, error)]
    Parse {
        path: String,
        #[error(source, nofrom)]
        error: pem::ParseError,
    },
    #[error(
        display = "invalid type of key in '{}', want {}, found {}",
        path,
        want,
        found
    )]
    InvalidKeyType {
        path: String,
        want: &'static str,
        found: &'static str,
    },
    #[error(display = "expected exactly one key in '{}', found {}", path, found)]
    ExpectedOneKey { path: String, found: usize },
}

/// Struct that contains configuration we pass around.
struct RotateConfig {
    keys_ttl: Duration,
    generate_rsa_command: Vec<String>,
    rng: Box<dyn SecureRandom + Send + Sync>,
}

/// KeyManager where we rotating 3 keys of each type.
pub struct RotatingKeys {
    ed25519_keys: Option<KeySetHandle<Ed25519KeyPair>>,
    rsa_keys: Option<KeySetHandle<RsaKeyPair>>,
}

impl RotatingKeys {
    pub async fn new(
        keysdir: impl AsRef<Path>,
        keys_ttl: Duration,
        signing_algs: &[SigningAlgorithm],
        generate_rsa_command: Vec<String>,
        rng: impl SecureRandom + Send + Sync + 'static,
    ) -> Result<Self, RotatingKeysError> {
        info!(
            "Using rotating keys with a {}s interval and algorithms: {}",
            keys_ttl.as_secs(),
            SigningAlgorithm::format_list(signing_algs)
        );
        let rng = Box::new(rng);
        let config = Arc::new(RotateConfig {
            keys_ttl,
            generate_rsa_command,
            rng,
        });
        let ed25519_keys = if signing_algs.contains(&SigningAlgorithm::EdDsa) {
            Some(KeySet::from_subdir(keysdir.as_ref(), "ed25519", &config).await?)
        } else {
            None
        };
        let rsa_keys = if signing_algs.contains(&SigningAlgorithm::Rs256) {
            Some(KeySet::from_subdir(keysdir.as_ref(), "rsa", &config).await?)
        } else {
            None
        };
        Ok(RotatingKeys {
            ed25519_keys,
            rsa_keys,
        })
    }
}

impl Agent for RotatingKeys {}

impl Handler<SignJws> for RotatingKeys {
    fn handle(&mut self, message: SignJws, reply: ReplySender<SignJws>) {
        // TODO: Read-locking is blocking.
        let maybe_jws = match message.signing_alg {
            SigningAlgorithm::EdDsa => self.ed25519_keys.as_ref().map(|key_set| {
                let key_set = key_set.read().unwrap();
                key_set
                    .current
                    .sign_jws(&message.payload, &*key_set.config.rng)
            }),
            SigningAlgorithm::Rs256 => self.rsa_keys.as_ref().map(|key_set| {
                let key_set = key_set.read().unwrap();
                key_set
                    .current
                    .sign_jws(&message.payload, &*key_set.config.rng)
            }),
        };
        reply.send(
            maybe_jws.unwrap_or_else(|| Err(SignError::UnsupportedAlgorithm(message.signing_alg))),
        );
    }
}

impl Handler<GetPublicJwks> for RotatingKeys {
    fn handle(&mut self, _message: GetPublicJwks, reply: ReplySender<GetPublicJwks>) {
        // TODO: Read-locking is blocking.
        let mut jwks = vec![];
        if let Some(ref key_set) = self.ed25519_keys {
            jwks.append(&mut key_set.read().unwrap().public_jwks());
        }
        if let Some(ref key_set) = self.rsa_keys {
            jwks.append(&mut key_set.read().unwrap().public_jwks());
        }
        reply.send(jwks)
    }
}

impl KeyManagerSender for Addr<RotatingKeys> {}

/// Thread-safe handle to a KeySet.
type KeySetHandle<T> = Arc<RwLock<KeySet<T>>>;

/// A rotating set of 3 keys of a single type.
struct KeySet<T: KeyPairExt> {
    config: Arc<RotateConfig>,
    mtime: SystemTime,
    current: NamedKeyPair<T>,
    current_path: PathBuf,
    next: NamedKeyPair<T>,
    next_path: PathBuf,
    previous: Option<NamedKeyPair<T>>,
    previous_path: PathBuf,
}

impl<T> KeySet<T>
where
    T: KeyPairExt + GeneratedKeyPair + Send + Sync + 'static,
{
    /// Read key pairs of type `T` from a subdir of `keysdir`.
    async fn from_subdir(
        keysdir: impl AsRef<Path>,
        subdir: &str,
        config: &Arc<RotateConfig>,
    ) -> Result<KeySetHandle<T>, RotatingKeysError> {
        let mut dir = keysdir.as_ref().to_path_buf();
        dir.push(subdir);

        fs::create_dir_all(&dir)
            .await
            .map_err(|error| RotatingKeysError::Mkdir {
                path: dir.to_string_lossy().into_owned(),
                error,
            })?;

        let mut current_path = dir.clone();
        current_path.push("current.pem");
        let current = match read_key_file::<T>(&current_path).await? {
            Some(key_pair) => key_pair,
            None => T::generate(config.clone(), current_path.clone()).await,
        };

        // The last modification time of `next.pem`, along with `keys_ttl`,
        // is used to determine when the next rotation should happen.
        let mut next_path = dir.clone();
        next_path.push("next.pem");
        let (next, mtime) = if let Some(key_pair) = read_key_file::<T>(&next_path).await? {
            let mtime = fs::metadata(&next_path)
                .await
                .and_then(|meta| meta.modified())
                .map_err(|error| RotatingKeysError::StatMtime {
                    path: next_path.to_string_lossy().into_owned(),
                    error,
                })?;
            (key_pair, mtime)
        } else {
            (
                T::generate(config.clone(), next_path.clone()).await,
                SystemTime::now(),
            )
        };

        let mut previous_path = dir;
        previous_path.push("previous.pem");
        let previous = read_key_file::<T>(&previous_path).await?;

        let key_set = Arc::new(RwLock::new(KeySet {
            config: config.clone(),
            mtime,
            current,
            current_path,
            next,
            next_path,
            previous,
            previous_path,
        }));

        let initial_delay = Self::check_expiry(key_set.clone()).await;
        task::spawn(Self::rotate_loop(key_set.clone(), initial_delay));

        Ok(key_set)
    }

    /// The async loop that performs key rotation when necessary.
    async fn rotate_loop(handle: KeySetHandle<T>, mut delay: Duration) {
        loop {
            tokio::time::delay_for(delay).await;
            delay = Self::check_expiry(handle.clone()).await;
        }
    }

    /// Check if we should rotate keys, and return how long to delay the next check.
    async fn check_expiry(handle: KeySetHandle<T>) -> Duration {
        let read_handle = handle.clone();
        let (keys_ttl, mtime) = task::spawn_blocking(move || {
            let key_set = read_handle.read().expect("could not read-lock key set");
            (key_set.config.keys_ttl, key_set.mtime)
        })
        .await
        .unwrap();
        let delay = if let Ok(age) = SystemTime::now().duration_since(mtime) {
            keys_ttl.checked_sub(age)
        } else {
            warn!("Key set mtime is from the future, treating as bad input.");
            None
        };
        if let Some(delay) = delay {
            delay
        } else {
            Self::rotate(handle).await;
            keys_ttl
        }
    }

    /// Rotate keys in memory and on disk.
    ///
    /// If this fails, we panic, because it may happen at an arbitrary moment at run-time.
    async fn rotate(handle: KeySetHandle<T>) {
        let read_handle = handle.clone();
        let (config, next_path) = task::spawn_blocking(move || {
            let key_set = read_handle.read().expect("could not read-lock key set");
            std::fs::rename(&key_set.current_path, &key_set.previous_path)
                .expect("could not rename current key for rotation");
            std::fs::rename(&key_set.next_path, &key_set.current_path)
                .expect("could not rename next key for rotation");
            (key_set.config.clone(), key_set.next_path.clone())
        })
        .await
        .unwrap();
        let mut tmp = T::generate(config, next_path).await;
        task::spawn_blocking(move || {
            let mut key_set = handle.write().expect("could not write-lock key set");
            mem::swap(&mut key_set.next, &mut tmp);
            mem::swap(&mut key_set.current, &mut tmp);
            key_set.previous = Some(tmp);
        })
        .await
        .unwrap()
    }
}

impl<T: KeyPairExt> KeySet<T> {
    /// Get a list of JWKs containing public keys.
    fn public_jwks(&self) -> Vec<json::Value> {
        let mut list = vec![self.current.public_jwk(), self.next.public_jwk()];
        if let Some(ref previous) = self.previous {
            list.push(previous.public_jwk());
        }
        list
    }
}

/// Trait for key pair types we can generate.
trait GeneratedKeyPair: KeyPairExt + Sized {
    /// Generate a new key pair.
    ///
    /// If this fails, we panic, because it may happen at an arbitrary moment at run-time.
    ///
    /// This should log a message at info-level on success.
    ///
    /// Note that this function may block.
    fn generate(config: Arc<RotateConfig>, out_file: PathBuf) -> BoxFuture<NamedKeyPair<Self>>;

    /// Convert a ParsedKeyPair, if it is of the correct type.
    fn from_parsed(
        parsed: ParsedKeyPair,
        path: &Path,
    ) -> Result<NamedKeyPair<Self>, RotatingKeysError>;
}

impl GeneratedKeyPair for Ed25519KeyPair {
    fn generate(config: Arc<RotateConfig>, out_file: PathBuf) -> BoxFuture<NamedKeyPair<Self>> {
        Box::pin(async move {
            let doc =
                Self::generate_pkcs8(&*config.rng).expect("could not generate Ed25519 key pair");
            let key_pair =
                Self::from_pkcs8(doc.as_ref()).expect("could not parse generated Ed25519 key pair");
            let file = File::create(&out_file)
                .await
                .expect("could not open generated key pair output file");
            pem::write_pkcs8(&doc, file)
                .await
                .expect("could not write generated key pair to output file");
            info!("Generated new Ed25519 key: {:?}", out_file);
            key_pair.into()
        })
    }

    fn from_parsed(
        parsed: ParsedKeyPair,
        path: &Path,
    ) -> Result<NamedKeyPair<Self>, RotatingKeysError> {
        match parsed {
            ParsedKeyPair::Ed25519(inner) => Ok(inner.into()),
            other => Err(RotatingKeysError::InvalidKeyType {
                path: path.to_string_lossy().into_owned(),
                want: "Ed25519",
                found: other.kind(),
            }),
        }
    }
}

impl GeneratedKeyPair for RsaKeyPair {
    fn generate(config: Arc<RotateConfig>, out_file: PathBuf) -> BoxFuture<NamedKeyPair<Self>> {
        Box::pin(async move {
            let mut args: Vec<OsString> = config
                .generate_rsa_command
                .iter()
                .map(|arg| arg.into())
                .collect();
            let program = args.remove(0);
            let file = if let Some(part) = args.iter_mut().find(|part| part.as_os_str() == "{}") {
                *part = out_file.clone().into();
                None
            } else {
                let file = File::create(&out_file)
                    .await
                    .expect("could not open generated key pair output file");
                Some(file)
            };
            let mut command = Command::new(program);
            command.args(args).stdin(Stdio::null());
            if let Some(file) = file {
                command.stdout(file.into_std().await);
            }
            let status = command
                .status()
                .await
                .expect("Failed to run command to generate RSA key");
            if !status.success() {
                panic!("Command to generate RSA key failed with status {}", status);
            }
            let key_pair = read_key_file(&out_file)
                .await
                .expect("could not read generated RSA key file")
                .expect("generated RSA key file not found");
            info!("Generated new RSA key: {:?}", out_file);
            key_pair
        })
    }

    fn from_parsed(
        parsed: ParsedKeyPair,
        path: &Path,
    ) -> Result<NamedKeyPair<Self>, RotatingKeysError> {
        match parsed {
            ParsedKeyPair::Rsa(inner) => Ok(inner.into()),
            other => Err(RotatingKeysError::InvalidKeyType {
                path: path.to_string_lossy().into_owned(),
                want: "RSA",
                found: other.kind(),
            }),
        }
    }
}

/// Read a single key pair of type `T` from `path`.
///
/// Returns `None` when the file does not exist.
///
/// Note that this function may block.
async fn read_key_file<T: KeyPairExt + GeneratedKeyPair>(
    path: &Path,
) -> Result<Option<NamedKeyPair<T>>, RotatingKeysError> {
    let file = match File::open(path).await {
        Ok(file) => file,
        Err(error) => {
            if error.kind() == IoErrorKind::NotFound {
                return Ok(None);
            } else {
                return Err(RotatingKeysError::Open {
                    path: path.to_string_lossy().into_owned(),
                    error,
                });
            }
        }
    };
    let mut key_pairs = pem::parse_key_pairs(BufReader::new(file))
        .await
        .map_err(|error| RotatingKeysError::Parse {
            path: path.to_string_lossy().into_owned(),
            error,
        })?;
    if key_pairs.len() != 1 {
        return Err(RotatingKeysError::ExpectedOneKey {
            path: path.to_string_lossy().into_owned(),
            found: key_pairs.len(),
        });
    }
    let key_pair = key_pairs.pop().unwrap();
    Ok(Some(T::from_parsed(key_pair, path)?))
}
