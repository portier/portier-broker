use crate::crypto::SigningAlgorithm;
use crate::keys::{KeyManager, KeyPairExt, NamedKeyPair, TryFromParsedKeyPair};
use crate::pemfile;
use log::{info, warn};
use ring::{
    rand::SecureRandom,
    signature::{Ed25519KeyPair, RsaKeyPair},
};
use serde_json as json;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{Duration, SystemTime};

/// Struct that contains configuration we pass around.
struct RotateConfig {
    keys_ttl: Duration,
    generate_rsa_command: Vec<String>,
    rng: Box<dyn SecureRandom + Send + Sync>,
}

/// KeyManager where we rotating 3 keys of each type.
pub struct RotatingKeys {
    ed25519_keys: KeySetHandle<Ed25519KeyPair>,
    rsa_keys: KeySetHandle<RsaKeyPair>,
}

impl RotatingKeys {
    pub fn new(
        keysdir: impl AsRef<Path>,
        keys_ttl: u64,
        generate_rsa_command: Vec<String>,
        rng: impl SecureRandom + Send + Sync + 'static,
    ) -> Self {
        info!("Using rotating keys with interval of {} seconds", keys_ttl);
        let rng = Box::new(rng);
        let config = Arc::new(RotateConfig {
            keys_ttl: Duration::from_secs(keys_ttl),
            generate_rsa_command,
            rng,
        });
        let ed25519_keys = KeySet::from_subdir(keysdir.as_ref(), "ed25519", &config);
        let rsa_keys = KeySet::from_subdir(keysdir.as_ref(), "rsa", &config);
        RotatingKeys {
            ed25519_keys,
            rsa_keys,
        }
    }

    /// Get a read lock on the Ed25519 key set, or panic.
    fn read_ed25519_keys(&self) -> RwLockReadGuard<KeySet<Ed25519KeyPair>> {
        self.ed25519_keys
            .read()
            .expect("could not read-lock key set")
    }

    /// Get a read lock on the RSA key set, or panic.
    fn read_rsa_keys(&self) -> RwLockReadGuard<KeySet<RsaKeyPair>> {
        self.rsa_keys.read().expect("could not read-lock key set")
    }
}

impl KeyManager for RotatingKeys {
    fn sign_jws(
        &self,
        payload: &json::Value,
        signing_alg: SigningAlgorithm,
        rng: &dyn SecureRandom,
    ) -> String {
        match signing_alg {
            SigningAlgorithm::EdDsa => self.read_ed25519_keys().current.sign_jws(payload, rng),
            SigningAlgorithm::Rs256 => self.read_rsa_keys().current.sign_jws(payload, rng),
        }
    }

    fn public_jwks(&self) -> Vec<json::Value> {
        let mut jwks = vec![];
        jwks.append(&mut self.read_ed25519_keys().public_jwks());
        jwks.append(&mut self.read_rsa_keys().public_jwks());
        jwks
    }

    fn signing_algs(&self) -> Vec<SigningAlgorithm> {
        // We prefer EdDSA, but list RSA first, in case a client treats the order as preference.
        vec![SigningAlgorithm::Rs256, SigningAlgorithm::EdDsa]
    }
}

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
    T: KeyPairExt + TryFromParsedKeyPair + GeneratedKeyPair + Send + Sync + 'static,
{
    /// Read key pairs of type `T` from a subdir of `keysdir`.
    fn from_subdir(
        keysdir: impl AsRef<Path>,
        subdir: &str,
        config: &Arc<RotateConfig>,
    ) -> KeySetHandle<T> {
        let mut dir = keysdir.as_ref().to_path_buf();
        dir.push(subdir);
        fs::create_dir_all(&dir).expect("could not create keys directory");

        let mut current_path = dir.clone();
        current_path.push("current.pem");
        let current =
            read_key_file::<T>(&current_path).unwrap_or_else(|| T::generate(config, &current_path));

        // The last modification time of `next.pem`, along with `keys_ttl`,
        // is used to determine when the next rotation should happen.
        let mut next_path = dir.clone();
        next_path.push("next.pem");
        let (next, mtime) = read_key_file::<T>(&next_path)
            .map(|key_pair| {
                let mtime = fs::metadata(&next_path)
                    .and_then(|meta| meta.modified())
                    .expect("could not last modification time of next.pem");
                (key_pair, mtime)
            })
            .unwrap_or_else(|| (T::generate(config, &next_path), SystemTime::now()));

        let mut previous_path = dir;
        previous_path.push("previous.pem");
        let previous = read_key_file::<T>(&previous_path);

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
        Self::check_expiry(key_set.clone());
        key_set
    }

    /// Check if we should rotate, and schedule the next check.
    fn check_expiry(handle: KeySetHandle<T>) {
        let delay = {
            let mut key_set = handle.write().expect("could not write-lock key set");
            let delay = if let Ok(age) = SystemTime::now().duration_since(key_set.mtime) {
                key_set.config.keys_ttl.checked_sub(age)
            } else {
                warn!("Key set mtime is from the future, treating as bad input.");
                None
            };
            delay.unwrap_or_else(|| {
                key_set.rotate();
                key_set.config.keys_ttl
            })
        };
        tokio::task::spawn(async move {
            tokio::time::delay_for(delay).await;
            Self::check_expiry(handle);
        });
    }

    /// Rotate keys in memory and on disk.
    fn rotate(&mut self) {
        fs::rename(&self.current_path, &self.previous_path)
            .and_then(|_| fs::rename(&self.next_path, &self.current_path))
            .expect("could not rename keys for rotation");
        let mut tmp = T::generate(&*self.config, &self.next_path);
        mem::swap(&mut self.next, &mut tmp);
        mem::swap(&mut self.current, &mut tmp);
        self.previous = Some(tmp);
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
    fn generate(config: &RotateConfig, out_file: &Path) -> NamedKeyPair<Self>;
}

impl GeneratedKeyPair for Ed25519KeyPair {
    fn generate(config: &RotateConfig, out_file: &Path) -> NamedKeyPair<Self> {
        let doc = Self::generate_pkcs8(&*config.rng).expect("could not generate Ed25519 key pair");
        let key_pair =
            Self::from_pkcs8(doc.as_ref()).expect("could not parse generated Ed25519 key pair");
        let mut file =
            File::create(out_file).expect("could not open generated key pair output file");
        pemfile::write_pkcs8(&doc, &mut file)
            .expect("could not write generated key pair to output file");
        info!("Generated new Ed25519 key: {:?}", out_file);
        key_pair.into()
    }
}

impl GeneratedKeyPair for RsaKeyPair {
    fn generate(config: &RotateConfig, out_file: &Path) -> NamedKeyPair<Self> {
        let mut args: Vec<OsString> = config
            .generate_rsa_command
            .iter()
            .map(|arg| arg.into())
            .collect();
        let program = args.remove(0);
        let file = if let Some(part) = args.iter_mut().find(|part| part.as_os_str() == "{}") {
            *part = out_file.to_path_buf().into();
            None
        } else {
            Some(File::create(out_file).expect("could not open generated key pair output file"))
        };
        let mut command = Command::new(program);
        command.args(args).stdin(Stdio::null());
        if let Some(file) = file {
            command.stdout(file);
        }
        let status = command
            .status()
            .expect("Failed to run command to generate RSA key");
        if !status.success() {
            panic!("Command to generate RSA key failed with status {}", status);
        }
        let key_pair = read_key_file(out_file).expect("generated RSA key file not found");
        info!("Generated new RSA key: {:?}", out_file);
        key_pair
    }
}

/// Read a single key pair of type `T` from `path`.
///
/// Returns `None` when the file does not exist.
fn read_key_file<T: KeyPairExt + TryFromParsedKeyPair>(path: &Path) -> Option<NamedKeyPair<T>> {
    let file = File::open(path).map(Some).unwrap_or_else(|err| {
        if err.kind() == ErrorKind::NotFound {
            None
        } else {
            panic!("Could not open '{:?}': {:?}", path, err)
        }
    })?;
    let mut key_pairs =
        pemfile::parse_key_pairs(&mut std::io::BufReader::new(file)).expect("Could not parse PEM");
    let key_pair = key_pairs.pop().expect("No keys found in PEM");
    if !key_pairs.is_empty() {
        panic!("Multiple keys found in PEM");
    }
    Some(
        T::try_from_parsed_key_pair(key_pair)
            .expect("Invalid key type")
            .into(),
    )
}
