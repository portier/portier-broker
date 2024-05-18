use crate::agents::*;
use crate::crypto::SigningAlgorithm;
use crate::utils::keys::GenerateRsaConfig;
use crate::utils::{
    agent::*,
    keys::{GeneratedKeyPair, KeyPairExt, NamedKeyPair, SignError},
    pem, DelayQueueTask, SecureRandom,
};
use aws_lc_rs::signature::{Ed25519KeyPair, RsaKeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Message used to do post-init checks.
pub struct Check;
impl Message for Check {
    type Reply = ();
}

/// Message requesting a key set be updated.
///
/// The store sends this message to load the initial keys, when it has updated the key set, or when
/// it noticed another worker has updated the key set (if applicable).
///
/// When received, the key manager will try to install keys, or start rotation if necessary by
/// sending `RotateKeysLocked` to the store. If keys were successfully installed, a timer will be
/// set for the next rotation, which is also initiated with `RotateKeysLocked`.
pub struct UpdateKeys(pub KeySet);
impl Message for UpdateKeys {
    type Reply = ();
}

/// Message requesting keys be rotated.
///
/// This message is part of a larger flow that starts with the key manager sending
/// `RotateKeysLocked` to the store, to acquire an exclusive lock. Once locked, the store then
/// sends `RotateKeys` back to let the key manager handle actual rotation.
///
/// The current key set is provided by the sender. The key manager will then inspect expiry times
/// and update the key set as necessary. A new key set is returned only if changes were made.
///
/// If the key manager returns an new key set, the store should save it, then send `UpdateKeys` to
/// the key manager to install the new key set. The returned key set is guaranteed to have at least
/// `current` and `next` keys set.
///
/// (The store is also responsible for notifying other workers of key updates, if applicable.)
pub struct RotateKeys(pub KeySet);
impl Message for RotateKeys {
    type Reply = Option<KeySet>;
}

/// Combines any type with an `SystemTime` expiry time.
#[derive(Clone, Serialize, Deserialize)]
pub struct Expiring<T> {
    pub value: T,
    pub expires: SystemTime,
}

impl<T> Expiring<T> {
    /// Whether this value has not yet expired.
    pub fn is_alive(&self) -> bool {
        self.expires > SystemTime::now()
    }
}

/// A rotating set of 3 keys.
///
/// This is the storage representation, and contains each of the keys in PEM format.
#[derive(Clone, Serialize, Deserialize)]
pub struct KeySet {
    pub signing_alg: SigningAlgorithm,
    pub current: Option<Expiring<String>>,
    pub next: Option<Expiring<String>>,
    pub previous: Option<String>,
}

impl KeySet {
    /// Create an empty key set.
    pub fn empty(signing_alg: SigningAlgorithm) -> Self {
        KeySet {
            signing_alg,
            current: None,
            next: None,
            previous: None,
        }
    }
}

/// Internal variant of `KeySet` where the PEM was parsed.
struct ActiveKeySet<T: KeyPairExt + GeneratedKeyPair> {
    current: NamedKeyPair<T>,
    next: NamedKeyPair<T>,
    previous: Option<NamedKeyPair<T>>,
    expires: SystemTime,
}

impl<T: KeyPairExt + GeneratedKeyPair> ActiveKeySet<T> {
    fn parse(key_set: &KeySet) -> Self {
        let (current, expires) = key_set
            .current
            .as_ref()
            .map(|entry| (Self::parse_one(&entry.value).into(), entry.expires))
            .expect("Provided key set does not have a current key");
        let next = key_set
            .next
            .as_ref()
            .map(|entry| Self::parse_one(&entry.value).into())
            .expect("Provided key set does not have a next key");
        let previous = key_set
            .previous
            .as_ref()
            .map(|value| Self::parse_one(value).into());
        Self {
            current,
            next,
            previous,
            expires,
        }
    }

    fn parse_one(pem: &str) -> T {
        let mut entries = pem::parse_key_pairs(pem.as_bytes()).unwrap();
        assert!(entries.len() == 1, "Expected exactly one key in PEM");
        let entry = entries.pop().unwrap().expect("Could not parse key as PEM");
        T::from_parsed(entry.key_pair).expect("Found key pair of incorrect type")
    }

    fn append_public_jwks(&self, vec: &mut Vec<serde_json::Value>) {
        vec.push(self.current.public_jwk());
        vec.push(self.next.public_jwk());
        if let Some(previous) = self.previous.as_ref() {
            vec.push(previous.public_jwk());
        }
    }
}

/// A `KeyManager` where we rotate 3 keys of each type.
pub struct RotatingKeys {
    store: Arc<dyn StoreSender>,
    keys_ttl: Duration,
    signing_algs: HashSet<SigningAlgorithm>,
    rsa_modulus_bits: usize,
    generate_rsa_command: Vec<String>,
    rng: SecureRandom,
    ed25519_keys: Option<ActiveKeySet<Ed25519KeyPair>>,
    rsa_keys: Option<ActiveKeySet<RsaKeyPair>>,
    delays: Option<DelayQueueTask<SigningAlgorithm>>,
}

impl RotatingKeys {
    pub fn new(
        store: Arc<dyn StoreSender>,
        keys_ttl: Duration,
        signing_algs: &[SigningAlgorithm],
        rsa_modulus_bits: usize,
        generate_rsa_command: Vec<String>,
        rng: SecureRandom,
    ) -> Self {
        log::info!(
            "Using rotating keys with a {}s interval and algorithms: {}",
            keys_ttl.as_secs(),
            SigningAlgorithm::format_list(signing_algs)
        );
        RotatingKeys {
            store,
            keys_ttl,
            signing_algs: signing_algs.iter().copied().collect(),
            rsa_modulus_bits,
            generate_rsa_command,
            rng,
            ed25519_keys: None,
            rsa_keys: None,
            delays: None,
        }
    }

    fn generate_one(&self, signing_alg: SigningAlgorithm) -> String {
        use SigningAlgorithm::*;
        match signing_alg {
            EdDsa => Ed25519KeyPair::generate(self.rng.clone()),
            Rs256 => <RsaKeyPair as GeneratedKeyPair>::generate(GenerateRsaConfig {
                rng: self.rng.clone(),
                modulus_bits: self.rsa_modulus_bits,
                command: self.generate_rsa_command.clone(),
            }),
        }
    }
}

impl Agent for RotatingKeys {
    fn started(&mut self, cx: Context<Self, AgentStarted>) {
        // Initialize timer task.
        let store = self.store.clone();
        self.delays = Some(DelayQueueTask::spawn(move |signing_alg| {
            log::info!(
                "Reached expiry time for {} keys, attempting rotation.",
                signing_alg
            );
            store.send(RotateKeysLocked(signing_alg));
        }));

        // Enable key rotation in the store.
        let me = cx.addr().clone();
        let store = self.store.clone();
        let enable_msg = EnableRotatingKeys {
            key_manager: cx.addr().clone(),
            signing_algs: self.signing_algs.clone(),
        };
        cx.reply_later(async move {
            store.send(enable_msg).await;
            me.send(Check).await;
        });
    }
}

impl Handler<Check> for RotatingKeys {
    fn handle(&mut self, _message: Check, cx: Context<Self, Check>) {
        // Make sure key sets are present for all algorithms.
        for signing_alg in &self.signing_algs {
            use SigningAlgorithm::*;
            if match signing_alg {
                EdDsa => self.ed25519_keys.is_none(),
                Rs256 => self.rsa_keys.is_none(),
            } {
                panic!("Store did not provide a key set for {signing_alg}");
            }
        }
        cx.reply(());
    }
}

impl Handler<UpdateKeys> for RotatingKeys {
    fn handle(&mut self, message: UpdateKeys, cx: Context<Self, UpdateKeys>) {
        use SigningAlgorithm::*;

        let key_set = message.0;

        // Start rotation if the store loaded incomplete or expired keys.
        let has_current = key_set
            .current
            .as_ref()
            .filter(|entry| entry.is_alive())
            .is_some();
        let has_next = key_set
            .next
            .as_ref()
            .filter(|entry| entry.is_alive())
            .is_some();
        if !has_current || !has_next {
            let store = self.store.clone();
            return cx.reply_later(async move {
                log::info!(
                    "Store loaded incomplete or expired keys for {}, attempting rotation.",
                    key_set.signing_alg
                );
                store.send(RotateKeysLocked(key_set.signing_alg)).await;
            });
        }

        // Parse and activate keys. After this, we can be sure usable keys are loaded.
        match key_set.signing_alg {
            Rs256 => self.rsa_keys = Some(ActiveKeySet::parse(&key_set)),
            EdDsa => self.ed25519_keys = Some(ActiveKeySet::parse(&key_set)),
        }

        // Sanity checks.
        let KeySet {
            signing_alg,
            current,
            next,
            ..
        } = key_set;
        let current = current.unwrap();
        let next = next.unwrap();
        assert!(next.expires > current.expires);

        // Set a timer for the next rotation.
        let delays = self.delays.clone();
        cx.reply_later(async move {
            delays.unwrap().insert(signing_alg, current.expires).await;
            log::info!("New {} keys installed.", signing_alg);
        });
    }
}

impl Handler<RotateKeys> for RotatingKeys {
    fn handle(&mut self, message: RotateKeys, cx: Context<Self, RotateKeys>) {
        // Sanity checks.
        let KeySet {
            signing_alg,
            mut current,
            mut next,
            mut previous,
        } = message.0;
        if let (Some(current), Some(next)) = (&current, &next) {
            assert!(next.expires > current.expires);
        }

        // Rotate twice, in case we skipped some time and `next` has also expired.
        for _ in 0..2 {
            if current.as_ref().filter(|entry| entry.is_alive()).is_none() {
                previous = current.map(|entry| entry.value);
                current = next;
                next = None;
            } else if let Some(entry) = next.as_ref() {
                assert!(entry.is_alive());
                break;
            }
        }

        if current.is_some() && next.is_some() {
            log::info!("No keys rotated for {}", signing_alg);
            return cx.reply(None);
        }

        if current.is_none() {
            current = Some(Expiring {
                value: self.generate_one(signing_alg),
                expires: SystemTime::now() + self.keys_ttl,
            });
            log::info!("Generated current key for {}.", signing_alg);
        }
        if next.is_none() {
            next = Some(Expiring {
                value: self.generate_one(signing_alg),
                expires: current.as_ref().unwrap().expires + self.keys_ttl,
            });
            log::info!("Generated next key for {}.", signing_alg);
        }

        cx.reply(Some(KeySet {
            signing_alg,
            current,
            next,
            previous,
        }));
    }
}

impl Handler<SignJws> for RotatingKeys {
    fn handle(&mut self, message: SignJws, cx: Context<Self, SignJws>) {
        use SigningAlgorithm::*;
        let maybe_jws = match message.signing_alg {
            EdDsa => self
                .ed25519_keys
                .as_ref()
                .map(|set| set.current.sign_jws(&message.payload, &self.rng)),
            Rs256 => self
                .rsa_keys
                .as_ref()
                .map(|set| set.current.sign_jws(&message.payload, &self.rng)),
        };
        cx.reply(maybe_jws.unwrap_or(Err(SignError::UnsupportedAlgorithm(message.signing_alg))));
    }
}

impl Handler<GetPublicJwks> for RotatingKeys {
    fn handle(&mut self, _message: GetPublicJwks, cx: Context<Self, GetPublicJwks>) {
        let mut jwks = vec![];
        let mut expires = SystemTime::now() + self.keys_ttl;
        if let Some(ref key_set) = self.ed25519_keys {
            key_set.append_public_jwks(&mut jwks);
            if key_set.expires < expires {
                expires = key_set.expires;
            }
        }
        if let Some(ref key_set) = self.rsa_keys {
            key_set.append_public_jwks(&mut jwks);
            if key_set.expires < expires {
                expires = key_set.expires;
            }
        }
        cx.reply(GetPublicJwksReply {
            jwks,
            expires: Some(expires),
        });
    }
}

impl KeyManagerSender for Addr<RotatingKeys> {}
