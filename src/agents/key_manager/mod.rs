use crate::crypto::SigningAlgorithm;
use crate::utils::agent::{Message, Sender};
use crate::utils::keys::SignError;
use serde_json::Value as JsonValue;

/// Message requesting a JSON payload to be signed.
pub struct SignJws {
    pub payload: JsonValue,
    pub signing_alg: SigningAlgorithm,
}
impl Message for SignJws {
    type Reply = Result<String, SignError>;
}

/// Message requesting a list of public JWKs.
pub struct GetPublicJwks;
impl Message for GetPublicJwks {
    type Reply = Vec<JsonValue>;
}

/// Key manager abstraction. Combines all message types.
///
/// Downside of this is that it needs to be implemented on the agent side as:
/// `impl KeyManagerSender for Addr<FoobarKeyManager> {}`
pub trait KeyManagerSender: Sender<SignJws> + Sender<GetPublicJwks> {}

pub mod manual;
pub mod rotating;

pub use self::manual::{ManualKeys, ManualKeysError};
pub use self::rotating::{Expiring, KeySet, RotateKeys, RotatingKeys, UpdateKeys};
