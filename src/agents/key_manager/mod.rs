use serde_json::Value as JsonValue;
use std::time::SystemTime;

use crate::crypto::SigningAlgorithm;
use crate::utils::{
    agent::{Message, Sender},
    keys::SignError,
};

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
pub struct GetPublicJwksReply {
    pub jwks: Vec<JsonValue>,
    pub expires: Option<SystemTime>,
}
impl Message for GetPublicJwks {
    type Reply = GetPublicJwksReply;
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
