extern crate rand;

use emailaddress::EmailAddress;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use self::rand::{OsRng, Rng};
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use super::AppConfig;
use rustc_serialize::base64::{self, ToBase64};
use std::io::Write;


/// Helper function to build a session ID for a login attempt.
///
/// Put the email address, the client ID (RP origin) and some randomness into
/// a SHA256 hash, and encode it with URL-safe bas64 encoding. This is used
/// as the key in Redis, as well as the state for OAuth authentication.
pub fn session_id(email: &EmailAddress, client_id: &str) -> String {
    let mut rng = OsRng::new().unwrap();
    let mut bytes_iter = rng.gen_iter();
    let rand_bytes: Vec<u8> = (0..16).map(|_| bytes_iter.next().unwrap()).collect();

    let mut hasher = hash::Hasher::new(hash::Type::SHA256);
    hasher.write(email.to_string().as_bytes()).unwrap();
    hasher.write(client_id.as_bytes()).unwrap();
    hasher.write(&rand_bytes).unwrap();
    hasher.finish().to_base64(base64::URL_SAFE)
}


/// Helper function to build a JWK key set JSON Value.
///
/// Returns a Value representing the JWK Key Set containing the public
/// components for the AppConfig's private key, for use in signature
/// verification.
pub fn jwk_key_set(app: &AppConfig) -> Value {

    fn json_big_num(n: &BigNum) -> String {
        n.to_vec().to_base64(base64::URL_SAFE)
    }

    let rsa = app.priv_key.get_rsa();
    ObjectBuilder::new()
        .insert_array("keys", |builder| {
            builder.push_object(|builder| {
                builder.insert("kty", "RSA")
                    .insert("alg", "RS256")
                    .insert("use", "sig")
                    .insert("kid", "base")
                    .insert("n", json_big_num(&rsa.n().unwrap()))
                    .insert("e", json_big_num(&rsa.e().unwrap()))
            })
        })
        .unwrap()
}
