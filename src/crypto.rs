extern crate rand;

use emailaddress::EmailAddress;
use openssl::bn::BigNum;
use openssl::crypto::hash;
use openssl::crypto::pkey::PKey;
use openssl::crypto::rsa::RSA;
use self::rand::{OsRng, Rng};
use serde_json::builder::ObjectBuilder;
use serde_json::value::Value;
use super::AppConfig;
use rustc_serialize::base64::{self, FromBase64, ToBase64};
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


/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(set: &Value, kid: &str) -> Result<PKey, ()> {
    let matching = set.find("keys").unwrap().as_array().unwrap().iter()
        .filter(|key_obj| {
            key_obj.find("kid").unwrap().as_string().unwrap() == kid &&
            key_obj.find("use").unwrap().as_string().unwrap() == "sig"
        })
        .collect::<Vec<&Value>>();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let n_b64 = matching[0].find("n").unwrap().as_string().unwrap();
    let e_b64 = matching[0].find("e").unwrap().as_string().unwrap();
    let n = BigNum::new_from_slice(&n_b64.from_base64().unwrap()).unwrap();
    let e = BigNum::new_from_slice(&e_b64.from_base64().unwrap()).unwrap();
    let mut pub_key = PKey::new();
    pub_key.set_rsa(&RSA::from_public_components(n, e).unwrap());
    Ok(pub_key)
}
