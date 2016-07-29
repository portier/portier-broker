extern crate openssl;
extern crate rand;
extern crate rustc_serialize;

use emailaddress::EmailAddress;
use self::openssl::bn::BigNum;
use self::openssl::crypto::hash;
use self::openssl::crypto::pkey::PKey;
use self::openssl::crypto::rsa::RSA;
use self::rand::{OsRng, Rng};
use self::rustc_serialize::base64::{self, FromBase64, ToBase64};
use serde_json::builder::ObjectBuilder;
use serde_json::de::from_slice;
use serde_json::value::Value;
use super::serde_json;
use std::fs::File;
use std::io::{BufReader, Write};


/// A named key pair, for use in JWS signing.
#[derive(Clone)]
pub struct NamedKey {
    id: String,
    key: PKey,
}


impl NamedKey {
    /// Creates a NamedKey for the given key ID. Reads the key pair from the
    /// PEM-encoded file named by the `file` argument.
    pub fn from_file(id: &str, file: &str) -> Result<NamedKey, &'static str> {
        let file_res = File::open(file);
        if file_res.is_err() {
            return Err("could not open key file");
        }
        let private_key_file = file_res.unwrap();
        let key_res = PKey::private_key_from_pem(&mut BufReader::new(private_key_file));
        if key_res.is_err() {
            return Err("could not instantiate private key");
        }
        Ok(NamedKey { id: id.to_string(), key: key_res.unwrap() })
    }

    /// Create a JSON Web Signature (JWS) for the given JSON structure.
    pub fn sign_jws(&self, payload: &Value) -> String {
        let header = serde_json::to_string(
            &ObjectBuilder::new()
                .insert("kid", &self.id)
                .insert("alg", "RS256")
                .build()
            ).unwrap();

        let payload = serde_json::to_string(&payload).unwrap();
        let mut input = Vec::<u8>::new();
        input.extend(header.as_bytes().to_base64(base64::URL_SAFE).into_bytes());
        input.push(b'.');
        input.extend(payload.as_bytes().to_base64(base64::URL_SAFE).into_bytes());

        let sha256 = hash::hash(hash::Type::SHA256, &input);
        let sig = self.key.sign(&sha256);
        input.push(b'.');
        input.extend(sig.to_base64(base64::URL_SAFE).into_bytes());
        String::from_utf8(input).unwrap()
    }

    /// Return JSON represenation of the public key for use in JWK key sets.
    pub fn public_jwk(&self) -> Value {
        fn json_big_num(n: &BigNum) -> String {
            n.to_vec().to_base64(base64::URL_SAFE)
        }
        let rsa = self.key.get_rsa();
        ObjectBuilder::new()
            .insert("kty", "RSA")
            .insert("alg", "RS256")
            .insert("use", "sig")
            .insert("kid", &self.id)
            .insert("n", json_big_num(&rsa.n().unwrap()))
            .insert("e", json_big_num(&rsa.e().unwrap()))
            .build()
    }
}


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


/// Helper function to deserialize key from JWK Key Set.
///
/// Searches the provided JWK Key Set Value for the key matching the given
/// id. Returns a usable public key if exactly one key is found.
pub fn jwk_key_set_find(set: &Value, kid: &str) -> Result<PKey, ()> {
    let matching = set.find("keys").unwrap().as_array().unwrap().iter()
        .filter(|key_obj| {
            key_obj.find("kid").unwrap().as_str().unwrap() == kid &&
            key_obj.find("use").unwrap().as_str().unwrap() == "sig"
        })
        .collect::<Vec<&Value>>();

    // Verify that we found exactly one key matching the key ID.
    if matching.len() != 1 {
        return Err(());
    }

    // Then, use the data to build a public key object for verification.
    let n_b64 = matching[0].find("n").unwrap().as_str().unwrap();
    let e_b64 = matching[0].find("e").unwrap().as_str().unwrap();
    let n = BigNum::new_from_slice(&n_b64.from_base64().unwrap()).unwrap();
    let e = BigNum::new_from_slice(&e_b64.from_base64().unwrap()).unwrap();
    let mut pub_key = PKey::new();
    pub_key.set_rsa(&RSA::from_public_components(n, e).unwrap());
    Ok(pub_key)
}


/// Verify a JWS signature, returning the payload as Value if successful.
pub fn verify_jws(jws: &str, key_set: &Value) -> Result<Value, ()> {
    // Extract the header from the JWT structure. Determine what key was used
    // to sign the token, so we can then verify the signature.
    let parts: Vec<&str> = jws.split('.').collect();
    let jwt_header: Value = from_slice(&parts[0].from_base64().unwrap()).unwrap();
    let kid = jwt_header.find("kid").unwrap().as_str().unwrap();
    let pub_key = try!(jwk_key_set_find(key_set, kid));

    // Verify the identity token's signature.
    let message = format!("{}.{}", parts[0], parts[1]);
    let sha256 = hash::hash(hash::Type::SHA256, message.as_bytes());
    let sig = parts[2].from_base64().unwrap();
    if !pub_key.verify(&sha256, &sig) {
        return Err(());
    }

    Ok(from_slice(&parts[1].from_base64().unwrap()).unwrap())
}
