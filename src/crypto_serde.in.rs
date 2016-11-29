// Included by src/crypto.rs until stable Rust supports custom_derive.
//
// See https://serde.rs/codegen-stable.html for more information.


/// Private key metadata
#[derive(Default,Deserialize)]
struct PrivateKeyMetadata {
    valid_from: Option<DateTime<UTC>>,
}
