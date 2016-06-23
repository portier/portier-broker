// Stable Rust 1.9 doesn't support the custom_derive feature, so we generate
// code to for structures which derive Serde's Serialize/Deserialize traits.
//
// See ../build.rs for the use of serde_codegen.

extern crate serde;

include!(concat!(env!("OUT_DIR"), "/lib.rs"));
