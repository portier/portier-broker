// Stable Rust 1.9 doesn't support the custom_derive feature, so we generate
// code to for structures which derive Serde's Serialize/Deserialize traits.

extern crate serde_codegen;

use std::env;
use std::path::Path;

pub fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();

    let src = Path::new("src/lib.rs.in");
    let dst = Path::new(&out_dir).join("lib.rs");

    serde_codegen::expand(&src, &dst).unwrap();
}
