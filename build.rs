// Stable Rust doesn't yet support the custom_derive feature, so we generate
// code for structures which #[derive] Serde's Serialize/Deserialize traits.
//
// See https://serde.rs/codegen-stable.html for more information.

extern crate serde_codegen;

use std::env;
use std::path::Path;

pub fn main() {
    let out_dir = env::var_os("OUT_DIR").expect("build.rs $OUT_DIR not specified");

    let src = Path::new("src/config_serde.in.rs");
    let dst = Path::new(&out_dir).join("config_serde.rs");

    serde_codegen::expand(&src, &dst).expect("serde codegen failed");
}
