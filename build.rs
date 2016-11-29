// Stable Rust doesn't yet support the custom_derive feature, so we generate
// code for structures which #[derive] Serde's Serialize/Deserialize traits.
//
// See https://serde.rs/codegen-stable.html for more information.

extern crate serde_codegen;

use std::env;
use std::path::Path;

pub fn main() {
    let src_dir = Path::new("src");
    let out_dir = env::var_os("OUT_DIR").expect("build.rs $OUT_DIR not specified");

    for basename in &["config", "crypto"] {
        let src_filename = format!("{}_serde.in.rs", basename);
        let out_filename = format!("{}_serde.rs", basename);

        let src = Path::new(&src_dir).join(&src_filename);
        let out = Path::new(&out_dir).join(&out_filename);

        serde_codegen::expand(&src, &out).expect("serde codegen failed");
    }
}
