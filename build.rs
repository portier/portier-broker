// Stable Rust doesn't yet support the custom_derive feature, so we generate
// code for structures which #[derive] Serde's Serialize/Deserialize traits.
//
// See https://serde.rs/codegen-stable.html for more information.

extern crate glob;
extern crate serde_codegen;

use glob::glob;
use std::env;
use std::path::Path;
use std::process::Command;

/// Build Serde generated code.
pub fn build_serde() {
    let out_dir = env::var_os("OUT_DIR").expect("build.rs $OUT_DIR not specified");

    let src = Path::new("src/serde_types.in.rs");
    let dst = Path::new(&out_dir).join("serde_types.rs");

    serde_codegen::expand(&src, &dst).expect("serde codegen failed");
}

// Build gettext catalogs.
pub fn build_gettext() {
    for entry in glob("lang/*.po").expect("failed to glob gettext files") {
        let src = entry.expect("failed to read glob entry");
        let dst = src.with_extension("mo");

        let mut cmd = Command::new("msgfmt");
        cmd.arg(src).arg("-o").arg(dst);
        println!("{:?}", cmd);

        let status = cmd.status().expect("failed to execute msgfmt");
        if !status.success() {
            panic!("msgfmt exited with a failure status");
        }
    }
}

pub fn main() {
    build_serde();
    build_gettext();
}
