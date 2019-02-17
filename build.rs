extern crate glob;

use glob::glob;
use std::process::Command;

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
    build_gettext();
}
