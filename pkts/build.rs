use std::process::{Command, Output};
use std::{env, str};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let version = rustc_minor_version();

    if version >= 77 {
        set_cfg("rustc_1_77");
    }
}

fn rustc_version_cmd(is_clippy_driver: bool) -> Output {
    let rustc = env::var_os("RUSTC").expect("Failed to get rustc version: missing RUSTC env");

    let mut cmd = match env::var_os("RUSTC_WRAPPER") {
        Some(ref wrapper) if wrapper.is_empty() => Command::new(rustc),
        Some(wrapper) => {
            let mut cmd = Command::new(wrapper);
            cmd.arg(rustc);
            if is_clippy_driver {
                cmd.arg("--rustc");
            }

            cmd
        }
        None => Command::new(rustc),
    };

    cmd.arg("--version");

    let output = cmd.output().expect("Failed to get rustc version");

    if !output.status.success() {
        panic!(
            "failed to run rustc: {}",
            String::from_utf8_lossy(output.stderr.as_slice())
        );
    }

    output
}

fn rustc_minor_version() -> u32 {
    let mut output = rustc_version_cmd(false);

    if str::from_utf8(&output.stdout)
        .unwrap()
        .starts_with("clippy")
    {
        output = rustc_version_cmd(true);
    }

    let version = str::from_utf8(&output.stdout).unwrap();

    let mut pieces = version.split('.');

    if pieces.next() != Some("rustc 1") {
        panic!("Rust version missing beginning `rustc 1.` tag");
    }

    pieces.next().unwrap().parse().unwrap()
}

fn set_cfg(cfg: &str) {
    println!("cargo:rustc-cfg={}", cfg);
}
