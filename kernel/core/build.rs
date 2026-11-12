// SPDX-License-Identifier: MPL-2.0

//! Generates the optional function-hook source tree without changing the inputs.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "rsm-hooks")]
    generate_hooks();
}

#[cfg(feature = "rsm-hooks")]
fn generate_hooks() {
    use std::{env, fs, path::PathBuf};

    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=rsm-hooks.toml");
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let source_tree = output.join("rsm-hook-src");
    println!(
        "cargo:rustc-env=SHORT_VIS_PATH_GENERATED_ROOT={}",
        source_tree.display()
    );
    let config = rsm_instrument::Config::from_file(&manifest.join("rsm-hooks.toml"))
        .expect("read the function-hook selection");
    let report = rsm_instrument::instrument_tree(&manifest.join("src"), &source_tree, &config)
        .expect("generate the function-hook source tree");
    report
        .write_json(&output.join("rsm-hooks-report.json"))
        .expect("write the function-hook coverage report");

    let mut modules = String::new();
    for (name, visibility) in [
        ("fs", "pub "),
        ("ipc", ""),
        ("net", ""),
        ("process", "pub "),
        ("syscall", ""),
        ("vm", "pub "),
    ] {
        let path = source_tree.join(name).join("mod.rs");
        modules.push_str(&format!("#[path = {path:?}] {visibility}mod {name};\n"));
    }
    fs::write(output.join("rsm-hook-modules.rs"), modules)
        .expect("write the function-hook module roots");
    println!(
        "cargo:warning=generated {} function hook candidates; coverage report: {}",
        report.instrumented_count(),
        output.join("rsm-hooks-report.json").display(),
    );
}
