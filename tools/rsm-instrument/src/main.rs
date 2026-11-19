// SPDX-License-Identifier: MPL-2.0

//! Generates an instrumented source tree and a candidate report.

use std::{env, path::Path};

use rsm_instrument::{Config, InstrumentError, instrument_tree};

fn main() -> Result<(), InstrumentError> {
    let arguments: Vec<_> = env::args_os().skip(1).collect();
    if !(2..=3).contains(&arguments.len()) {
        return Err("usage: rsm-instrument SOURCE DESTINATION [CONFIG.toml]".into());
    }
    let source = Path::new(&arguments[0]);
    let destination = Path::new(&arguments[1]);
    let config = arguments
        .get(2)
        .map(|path| Config::from_file(Path::new(path)))
        .transpose()?
        .unwrap_or_default();
    let report = instrument_tree(source, destination, &config)?;
    report.write_json(&destination.join("rsm-hooks.json"))?;
    println!(
        "instrumented {} of {} source candidates; report: {}",
        report.instrumented_count(),
        report.functions.len(),
        destination.join("rsm-hooks.json").display(),
    );
    Ok(())
}
