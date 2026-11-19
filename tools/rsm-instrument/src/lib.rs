// SPDX-License-Identifier: MPL-2.0

//! Build-time source instrumentation for dynamically attached RSM observers.
//!
//! The generator copies a source tree and wraps eligible function bodies in
//! ordinary safe Rust. Generated code still passes through the target crate's
//! type and borrow checking. The source report lists candidates before `cfg`
//! expansion; the running kernel's hook catalog is authoritative for its build.

mod transform;

use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

/// An instrumentation error with source-file context.
pub type InstrumentError = Box<dyn Error + Send + Sync>;

/// Source selection for a generated copy of a crate.
///
/// Patterns match slash-separated paths relative to the source directory.
/// `*` matches any sequence, including `/`; exclusions take precedence.
/// Function patterns additionally match the report's source-qualified name.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub functions: Vec<String>,
    pub exclude_functions: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            include: ["syscall/*", "fs/*", "net/*", "vm/*", "process/*", "ipc/*"]
                .map(str::to_owned)
                .to_vec(),
            exclude: vec!["syscall/rsm.rs".into()],
            functions: Vec::new(),
            exclude_functions: Vec::new(),
        }
    }
}

impl Config {
    /// Reads a TOML selection file.
    pub fn from_file(path: &Path) -> Result<Self, InstrumentError> {
        Ok(toml::from_str(&fs::read_to_string(path)?)?)
    }

    fn selects_file(&self, path: &str) -> bool {
        self.include.iter().any(|pattern| matches(pattern, path))
            && !self.exclude.iter().any(|pattern| matches(pattern, path))
    }

    fn selects_function(&self, name: &str) -> bool {
        (self.functions.is_empty() || self.functions.iter().any(|pattern| matches(pattern, name)))
            && !self
                .exclude_functions
                .iter()
                .any(|pattern| matches(pattern, name))
    }
}

/// A source-level function considered by the generator.
#[derive(Clone, Debug, Serialize)]
pub struct FunctionReport {
    pub source: String,
    pub line: usize,
    pub function: String,
    pub instrumented: bool,
    pub reason: Option<String>,
    pub entry_fields: Vec<FieldReport>,
    pub return_fields: Vec<FieldReport>,
    pub omitted_arguments: Vec<String>,
}

/// A scalar field copied into an event.
#[derive(Clone, Debug, Serialize)]
pub struct FieldReport {
    pub name: String,
    pub ty: String,
}

/// Source candidates and omissions from one generation pass.
#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub functions: Vec<FunctionReport>,
}

impl Report {
    /// Returns the number of source-level instrumented candidates.
    pub fn instrumented_count(&self) -> usize {
        self.functions
            .iter()
            .filter(|item| item.instrumented)
            .count()
    }

    /// Writes the report without claiming that all `cfg` branches were compiled.
    pub fn write_json(&self, path: &Path) -> Result<(), InstrumentError> {
        replace_file(path)?.write_all(&serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }
}

/// Copies a source tree and instruments selected function bodies.
///
/// The destination must be outside the source tree and dedicated to generation.
/// Its contents are replaced completely; source files are never modified. Only ordinary files and
/// directories are accepted. Existing destination symlinks are rejected before
/// copying, and files are recreated rather than truncating possible hard links.
/// The caller must keep the destination exclusively owned during generation.
pub fn instrument_tree(
    source: &Path,
    destination: &Path,
    config: &Config,
) -> Result<Report, InstrumentError> {
    let source = source.canonicalize()?;
    let destination = resolve_destination(destination)?;
    if destination.starts_with(&source) || source.starts_with(&destination) {
        return Err("source and generated destination must be disjoint".into());
    }
    validate_destination_tree(&destination)?;
    if destination.exists() {
        fs::remove_dir_all(&destination)?;
    }
    fs::create_dir_all(&destination)?;

    let mut report = Report::default();
    copy_directory(&source, &source, &destination, config, &mut report)?;
    Ok(report)
}

/// Instruments a source file while preserving text outside function bodies.
///
/// `relative_path` identifies the source in diagnostics and selection patterns.
/// The returned report contains pre-configuration source candidates, including
/// skipped signatures and payload omissions.
pub fn instrument_source(
    source: &str,
    relative_path: &str,
    config: &Config,
) -> Result<(String, Report), InstrumentError> {
    if !config.selects_file(relative_path) {
        return Ok((source.to_owned(), Report::default()));
    }
    transform::instrument(source, relative_path, config)
}

fn copy_directory(
    root: &Path,
    source: &Path,
    destination: &Path,
    config: &Config,
    report: &mut Report,
) -> Result<(), InstrumentError> {
    fs::create_dir_all(destination)?;
    let mut entries = fs::read_dir(source)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        // macOS archive/copy tools can add AppleDouble metadata beside sources.
        // Those binary files are not Rust modules, even when named `._foo.rs`.
        if entry.file_name().to_string_lossy().starts_with("._") {
            continue;
        }
        let file_type = entry.file_type()?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if file_type.is_dir() {
            copy_directory(root, &source_path, &destination_path, config, report)?;
        } else if file_type.is_file() {
            let relative = relative_name(root, &source_path)?;
            if source_path
                .extension()
                .is_some_and(|extension| extension == "rs")
                && config.selects_file(&relative)
            {
                let contents = fs::read_to_string(&source_path)?;
                let (generated, file_report) = instrument_source(&contents, &relative, config)
                    .map_err(|error| format!("{}: {error}", source_path.display()))?;
                replace_file(&destination_path)?.write_all(generated.as_bytes())?;
                report.functions.extend(file_report.functions);
            } else {
                let mut source = fs::File::open(source_path)?;
                io::copy(&mut source, &mut replace_file(&destination_path)?)?;
            }
        } else {
            return Err(format!("unsupported source file: {}", source_path.display()).into());
        }
    }
    Ok(())
}

fn resolve_destination(path: &Path) -> Result<PathBuf, InstrumentError> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(format!("generated destination is a symlink: {}", path.display()).into());
    }
    let mut ancestor = std::path::absolute(path)?;
    if ancestor
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err("generated destination must not contain parent components".into());
    }
    let mut suffix = Vec::new();
    while !ancestor.exists() {
        suffix.push(
            ancestor
                .file_name()
                .ok_or("invalid generated destination")?
                .to_owned(),
        );
        if !ancestor.pop() {
            return Err("invalid generated destination".into());
        }
    }
    let mut resolved = ancestor.canonicalize()?;
    resolved.extend(suffix.into_iter().rev());
    Ok(resolved)
}

fn validate_destination_tree(path: &Path) -> Result<(), InstrumentError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "generated destination contains a symlink: {}",
            path.display()
        )
        .into());
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            validate_destination_tree(&entry?.path())?;
        }
    } else if !metadata.is_file() {
        return Err(format!("unsupported generated destination: {}", path.display()).into());
    }
    Ok(())
}

fn replace_file(path: &Path) -> Result<fs::File, InstrumentError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(format!(
                "generated output is not an ordinary file: {}",
                path.display()
            )
            .into());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // Recreating the file avoids modifying another name for the same inode.
    // create_new also refuses a leaf symlink inserted after the metadata check.
    Ok(fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?)
}

fn relative_name(root: &Path, path: &Path) -> Result<String, InstrumentError> {
    let path: PathBuf = path.strip_prefix(root)?.into();
    Ok(path
        .to_str()
        .ok_or("source paths must be UTF-8")?
        .replace('\\', "/"))
}

fn matches(pattern: &str, text: &str) -> bool {
    let mut remaining = text;
    let mut pieces = pattern.split('*').peekable();
    let first = pieces.next().unwrap_or_default();
    if !remaining.starts_with(first) {
        return false;
    }
    remaining = &remaining[first.len()..];
    if pieces.peek().is_none() {
        return remaining.is_empty();
    }
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_none() {
            return remaining.ends_with(piece);
        }
        let Some(position) = remaining.find(piece) else {
            return false;
        };
        remaining = &remaining[position + piece.len()..];
    }
    true
}

#[cfg(test)]
mod tests {
    use super::matches;

    #[test]
    fn selection_patterns_cover_nested_modules() {
        assert!(matches("fs/*", "fs/vfs/path/resolver.rs"));
        assert!(matches("*/rsm*.rs", "fs/proc/rsm_log.rs"));
        assert!(!matches("syscall/*.rs", "syscall/read.rs.bak"));
        assert!(!matches("syscall/read.rs", "syscall/read.rs.bak"));
        assert!(!matches("fs/*", "net/fs/mod.rs"));
    }
}
