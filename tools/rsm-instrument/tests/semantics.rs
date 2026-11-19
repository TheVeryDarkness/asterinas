// SPDX-License-Identifier: MPL-2.0

//! Compiles generated safe Rust and checks observable control flow and payloads.

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use rsm_instrument::{Config, instrument_source, instrument_tree};

const RUNTIME: &str = r#"
extern crate self as aster_rsm;
use std::sync::Mutex;
static EVENTS: Mutex<Vec<(&'static str, u64, [u64; 4])>> = Mutex::new(Vec::new());
pub mod hooks {
    pub struct Field;
    impl Field {
        pub const fn new(_: &str, _: &str) -> Self { Self }
    }
}
pub struct Hook(&'static str);
pub struct Invocation(&'static str);
impl Hook {
    pub fn enter(&self, values: [u64; 4]) -> Invocation {
        EVENTS.lock().unwrap().push((self.0, 0, values));
        Invocation(self.0)
    }
}
impl Invocation {
    pub fn finish(self, values: [u64; 4]) {
        EVENTS.lock().unwrap().push((self.0, 1, values));
    }
}
#[macro_export]
macro_rules! function_hook {
    ($name:literal, $entry:expr, $exit:expr) => {{
        let _: &[hooks::Field] = $entry;
        let _: &[hooks::Field] = $exit;
        static HOOK: Hook = Hook($name);
        &HOOK
    }};
}
"#;

#[test]
fn observes_normal_returns_and_preserves_body_control_flow() {
    let source = r#"
// Original comments, including 中文 before a body on the same line, survive.
fn flow(value: i32) -> Result<u64, i32> {
    macro_rules! fail { () => { return Err(-7) }; }
    if value == 0 { return Ok(10); }
    if value == 1 { Err(-3)?; }
    if value == 2 { fail!(); }
    let local = || { return 3; };
    fn nested() -> u64 { return 4; }
    Ok(local() + nested())
}
fn unicode() /* 中文 */ -> u64 { 42 }
struct Counter(u64);
impl Counter {
    fn bump(&mut self, delta: u64) -> u64 {
        self.0 += delta;
        self.0
    }
}
fn move_value<T>(value: T) -> T { value }
fn returns_reference(value: &mut u64) -> &mut u64 { value }
fn cleanup(value: String) -> usize {
    struct Witness;
    impl Drop for Witness {
        fn drop(&mut self) { DROPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }
    }
    let _witness = Witness;
    value.len()
}
"#;
    let (generated, report) = instrument_source(source, "syscall/example.rs", &Config::default())
        .expect("instrument fixture");
    assert!(generated.contains("Original comments, including 中文"));
    assert_eq!(report.instrumented_count(), 5);
    assert!(report.functions.iter().any(|function| {
        function.function.ends_with("returns_reference") && !function.instrumented
    }));
    // Neither nested functions nor the nested Drop implementation are rewritten.
    assert!(
        !report
            .functions
            .iter()
            .any(|function| function.function.ends_with("nested"))
    );

    compile_and_run(&format!(
        "{RUNTIME}\n{generated}\n{}",
        r#"
static DROPS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
fn main() {
    assert_eq!(flow(0), Ok(10));
    assert_eq!(flow(1), Err(-3));
    assert_eq!(flow(2), Err(-7));
    assert_eq!(flow(3), Ok(7));
    assert_eq!(unicode(), 42);
    assert_eq!(Counter(2).bump(5), 7);
    assert_eq!(move_value(String::from("owned")), "owned");
    let mut value = 11;
    *returns_reference(&mut value) = 12;
    assert_eq!(value, 12);
    assert_eq!(cleanup(String::from("abc")), 3);
    assert_eq!(DROPS.load(std::sync::atomic::Ordering::Relaxed), 1);
    let events = EVENTS.lock().unwrap();
    let flow: Vec<_> = events.iter().filter(|event| event.0 == "flow").collect();
    assert_eq!(flow.len(), 8);
    assert_eq!(flow[0].2, [0, 0, 0, 0]);
    assert_eq!(flow[1].2, [0, 10, 0, 0]);
    assert_eq!(flow[3].2, [1, 0, 0, 0]);
    assert_eq!(flow[5].2, [1, 0, 0, 0]);
    assert_eq!(flow[7].2, [0, 7, 0, 0]);
    assert_eq!(events.iter().filter(|event| event.0 == "Counter::bump").count(), 2);
}
"#
    ));
}

#[test]
fn skips_unsupported_signatures_and_reports_payload_omissions() {
    let source = r#"
const fn constant() -> u64 { 1 }
async fn asynchronous() {}
unsafe fn unchecked() {}
extern "C" fn foreign() {}
fn opaque() -> impl Iterator<Item = u8> { [1].into_iter() }
fn borrowed<'a>(value: &'a u8) -> Result<&'a u8, ()> { Ok(value) }
fn diverging() -> ! { loop {} }
#[track_caller]
fn caller() {}
struct Owned;
impl Drop for Owned { fn drop(&mut self) {} }
fn ordinary(a: u64, b: i32, c: bool, d: char, e: usize, object: &Owned) {}
"#;
    let (_, report) = instrument_source(source, "fs/example.rs", &Config::default()).unwrap();
    assert_eq!(report.instrumented_count(), 1);
    let ordinary = report.functions.last().unwrap();
    assert_eq!(ordinary.entry_fields.len(), 4);
    assert_eq!(ordinary.omitted_arguments.len(), 2);
    assert!(
        report
            .functions
            .iter()
            .any(|function| function.reason.as_deref() == Some("destructor"))
    );
}

#[test]
fn nested_cfg_and_source_attributes_are_preserved() {
    let source = r#"
#[cfg(any())]
mod absent { fn invisible() -> u64 { undefined_name } }
#[inline(always)]
fn present(value: u64) -> u64 { value + 1 }
"#;
    let (generated, report) =
        instrument_source(source, "net/example.rs", &Config::default()).unwrap();
    assert_eq!(report.instrumented_count(), 2);
    assert!(generated.contains("#[inline(always)]"));
    compile_and_run(&format!(
        "{RUNTIME}\n{generated}\nfn main() {{ assert_eq!(present(1), 2); }}"
    ));
}

#[test]
fn failed_execution_does_not_emit_a_normal_return() {
    let (generated, _) = instrument_source(
        "fn fails() { panic!(\"expected\"); }",
        "ipc/example.rs",
        &Config::default(),
    )
    .unwrap();
    compile_and_run(&format!(
        "{RUNTIME}\n{generated}\n{}",
        r#"
fn main() {
    assert!(std::panic::catch_unwind(fails).is_err());
    let events = EVENTS.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].1, 0);
}
"#
    ));
}

#[test]
fn preserves_parameter_and_owned_receiver_destruction_order() {
    let source = r#"
static DROPS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());
struct Tracked(u64);
impl Drop for Tracked {
    fn drop(&mut self) { DROPS.lock().unwrap().push(self.0); }
}
fn touch(_: &Tracked) {}
fn plain(a: Tracked, b: Tracked, conditional: bool) {
    touch(&a);
    if conditional { drop(b); }
}
fn observed(a: Tracked, b: Tracked, conditional: bool) {
    touch(&a);
    if conditional { drop(b); }
}
struct Receiver { first: Tracked, second: Tracked }
impl Receiver {
    fn plain(self, a: Tracked, b: Tracked) {
        touch(&self.second);
        touch(&a);
        touch(&b);
    }
    fn observed(self, a: Tracked, b: Tracked) {
        touch(&self.second);
        touch(&a);
        touch(&b);
    }
}
fn observed_mut(mut value: u64) -> u64 { value += 1; value }
"#;
    let config = Config {
        functions: vec!["*::observed*".into()],
        ..Config::default()
    };
    let (generated, _) = instrument_source(source, "syscall/drop_order.rs", &config).unwrap();
    compile_and_run(&format!(
        "{RUNTIME}\n{generated}\n{}",
        r#"
fn take_drops() -> Vec<u64> { std::mem::take(&mut *DROPS.lock().unwrap()) }
fn main() {
    for conditional in [false, true] {
        plain(Tracked(1), Tracked(2), conditional);
        let expected = take_drops();
        observed(Tracked(1), Tracked(2), conditional);
        assert_eq!(take_drops(), expected);
    }
    Receiver { first: Tracked(0), second: Tracked(1) }.plain(Tracked(2), Tracked(3));
    let expected = take_drops();
    Receiver { first: Tracked(0), second: Tracked(1) }.observed(Tracked(2), Tracked(3));
    assert_eq!(take_drops(), expected);
    assert_eq!(observed_mut(7), 8);
}
"#
    ));
}

#[test]
fn copies_selected_tree_without_mutating_originals() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("generated");
    fs::create_dir_all(source.join("syscall")).unwrap();
    let original = "fn sample() -> u64 { 42 }\n";
    fs::write(source.join("syscall/sample.rs"), original).unwrap();
    fs::write(source.join("syscall/rsm.rs"), original).unwrap();
    fs::write(source.join("asset.bin"), [0, 255]).unwrap();
    let report = instrument_tree(&source, &destination, &Config::default()).unwrap();
    assert_eq!(report.instrumented_count(), 1);
    assert_eq!(
        fs::read_to_string(source.join("syscall/sample.rs")).unwrap(),
        original
    );
    assert_eq!(
        fs::read_to_string(destination.join("syscall/rsm.rs")).unwrap(),
        original
    );
    assert_eq!(fs::read(destination.join("asset.bin")).unwrap(), [0, 255]);
    assert!(instrument_tree(&source, &source.join("nested"), &Config::default()).is_err());
    assert!(!source.join("nested").exists());
}

#[cfg(unix)]
#[test]
fn rejects_nested_destination_symlinks_before_writing() {
    use std::os::unix::fs::symlink;

    for directory_link in [false, true] {
        let directory = TestDirectory::new();
        let source = directory.0.join("source");
        let destination = directory.0.join("generated");
        fs::create_dir_all(source.join("syscall")).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let original = "fn sample() -> u64 { 42 }\n";
        fs::write(source.join("syscall/sample.rs"), original).unwrap();
        fs::write(source.join("asset.bin"), b"new asset").unwrap();
        fs::write(destination.join("asset.bin"), b"old asset").unwrap();
        if directory_link {
            symlink(source.join("syscall"), destination.join("syscall")).unwrap();
        } else {
            fs::create_dir(destination.join("syscall")).unwrap();
            symlink(
                source.join("syscall/sample.rs"),
                destination.join("syscall/sample.rs"),
            )
            .unwrap();
        }

        let error = instrument_tree(&source, &destination, &Config::default()).unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert_eq!(
            fs::read_to_string(source.join("syscall/sample.rs")).unwrap(),
            original
        );
        assert_eq!(
            fs::read(destination.join("asset.bin")).unwrap(),
            b"old asset"
        );
    }
}

#[test]
fn replacing_generated_hard_links_keeps_source_files_unchanged() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("generated");
    fs::create_dir_all(source.join("syscall")).unwrap();
    fs::create_dir_all(destination.join("syscall")).unwrap();
    let original = "fn sample() -> u64 { 42 }\n";
    let original_path = source.join("syscall/sample.rs");
    let generated_path = destination.join("syscall/sample.rs");
    fs::write(&original_path, original).unwrap();
    fs::hard_link(&original_path, &generated_path).unwrap();

    instrument_tree(&source, &destination, &Config::default()).unwrap();
    assert_eq!(fs::read_to_string(&original_path).unwrap(), original);
    assert!(
        fs::read_to_string(&generated_path)
            .unwrap()
            .contains("function_hook!")
    );
    fs::write(&generated_path, "replacement").unwrap();
    assert_eq!(fs::read_to_string(&original_path).unwrap(), original);
}

#[test]
fn regeneration_removes_deleted_modules_and_handles_module_moves() {
    let directory = TestDirectory::new();
    let source = directory.0.join("source");
    let destination = directory.0.join("generated");
    fs::create_dir_all(source.join("syscall")).unwrap();
    fs::write(source.join("syscall/sample.rs"), "fn old() {}\n").unwrap();
    fs::write(source.join("syscall/deleted.rs"), "fn deleted() {}\n").unwrap();
    instrument_tree(&source, &destination, &Config::default()).unwrap();

    fs::remove_file(source.join("syscall/sample.rs")).unwrap();
    fs::remove_file(source.join("syscall/deleted.rs")).unwrap();
    fs::create_dir(source.join("syscall/sample")).unwrap();
    fs::write(
        source.join("syscall/sample/mod.rs"),
        "fn replacement() {}\n",
    )
    .unwrap();
    instrument_tree(&source, &destination, &Config::default()).unwrap();

    assert!(!destination.join("syscall/sample.rs").exists());
    assert!(!destination.join("syscall/deleted.rs").exists());
    assert!(destination.join("syscall/sample/mod.rs").is_file());
    assert_eq!(
        fs::read_to_string(source.join("syscall/sample/mod.rs")).unwrap(),
        "fn replacement() {}\n"
    );
}

#[test]
fn generated_code_respects_lints_and_preserves_expectation_scopes() {
    let source = r#"
#[deny(unused_braces)]
fn value(value: u64) -> u64 { value }
fn result(value: u64) -> Result<u64, ()> { Ok(value) }
#[expect(unused_mut)]
fn expected(mut value: u64) -> u64 { value }
struct Bits(u64);
#[expect(clippy::suspicious_arithmetic_impl)]
impl std::ops::BitOr for Bits {
    type Output = Self;
    fn bitor(self, other: Self) -> Self { Self(self.0 + other.0) }
}
struct Receiver;
impl Receiver {
    fn absent(#[cfg(any())] &self) -> u64 { 9 }
}
#[derive(Copy, Eq, PartialEq)]
struct Canonical(u64);
impl Clone for Canonical {
    fn clone(&self) -> Self { *self }
}
impl PartialOrd for Canonical {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}
impl Ord for Canonical {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.0.cmp(&other.0) }
}
"#;
    let (generated, report) =
        instrument_source(source, "syscall/lints.rs", &Config::default()).unwrap();
    assert_eq!(report.instrumented_count(), 3);
    assert!(
        report
            .functions
            .iter()
            .any(|function| function.function.ends_with("::bitor")
                && function.reason.as_deref() == Some("lint expectation scope"))
    );
    compile_and_run_with(
        &format!(
            "{RUNTIME}\n{generated}\n{}",
            r#"
fn main() {
    assert_eq!(value(3), 3);
    assert_eq!(result(4), Ok(4));
    assert_eq!(expected(5), 5);
    assert_eq!((Bits(1) | Bits(2)).0, 3);
    assert_eq!(Receiver::absent(), 9);
    assert_eq!(Canonical(1).partial_cmp(&Canonical(2)), Some(std::cmp::Ordering::Less));
}
"#
        ),
        "clippy-driver",
        &["-Dwarnings", "-Dclippy::allow_attributes"],
    );
}

fn compile_and_run(source: &str) {
    compile_and_run_with(source, "rustc", &[]);
}

fn compile_and_run_with(source: &str, compiler: &str, flags: &[&str]) {
    let directory = TestDirectory::new();
    let source_path = directory.0.join("fixture.rs");
    let binary_path = directory.0.join("fixture");
    fs::write(&source_path, source).unwrap();
    let output = Command::new(compiler)
        .args(flags)
        .args(["--edition=2024", "-Copt-level=2", "-Cpanic=unwind"])
        .arg(&source_path)
        .arg("-o")
        .arg(&binary_path)
        .output()
        .expect("run rustc");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(binary_path).output().expect("run fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "rsm-instrument-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
