# RSM function instrumentation

`rsm-instrument` generates ordinary safe Rust calls around selected Asterinas
function bodies. The kernel build uses the library; the CLI is useful for
inspecting generated code and coverage without building a kernel:

```sh
cargo run --manifest-path tools/rsm-instrument/Cargo.toml -- \
    kernel/core/src /tmp/asterinas-hook-source [selection.toml]
```

Run development commands in the project's development container. The generated
directory must be outside the input tree and dedicated to this generator. Its
contents are recreated on every pass, so deleted or moved modules cannot leave
stale sources behind. Sources are copied, not rewritten in place. Existing
symlinks inside the destination are rejected before copying;
output files are recreated to avoid writing through hard links. The destination
must be exclusively owned while the generator runs. Comments and attributes
outside the inserted wrappers are preserved.

The optional TOML configuration selects paths relative to `kernel/core/src`:

```toml
include = ["syscall/*", "fs/*", "net/*", "vm/*", "process/*", "ipc/*"]
exclude = ["syscall/rsm.rs"]
# Optional restriction by source-qualified name, before cfg expansion:
functions = ["syscall::*", "fs::vfs::*"]
# Optional exclusions for signatures hidden behind application-specific aliases:
exclude_functions = []
```

`*` matches any sequence, including directory separators. Exclusions take
precedence. Configuration replaces each specified list; unspecified lists keep
their defaults. The `rsm-hooks.json` report lists source candidates, skipped
signatures, copied fields, and omitted arguments. It includes inactive `cfg`
branches. Use the running kernel's catalog to discover actually compiled hooks.

Each supported function receives an entry hook and a normal-return hook. Both
use a static descriptor, and an invocation ID connects their events. Function
arguments are not borrowed across the original body. At most four supported
scalar fields are copied per event; other arguments are omitted and recorded in
the report. Primitive integers up to 64 bits, `bool`, `char`, and the Asterinas
integer aliases `Vaddr`, `RawFileDesc`, `Pid`, and `Tid` are recognized. Signed
values use Rust's `as u64` conversion. Raw pointers are never dereferenced or
exported. A primitive result is copied; a `Result` exposes `is_error` and, when
its success type is supported, `ok` (zero on errors).

The body runs in an immediately invoked closure with explicit forwarded
parameters, so early `return`, `?`, and return-producing macros reach the
normal-return hook. Explicit parameters preserve their destruction order; an
owned receiver is captured as a whole to preserve its field destruction order.
Nested closures and nested items keep their own control flow. The normal-return
hook runs after body-local and parameter destructors. Panic, abort, or
non-returning execution does not produce a normal-return event. Entry and return
observers can independently be skipped by the runtime's execution-context checks.

The first implementation excludes `const`, `async`, unsafe and foreign-ABI
functions, destructors, trait default methods, `track_caller`/naked/test
functions, `Clone`/`PartialOrd` implementations whose canonical body shape is
checked by Clippy, functions with inner attributes or source-level lint expectation
scopes, and explicitly reference-containing, lifetime-bearing, opaque, or
diverging return types. Destructured, `ref`, attributed, and `impl Trait`
parameters are excluded
because they cannot be forwarded by this wrapper. Macro-generated functions are
not discovered. Ordinary generic functions
can be instrumented; all instantiations share one descriptor, whose payload only
contains recognized scalar types. Source generation cannot resolve arbitrary
type aliases or prove a closure transformation valid for every Rust signature.
Generated code is therefore compiled and borrow-checked normally; an unsupported
named alias or macro-sensitive body can require excluding that function.

The tool preserves optimization settings. Instrumentation overhead should be
measured against the same build profile with instrumentation disabled, enabled
without attachments, and enabled with observers.

## Build the regression observer

The observer build requires Linux, Python 3.11+, Cargo, and the pinned Rust
toolchain from the Rssembly checkout (including `rustc-dev` and `rust-src`).

```sh
python3 tools/rsm-instrument/build-observer.py /path/to/rssembly \
    target/rsm-function-hooks/function-hook-observer.rsm.bin
```

The helper compiles `function-hook-observer.rs` to Rssembly bytecode and runs
the x86-64 `rsm-emit --host` verifier and emitter. It prints the SHA-256 of the
resulting v2 artifact. Pass the file to `run-kernel-tests.py --observer-artifact`.
Use `--source path/to/observer.rs` to compile a different observer. The
[stateful examples](../../book/src/kernel/rsm-function-hooks.md#run-the-stateful-examples)
include the build commands and the two-CPU QEMU regression.

On an ARM64 Linux build host, install the pinned nightly's
`x86_64-unknown-linux-gnu` standard library, an x86-64 GNU cross toolchain,
and an x86-64 userspace runner. With Docker's x86-64 binary emulation and the
Ubuntu cross sysroot, set these before running the same build command.

```sh
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc
export QEMU_LD_PREFIX=/usr/x86_64-linux-gnu
```
