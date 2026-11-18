# RSM Function Hooks (Research Prototype)

[中文：实现、使用与取舍](rsm-function-hooks-zh.md)

The optional `rsm-hooks` feature generates function-entry and normal-return hooks
for the RSM research prototype.
Build the kernel once with instrumentation,
then discover and attach observers at runtime without rebuilding it.
This is an Asterinas extension, not the Linux `bpf` ABI.

## Build and discover

Run development commands in the Asterinas development container.
Enable instrumentation through the existing feature option:

```sh
make kernel FEATURES=rsm-hooks
```

`kernel/core/rsm-hooks.toml` selects source paths and optional function patterns.
The default selection covers system calls, file systems, networking,
process management, virtual memory, and IPC in `aster-core`.
The generator excludes the RSM management and inspection paths.
It copies sources into Cargo's build directory and inserts ordinary safe Rust;
the source checkout is not rewritten.
Generated code undergoes the usual type checking, borrow checking, and optimization.

The build prints the location of `rsm-hooks-report.json`.
This report describes source candidates before conditional compilation,
including unsupported signatures and omitted payload fields.
The authoritative catalog of hooks in the running kernel is:

```sh
cat /proc/rsm/hooks
```

Each tab-separated row contains a hexadecimal hook ID, a qualified function name,
entry fields, and return fields.
A field is written as `name:type`; `-` means no fields.
The catalog is immutable for the lifetime of the kernel,
so partial reads are unaffected by concurrent attach and detach operations.
IDs are derived from names but are not a cross-build ABI;
rediscover the catalog after rebuilding the kernel.
Ambiguous IDs are rejected when attaching.

## Attach an observer

The existing `SYS_RSM` syscall number is 500.
Commands 0 through 3 retain their existing load, legacy attach, detach,
and statistics behavior.
The function-hook commands are:

| Command | `arg1` | `arg2` | Effect |
| --- | --- | --- | --- |
| 4 (`AttachHook`) | Hook ID | Phase | Attaches the loaded program to a vacant phase |
| 5 (`DetachHook`) | Hook ID | Phase | Detaches the phase |
| 6 (`ReadHookStats`) | Statistics pointer | Unused | Reads cumulative phase statistics |

Phase 0 is entry; phase 1 is normal return.
Loading and changing attachments require `CAP_SYS_MODULE`.
Each phase accepts one observer,
and one loaded program may be attached to multiple hooks.
An unknown ID returns `ENOENT`, an invalid phase returns `EINVAL`,
and attaching to an occupied phase returns `EBUSY`.

For example, after loading an artifact and obtaining `hook_id` from the catalog:

```c
syscall(500, 4, hook_id, 0); /* Observe entry. */
syscall(500, 4, hook_id, 1); /* Observe normal return. */
/* Run the workload. */
syscall(500, 5, hook_id, 0);
syscall(500, 5, hook_id, 1);
```

The artifact's `main` entry receives seven scalar slots:
`hook_id`, `phase`, `invocation_id`, and four payload values.
The same invocation ID relates entry and return events across task migration.
Unused payload slots are zero.
The catalog describes which payload slots are meaningful for each phase.
Primitive integers up to 64 bits, `bool`, `char`, and selected integer aliases
are copied without exporting object pointers.
Signed values use Rust's conversion to `u64`.
For supported `Result` returns, `is_error` describes the outcome;
a scalar success value is additionally exposed as `ok`, zero on errors.
Opaque objects, borrowed objects, and excess arguments are omitted from the payload
and identified in the source report.
Observers do not change arguments, return values, or syscall results.

The statistics command reads the identity fields and overwrites the counters:

```c
struct rsm_hook_stats {
    uint64_t hook_id;
    uint32_t phase;
    uint32_t reserved; /* Must be zero. */
    uint64_t invocations;
    uint64_t skipped;
    uint64_t traps;
};
```

Counters are cumulative for each hook phase and are not reset on reattachment.
Concurrent reads are approximate; compare deltas around a controlled workload.

## Execution and lifetime contract

Native observer execution is currently supported on x86-64.
An observer runs synchronously only in a normal task context.
Callbacks are skipped in atomic or interrupt contexts,
on attachment-lock contention, or when native stack headroom is insufficient.
The callback disables local interrupts and preemption while executing native code.
Nested instrumented calls therefore skip their observers.
No hook lock or CPU guard is held while the original function body runs.
Only the existing bounded native helpers are available.

Each function invocation records the return attachment's generation.
Detaching suppresses return callbacks that have not yet captured their observer.
Reattaching does not redirect an old function invocation to the replacement program.
A callback that already captured its program may complete after detach;
its reference keeps the executable mapping alive until that callback finishes.
The token held across the original body contains no program ownership or argument borrow.
This matters for functions that return lock guards or otherwise change execution context.

Return events represent normal completion, including early `return` and `?` paths.
Panic, abort, and non-returning execution do not produce a normal-return event.
The generated wrapper runs the body in an immediately invoked closure
with explicitly forwarded parameters and a whole-receiver capture.
Body-local and parameter destructors run before the return observer;
their original destruction order is preserved.
The source report excludes signatures for which this transformation is unsupported,
including explicit borrowed, lifetime-bearing or opaque returns, `const` and `async` functions,
destructors, foreign ABIs, and special caller-tracking functions.
Functions with inner attributes or inherited lint expectations are also excluded
to preserve their source-level checking behavior.
Destructured, attributed, `ref`, and `impl Trait` parameters are also excluded.
Macro-generated functions are not automatically discovered.
Generic instantiations share their definition's descriptor and scalar schema.

The new hook runtime and generated kernel code use safe Rust.
OSTD provides execution-context and stack-bound queries.
The inherited RSM native loader remains a trusted research prototype:
it accepts externally verified machine-code artifacts under `CAP_SYS_MODULE`
and does not authenticate or verify uploaded code at load time.
The existing native adapter still contains its documented unsafe boundary.
Function hooks do not turn that loader into an untrusted-code sandbox.

The x86-64 loader accepts Rssembly v1 and v2 machine artifacts.
Version 2 lets an observer refer to read-only data such as string literals.
The loader preserves the image offsets specified by the compiler,
applies the code and data relocations, and maps the code and data on separate pages.
Code pages are read-execute and data pages are read-only and non-executable.
The image alignment must be a power of two up to the kernel page size.

## Validation and measurement

The generator's semantic tests compile and execute generated Rust:

```sh
cargo test --manifest-path tools/rsm-instrument/Cargo.toml
cargo test -p aster-rsm --no-default-features
python3 tools/rsm-instrument/test-runner.py
```

For a focused two-CPU x86-64 QEMU run in an isolated development-container checkout:

```sh
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2 --profile release-lto
```

The runner builds a checkout-local OSDK and a minimal initramfs,
then tests discovery, native observer invocation, normal and error returns,
detach and replacement, concurrency, and the legacy syscall observer.
Logs are written under `target/rsm-function-hooks/`.

To test both artifact versions, first compile the Rust observer
with a local Rssembly checkout on Linux.
On an ARM64 host, follow the cross-compilation instructions
in `tools/rsm-instrument/README.md`.
Then pass that file to the QEMU runner in the Asterinas development container.

```sh
python3 tools/rsm-instrument/build-observer.py /path/to/rssembly \
    target/rsm-function-hooks/function-hook-observer.rsm.bin
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2 \
    --observer-artifact target/rsm-function-hooks/function-hook-observer.rsm.bin
```

The runner prints the SHA-256 of the artifact it puts in the initramfs.
The guest attaches the observer to both phases of `sys_read`
and calls `read(-1, &byte, 1)`.
It checks the two phase-specific messages in `/proc/rsm/log`,
a single counter increment, and the original `EBADF` result.
The serial log contains `FUNCTION_HOOKS_V2_OBSERVER_PASS` when these checks pass.

Software-emulated QEMU results establish functionality, not paper-quality timing.
For performance measurements, compare the same optimized build profile
without instrumentation, with unattached hooks, and with attached observers.
