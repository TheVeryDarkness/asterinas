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
| 7 (`ReadStateWord`) | State-word request pointer | Unused | Reads one word of the currently loaded program's named storage |
| 8 (`Unload`) | Unused | Unused | Releases an idle loaded program and its storage |

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

## Keep state between hook calls

Every successful load creates a new program instance.
The instance owns its memory and all of its attachments share that memory.
For example, a read-size histogram can reopen a named four-word array
on every entry to `sys_read` and increment one bucket.

```rust
let histogram = rsm_map_get_or_create(0, 4);
if histogram != 0 {
    rsm_map_fetch_add(histogram, bucket, 1);
}
```

The key is a program-chosen `u64`.
Another instance may use the same key with its own length and contents.
Each instance can hold 16 arrays of 1 to 64 `u64` words.
The kernel reserves capacity at load and zeroes each newly allocated array.
Hooks access words through bounds-checked helpers.

| Rust operation in `rsm_apis` | Result |
| --- | --- |
| `rsm_map_get_or_create(key, words)` | Returns the existing handle for that key and length, or creates an array. Zero means an invalid length, a conflicting length, or exhausted capacity. |
| `rsm_map_load(handle, index)` | Returns the word. An invalid handle or index returns zero. |
| `rsm_map_store(handle, index, value)` | Stores a word and returns whether the operation succeeded. |
| `rsm_map_fetch_add(handle, index, delta)` | Atomically adds with wrapping arithmetic and returns the previous value. An invalid handle or index returns zero. |
| `rsm_map_free(handle)` | Deletes the named allocation and invalidates its handle. A stale or foreign handle returns false. |
| `rsm_map_save_bytes(handle, base)` | Copies an entire live Rust allocation into this array. Eight consecutive bytes form one little-endian word. |
| `rsm_map_restore_bytes(handle, base)` | Restores the complete array into a live Rust allocation belonging to the current callback. |

Each helper operation is synchronized across CPUs.
A sequence of separate loads and stores can interleave with another invocation.
Use `fetch_add` for counters updated on multiple CPUs.
Handles remain valid across detach and reattach until the allocation is freed or the instance is destroyed.
The byte-copy helpers require an exact size match and return false without a partial update on failure.
Each copy publishes or reads one complete snapshot.
Two callbacks that read a snapshot, modify it, and save it can overwrite one another's changes.

An administrator with `CAP_SYS_MODULE` can read a word using command 7.
The request consists of three consecutive `uint64_t` fields named `key`, `index`, and `value`.
The kernel fills in `value` on success.
A missing program or key returns `ENOENT`. An out-of-range index returns `EINVAL`.
Each call reads a single word from the instance it acquired.

Command 8 requires the same capability. It returns `EBUSY` while an attachment,
callback, or state reader still holds a reference.
Replacing the loaded program leaves existing attachments on the old instance.
Its last reference releases its storage, including any allocations the plugin left behind.
Reloading the same artifact starts with empty maps.

### Use Rust allocation inside a callback

For scratch memory, the Rssembly frontend recognizes `std::alloc::alloc`
and `std::alloc::dealloc` with a supported constant `Layout`.
The verified heap operations are linked to the Asterinas allocator.
The program reserves eight 512-byte regions when it is loaded.
An invocation claims one region lazily and has exclusive access until it returns.
It can allocate up to 16 live blocks with alignment up to 16 bytes.
Padding counts toward the 512-byte budget. Freed addresses are retired for that invocation.
The kernel releases outstanding blocks when a callback returns or is aborted.
Exhaustion terminates that callback and increments the hook's `traps` counter.

`rsm_heap_write_byte(base, offset, value)` and `rsm_heap_read_byte(base, offset)`
check ownership and bounds. A failed write returns false and a failed read returns 256.
Use these helpers to work with bytes and save results in a named array before returning.
The compiler still checks proofs for direct raw-pointer dereferences.
The tested Rust source uses the allocator functions directly.
General `Box` and `Vec` support would also require their standard-library code paths.

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
The adapter retains its existing unsafe call into OSTD. For v2 logging OSTD checks the
entire requested range against the program's read-only data, the active native
stack, or the current callback's live allocations. For stack buffers the external
compiler must also ensure that the selected bytes belong to an initialized object.

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

### Run the stateful examples

The five observers below were tested with Rssembly revision
`25dbf9e303c9ce0643e0bf7a84c1a5103399afd7` on `codex/plugin-memory`.
Run the following commands from the Asterinas root in the Linux build environment.

```sh
for name in read-histogram read-outcomes read-latency heap-snapshot allocator; do
    python3 tools/rsm-instrument/build-observer.py /path/to/rssembly \
        "target/rsm-allocator/$name.rsm.bin" \
        --source "tools/rsm-instrument/observers/$name.rs" || exit 1
done
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2 \
    --state-observers target/rsm-allocator \
    --allocator-observer target/rsm-allocator/allocator.rsm.bin
```

| Observer | Result |
| --- | --- |
| `read-histogram` | Four read-size buckets shared across CPUs, readable even after detach. |
| `read-outcomes` | Separate successful and failed read counts, with one log message on the third failure. |
| `read-latency` | Matches entry and return by invocation ID, frees the temporary record, and accumulates completed samples and nanoseconds. |
| `heap-snapshot` | Restores an eight-byte sample window into a fresh Rust allocation, records the next read size, and saves the whole buffer for later callbacks. Use it on a serialized stream. |
| `allocator` | Writes and reads a hook-derived byte through a Rust allocation, frees it, and adds it to a persistent sum. |

The latency example reserves key zero for totals and can track 15 reads in flight.
A skipped return can leave an unmatched record until unload.
Its third counter counts callbacks that encountered a full table or could not record a valid duration.
Use the hook's skipped counter alongside the sample count when interpreting results.

Software-emulated QEMU results establish functionality, not paper-quality timing.
For performance measurements, compare the same optimized build profile
without instrumentation, with unattached hooks, and with attached observers.

### Trace a workload

These four observers adapt questions from Linux eBPF tools to the scalar values
that Asterinas exposes on its own function hooks. Each report can be read from
userspace after detach.

| Observer | What it measures | Linux example |
| --- | --- | --- |
| `open-intent` | Which kinds of opens fail? Pairs `sys_openat` entry flags with the return outcome. Counts read-only, write or read/write, create-requested, and other opens (including `O_PATH`). | [BCC opensnoop](https://github.com/iovisor/bcc/blob/master/tools/opensnoop_example.txt) |
| `bind-outcomes` | Are TCP or UDP binds failing? The same observer attaches to the two socket implementations. Each hook ID gets its own success and failure counts. Errors rejected before socket dispatch, such as a bad descriptor, fall outside these counts. | [BCC bindsnoop](https://github.com/iovisor/bcc/blob/master/tools/bindsnoop_example.txt) |
| `page-faults` | Does a second pass over the same memory still fault? Counts successful and rejected returns from the process address-space fault handler. These counts include all observed calls to that handler and carry no PID or major/minor classification. | [bpftrace page-fault counter](https://bpftrace.org/one-liners) |
| `futex-wait` | How long do successful plain `FUTEX_WAIT` calls take, including sleep and rescheduling? Matches entry and return by invocation ID, groups elapsed time into four buckets, and counts errors separately. | [BCC futexctn](https://github.com/iovisor/bcc/blob/master/libbpf-tools/futexctn.bpf.c) |

Build each observer with the Rssembly revision above, then boot the test guest.

```sh
for name in open-intent bind-outcomes page-faults futex-wait; do
    python3 tools/rsm-instrument/build-observer.py /path/to/rssembly \
        "target/rsm-showcases/$name.rsm.bin" \
        --source "tools/rsm-instrument/observers/$name.rs" || exit 1
done
python3 tools/rsm-instrument/run-kernel-tests.py --smp 2 \
    --showcase-observers target/rsm-showcases
```

The guest creates and opens files, binds local sockets to free and occupied
ports, writes twice to an anonymous mapping, and wakes a waiting thread.
It prints the observed values and checks them before emitting `RSM_SHOWCASES_QEMU_PASS`.

To observe your own command in a running Asterinas guest, install the artifacts and the
`rsm-observe` userspace driver together. The QEMU runner installs them under
`/test/rsm`. To build the driver separately for an x86-64 guest, run
`x86_64-linux-gnu-gcc -O2 -static tools/rsm-instrument/rsm-observe.c -o rsm-observe`
in the development container. For example, run this in a guest with `/bin/ls`:

```sh
cd /test/rsm
./rsm-observe open-intent.rsm.bin \
    --attach both aster_core::syscall::open::sys_openat \
    --read 0 9 -- /bin/ls /proc
```

The first eight words are success/failure pairs in the order read, write,
create, other. The ninth counts returns that could not be matched to an entry.
The plugin retains 64 entry records. Overlapping calls that reuse a slot can
lose a match. A create request includes opens of an existing file with `O_CREAT`.

| Observer | `--attach` phase and qualified hook | `--read` selector and word count |
| --- | --- | --- |
| `bind-outcomes` | `return` on `aster_core::net::socket::ip::stream::<StreamSocket as Socket>::bind` and `aster_core::net::socket::ip::datagram::<DatagramSocket as Socket>::bind` | `'@<qualified hook name>' 2` for each transport, yielding successful and failed binds. Quote each complete hook name in the shell. |
| `page-faults` | `return` on `aster_core::vm::vmar::vmar_impls::page_fault::Vmar::handle_page_fault` | `0 2` yields resolved and rejected faults. |
| `futex-wait` | `both` on `aster_core::process::posix_thread::futex::futex_wait` | `0 6` yields waits under 100 µs, 100 µs to under 1 ms, 1 ms to under 10 ms, and 10 ms or more, followed by errors and unmatched successes. |

The driver requires `CAP_SYS_MODULE` and exclusive use of the loaded-program slot.
It attaches system-wide for the duration of the command, so other tasks can contribute.
It detaches before reading the maps and propagates the command's exit status.
Each word is read separately. A callback already in flight can still finish after detach.
