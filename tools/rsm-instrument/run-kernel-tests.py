#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Build and run generated-function-hook regressions in the development container.

The runner uses a small, freshly built initramfs and x86-64 QEMU software
emulation. Run it in an isolated checkout inside the Asterinas development
container; it does not require KVM or the full distribution's test disks.
"""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import signal
import subprocess
import time
import tomllib


INIT_SOURCE = r"""// SPDX-License-Identifier: MPL-2.0
#include <errno.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RSM_OBSERVER_PATH
#define RSM_OBSERVER_PATH NULL
#endif

static int run(const char *program, const char *argument)
{
    pid_t child = fork();
    if (child < 0) {
        perror("fork test");
        return 1;
    }
    if (child == 0) {
        execl(program, program, argument, (char *)NULL);
        perror(program);
        _exit(127);
    }
    int status;
    if (waitpid(child, &status, 0) != child) {
        perror("wait test");
        return 1;
    }
    return !WIFEXITED(status) || WEXITSTATUS(status) != 0;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    int failed = 0;
    if (mount("proc", "/proc", "proc", 0, NULL) != 0 && errno != EBUSY) {
        perror("mount proc");
        failed = 1;
    }
    if (!failed)
        failed = run("/test/rsm/function_hooks_test", RSM_OBSERVER_PATH);
    if (!failed)
        failed = run("/test/rsm/rsm_test", NULL);
#ifdef RSM_TEST_MAPS
    if (!failed)
        failed = run("/test/rsm/plugin_memory_test", "maps");
#endif
#ifdef RSM_TEST_ALLOCATOR
    if (!failed)
        failed = run("/test/rsm/plugin_memory_test", "allocator");
#endif
    puts(failed ? "FUNCTION_HOOKS_QEMU_FAIL" : "FUNCTION_HOOKS_QEMU_PASS");
    reboot(RB_POWER_OFF);
    for (;;)
        pause();
}
"""


def build_initramfs(root, output, compiler, observer, state_observers, allocator_observer):
    """Build the current tests and archive a minimal, self-contained rootfs."""
    tests = root / "test/initramfs/src/regression/rsm"
    image = output / "initramfs"
    binaries = image / "test/rsm"
    binaries.mkdir(parents=True, exist_ok=True)
    for directory in ["proc", "dev", "tmp"]:
        (image / directory).mkdir(exist_ok=True)
    programs = ["function_hooks_test", "rsm_test"]
    if state_observers or allocator_observer:
        programs.append("plugin_memory_test")
    for name in programs:
        subprocess.run(
            [compiler, "-O2", "-Wall", "-Wextra", "-Werror", "-static", "-pthread",
             str(tests / f"{name}.c"), "-o", str(binaries / name)],
            check=True,
        )
    init_source = output / "test_init.c"
    init_source.write_text(INIT_SOURCE)
    init_flags = []
    artifacts = {}
    if observer:
        artifacts["function-hook-observer.rsm.bin"] = observer
        init_flags.append('-DRSM_OBSERVER_PATH="/test/rsm/function-hook-observer.rsm.bin"')
    if state_observers:
        for name in ["read-histogram", "read-outcomes", "read-latency", "heap-snapshot"]:
            filename = f"{name}.rsm.bin"
            artifacts[filename] = state_observers / filename
        init_flags.append("-DRSM_TEST_MAPS")
    if allocator_observer:
        artifacts["allocator.rsm.bin"] = allocator_observer
        init_flags.append("-DRSM_TEST_ALLOCATOR")
    for filename, source in artifacts.items():
        artifact = source.read_bytes()
        if not artifact.startswith(b"RSMPIC\0\0\x02\0\0\0"):
            raise ValueError(f"{source} is not an Rssembly v2 machine artifact")
        (binaries / filename).write_bytes(artifact)
        print(f"QEMU observer: {source} ({len(artifact)} bytes, "
              f"SHA-256 {hashlib.sha256(artifact).hexdigest()})", flush=True)
    subprocess.run(
        [compiler, *init_flags, "-O2", "-Wall", "-Wextra", "-Werror", "-static",
         str(init_source), "-o", str(image / "init")],
        check=True,
    )
    paths = [".", "dev", "init", "proc", "test", "test/rsm", "tmp"]
    paths.extend(f"test/rsm/{name}" for name in [*programs, *artifacts])
    archive = output / "initramfs.cpio"
    with archive.open("wb") as destination:
        subprocess.run(
            ["cpio", "--create", "--format=newc", "--null", "--owner=0:0"],
            cwd=image, input=("\0".join(paths) + "\0").encode(),
            stdout=destination, check=True,
        )
    return archive


def run_command(command, directory, environment, log_path, timeout):
    """Stop the whole Cargo/QEMU process group when a run is interrupted."""
    with log_path.open("w") as log:
        with subprocess.Popen(
            command, cwd=directory, env=environment,
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
        ) as process:
            try:
                deadline = time.monotonic() + timeout
                while True:
                    # Keep an exited leader waitable until cleanup is decided.
                    # Reaping it first would allow its process-group ID to be
                    # reused before a later signal to the remaining children.
                    status = os.waitid(
                        os.P_PID, process.pid,
                        os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    )
                    if status is not None:
                        return process.wait()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    time.sleep(min(0.1, remaining))
            except (subprocess.TimeoutExpired, KeyboardInterrupt):
                terminate_process_group(process)
                raise


def terminate_process_group(process):
    """Kill descendants even when the group leader exits during the grace period."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        # A second interrupt shortens the grace period, never skips cleanup.
        pass
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        # The leader has not been reaped before the final group signal, so its
        # PID cannot identify an unrelated newly created process group.
        process.wait()


def build_osdk(root, output, environment, timeout):
    """Compile OSDK against this checkout rather than an installed dev path."""
    build_environment = dict(environment)
    target_dir = Path(environment.get(
        "RSM_OSDK_TARGET_DIR", root / "target/function-hooks-osdk"
    )).resolve()
    build_environment["CARGO_TARGET_DIR"] = str(target_dir)
    build_environment["OSDK_LOCAL_DEV"] = "1"
    log_path = output / "osdk-build.log"
    command = ["cargo", "build", "--manifest-path", str(root / "osdk/Cargo.toml"),
               "--bin", "cargo-osdk"]
    print(f"Building this checkout's OSDK; log: {log_path}", flush=True)
    returncode = run_command(command, root / "osdk", build_environment, log_path, timeout)
    if returncode != 0:
        raise SystemExit(f"local OSDK build failed ({returncode}); see {log_path}")
    return target_dir / "debug/cargo-osdk"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--smp", type=int, default=2)
    parser.add_argument("--cc", default="x86_64-linux-gnu-gcc")
    parser.add_argument("--profile", default="dev", choices=["dev", "release", "release-lto"])
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--observer-artifact", type=Path,
                        help="run the function-hook observer regression with this v2 artifact")
    parser.add_argument("--state-observers", type=Path,
                        help="directory containing the compiled stateful example observers")
    parser.add_argument("--allocator-observer", type=Path,
                        help="compiled Rust allocator regression observer")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("run inside the Asterinas Linux development container")
    if args.smp < 1 or args.timeout < 1:
        parser.error("--smp and --timeout must be positive")

    root = Path(__file__).resolve().parents[2]
    manifest = root / "kernel/OSDK.toml"
    if manifest.exists():
        parser.error(f"refusing to replace existing configuration: {manifest}")
    output = root / "target/rsm-function-hooks" / f"{args.profile}-smp{args.smp}"
    output.mkdir(parents=True, exist_ok=True)
    archive = build_initramfs(root, output, args.cc, args.observer_artifact,
                              args.state_observers, args.allocator_observer)
    serial = output / "serial.log"
    serial.unlink(missing_ok=True)
    configuration = f'''# Temporary focused function-hook regression configuration.
[boot]
method = "vmm-direct"
[qemu]
args = "-cpu max,+x2apic -machine q35 -m 2G -smp {args.smp} --no-reboot -nographic -display none -monitor none -chardev stdio,id=serial,signal=off,logfile={serial} -serial chardev:serial -nic none -device isa-debug-exit,iobase=0xf4,iosize=0x04"
log_file = "{serial}"
'''
    with (root / "rust-toolchain.toml").open("rb") as toolchain:
        channel = tomllib.load(toolchain)["toolchain"]["channel"]
    environment = dict(os.environ)
    environment["RUSTUP_TOOLCHAIN"] = channel
    environment.setdefault("CARGO_TARGET_DIR", str(root / "target/function-hooks-cargo"))
    environment.setdefault("CARGO_BUILD_JOBS", "4")
    osdk = build_osdk(root, output, environment, args.timeout)
    command = [
        str(osdk), "osdk", "build" if args.build_only else "run",
        "--target-arch", "x86_64", "--no-default-features",
        "--features", "pvh_boot,rsm-hooks",
        "--profile", args.profile,
        "--boot-method", "vmm-direct", "--initramfs", str(archive),
        "--kcmd-args=console=ttyS0", "--kcmd-args=loglevel=warn",
        "--kcmd-args=earlycon",
    ]
    target = manifest.open("x")
    try:
        with target:
            target.write(configuration)
        (output / "OSDK.toml").write_text(configuration)
        (output / "command.txt").write_text(
            f"RUSTUP_TOOLCHAIN={channel}\n"
            f"CARGO_TARGET_DIR={environment['CARGO_TARGET_DIR']}\n"
            + " ".join(command) + "\n"
        )
        log_path = output / "build-and-run.log"
        print(f"Running {'build' if args.build_only else 'QEMU tests'}; log: {log_path}", flush=True)
        returncode = run_command(command, root / "kernel", environment, log_path, args.timeout)
        if args.build_only:
            if returncode != 0:
                raise SystemExit(f"kernel build failed ({returncode}); see {log_path}")
            print("Function-hook kernel build passed; guest tests were not run.")
            return
        contents = serial.read_text(errors="replace") if serial.exists() else ""
        for line in contents.splitlines():
            if "PASS:" in line or "FAIL" in line or "FUNCTION_HOOKS_" in line or "PLUGIN_" in line:
                print(line)
        if ((args.observer_artifact and "FUNCTION_HOOKS_V2_OBSERVER_PASS" not in contents)
                or (args.state_observers and "PLUGIN_STATE_QEMU_PASS" not in contents)
                or (args.allocator_observer and "PLUGIN_ALLOCATOR_QEMU_PASS" not in contents)
                or "FUNCTION_HOOKS_TEST_PASS" not in contents
                or "FUNCTION_HOOKS_QEMU_PASS" not in contents
                or "FUNCTION_HOOKS_QEMU_FAIL" in contents):
            raise SystemExit(f"function-hook regression did not pass ({returncode}); see {output}")
        print(f"Function-hook regression passed on {args.smp} CPUs; logs: {output}")
    finally:
        manifest.unlink()


if __name__ == "__main__":
    main()
