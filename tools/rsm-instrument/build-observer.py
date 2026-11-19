#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Compile the function-hook regression observer with a local Rssembly checkout."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import tomllib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rssembly", type=Path, help="Rssembly source checkout")
    parser.add_argument("output", type=Path, help="destination .rsm.bin file")
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).with_name("function-hook-observer.rs"),
                        help="Rust file containing the observer's exported main function")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("the kernel observer requires the Linux x86-64 Rssembly JIT")

    rssembly = args.rssembly.resolve()
    output = args.output.resolve()
    source = args.source.resolve(strict=True)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Run Cargo in Rssembly so rustup uses its pinned compiler. cargo-rsmc
    # locates the matching rustc driver next to its own executable.
    def cargo(*arguments):
        subprocess.run(["cargo", *arguments], cwd=rssembly, check=True)

    with (rssembly / "rust-toolchain.toml").open("rb") as config:
        nightly = tomllib.load(config)["toolchain"]["channel"]
    cargo("build", "--locked", "-p", "cargo-rsmc", "-p",
          f"rsm-rustc-driver-{nightly}")
    # Keep the compiler and its memory-mapped intermediates on the Linux build
    # filesystem even when the requested artifact is on a shared host mount.
    with tempfile.TemporaryDirectory(prefix="rsm-observer-") as temp:
        build = Path(temp)
        # A separate manifest keeps both source checkouts untouched. A fresh
        # package also makes Cargo run the driver's bytecode emission each time.
        def quote(path):
            return json.dumps(str(path), ensure_ascii=False)

        manifest = build / "Cargo.toml"
        manifest.write_text(
            '[package]\nname = "function-hook-observer"\n'
            'version = "0.1.0"\nedition = "2024"\n'
            f'[lib]\npath = {quote(source)}\n'
            '[dependencies]\n'
            f'rsm = {{ path = {quote(rssembly / "crates/rsm")} }}\n'
            f'rsm-apis = {{ path = {quote(rssembly / "examples/rsm-apis")} }}\n'
            '[workspace]\n'
        )
        shutil.copyfile(rssembly / "Cargo.lock", build / "Cargo.lock")
        bytecode = build / "observer.rsm"
        cargo("run", "--locked", "-p", "cargo-rsmc", "--", "--manifest-path",
              str(manifest), "-o", str(bytecode))
        artifact = build / "observer.rsm.bin"
        target = [] if platform.machine() == "x86_64" else [
            "--target", "x86_64-unknown-linux-gnu"
        ]
        cargo("run", "--locked", *target, "-p", "rsm-emit", "--", str(bytecode),
              "--host", "-o", str(artifact))
        data = artifact.read_bytes()
        if data[:12] != b"RSMPIC\x00\x00\x02\x00\x00\x00":
            raise ValueError("the emitter did not produce a version 2 machine artifact")
        with tempfile.TemporaryDirectory(prefix=".rsm-publish-", dir=output.parent) as publish:
            staged = Path(publish) / output.name
            staged.write_bytes(data)
            os.replace(staged, output)
    print(f"{hashlib.sha256(data).hexdigest()}  {output}")


if __name__ == "__main__":
    main()
