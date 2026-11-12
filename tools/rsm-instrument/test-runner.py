#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0

"""Test validation-runner cleanup inside the Linux development container."""

import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest


SPEC = importlib.util.spec_from_file_location(
    "rsm_kernel_runner", Path(__file__).with_name("run-kernel-tests.py")
)
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def is_live(pid):
    """Treat exited children awaiting the container's reaper as terminated."""
    try:
        status = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return False
    return status.rsplit(")", 1)[1].split()[0] not in ("Z", "X")


class ProcessGroupTests(unittest.TestCase):
    def test_normal_exit_status(self):
        with tempfile.TemporaryDirectory(prefix="rsm-runner-test-") as temporary:
            root = Path(temporary)
            status = RUNNER.run_command(
                [sys.executable, "-c", "raise SystemExit(7)"], root,
                dict(os.environ), root / "command.log", 3,
            )
            self.assertEqual(status, 7)

    def test_timeout_kills_descendant_after_leader_exits(self):
        self.check_interrupted_group(subprocess.TimeoutExpired)

    def test_keyboard_interrupt_kills_descendant_after_leader_exits(self):
        self.check_interrupted_group(KeyboardInterrupt)

    def check_interrupted_group(self, exception):
        with tempfile.TemporaryDirectory(prefix="rsm-runner-test-") as temporary:
            root = Path(temporary)
            ready = root / "ready.json"
            child = (
                "import json,os,pathlib,signal,time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                f"pathlib.Path({str(ready)!r}).write_text("
                "json.dumps({'leader': os.getppid(), 'child': os.getpid()})); "
                "time.sleep(300)"
            )
            leader = (
                "import signal,subprocess,sys; "
                f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
                "signal.pause()"
            )
            interrupter = None
            if exception is KeyboardInterrupt:
                def interrupt_when_ready():
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline:
                        if ready.exists():
                            os.kill(os.getpid(), signal.SIGINT)
                            return
                        time.sleep(0.01)
                interrupter = threading.Thread(target=interrupt_when_ready, daemon=True)
                interrupter.start()
            try:
                with self.assertRaises(exception):
                    RUNNER.run_command(
                        [sys.executable, "-c", leader], root, dict(os.environ),
                        root / "command.log", 2 if interrupter is None else 5,
                    )
                self.assertTrue(ready.exists(), "descendant did not become ready")
                pids = json.loads(ready.read_text())
                deadline = time.monotonic() + 2
                while is_live(pids["child"]) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(is_live(pids["child"]), "descendant survived cleanup")
                self.assertFalse(
                    Path(f"/proc/{pids['leader']}").exists(),
                    "group leader was not reaped",
                )
            finally:
                if interrupter is not None:
                    interrupter.join(timeout=3)
                if ready.exists():
                    for pid in json.loads(ready.read_text()).values():
                        if is_live(pid):
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass


if __name__ == "__main__":
    unittest.main()
