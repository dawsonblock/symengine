"""The Codex CLI adapter must not leave the CLI's children running."""
from __future__ import annotations

import os
import shlex
import stat
import tempfile
import time
import unittest
from pathlib import Path

from sis.v3.adapters.codex_cli import CodexCliAdapter


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            return handle.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except OSError:
        return True


@unittest.skipUnless(os.name == "posix", "POSIX process groups")
class CodexCliGroupCleanupTests(unittest.TestCase):
    def test_background_child_is_killed_after_a_normal_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workspace = root / "ws"
            workspace.mkdir()
            pidfile = root / "child.pid"
            fake = root / "codex-fake"
            fake.write_text(
                "#!/bin/sh\n"
                "sleep 60 </dev/null >/dev/null 2>&1 &\n"
                f"echo $! > {shlex.quote(str(pidfile))}\n"
                "printf '%s\\n' '{\"type\":\"turn.completed\"}'\n"
                "exit 0\n")
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            adapter = CodexCliAdapter(codex_path=fake, wall_seconds=30)
            events = list(adapter.start_task(
                "work", workspace, sandbox="read_only").events)
            self.assertEqual(
                events[-1].payload["summary"]["cli_exit_status"], 0)
            pid = int(pidfile.read_text().strip())
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and _alive(pid):
                time.sleep(0.05)
            if _alive(pid):
                os.kill(pid, 9)
                self.fail("the CLI's background child outlived the turn")


if __name__ == "__main__":
    unittest.main()
