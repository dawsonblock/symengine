"""CodexCliAdapter normalization, lifecycle, and safety bounds.

Uses a fake ``codex`` shell script emitting canned JSONL; no network or real
Codex backend is touched.
"""
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

from sis.v3.adapters.codex_cli import CodexCliAdapter, CodexCliError


EVENTS = [
    '{"type":"thread.started","thread_id":"th-1"}',
    '{"type":"turn.started"}',
    '{"type":"item.completed","item":{"type":"command_execution","exit_code":1,"status":"failed","aggregated_output":"SECRET"}}',
    '{"type":"item.completed","item":{"type":"file_change","status":"completed","changes":[{"path":"a.py"}]}}',
    '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5}}',
]

SLEEP_EVENTS = ['{"type":"thread.started","thread_id":"th-1"}']


def _make_fake(tmpdir: Path, lines, *, sleep: bool = False) -> Path:
    """Write a platform-executable fake ``codex`` emitting canned JSONL.

    The Windows branch emits lines with ``echo``, so fixture lines must
    stay free of cmd metacharacters (``|``, ``&``, ``<``, ``>``); escape
    them if a future event ever needs one.
    """
    if os.name == "nt":
        # Windows cannot exec a POSIX script; a .cmd runs via cmd.exe.
        path = tmpdir / "codex-fake.cmd"
        script = "".join(f"@echo {line}\r\n" for line in lines)
        if sleep:
            script += "@ping -n 31 127.0.0.1 >nul\r\n"
        path.write_text(script)
        return path
    path = tmpdir / "codex-fake"
    script = "#!/bin/sh\n" + "".join(
        f"printf '%s\\n' '{line}'\n" for line in lines)
    if sleep:
        script += "sleep 30\n"
    script += "exit 0\n"
    path.write_text(script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class CodexCliAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ws = self.root / "ws"
        self.ws.mkdir()

    def test_streams_normalized_events(self):
        fake = _make_fake(self.root, EVENTS)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=30)
        turn = adapter.start_task("fix the bug", self.ws, sandbox="workspace_write")
        events = list(turn.events)
        methods = [e.payload["sdk_method"] for e in events]
        self.assertIn("thread.started", methods)
        self.assertIn("turn.completed", methods)
        self.assertIn("sis/process_exit", methods)
        types = [e.event_type for e in events]
        self.assertIn("tool_result", types)
        self.assertIn("edit", types)
        self.assertIn("completion", types)
        # No raw content: the SECRET output string never appears.
        for e in events:
            self.assertNotIn("SECRET", str(e.payload))
        self.assertEqual(events[0].seq, 0)
        self.assertEqual(events[-1].payload["summary"]["cli_exit_status"], 0)
        # Chain: each event's prior digest links to its predecessor.
        self.assertIsNone(events[0].prior_event_digest)
        for prev, cur in zip(events, events[1:]):
            self.assertEqual(cur.prior_event_digest, prev.digest)

    def test_timeout_kills_process_group(self):
        fake = _make_fake(self.root, SLEEP_EVENTS, sleep=True)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=1)
        turn = adapter.start_task("work", self.ws, sandbox="read_only")
        start = time.monotonic()
        events = list(turn.events)
        self.assertLess(time.monotonic() - start, 20)
        last = events[-1]
        self.assertTrue(last.payload["summary"].get("timed_out"))

    @unittest.skipIf(os.name == "nt", "POSIX shell fixture")
    def test_oversized_line_is_drained_without_unbounded_read(self):
        big = self.root / "big.txt"
        big.write_text("x" * ((1 << 20) + 64) + "\n")
        fake = self.root / "codex-big"
        fake.write_text(
            "#!/bin/sh\n"
            f"cat '{big}'\n"
            "printf '%s\\n' '{\"type\":\"turn.completed\"}'\n"
            "exit 0\n")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=30)
        turn = adapter.start_task("work", self.ws, sandbox="read_only")
        events = list(turn.events)
        methods = [e.payload["sdk_method"] for e in events]
        oversized = [e for e in events
                     if e.payload["sdk_method"] == "sis/oversized_line"]
        self.assertEqual(len(oversized), 1)
        self.assertGreater(
            oversized[0].payload["summary"]["skipped_bytes"], 1 << 20)
        # The following line is still parsed after the oversized one.
        self.assertIn("turn.completed", methods)

    @unittest.skipIf(os.name == "nt", "POSIX shell fixture")
    def test_stderr_flood_does_not_deadlock_the_turn(self):
        fake = self.root / "codex-stderr"
        fake.write_text(
            "#!/bin/sh\n"
            "head -c 200000 /dev/zero >&2\n"
            "printf '%s\\n' '{\"type\":\"turn.completed\"}'\n"
            "exit 0\n")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=30)
        start = time.monotonic()
        turn = adapter.start_task("work", self.ws, sandbox="read_only")
        events = list(turn.events)
        elapsed = time.monotonic() - start
        last = events[-1]
        self.assertLess(elapsed, 10)
        self.assertNotIn("timed_out", last.payload["summary"])
        self.assertEqual(last.payload["summary"]["cli_exit_status"], 0)
        self.assertEqual(last.payload["summary"]["stderr_bytes"], 64 * 1024)

    def test_line_limit_counts_the_newline(self):
        from io import BytesIO
        from sis.v3.adapters.codex_cli import _MAX_LINE_BYTES

        raw, _ = CodexCliAdapter._read_bounded_line(
            BytesIO(b"x" * _MAX_LINE_BYTES))
        self.assertEqual(len(raw), _MAX_LINE_BYTES)
        raw, _ = CodexCliAdapter._read_bounded_line(
            BytesIO(b"x" * (_MAX_LINE_BYTES - 1) + b"\n"))
        self.assertEqual(len(raw), _MAX_LINE_BYTES)
        raw, skipped = CodexCliAdapter._read_bounded_line(
            BytesIO(b"x" * _MAX_LINE_BYTES + b"\n"))
        self.assertIsNone(raw)
        self.assertEqual(skipped, _MAX_LINE_BYTES + 1)

    def test_cancel_unknown_turn(self):
        fake = _make_fake(self.root, EVENTS)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(CodexCliError):
            adapter.cancel("nope")

    def test_missing_binary(self):
        with self.assertRaises(CodexCliError):
            CodexCliAdapter(codex_path=self.root / "nonexistent")

    def test_bad_sandbox_and_prompt(self):
        fake = _make_fake(self.root, EVENTS)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(ValueError):
            adapter.start_task("x", self.ws, sandbox="danger-full-access")  # type: ignore
        with self.assertRaises(ValueError):
            adapter.start_task("", self.ws)
        with self.assertRaises(ValueError):
            adapter.start_task("x", self.root / "missing-dir")

    def test_resume_and_external_message_unsupported(self):
        fake = _make_fake(self.root, EVENTS)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(CodexCliError):
            adapter.resume_thread("th-1", self.ws)
        with self.assertRaises(CodexCliError):
            adapter.send_external_message("th-1", "content")
        with self.assertRaises(CodexCliError):
            adapter.stream_turn("th-1", "msg")


if __name__ == "__main__":
    unittest.main()
