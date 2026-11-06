"""CodexCliAdapter normalization, lifecycle, and safety bounds.

Uses a fake ``codex`` shell script emitting canned JSONL; no network or real
Codex backend is touched.
"""
import os
import stat
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from sis.v3.adapters.codex_cli import CodexCliAdapter, CodexCliError


FAKE = textwrap.dedent("""\
    #!/bin/sh
    printf '%s\\n' '{"type":"thread.started","thread_id":"th-1"}'
    printf '%s\\n' '{"type":"turn.started"}'
    printf '%s\\n' '{"type":"item.completed","item":{"type":"command_execution","exit_code":1,"status":"failed","aggregated_output":"SECRET"}}'
    printf '%s\\n' '{"type":"item.completed","item":{"type":"file_change","status":"completed","changes":[{"path":"a.py"}]}}'
    printf '%s\\n' '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":5}}'
    exit 0
""")

FAKE_SLEEP = textwrap.dedent("""\
    #!/bin/sh
    printf '%s\\n' '{"type":"thread.started","thread_id":"th-1"}'
    sleep 30
""")


def _make_fake(tmpdir: Path, body: str) -> Path:
    path = tmpdir / "codex-fake"
    path.write_text(body)
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
        fake = _make_fake(self.root, FAKE)
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
        fake = _make_fake(self.root, FAKE_SLEEP)
        adapter = CodexCliAdapter(codex_path=fake, wall_seconds=1)
        turn = adapter.start_task("work", self.ws, sandbox="read_only")
        start = time.monotonic()
        events = list(turn.events)
        self.assertLess(time.monotonic() - start, 20)
        last = events[-1]
        self.assertTrue(last.payload["summary"].get("timed_out"))

    def test_cancel_unknown_turn(self):
        fake = _make_fake(self.root, FAKE)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(CodexCliError):
            adapter.cancel("nope")

    def test_missing_binary(self):
        with self.assertRaises(CodexCliError):
            CodexCliAdapter(codex_path=self.root / "nonexistent")

    def test_bad_sandbox_and_prompt(self):
        fake = _make_fake(self.root, FAKE)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(ValueError):
            adapter.start_task("x", self.ws, sandbox="danger-full-access")  # type: ignore
        with self.assertRaises(ValueError):
            adapter.start_task("", self.ws)
        with self.assertRaises(ValueError):
            adapter.start_task("x", self.root / "missing-dir")

    def test_resume_and_external_message_unsupported(self):
        fake = _make_fake(self.root, FAKE)
        adapter = CodexCliAdapter(codex_path=fake)
        with self.assertRaises(CodexCliError):
            adapter.resume_thread("th-1", self.ws)
        with self.assertRaises(CodexCliError):
            adapter.send_external_message("th-1", "content")
        with self.assertRaises(CodexCliError):
            adapter.stream_turn("th-1", "msg")


if __name__ == "__main__":
    unittest.main()
