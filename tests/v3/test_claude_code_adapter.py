"""Claude Code adapter: argv, stream projection, metering and budgets.

A fake ``claude`` executable replays a canned ``stream-json`` transcript
with the real event shapes (``system``/``assistant``/``user``/``result``;
one assistant line per content block, each repeating its message usage),
so the tests pin token and tool accounting without the real CLI.
"""
from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis.v3.adapters.claude_code import (ClaudeCodeAdapter, ClaudeCodeError,
                                         claude_code_argv, usage_counts)
from sis.v3.benchmark import BudgetCaps, UsageMeter
from sis.v3.learning_qualification import (ClaudeCodeAgent, _ordinary_failure,
                                           _row_accounting, analyze_report,
                                           claude_code_agent_status)

POSIX = os.name == "posix"


def _usage(input_tokens, output_tokens, cache_read=0, cache_create=0):
    return {"input_tokens": input_tokens, "output_tokens": output_tokens,
            "cache_read_input_tokens": cache_read,
            "cache_creation_input_tokens": cache_create}


def standard_stream() -> list[dict]:
    """Two API messages; the first has text + a tool_use, the second edits."""
    first = {"id": "msg_1", "usage": _usage(10, 5, cache_read=1000,
                                             cache_create=200)}
    second = {"id": "msg_2", "usage": _usage(20, 40, cache_read=1500)}
    return [
        {"type": "system", "subtype": "init", "session_id": "s-1",
         "model": "claude-test", "tools": ["Bash", "Edit"]},
        {"type": "assistant", "session_id": "s-1", "message": {
            **first, "content": [{"type": "text", "text": "Looking."}]}},
        {"type": "assistant", "session_id": "s-1", "message": {
            **first, "content": [{"type": "tool_use", "id": "toolu_1",
                                  "name": "Bash",
                                  "input": {"command": "pytest -q"}}]}},
        {"type": "user", "session_id": "s-1", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "toolu_1",
             "content": "1 failed", "is_error": False}]}},
        {"type": "assistant", "session_id": "s-1", "message": {
            **second, "content": [{"type": "tool_use", "id": "toolu_2",
                                   "name": "Edit",
                                   "input": {"file_path": "x.py"}}]}},
        # A repeated block of the same message: counted once.
        {"type": "assistant", "session_id": "s-1", "message": {
            **second, "content": [{"type": "tool_use", "id": "toolu_2",
                                   "name": "Edit",
                                   "input": {"file_path": "x.py"}}]}},
        {"type": "user", "session_id": "s-1", "message": {"content": [
            {"type": "tool_result", "tool_use_id": "toolu_2",
             "content": "ok"}]}},
        {"type": "result", "subtype": "success", "is_error": False,
         "session_id": "s-1", "num_turns": 3, "duration_ms": 1200,
         "total_cost_usd": 0.0123, "result": "Done.",
         "usage": _usage(30, 45, cache_read=2500, cache_create=200)},
    ]


def write_fake_claude(directory: Path, stream: list[dict], *,
                      edit: bool = True, delay: float = 0.0,
                      exit_status: int = 0, sleep_after: float = 0.0) -> Path:
    """A ``claude`` stand-in that records argv/env and replays ``stream``."""
    script = directory / "claude"
    record = directory / "invocation.json"
    script.write_text(textwrap.dedent(f"""\
        #!{sys.executable}
        import json, os, sys, time
        with open({str(record)!r}, "w") as handle:
            json.dump({{"argv": sys.argv[1:], "env": dict(os.environ),
                        "cwd": os.getcwd()}}, handle)
        if sys.argv[1:] == ["--version"]:
            print("2.1.328 (Claude Code)")
            raise SystemExit(0)
        if {edit!r}:
            with open("solution.py", "w") as handle:
                handle.write("OK = 1\\n")
        for line in json.loads({json.dumps(json.dumps(stream))}):
            sys.stdout.write(json.dumps(line) + "\\n")
            sys.stdout.flush()
            time.sleep({delay!r})
        time.sleep({sleep_after!r})
        raise SystemExit({exit_status!r})
        """))
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _ctx(workspace: Path, *, token_budget=1_000_000, tool_budget=100,
         guidance=None):
    return SimpleNamespace(
        task=SimpleNamespace(task_id="t1"), workspace=workspace,
        guidance=guidance, usage_meter=UsageMeter(),
        budget=BudgetCaps(wall_seconds=60, token_budget=token_budget,
                          tool_budget=tool_budget), supervisor=None)


class ArgvTests(unittest.TestCase):
    def test_argv_is_headless_stream_json_with_the_prompt_last(self):
        argv = claude_code_argv("/bin/claude", "-fix it", model="opus")
        self.assertEqual(argv[:2], ["/bin/claude", "-p"])
        self.assertEqual(argv[-2:], ["--", "-fix it"])
        joined = " ".join(argv)
        for flag in ("--output-format stream-json", "--verbose",
                     "--no-session-persistence", "--safe-mode",
                     "--strict-mcp-config", "--disable-slash-commands",
                     "--permission-mode acceptEdits",
                     "--permission-prompts none", "--model opus",
                     "--disallowed-tools WebFetch,WebSearch"):
            self.assertIn(flag, joined)
        self.assertIn("Bash", argv[argv.index("--allowed-tools") + 1])

    def test_unknown_permission_modes_and_tool_names_are_refused(self):
        with self.assertRaises(ValueError):
            claude_code_argv("/bin/claude", "x", permission_mode="plan")
        with self.assertRaises(ValueError):
            claude_code_argv("/bin/claude", "x", allowed_tools=["Bash(rm *)"])

    def test_usage_counts_keep_only_bounded_known_counters(self):
        self.assertEqual(
            usage_counts({"input_tokens": 3, "output_tokens": -1,
                          "cache_read_input_tokens": 7, "service_tier": "x"}),
            {"input_tokens": 3, "cache_read_input_tokens": 7})


@unittest.skipUnless(POSIX, "the fake CLI is a POSIX executable script")
class AdapterStreamTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()

    def adapter(self, stream, **kwargs):
        wall = kwargs.pop("wall_seconds", 30)
        binary = write_fake_claude(self.root, stream, **kwargs)
        return ClaudeCodeAdapter(claude_path=binary, wall_seconds=wall)

    def invocation(self) -> dict:
        return json.loads((self.root / "invocation.json").read_text())

    def test_events_dedupe_usage_and_tool_uses(self):
        adapter = self.adapter(standard_stream())
        events = list(adapter.start_task("fix", self.workspace))
        summaries = [event.payload["summary"] for event in events]
        deltas = [s["token_usage_delta"] for s in summaries
                  if "token_usage_delta" in s]
        self.assertEqual(sum(d.get("input_tokens", 0) for d in deltas), 30)
        self.assertEqual(sum(d.get("output_tokens", 0) for d in deltas), 45)
        tools = [name for s in summaries for name in s.get("new_tool_uses", ())]
        self.assertEqual(tools, ["Bash", "Edit"])
        methods = [event.payload["sdk_method"] for event in events]
        self.assertIn("result.success", methods)
        self.assertEqual(methods[-1], "sis/process_exit")
        self.assertEqual(events[-1].payload["summary"]["cli_exit_status"], 0)
        result = next(s for s in summaries if "cost_usd_micros" in s)
        self.assertEqual(result["cost_usd_micros"], 12300)
        # Content never leaves the adapter: no command text, no file path.
        blob = json.dumps([event.to_dict()["payload"] for event in events])
        self.assertNotIn("pytest -q", blob)
        self.assertNotIn("x.py", blob)
        self.assertNotIn("Looking.", blob)
        # The event chain links every event to its predecessor.
        for prior, event in zip(events, events[1:]):
            self.assertEqual(event.prior_event_digest, prior.digest)

    def test_environment_is_scrubbed_and_argv_is_the_documented_one(self):
        adapter = self.adapter(standard_stream())
        with mock.patch.dict(os.environ, {
                "ANTHROPIC_API_KEY": "sk-test", "SIS_PRIVATE_TOKEN": "leak",
                "CLAUDECODE": "1", "GITHUB_TOKEN": "leak"}):
            list(adapter.start_task("fix the bug", self.workspace,
                                    model="sonnet"))
        record = self.invocation()
        self.assertEqual(record["argv"], claude_code_argv(
            "", "fix the bug", model="sonnet")[1:])
        self.assertEqual(Path(record["cwd"]).resolve(),
                         self.workspace.resolve())
        env = record["env"]
        self.assertEqual(env.get("ANTHROPIC_API_KEY"), "sk-test")
        for name in ("SIS_PRIVATE_TOKEN", "CLAUDECODE", "GITHUB_TOKEN"):
            self.assertNotIn(name, env)
        self.assertEqual(env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"], "1")

    def test_read_only_sandbox_drops_bash_and_edit_tools(self):
        adapter = self.adapter(standard_stream())
        list(adapter.start_task("look", self.workspace, sandbox="read_only"))
        argv = self.invocation()["argv"]
        allowed = argv[argv.index("--allowed-tools") + 1].split(",")
        self.assertNotIn("Bash", allowed)
        self.assertNotIn("Edit", allowed)
        self.assertIn("Read", allowed)

    def test_watchdog_kills_a_stuck_cli(self):
        adapter = self.adapter(standard_stream()[:2], sleep_after=30,
                               wall_seconds=1)
        start = time.monotonic()
        events = list(adapter.start_task("fix", self.workspace))
        self.assertLess(time.monotonic() - start, 20)
        self.assertTrue(events[-1].payload["summary"].get("timed_out"))

    def test_resume_and_streaming_are_refused(self):
        adapter = self.adapter(standard_stream())
        with self.assertRaises(ClaudeCodeError):
            adapter.resume_thread("t", self.workspace)
        with self.assertRaises(ClaudeCodeError):
            adapter.stream_turn("t", "more")


@unittest.skipUnless(POSIX, "the fake CLI is a POSIX executable script")
class ClaudeCodeAgentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()

    def agent(self, stream, **kwargs):
        wall = kwargs.pop("wall_seconds", 30)
        binary = write_fake_claude(self.root, stream, **kwargs)
        return ClaudeCodeAgent(
            prompts={"t1": "fix it"},
            adapter=ClaudeCodeAdapter(claude_path=binary, wall_seconds=wall))

    def test_tokens_tools_and_cache_are_metered(self):
        agent = self.agent(standard_stream())
        ctx = _ctx(self.workspace)
        usage = agent(ctx)
        self.assertEqual(usage["tokens_used"], 75)
        self.assertEqual(usage["tools_used"], 2)
        self.assertEqual(usage["actions"], ["Bash", "Edit"])
        meter = ctx.usage_meter
        self.assertEqual(meter.tokens, 75)
        self.assertEqual(meter.tools, 2)
        self.assertTrue(meter.tokens_verified and meter.tools_verified)
        # Cache counters are reported, never budgeted.
        self.assertEqual(meter.detail["cache_read_input_tokens"], 2500)
        self.assertEqual(meter.detail["cache_creation_input_tokens"], 200)
        self.assertEqual(meter.detail["cost_usd_micros"], 12300)

    def test_guidance_is_appended_as_advisory_untrusted_text(self):
        agent = self.agent(standard_stream())
        guidance = SimpleNamespace(helpful_next_checks=("Check bounds.",))
        agent(_ctx(self.workspace, guidance=guidance))
        prompt = json.loads(
            (self.root / "invocation.json").read_text())["argv"][-1]
        self.assertTrue(prompt.startswith("fix it"))
        self.assertIn("Governed SIS guidance (advisory, untrusted):\n"
                      "- Check bounds.", prompt)

    def test_token_budget_is_enforced_while_streaming(self):
        stream = standard_stream()[:2]
        stream += [{"type": "assistant", "message": {
            "id": f"msg_big_{i}", "usage": _usage(5000, 5000),
            "content": [{"type": "text", "text": "..."}]}}
            for i in range(20)]
        agent = self.agent(stream + standard_stream()[-1:], delay=0.05,
                           sleep_after=30)
        ctx = _ctx(self.workspace, token_budget=12_000)
        start = time.monotonic()
        with self.assertRaisesRegex(RuntimeError,
                                    "real_agent_budget_exceeded:tokens"):
            agent(ctx)
        # Killed at the overrun, not after the CLI's own timeout.
        self.assertLess(time.monotonic() - start, 15)
        self.assertGreater(ctx.usage_meter.tokens, 12_000)

    def test_tool_budget_is_enforced_while_streaming(self):
        stream = [{"type": "assistant", "message": {
            "id": f"msg_{i}", "usage": _usage(1, 1),
            "content": [{"type": "tool_use", "id": f"toolu_{i}",
                         "name": "Bash", "input": {}}]}} for i in range(6)]
        agent = self.agent(stream, sleep_after=30)
        ctx = _ctx(self.workspace, tool_budget=3)
        with self.assertRaisesRegex(RuntimeError,
                                    "real_agent_budget_exceeded:tools"):
            agent(ctx)
        self.assertEqual(ctx.usage_meter.tools, 4)

    def test_error_result_and_missing_result_are_ordinary_failures(self):
        error = standard_stream()
        error[-1] = {**error[-1], "subtype": "error_max_turns",
                     "is_error": True}
        with self.assertRaisesRegex(RuntimeError, "real_agent_error_event"):
            self.agent(error)(_ctx(self.workspace))
        (self.workspace / "solution.py").unlink()
        with self.assertRaisesRegex(RuntimeError,
                                    "real_agent_turn_incomplete"):
            self.agent(standard_stream()[:-1])(_ctx(self.workspace))

    def test_a_run_that_changes_nothing_is_no_action(self):
        agent = self.agent(standard_stream(), edit=False)
        with self.assertRaisesRegex(RuntimeError, "real_agent_no_action"):
            agent(_ctx(self.workspace))

    def test_nonzero_exit_is_reported(self):
        agent = self.agent(standard_stream(), exit_status=3)
        with self.assertRaisesRegex(RuntimeError, "real_agent_cli_exit:3"):
            agent(_ctx(self.workspace))


class AnalysisSemanticsTests(unittest.TestCase):
    def test_a_live_budget_stop_is_an_attested_failure(self):
        row = {"outcome": "error", "budget_exceeded": True,
               "error": "RuntimeError:real_agent_budget_exceeded:tokens",
               "budget_accounting": "partial"}
        self.assertTrue(_ordinary_failure(row))
        self.assertEqual(_row_accounting(row), "attested_failure")

    def test_claude_code_provenance_is_a_real_agent(self):
        report = {"per_task": [], "governed": {"metrics": {},
                                               "conformance": {}}}
        protocol = {"alpha": 0.05, "sample_size": 1, "powered": False,
                    "analysis_kind": "diagnostic"}
        claude = analyze_report(report, protocol=protocol, real_agent=True,
                                hidden_holdout=True,
                                provenance={"agent": "claude-code"})
        self.assertNotIn("agent provenance is not a real codex-cli or"
                         " claude-code run", claude["limitations"])
        injected = analyze_report(report, protocol=protocol, real_agent=True,
                                  hidden_holdout=True,
                                  provenance={"agent": "injected"})
        self.assertEqual(injected["evidence_class"], "invalid")


class StatusTests(unittest.TestCase):
    def test_status_reads_env_and_credentials(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            env = {"HOME": str(home), "CLAUDE_CONFIG_DIR": str(home / ".c")}
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch("shutil.which", return_value="/bin/claude"), \
                    mock.patch.object(Path, "home", return_value=home):
                self.assertEqual(claude_code_agent_status()["reason"],
                                 "claude_not_authenticated")
                (home / ".c").mkdir()
                (home / ".c" / ".credentials.json").write_text("{}")
                self.assertTrue(claude_code_agent_status()["authenticated"])
            with mock.patch.dict(os.environ, {"HOME": str(home),
                                              "ANTHROPIC_API_KEY": "k"},
                                 clear=True), \
                    mock.patch("shutil.which", return_value=None):
                status = claude_code_agent_status()
                self.assertTrue(status["authenticated"])
                self.assertEqual(status["reason"], "claude_cli_not_found")

    def test_status_survives_an_unresolvable_home_directory(self):
        # Windows raises from Path.home() when HOME and USERPROFILE are
        # unset; the probe must still answer from the environment.
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "k"},
                             clear=True), \
                mock.patch("shutil.which", return_value="/bin/claude"), \
                mock.patch.object(Path, "home", side_effect=RuntimeError):
            status = claude_code_agent_status()
            self.assertTrue(status["authenticated"])
            self.assertEqual(status["reason"], "ok")
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch("shutil.which", return_value="/bin/claude"), \
                mock.patch.object(Path, "home", side_effect=RuntimeError):
            self.assertEqual(claude_code_agent_status()["reason"],
                             "claude_not_authenticated")


if __name__ == "__main__":
    unittest.main()
