"""Red-team suite expectation logic (C3), with a scripted fake executor.

The live suite needs Docker (and gVisor for the production profile) and
runs in the sandbox-qualification CI job. These tests pin the outcome
classification, the report shape and the non-zero exit on any unexpected
outcome without a daemon.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import redteam_sandbox as redteam  # noqa: E402
from sis.v3.runner import RunnerError, Workspace  # noqa: E402

#: What a contained sandbox produces for each payload.
CONTAINED = {
    "fork_bomb": {"exit_status": 1},
    "memory_bomb": {"exit_status": 137},
    "disk_fill": {"exit_status": 1},
    "huge_output": {"exit_status": -1,
                    "markers": ("output:stdout_truncated",
                                "fs:workspace_state_unavailable")},
    "sleep_forever": {"exit_status": -1, "timeout": True,
                      "markers": ("process:wall_clock_killed",)},
    "symlink_copy_out": {"exit_status": 4,
                         "markers": ("fs:workspace_state_unavailable",)},
    "hardlink_copy_out": {"exit_status": 4,
                          "markers": ("fs:workspace_state_unavailable",)},
}


class FakeExecutor:
    """Answers each payload from a script keyed by the payload name."""

    worker_identity = "fake-redteam"
    runtime = "runsc"
    seccomp_profile_sha256 = "f" * 64
    server_version = "fake"

    def __init__(self, root: Path, script: dict):
        self.root = root
        self.script = script
        self.seen: list[str] = []
        self.argv: dict[str, tuple[str, ...]] = {}
        self.env_canary: dict[str, str | None] = {}
        self.destroyed = 0
        self.terminated = False
        self._outputs: dict[str, tuple[bytes, bytes]] = {}

    def policy_digest(self):
        return "e" * 64

    def image_id(self):
        return "d" * 64

    def prepare(self, base, *, label="task"):
        self.script_source = (Path(base) / redteam.SCRIPT).read_text()
        path = self.root / label
        path.mkdir(parents=True, exist_ok=True)
        return Workspace(label, path, "0" * 64, self.worker_identity)

    def run(self, workspace, spec):
        assert spec.argv == redteam.ARGV
        code = self.script_source
        name = code.splitlines()[0].removeprefix("# redteam:")
        self.seen.append(name)
        self.argv[name] = code
        self.env_canary[name] = os.environ.get(redteam.CANARY_ENV)
        entry = self.script.get(name, {"exit_status": 0})
        if "raise" in entry:
            raise RunnerError(entry["raise"])
        if entry.get("plant_symlink"):
            (workspace.path / "escape").symlink_to("/etc/passwd")
        execution_id = f"exec-{name}"
        self._outputs[execution_id] = (entry.get("stdout", b""), b"")
        return SimpleNamespace(
            execution_id=execution_id,
            exit_status=entry["exit_status"],
            timeout=entry.get("timeout", False),
            security_errors=("isolation:docker_sandbox",
                             *entry.get("markers", ())))

    def output(self, execution_id):
        return self._outputs[execution_id]

    def destroy(self, workspace):
        self.destroyed += 1

    def terminate_all(self):
        self.terminated = True


class ClassificationTests(unittest.TestCase):
    def test_each_outcome_label(self):
        cases = [
            (dict(exit_status=0, timeout=False, markers=(), error=None),
             "contained"),
            (dict(exit_status=3, timeout=False, markers=(), error=None),
             "escaped"),
            (dict(exit_status=137, timeout=False, markers=(), error=None),
             "limited"),
            (dict(exit_status=-1, timeout=True, markers=(), error=None),
             "timeout"),
            (dict(exit_status=-1, timeout=False,
                  markers=("output:stderr_truncated",), error=None),
             "output_capped"),
            (dict(exit_status=4, timeout=False,
                  markers=("fs:workspace_state_unavailable",), error=None),
             "copy_out_rejected"),
            (dict(exit_status=4, timeout=False, markers=(), error=None),
             "staged_accepted"),
            (dict(exit_status=None, timeout=False, markers=(),
                  error="workspace_copy_out_failed:unsupported_member_type"),
             "copy_out_rejected"),
            (dict(exit_status=None, timeout=False, markers=(),
                  error="docker_start_failed:boom"),
             "harness_error"),
            (dict(exit_status=0, timeout=False, markers=(), error=None,
                  host_symlinks=True), "escaped"),
        ]
        for kwargs, expected in cases:
            with self.subTest(expected=expected, kwargs=kwargs):
                self.assertEqual(redteam.classify(**kwargs), expected)
                self.assertIn(expected, redteam.OUTCOMES)

    def test_every_payload_has_a_known_expected_outcome(self):
        names = [payload.name for payload in redteam.PAYLOADS]
        self.assertEqual(len(names), len(set(names)))
        for payload in redteam.PAYLOADS:
            self.assertIn(payload.expected, redteam.OUTCOMES)
            self.assertNotIn(payload.expected,
                             ("escaped", "staged_accepted", "harness_error"))
        required = {"fork_bomb", "memory_bomb", "disk_fill", "huge_output",
                    "sleep_forever", "egress_tcp", "egress_udp", "egress_dns",
                    "docker_socket", "setuid", "ptrace", "mount_unshare",
                    "kill_outside", "symlink_copy_out", "hardlink_copy_out",
                    "proc_sys_writes", "host_credentials"}
        self.assertLessEqual(required, set(names))

    def test_payload_code_compiles(self):
        for payload in redteam.PAYLOADS:
            with self.subTest(payload=payload.name):
                source = payload.script("canary-x")
                compile(source, payload.name, "exec")
                self.assertTrue(source.startswith(
                    f"# redteam:{payload.name}\n"))

    def test_the_canary_is_embedded_where_it_is_searched_for(self):
        payload = next(p for p in redteam.PAYLOADS
                       if p.name == "host_credentials")
        self.assertIn('canary = "canary-xyz"', payload.script("canary-xyz"))


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_a_contained_sandbox_passes(self):
        executor = FakeExecutor(self.root, CONTAINED)
        report = redteam.run_suite(executor)
        self.assertTrue(report["ok"], report["unexpected"])
        self.assertEqual(report["payloads"], len(redteam.PAYLOADS))
        self.assertEqual(executor.seen,
                         [payload.name for payload in redteam.PAYLOADS])
        self.assertEqual(executor.destroyed, len(redteam.PAYLOADS))
        self.assertEqual(report["policy_digest"], "e" * 64)
        self.assertEqual(report["runtime"], "runsc")

    def test_an_escape_fails_the_suite(self):
        script = dict(CONTAINED, ptrace={"exit_status": 3,
                                         "stdout": b"ESCAPED: ptrace"})
        report = redteam.run_suite(FakeExecutor(self.root, script))
        self.assertFalse(report["ok"])
        self.assertEqual(report["unexpected"], ["ptrace"])
        result = next(r for r in report["results"] if r["name"] == "ptrace")
        self.assertEqual(result["observed"], "escaped")
        self.assertIn("ESCAPED", result["stdout"])

    def test_a_missing_limit_fails_the_suite(self):
        # A fork bomb that is never stopped runs into the wall clock.
        script = dict(CONTAINED, fork_bomb={"exit_status": -1,
                                            "timeout": True})
        report = redteam.run_suite(FakeExecutor(self.root, script))
        self.assertEqual(report["unexpected"], ["fork_bomb"])

    def test_links_copied_back_fail_the_suite(self):
        script = dict(CONTAINED, symlink_copy_out={
            "exit_status": 4, "plant_symlink": True})
        report = redteam.run_suite(FakeExecutor(self.root, script))
        result = next(r for r in report["results"]
                      if r["name"] == "symlink_copy_out")
        self.assertEqual(result["observed"], "escaped")
        self.assertFalse(report["ok"])

    def test_copy_out_refusal_raised_by_a_passing_command_counts(self):
        script = dict(CONTAINED, hardlink_copy_out={
            "raise": "workspace_copy_out_failed:unsupported_member_type"})
        report = redteam.run_suite(FakeExecutor(self.root, script))
        self.assertTrue(report["ok"], report["unexpected"])

    def test_an_executor_failure_is_not_containment(self):
        script = dict(CONTAINED, egress_dns={
            "raise": "docker_start_failed:no space"})
        report = redteam.run_suite(FakeExecutor(self.root, script))
        result = next(r for r in report["results"]
                      if r["name"] == "egress_dns")
        self.assertEqual(result["observed"], "harness_error")
        self.assertFalse(report["ok"])

    def test_the_host_canary_is_set_only_for_the_suite(self):
        os.environ.pop(redteam.CANARY_ENV, None)
        executor = FakeExecutor(self.root, CONTAINED)
        redteam.run_suite(executor)
        canary = executor.env_canary["host_credentials"]
        self.assertTrue(canary.startswith("canary-"))
        self.assertIn(canary, executor.argv["host_credentials"])
        self.assertNotIn(redteam.CANARY_ENV, os.environ)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, script, *extra):
        holder = {}

        def factory(args, root):
            holder["args"] = args
            holder["executor"] = FakeExecutor(self.root / "ws", script)
            return holder["executor"]

        output = self.root / "report.json"
        code = redteam.main(
            ["--image", "sis-evaluator@sha256:" + "a" * 64,
             "--output", str(output), *extra],
            executor_factory=factory)
        return code, json.loads(output.read_text()), holder

    def test_exit_zero_and_report_when_everything_is_expected(self):
        code, report, holder = self.invoke(CONTAINED)
        self.assertEqual(code, 0)
        self.assertEqual(report["kind"], "docker_sandbox_redteam")
        self.assertTrue(report["ok"])
        self.assertEqual(holder["args"].runtime, "runsc")
        self.assertTrue(holder["executor"].terminated)

    def test_exit_nonzero_on_any_unexpected_outcome(self):
        code, report, _ = self.invoke(
            dict(CONTAINED, egress_tcp={"exit_status": 3}))
        self.assertEqual(code, 1)
        self.assertEqual(report["unexpected"], ["egress_tcp"])

    def test_only_selects_payloads(self):
        code, report, holder = self.invoke(CONTAINED, "--only", "ptrace")
        self.assertEqual(code, 0)
        self.assertEqual(holder["executor"].seen, ["ptrace"])
        self.assertEqual(report["payloads"], 1)


if __name__ == "__main__":
    unittest.main()
