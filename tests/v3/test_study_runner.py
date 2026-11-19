"""Runner robustness: resume from the journal, parallel workers, executor choice."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.benchmark import (BenchmarkError, BenchmarkHarness, BudgetCaps,
                              arm_result_from_row)
from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.runner import LocalSubprocessExecutor, RunnerError, tree_digest
from sis.v3.study_runtime import RunJournal
from sis.v3.verifier import OutcomeVerifier
from tests.v3.test_five_arm_real_run import (GIT, POSIX_CUSTODY, _manifest,
                                             _scripted_agent, _status, _write)
from tests.v3.test_five_arm_real_run import campaign_tool as tool

PY = sys.executable
ACCEPTANCE = (b"from pathlib import Path\n\n"
              b"def test_solution():\n"
              b"    assert 'OK' in Path('solution.py').read_text()\n")


def _tasks(root: Path, verifier, count: int):
    repo = root / "repo"
    repo.mkdir()
    (repo / "solution.py").write_text("NO = 1\n")
    tasks = []
    for index in range(count):
        task_id = f"task-{index}"
        verifier.register_task(
            actor_role="evaluator", task_id=task_id, criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py": ACCEPTANCE}, custody="shared",
            base_commit="abc1234")
        tasks.append((TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(repo, version=3),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(task_id.encode()).hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=100, tool_budget=10, actor_id="agent",
            evaluator_task_ref=task_id), repo))
    return tasks


def _verifier(root: Path) -> OutcomeVerifier:
    return OutcomeVerifier(
        executor=LocalSubprocessExecutor(
            root / "exec", protected_paths=(root / "keys", root / "registry")),
        key_dir=root / "keys", registry_dir=root / "registry",
        allow_shared_custody=True)


def _agent(calls: list):
    lock = threading.Lock()

    def agent(ctx):
        with lock:
            calls.append((ctx.task.task_id, ctx.arm))
        if ctx.arm == "E" or (ctx.arm == "B" and ctx.task.task_id.endswith(
                ("1", "3"))):
            (ctx.workspace / "solution.py").write_text("OK = 1\n")
        ctx.usage_meter.record_tokens(7)
        ctx.usage_meter.record_tool_call()
        return None
    return agent


def _outcomes(report):
    return [(row["task_id"], row["arm_order"],
             {arm: (value["outcome"], value["tokens_used"],
                    value["budget_accounting"])
              for arm, value in row["arms"].items()})
            for row in report["per_task"]]


@unittest.skipUnless(POSIX_CUSTODY, "evaluator key custody is POSIX-only")
class HarnessWorkerAndJournalTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.budget = BudgetCaps(wall_seconds=60, token_budget=100,
                                 tool_budget=10)

    def run_harness(self, name, *, workers=1, journal=None, calls=None,
                    provider_calls=None):
        root = self.root / name
        root.mkdir(exist_ok=True)
        verifier = _verifier(root)
        tasks = _tasks(root, verifier, 4) if not (root / "repo").exists() \
            else self._tasks_cache[name]
        self._tasks_cache = getattr(self, "_tasks_cache", {})
        self._tasks_cache[name] = tasks
        harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")

        def provider(task, arm):
            if provider_calls is not None:
                provider_calls.append((task.task_id, arm))
            return None
        return harness.run(
            tasks, _agent(calls if calls is not None else []),
            budget=self.budget, context_provider=provider,
            arms=("A", "B", "E"), arm_order_seed=1234, workers=workers,
            journal=journal)

    def test_parallel_workers_match_a_serial_run(self):
        serial_provider, parallel_provider = [], []
        serial = self.run_harness("serial", provider_calls=serial_provider)
        parallel = self.run_harness("parallel", workers=3,
                                    provider_calls=parallel_provider)
        self.assertEqual(_outcomes(serial), _outcomes(parallel))
        self.assertEqual(serial["solved_counts"], parallel["solved_counts"])
        self.assertEqual(serial["paired"], parallel["paired"])
        # Guidance is resolved in serial order even with parallel workers.
        self.assertEqual(serial_provider, parallel_provider)
        orders = {tuple(row["arm_order"]) for row in serial["per_task"]}
        self.assertGreater(len(orders), 1, "arm order is seeded per task")

    def test_a_journal_resumes_without_rerunning_finished_arms(self):
        path = self.root / "journal.jsonl"
        identity = {"study": "x"}
        first_calls: list = []
        journal = RunJournal(path, identity)
        original = journal.record
        recorded = []

        def stop_after_five(task_id, arm, row):
            original(task_id, arm, row)
            recorded.append((task_id, arm))
            if len(recorded) == 5:
                raise KeyboardInterrupt("simulated interruption")
        journal.record = stop_after_five
        with self.assertRaises(KeyboardInterrupt):
            self.run_harness("resume", journal=journal, calls=first_calls)
        resumed_calls: list = []
        reopened = RunJournal(path, identity)
        self.assertEqual(reopened.resumed_rows, 5)
        report = self.run_harness("resume", journal=reopened,
                                  calls=resumed_calls)
        self.assertEqual(len(resumed_calls), 12 - 5)
        self.assertFalse(set(resumed_calls) & set(recorded))
        reference = self.run_harness("reference")
        self.assertEqual(_outcomes(report), _outcomes(reference))

    def test_malformed_journal_rows_are_refused(self):
        with self.assertRaisesRegex(BenchmarkError, "outcome"):
            arm_result_from_row("t", "A", {"outcome": "won"})
        with self.assertRaisesRegex(BenchmarkError, "receipt_digest"):
            arm_result_from_row("t", "A", {
                "outcome": "pass", "budget_accounting": "verified",
                "wall_seconds": 1, "budget_exceeded": False})


@unittest.skipUnless(GIT and POSIX_CUSTODY,
                     "git and POSIX key custody are required")
class RunRealOptionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        patcher = mock.patch.object(tool, "codex_agent_status", _status)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_cli_passes_the_docker_options_through(self):
        captured = {}

        def fake_run_real(output, manifest, **kwargs):
            captured.update(kwargs)
            return 0
        with mock.patch.object(tool, "run_real", fake_run_real):
            tool.main(["--real-agent", "--manifest", "m.json",
                       "--executor", "docker", "--docker-image", "img@x",
                       "--docker-split-user", "2000:2000",
                       "--docker-runtime", "runsc", "--state-dir", "state",
                       "--workers", "3", "-o", "out.json"])
        self.assertEqual(captured["executor"], "docker")
        self.assertEqual(captured["docker_image"], "img@x")
        self.assertEqual(captured["docker_split_user"], "2000:2000")
        self.assertEqual(captured["docker_runtime"], "runsc")
        self.assertEqual(captured["state_dir"], Path("state"))
        self.assertEqual(captured["workers"], 3)
        self.assertTrue(captured["require_image_digest"])

    def test_cli_refuses_contradictory_options(self):
        cases = [
            ["--real-agent", "-o", "o.json"],  # local without opt-in
            ["--real-agent", "--executor", "docker",
             "--allow-shared-custody", "-o", "o.json"],
            ["--demo", "--allow-local-executor", "--workers", "2",
             "-o", "o.json"],
        ]
        for argv in cases:
            with self.subTest(argv=argv), \
                    contextlib.redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit):
                tool.main(argv)

    def test_an_unavailable_docker_daemon_blocks_the_run(self):
        manifest = _write(self.root, _manifest(self.root))
        output = self.root / "report.json"
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               side_effect=RunnerError("docker_unavailable")):
            code = tool.run_real(output, manifest, executor="docker",
                                 agent_factory=_scripted_agent)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_EXECUTOR")

    def test_docker_split_custody_is_recorded_as_split(self):
        """The Docker backend registers private tests under split custody."""
        manifest = _write(self.root, _manifest(self.root))
        output = self.root / "report.json"
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               return_value="test"), \
                mock.patch.object(DockerSandboxExecutor, "prepare",
                                  side_effect=RunnerError("no_daemon")), \
                contextlib.redirect_stdout(io.StringIO()):
            code = tool.run_real(
                output, manifest, executor="docker",
                docker_user="1000:1000", agent_factory=_scripted_agent,
                state_dir=self.root / "state")
        report = json.loads(output.read_text(encoding="utf-8"))
        # No daemon: every evaluation errors, but the run is configured
        # for split custody end to end.
        self.assertIn(code, (0, 1), report.get("note"))
        self.assertEqual(report["executor"]["class"], "DockerSandboxExecutor")
        self.assertTrue(report["executor"]["supports_split_custody"])
        provenance = report["learning_qualification"]["provenance"]
        self.assertEqual(provenance["custody"], "split")
        self.assertNotIn("private acceptance tests ran under shared custody",
                         report["learning_qualification"]["limitations"])
        registry = json.loads(
            (self.root / "state" / "registry" / "tasks.json").read_text())
        self.assertEqual({task["custody"] for task in registry["tasks"]},
                         {"split"})

    def test_a_resume_under_another_executor_configuration_is_blocked(self):
        """Journaled rows are reused only under the executor that made them."""
        manifest = _write(self.root, _manifest(self.root))
        output = self.root / "report.json"
        state = self.root / "state"

        def run(image):
            with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                                   return_value="test"), \
                    mock.patch.object(DockerSandboxExecutor, "prepare",
                                      side_effect=RunnerError("no_daemon")), \
                    contextlib.redirect_stdout(io.StringIO()):
                code = tool.run_real(
                    output, manifest, executor="docker", docker_image=image,
                    require_image_digest=False, docker_user="1000:1000",
                    agent_factory=_scripted_agent, state_dir=state)
            return code, json.loads(output.read_text(encoding="utf-8"))

        first, _ = run("sis-evaluator:a")
        self.assertIn(first, (0, 1))
        code, report = run("sis-evaluator:b")
        self.assertEqual(code, 2, report.get("note"))
        self.assertEqual(report["release_gate"], "BLOCKED_RESUME")
        self.assertIn("journal_identity_mismatch", report["note"])
        again, report = run("sis-evaluator:a")
        self.assertIn(again, (0, 1), report.get("note"))
        self.assertNotEqual(report.get("release_gate"), "BLOCKED_RESUME")

    def test_a_state_dir_open_to_others_is_refused(self):
        state = self.root / "state"
        state.mkdir(mode=0o755)
        state.chmod(0o755)
        manifest = _write(self.root, _manifest(self.root))
        output = self.root / "report.json"
        code = tool.run_real(output, manifest, allow_shared_custody=True,
                             agent_factory=_scripted_agent, state_dir=state)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_STATE")

    def test_a_tampered_journal_receipt_blocks_the_resume(self):
        state = self.root / "state"
        manifest = _write(self.root, _manifest(self.root))
        output = self.root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            tool.run_real(output, manifest, allow_shared_custody=True,
                          agent_factory=_scripted_agent, state_dir=state)
        journal = state / "journal.jsonl"
        lines = journal.read_text().splitlines()
        # Rewrite one row's receipt and re-chain the journal so only the
        # receipt check can catch it.
        from sis.v3.contracts import canonical_digest
        from sis.v3.study_runtime import _normalized
        rebuilt = [lines[0]]
        head = json.loads(lines[0])["identity_digest"]
        for index, line in enumerate(lines[1:]):
            entry = json.loads(line)
            if index == 0:
                entry["row"]["receipt_digest"] = "f" * 64
            body = {key: entry[key] for key in
                    ("task_id", "arm", "row", "annotations")}
            body["prior"] = head
            entry = {**body, "entry_digest": canonical_digest(
                "five_arm_run_journal_entry", 1, _normalized(body))}
            head = entry["entry_digest"]
            rebuilt.append(json.dumps(entry))
        journal.write_text("\n".join(rebuilt) + "\n")
        with contextlib.redirect_stdout(io.StringIO()):
            code = tool.run_real(output, manifest, allow_shared_custody=True,
                                 agent_factory=_scripted_agent,
                                 state_dir=state)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_RESUME")
        self.assertIn("journal_receipt_not_issued", report["note"])


if __name__ == "__main__":
    unittest.main()
