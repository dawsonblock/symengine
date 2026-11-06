"""PR-05: execution qualification — hard budgets, usage metering, auth gate."""
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from sis.v3.adapters import CodexAdapter, CodexAdapterError
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, UsageMeter
from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier

from tests.v3.test_codex_adapter import (
    FakeCodex, FakeSdk, FakeThread, notification,
)


class BudgetEnforcementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False),
            key_dir=self.root / "keys", registry_dir=self.root / "registry")
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"})
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1")
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work")

    def test_runaway_agent_abandoned_at_wall_budget(self):
        def agent(ctx):
            time.sleep(30)

        start = time.monotonic()
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=1, token_budget=1000, tool_budget=10),
            arms=("A",))
        elapsed = time.monotonic() - start
        arm = report["per_task"][0]["arms"]["A"]
        # Suite does NOT wait for the runaway: ~1s + eval, not 30s.
        self.assertLess(elapsed, 20)
        self.assertTrue(arm["budget_exceeded"])
        self.assertEqual(arm["outcome"], "error")
        self.assertEqual(arm["error"], "agent_timeout")
        self.assertEqual(report["solved_counts"]["A"], 0)

    def test_usage_meter_verified_accounting(self):
        def agent(ctx):
            ctx.usage_meter.record_tokens(1234)
            ctx.usage_meter.record_tool_call(3)
            (ctx.workspace / "calc.py").write_text(
                "def scale(a, b):\n    return a * b\n")

        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=60, token_budget=1000,
                              tool_budget=10), arms=("A",))
        arm = report["per_task"][0]["arms"]["A"]
        self.assertEqual(arm["budget_accounting"], "verified")
        self.assertEqual(arm["tokens_used"], 1234)
        self.assertEqual(arm["tools_used"], 3)
        self.assertTrue(arm["budget_exceeded"])  # 1234 > 1000
        self.assertEqual(report["solved_counts"]["A"], 0)

    def test_agent_reported_usage_marked_reported_not_verified(self):
        def agent(ctx):
            return {"tokens_used": 12, "tools_used": 1}

        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget_or_default(),
            arms=("A",))
        arm = report["per_task"][0]["arms"]["A"]
        self.assertEqual(arm["budget_accounting"], "reported")
        self.assertEqual(arm["tokens_used"], 12)

    def test_missing_usage_marked_unverified(self):
        def agent(ctx):
            pass

        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=self.budget_or_default(), arms=("A",))
        self.assertEqual(
            report["per_task"][0]["arms"]["A"]["budget_accounting"],
            "unverified")

    def budget_or_default(self):
        return BudgetCaps(wall_seconds=60, token_budget=1000, tool_budget=10)


class CodexAuthenticationTests(unittest.TestCase):
    def test_authenticated_client_passes(self):
        class AuthClient(FakeCodex):
            def authenticated(self):
                return True
        adapter = CodexAdapter(
            sdk=FakeSdk(AuthClient()), require_authentication=True)
        with tempfile.TemporaryDirectory() as ws:
            turn = adapter.start_task("prompt", ws)
            self.assertTrue(turn.thread_id)
        adapter.close()

    def test_unauthenticated_client_fails_closed(self):
        class AnonClient(FakeCodex):
            def authenticated(self):
                return False
        adapter = CodexAdapter(
            sdk=FakeSdk(AnonClient()), require_authentication=True)
        with tempfile.TemporaryDirectory() as ws:
            with self.assertRaises(CodexAdapterError):
                adapter.start_task("prompt", ws)

    def test_missing_probe_is_unverifiable_not_anonymous(self):
        adapter = CodexAdapter(
            sdk=FakeSdk(FakeCodex()), require_authentication=True)
        with tempfile.TemporaryDirectory() as ws:
            with self.assertRaises(CodexAdapterError) as ctx:
                adapter.start_task("prompt", ws)
        self.assertIn("authentication_unverifiable", str(ctx.exception))

    def test_no_requirement_keeps_legacy_behavior(self):
        adapter = CodexAdapter(sdk=FakeSdk(FakeCodex()))
        with tempfile.TemporaryDirectory() as ws:
            turn = adapter.start_task("prompt", ws)
            self.assertTrue(turn.thread_id)
        adapter.close()


class RuntimeUsageExtractionTests(unittest.TestCase):
    def test_usage_tracks_stream_derived_tokens_and_tools(self):
        events = [
            notification("item/started", SimpleNamespace(
                item=SimpleNamespace(type="commandExecution"))),
            notification("turn/completed", SimpleNamespace(
                turn=SimpleNamespace(status="completed"),
                token_usage=SimpleNamespace(
                    total=SimpleNamespace(total_tokens=777)))),
        ]
        thread = FakeThread("thr-u", event_sets=[events])
        adapter = CodexAdapter(sdk=FakeSdk(FakeCodex(thread)))
        with tempfile.TemporaryDirectory() as ws:
            turn = adapter.start_task("prompt", ws)
            list(turn.events)  # drain the stream
        usage = adapter.usage("thr-u")
        self.assertEqual(usage["tokens"], 777)
        self.assertEqual(usage["tools"], 1)
        adapter.close()

    def test_usage_without_token_reports_none(self):
        adapter = CodexAdapter(sdk=FakeSdk(FakeCodex()))
        with tempfile.TemporaryDirectory() as ws:
            turn = adapter.start_task("prompt", ws)
            list(turn.events)
        usage = adapter.usage("thr-1")
        self.assertIsNone(usage["tokens"])
        self.assertEqual(usage["tools"], 0)
        adapter.close()


if __name__ == "__main__":
    unittest.main()
