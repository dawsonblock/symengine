"""SIS3-012: paired four-arm harness with independent scoring."""
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"},
        )
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work",
        )
        self.budget = BudgetCaps(wall_seconds=60, token_budget=1000, tool_budget=10)

    def test_d_guided_agent_wins_paired(self):
        """D arm gets guidance and fixes; A/B/C leave the bug in place."""
        def agent(ctx):
            if ctx.arm == "D" and ctx.guidance is not None:
                (ctx.workspace / "calc.py").write_text(
                    "def scale(a, b):\n    return a * b\n")

        seen_arms = []
        def provider(task, arm):
            seen_arms.append(arm)
            return object() if arm == "D" else None

        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
            context_provider=provider,
        )
        self.assertEqual(report["solved_counts"]["D"], 1)
        self.assertEqual(report["solved_counts"]["A"], 0)
        self.assertEqual(report["paired"]["D_vs_A"]["wins"], 1)
        self.assertEqual(report["paired"]["D_vs_C"]["solved_delta"], 1)
        self.assertTrue(report_digest(report))

    def test_arm_exception_is_error_observation_not_verdict(self):
        def agent(ctx):
            raise RuntimeError("boom")
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
            arms=("A",),
        )
        self.assertEqual(report["per_task"][0]["arms"]["A"]["outcome"], "error")

    def test_all_arms_same_pass_counts(self):
        def agent(ctx):
            (ctx.workspace / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
        )
        self.assertTrue(all(v == 1 for v in report["solved_counts"].values()))
        self.assertEqual(report["paired"]["D_vs_A"]["ties"], 1)

    def test_budget_violation_flagged(self):
        import time
        def agent(ctx):
            time.sleep(2.1)
        report = self.harness.run(
            [(self.task, self.repo)], agent,
            budget=BudgetCaps(wall_seconds=1, token_budget=1000, tool_budget=10),
            arms=("A",),
        )
        self.assertEqual(report["budget_violations"], 1)
        self.assertTrue(report["per_task"][0]["arms"]["A"]["budget_exceeded"])

    def test_fresh_workspace_per_arm(self):
        seen = []
        def agent(ctx):
            # Each arm must see the pristine buggy file, not a prior arm's edit.
            seen.append((ctx.arm, (ctx.workspace / "calc.py").read_text()))
        self.harness.run([(self.task, self.repo)], agent, budget=self.budget)
        self.assertEqual(len(seen), 4)
        self.assertTrue(all("a - b" in text for _, text in seen))


if __name__ == "__main__":
    unittest.main()
