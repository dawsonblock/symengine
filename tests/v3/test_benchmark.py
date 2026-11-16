"""SIS3-012: paired four-arm harness with independent scoring."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.benchmark import (BenchmarkError, BenchmarkHarness, BudgetCaps,
                              report_digest)
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
            allow_shared_custody=True,
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
            repo_snapshot_digest=tree_digest(self.repo, version=3),
            base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work",
        )
        self.budget = BudgetCaps(wall_seconds=60, token_budget=1000, tool_budget=10)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_a_local_git_clone_stages_and_scores(self):
        source = self.root / "git-source"
        source.mkdir()
        (source / "calc.py").write_text(
            "def scale(a, b):\n    return a - b\n")
        subprocess.run(["git", "-C", str(source), "init", "-q"],
                       check=True, capture_output=True)
        subprocess.run(["git", "-C", str(source), "add", "."],
                       check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(source), "-c", "user.name=t", "-c",
             "user.email=t@e", "commit", "-qm", "base"],
            check=True, capture_output=True)
        clone = self.root / "git-clone"
        subprocess.run(
            ["git", "clone", "--local", "-q", str(source), str(clone)],
            check=True, capture_output=True)
        self.verifier.register_task(
            actor_role="evaluator", task_id="t-git",
            criterion_version="v1", argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"})
        task = TaskEnvelopeV1(
            schema_version=1, task_id="t-git",
            repo_snapshot_digest=tree_digest(clone, version=3),
            base_commit=None, task_statement_digest="0" * 64,
            permitted_commands=("x",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=10,
            actor_id="a", evaluator_task_ref="t-git")

        def agent(ctx):
            (ctx.workspace / "calc.py").write_text(
                "def scale(a, b):\n    return a * b\n")

        report = self.harness.run([(task, clone)], agent,
                                  budget=self.budget, arms=("A",))
        row = report["per_task"][0]["arms"]["A"]
        self.assertNotIn("error", row)
        self.assertEqual(row["outcome"], "pass")

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

    def test_worker_system_exit_is_an_error_not_a_pass(self):
        def agent(ctx):
            raise SystemExit(3)
        report = self.harness.run(
            [(self.task, self.repo)], agent, budget=self.budget,
            arms=("A",),
        )
        row = report["per_task"][0]["arms"]["A"]
        self.assertEqual(row["outcome"], "error")
        self.assertIn("SystemExit", row["error"])

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

    def test_staged_tree_must_match_the_task_envelope(self):
        from dataclasses import replace
        stale = replace(self.task, repo_snapshot_digest="0" * 64)
        with self.assertRaisesRegex(BenchmarkError,
                                    "repository_snapshot_mismatch"):
            self.harness.run([(stale, self.repo)], lambda ctx: None,
                             budget=self.budget, arms=("A",))

    def test_legacy_snapshot_digest_still_replays(self):
        from dataclasses import replace
        legacy = replace(
            self.task,
            repo_snapshot_digest=tree_digest(self.repo, version=1))

        def agent(ctx):
            (ctx.workspace / "calc.py").write_text(
                "def scale(a, b):\n    return a * b\n")

        report = self.harness.run([(legacy, self.repo)], agent,
                                  budget=self.budget, arms=("A",))
        row = report["per_task"][0]["arms"]["A"]
        self.assertNotIn("error", row)
        self.assertEqual(row["outcome"], "pass")


class StagingTests(unittest.TestCase):
    """A repository symlink must never copy outside material into a workspace."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.outside = self.root / "private" / "secret.txt"
        self.outside.parent.mkdir()
        self.outside.write_text("EVALUATOR-ONLY")
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("OK = 1\n")
        self.verifier = OutcomeVerifier(
            allow_shared_custody=True,
            executor=LocalSubprocessExecutor(self.root / "eval"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"assert True\n"})
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo, version=3),
            base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1")
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work")
        self.budget = BudgetCaps(wall_seconds=60, token_budget=1000,
                                 tool_budget=10)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_external_symlink_is_rejected_before_staging(self):
        (self.repo / "escape").symlink_to(self.outside)

        def agent(ctx):
            raise AssertionError("the agent must never run on this repo")

        with self.assertRaisesRegex(BenchmarkError,
                                    "repository_contains_external_symlinks"):
            self.harness.run([(self.task, self.repo)], agent,
                             budget=self.budget, arms=("A",))
        leftovers = list((self.root / "work").rglob("secret.txt"))
        self.assertEqual(leftovers, [])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_external_directory_symlink_is_rejected(self):
        private_dir = self.root / "private-dir"
        private_dir.mkdir()
        (private_dir / "secret.txt").write_text("EVALUATOR-ONLY")
        (self.repo / "escape-dir").symlink_to(
            private_dir, target_is_directory=True)
        with self.assertRaisesRegex(BenchmarkError,
                                    "repository_contains_external_symlinks"):
            self.harness.run([(self.task, self.repo)], lambda ctx: None,
                             budget=self.budget, arms=("A",))
        self.assertEqual(
            list((self.root / "work").rglob("secret.txt")), [])

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_hard_link_to_an_outside_file_is_rejected(self):
        os.link(self.outside, self.repo / "hardlink")
        with self.assertRaisesRegex(BenchmarkError,
                                    "repository_contains_hard_links"):
            self.harness.run([(self.task, self.repo)], lambda ctx: None,
                             budget=self.budget, arms=("A",))
        self.assertEqual(
            list((self.root / "work").rglob("secret.txt")), [])

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_internal_hard_links_are_staged(self):
        from dataclasses import replace
        (self.repo / "a.py").write_text("A = 1\n")
        os.link(self.repo / "a.py", self.repo / "b.py")
        task = replace(self.task,
                       repo_snapshot_digest=tree_digest(self.repo, version=3))
        seen = {}

        def agent(ctx):
            seen["a"] = (ctx.workspace / "a.py").read_text()
            seen["b"] = (ctx.workspace / "b.py").read_text()

        self.harness.run([(task, self.repo)], agent,
                         budget=self.budget, arms=("A",))
        self.assertEqual(seen["a"], "A = 1\n")
        self.assertEqual(seen["b"], "A = 1\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_internal_symlink_is_staged_as_a_link(self):
        from dataclasses import replace
        (self.repo / "alias.py").symlink_to("calc.py")
        task = replace(self.task,
                       repo_snapshot_digest=tree_digest(self.repo, version=3))
        seen = {}

        def agent(ctx):
            seen["is_link"] = (ctx.workspace / "alias.py").is_symlink()

        self.harness.run([(task, self.repo)], agent,
                         budget=self.budget, arms=("A",))
        self.assertTrue(seen["is_link"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlinks unavailable")
    def test_link_created_during_copy_is_detected(self):
        import shutil as shutil_module
        original = shutil_module.copytree

        def racing_copy(src, dst, **kwargs):
            original(src, dst, **kwargs)
            (Path(dst) / "escape").symlink_to(self.outside)

        with mock.patch("sis.v3.benchmark.shutil.copytree",
                        side_effect=racing_copy):
            with self.assertRaisesRegex(
                    BenchmarkError, "repository_contains_external_symlinks"):
                self.harness.run([(self.task, self.repo)], lambda ctx: None,
                                 budget=self.budget, arms=("A",))


class TerminationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("OK = 1\n")
        self.verifier = OutcomeVerifier(
            allow_shared_custody=True,
            executor=LocalSubprocessExecutor(self.root / "eval"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.verifier.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"assert True\n"})
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo, version=3),
            base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=1,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1")
        self.harness = BenchmarkHarness(
            verifier=self.verifier, work_root=self.root / "work")
        self.budget = BudgetCaps(wall_seconds=1, token_budget=1000,
                                 tool_budget=10)

    def test_registered_terminator_stops_the_arm(self):
        child = {}

        def agent(ctx):
            child["proc"] = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"])
            ctx.supervisor.register_terminator(child["proc"].kill)
            child["proc"].wait(timeout=25)

        start = time.monotonic()
        report = self.harness.run([(self.task, self.repo)], agent,
                                  budget=self.budget, arms=("A",))
        elapsed = time.monotonic() - start
        row = report["per_task"][0]["arms"]["A"]
        self.assertEqual(row["outcome"], "error")
        self.assertEqual(row["error"], "agent_timeout")
        self.assertLess(elapsed, 10)
        self.assertIsNotNone(child["proc"].poll())

    def test_worker_that_survives_abort_keeps_its_workspace(self):
        def agent(ctx):
            time.sleep(2.0)

        with mock.patch("sis.v3.benchmark._TERMINATION_GRACE_SECONDS", 0.05):
            report = self.harness.run([(self.task, self.repo)], agent,
                                      budget=self.budget, arms=("A",))
        row = report["per_task"][0]["arms"]["A"]
        self.assertEqual(row["error"], "agent_timeout_unterminated")
        self.assertTrue(row["workspace_retained"])
        self.assertTrue(list((self.root / "work").glob("arm-A-*")))

    def test_a_retained_workspace_is_not_hashed(self):
        def agent(ctx):
            time.sleep(2.0)

        with mock.patch("sis.v3.benchmark._TERMINATION_GRACE_SECONDS", 0.05), \
                mock.patch("sis.v3.benchmark.tree_digest",
                           side_effect=AssertionError(
                               "hashed a workspace with a live writer")):
            report = self.harness.run([(self.task, self.repo)], agent,
                                      budget=self.budget, arms=("A",))
        row = report["per_task"][0]["arms"]["A"]
        self.assertEqual(row["error"], "agent_timeout_unterminated")
        self.assertTrue(row["workspace_retained"])


if __name__ == "__main__":
    unittest.main()
