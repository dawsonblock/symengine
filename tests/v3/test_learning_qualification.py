"""PR-06: five-arm learning qualification and honest statistics."""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps
from sis.v3.contracts import GuidanceV1, TaskEnvelopeV1
from sis.v3.governed_eval import (GOVERNED_ARMS, compute_metrics,
                                  preregister)
from sis.v3.learning_qualification import (
    CONFIRMATORY,
    DEMONSTRATION,
    EXPLORATORY,
    FiveArmCampaign,
    analyze_report,
    build_context_provider,
    codex_agent_status,
    mcnemar_exact,
    newcombe_difference_interval,
    paired_contrast,
    wilson_interval,
)
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier

PY = __import__("sys").executable


def guidance(text="WRITE_OK"):
    return GuidanceV1(
        schema_version=1, decision="recommend", procedure_ids=("p",),
        revision="0" * 64,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64, helpful_next_checks=(text,),
        reason_code=None, approximate_tokens=20)


def synthetic_report(n, *, a_pass, e_pass, b_pass=None, c_pass=None,
                     d_pass=None, conformance=True):
    b_pass = a_pass if b_pass is None else b_pass
    c_pass = a_pass if c_pass is None else c_pass
    d_pass = a_pass if d_pass is None else d_pass
    per_task = []
    for index in range(n):
        def arm(ok):
            return {"outcome": "pass" if ok else "fail",
                    "budget_exceeded": False, "error": None,
                    "wall_seconds": 1, "tokens_used": 10, "tools_used": 2}
        per_task.append({
            "task_id": f"t{index}",
            "arms": {"A": arm(a_pass), "B": arm(b_pass),
                     "C": arm(c_pass), "D": arm(d_pass),
                     "E": arm(e_pass)},
        })
    report = {"per_task": per_task, "tasks": n,
              "budget": {"wall_seconds": 60, "token_budget": 1000,
                         "tool_budget": 100}}
    report["governed"] = {
        "metrics": compute_metrics(report),
        "conformance": {"conforms": conformance,
                        "mismatches": [] if conformance else ["sample_size"]},
    }
    return report


class StatisticsTests(unittest.TestCase):
    def test_mcnemar_exact(self):
        self.assertEqual(mcnemar_exact(0, 0), 1.0)
        self.assertAlmostEqual(mcnemar_exact(5, 0), 0.0625)
        self.assertAlmostEqual(mcnemar_exact(10, 0), 0.001953125)
        self.assertAlmostEqual(mcnemar_exact(2, 0), 0.5)
        self.assertAlmostEqual(mcnemar_exact(3, 2),
                               mcnemar_exact(2, 3))

    def test_wilson_interval(self):
        self.assertEqual(wilson_interval(0, 0), (0.0, 1.0))
        low, high = wilson_interval(10, 10)
        self.assertGreater(low, 0.7)
        self.assertAlmostEqual(high, 1.0)
        low, high = wilson_interval(0, 10)
        self.assertEqual(low, 0.0)
        self.assertLess(high, 0.3)

    def test_newcombe_difference_interval(self):
        low, high = newcombe_difference_interval(10, 10, 0, 10)
        self.assertGreater(low, 0.5)
        self.assertEqual(high, 1.0)
        low, high = newcombe_difference_interval(0, 10, 10, 10)
        self.assertLess(high, -0.5)
        self.assertEqual(low, -1.0)

    def test_paired_contrast_counts(self):
        report = synthetic_report(10, a_pass=False, e_pass=True)
        contrast = paired_contrast(report, baseline="A", treatment="E")
        self.assertEqual(contrast["wins"], 10)
        self.assertEqual(contrast["losses"], 0)
        self.assertEqual(contrast["delta"], 1.0)
        self.assertLess(contrast["mcnemar_exact_p"], 0.05)
        self.assertGreater(contrast["difference_interval_95"][0], 0)


class AnalysisTests(unittest.TestCase):
    def test_confirmatory_requires_real_agent_hidden_and_conforming(self):
        report = synthetic_report(103, a_pass=False, e_pass=True)
        analysis = analyze_report(
            report, protocol={"sample_size": 103, "alpha": 0.05},
            real_agent=True, hidden_holdout=True)
        self.assertEqual(analysis["evidence_class"], CONFIRMATORY)
        self.assertEqual(analysis["efficacy_claim"], "supported")
        self.assertEqual(analysis["release_gate"], "EFFICACY_SUPPORTED")

    def test_scripted_run_is_demonstration_not_efficacy(self):
        report = synthetic_report(29, a_pass=False, e_pass=True)
        analysis = analyze_report(
            report, protocol={"sample_size": 29, "alpha": 0.05},
            real_agent=False, hidden_holdout=True)
        self.assertEqual(analysis["evidence_class"], DEMONSTRATION)
        self.assertEqual(analysis["release_gate"],
                         "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")
        self.assertTrue(any("scripted" in item
                            for item in analysis["limitations"]))

    def test_underpowered_real_run_is_exploratory(self):
        report = synthetic_report(2, a_pass=False, e_pass=True)
        analysis = analyze_report(
            report, protocol={"sample_size": 29, "alpha": 0.05},
            real_agent=True, hidden_holdout=True)
        self.assertTrue(analysis["underpowered"])
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)
        self.assertEqual(analysis["release_gate"],
                         "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")
        self.assertTrue(any("underpowered" in item
                            for item in analysis["limitations"]))

    def test_regression_is_preserved(self):
        report = synthetic_report(103, a_pass=True, e_pass=False)
        analysis = analyze_report(
            report, protocol={"sample_size": 103, "alpha": 0.05},
            real_agent=True, hidden_holdout=True)
        self.assertEqual(analysis["efficacy_claim"], "regressed")
        self.assertEqual(analysis["release_gate"], "NO_EFFICACY_CLAIM")
        self.assertLess(analysis["decisive_contrast"]["delta"], 0)

    def test_nonconforming_protocol_is_invalid(self):
        report = synthetic_report(29, a_pass=False, e_pass=True,
                                  conformance=False)
        analysis = analyze_report(
            report, protocol={"sample_size": 29, "alpha": 0.05},
            real_agent=True, hidden_holdout=True)
        self.assertEqual(analysis["evidence_class"], "invalid")
        self.assertEqual(analysis["release_gate"],
                         "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")

    def test_integration_vs_components_reported(self):
        report = synthetic_report(
            10, a_pass=False, e_pass=True, b_pass=True, c_pass=False,
            d_pass=False)
        analysis = analyze_report(
            report, protocol={"sample_size": 10, "alpha": 0.05},
            real_agent=True, hidden_holdout=True)
        self.assertIn("B", analysis["integration_vs_components"])
        self.assertEqual(
            analysis["integration_vs_components"]["B"]["wins"], 0)
        self.assertEqual(
            analysis["integration_vs_components"]["C"]["wins"], 10)


class CampaignTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "solution.py").write_text("NO = 1\n")
        self.verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.tasks = []
        for index in range(2):
            task_id = f"task-{index}"
            self.verifier.register_task(
                actor_role="evaluator", task_id=task_id,
                criterion_version="v1",
                argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
                files={"eval_tests.py":
                       b"from pathlib import Path\n\n"
                       b"def test_solution():\n"
                       b"    assert 'OK' in Path('solution.py').read_text()\n"},
                base_commit="abc1234")
            self.tasks.append((TaskEnvelopeV1(
                schema_version=1, task_id=task_id,
                repo_snapshot_digest=tree_digest(self.repo),
                base_commit="abc1234",
                task_statement_digest=hashlib.sha256(
                    task_id.encode()).hexdigest(),
                permitted_commands=("pytest",),
                isolation_profile="unverified_local",
                time_budget_seconds=60, token_budget=1000, tool_budget=100,
                actor_id="agent", evaluator_task_ref=task_id), self.repo))

    def _agent(self, ctx):
        text = " ".join(ctx.guidance.helpful_next_checks) \
            if ctx.guidance is not None else ""
        if "WRITE_OK" in text:
            (ctx.workspace / "solution.py").write_text("OK = 1\n")
        return {"tokens_used": 10, "tools_used": 1}

    def _protocol(self, sample_size=2):
        return preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=sample_size,
            budget={"wall_seconds": 60, "token_budget": 1000,
                    "tool_budget": 100},
            arms=GOVERNED_ARMS)

    def test_campaign_runs_five_arms_and_labels_demonstration(self):
        served = {}
        provider = build_context_provider(
            {"A": None, "B": guidance(), "C": guidance(),
             "D": guidance(), "E": guidance()}, served)
        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=self.verifier, work_root=self.root / "work"),
            tasks=self.tasks, agent=self._agent,
            budget=BudgetCaps(wall_seconds=60, token_budget=1000,
                              tool_budget=100),
            protocol=self._protocol(), context_provider=provider,
            learned_repo_digests=(), real_agent=False)
        report = campaign.run()
        analysis = report["learning_qualification"]
        self.assertEqual(analysis["evidence_class"], DEMONSTRATION)
        self.assertEqual(analysis["decisive_contrast"]["wins"], 2)
        self.assertEqual(analysis["decisive_contrast"]["losses"], 0)
        self.assertEqual(analysis["metrics"]["A"]["solved_task_rate"], 0.0)
        self.assertEqual(analysis["metrics"]["E"]["solved_task_rate"], 1.0)
        # No misleading tasks were declared, so negative transfer is
        # unmeasured (None), never fabricated as zero.
        self.assertIsNone(analysis["negative_transfer"]["integrated_rate"])
        self.assertEqual(served[("task-0", "A")], False)
        self.assertEqual(served[("task-0", "E")], True)

    def test_campaign_rejects_learning_repo_overlap(self):
        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=self.verifier, work_root=self.root / "work"),
            tasks=self.tasks, agent=self._agent,
            budget=BudgetCaps(wall_seconds=60, token_budget=1000,
                              tool_budget=100),
            protocol=self._protocol(),
            context_provider=lambda task, arm: None,
            learned_repo_digests=(tree_digest(self.repo),),
            real_agent=False)
        with self.assertRaisesRegex(ValueError, "overlap"):
            campaign.validate()

    def test_campaign_rejects_wrong_arm_set(self):
        protocol = dict(self._protocol())
        protocol["arms"] = ["A", "B"]
        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=self.verifier, work_root=self.root / "work"),
            tasks=self.tasks, agent=self._agent,
            budget=BudgetCaps(wall_seconds=60, token_budget=1000,
                              tool_budget=100),
            protocol=protocol,
            context_provider=lambda task, arm: None,
            real_agent=False)
        with self.assertRaisesRegex(ValueError, "protocol arms"):
            campaign.validate()

    def test_context_provider_records_delivery(self):
        served = {}
        provider = build_context_provider(
            {"A": None, "E": guidance()}, served)
        task = self.tasks[0][0]
        self.assertIsNone(provider(task, "A"))
        self.assertIsNotNone(provider(task, "E"))
        self.assertFalse(served[(task.task_id, "A")])
        self.assertTrue(served[(task.task_id, "E")])

    def test_real_agent_gate_reports_status_without_calling(self):
        status = codex_agent_status()
        self.assertIn("available", status)
        self.assertIn("authenticated", status)
        self.assertIn("reason", status)


if __name__ == "__main__":
    unittest.main()
