"""Review fixes: the efficacy decision honors the preregistered plan.

Each test pins one finding: the protocol alpha reaches every statistic,
the power floor is bound to the minimum effect of interest, agent-side
failures do not demote a study, negative transfer is measured and gated,
the decision is repository-clustered, and secondary contrasts are
Holm-corrected.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from pathlib import Path
import tempfile

from sis.v3.contracts import ContractError
from sis.v3.governed_eval import (PRIMARY_CONTRAST_ARMS, preregister,
                                  protocol_required_sample_size)
from sis.v3.learning_qualification import (
    CONFIRMATORY, EXPLORATORY, MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES,
    analyze_report, holm_adjust, paired_contrast, repository_sign_flip_test)
from tests.v3.test_learning_qualification import (eligible_provenance,
                                                  synthetic_report)

BUDGET = {"wall_seconds": 60, "token_budget": 1000, "tool_budget": 100}


def _row(task_id, a_ok, e_ok, repository, **extra):
    def arm(ok):
        return {"outcome": "pass" if ok else "fail",
                "budget_exceeded": False, "budget_accounting": "verified",
                "wall_seconds": 1, "tokens_used": 1, "tools_used": 1}
    row = {"task_id": task_id, "arms": {"A": arm(a_ok), "E": arm(e_ok)},
           "repository_id": repository}
    row.update(extra)
    return row


def _report(rows):
    return {"per_task": rows, "governed": {
        "metrics": {}, "conformance": {"conforms": True, "mismatches": []}}}


def _two_arm_protocol(*, alpha=0.05, sample_size=103, **kwargs):
    return preregister(
        primary_metric="paired solved_delta E vs A", method="mcnemar_exact",
        alpha=alpha, min_effect=0.2, sample_size=sample_size, budget=BUDGET,
        arms=PRIMARY_CONTRAST_ARMS, **kwargs)


class PreregisteredAlphaTests(unittest.TestCase):
    def test_alpha_reaches_the_task_level_contrast(self):
        # 7 wins, 0 losses: exact p = 0.015625 — significant at 0.05,
        # not at a preregistered 0.01.
        rows = [_row(f"t{i}", False, i < 7, "r") for i in range(23)]
        report = _report(rows)
        loose = paired_contrast(report, alpha=0.05)
        strict = paired_contrast(report, alpha=0.01)
        self.assertAlmostEqual(strict["mcnemar_exact_p"], 0.015625)
        self.assertTrue(loose["significant"])
        self.assertFalse(strict["significant"])
        # The interval widens with the preregistered confidence level.
        self.assertLess(strict["difference_interval"][0],
                        loose["difference_interval"][0])
        self.assertEqual(strict["confidence_level"], 0.99)
        self.assertEqual(strict["difference_interval_95"],
                         loose["difference_interval"])

    def test_analysis_uses_the_protocol_alpha(self):
        rows = [_row(f"t{i}", False, i < 7, "r") for i in range(23)]
        analysis = analyze_report(
            _report(rows), protocol={"alpha": 0.01, "sample_size": 23},
            real_agent=False, hidden_holdout=True, arms=("A", "E"))
        self.assertEqual(analysis["alpha"], 0.01)
        self.assertFalse(analysis["decisive_contrast"]["significant"])
        self.assertNotEqual(analysis["efficacy_claim"], "supported")

    def test_alpha_outside_the_open_interval_is_refused(self):
        for bad in (0, 0.5, 1, -0.1, float("nan"), "0.05", True, None):
            with self.subTest(alpha=bad):
                with self.assertRaises(ValueError):
                    paired_contrast(_report([]), alpha=bad)
        analysis = analyze_report(
            synthetic_report(103, a_pass=False, e_pass=True,
                             repositories=20),
            protocol=_two_arm_protocol() | {"alpha": 0.7},
            real_agent=True, hidden_holdout=True, arms=("A", "E"),
            provenance=eligible_provenance())
        self.assertNotEqual(analysis["evidence_class"], CONFIRMATORY)
        self.assertTrue(any("alpha" in item
                            for item in analysis["limitations"]))


class PowerFloorTests(unittest.TestCase):
    def test_declared_effect_cannot_exceed_min_effect(self):
        with self.assertRaisesRegex(ContractError, "exceeds the preregistered"):
            preregister(primary_metric="x", method="m", alpha=0.01,
                        min_effect=0.2, sample_size=23, budget=BUDGET,
                        expected_baseline=0.2, expected_treatment=0.8)

    def test_the_check_is_direction_agnostic(self):
        up = _two_arm_protocol(expected_baseline=0.4, expected_treatment=0.6)
        down = _two_arm_protocol(expected_baseline=0.6,
                                 expected_treatment=0.4)
        self.assertEqual(up["power_analysis"]["required_n"],
                         down["power_analysis"]["required_n"])
        with self.assertRaisesRegex(ContractError, "exceeds"):
            _two_arm_protocol(expected_baseline=0.9, expected_treatment=0.1)

    def test_rates_and_min_effect_must_be_in_range(self):
        for kwargs in ({"expected_baseline": 0.0},
                       {"expected_treatment": 1.0},
                       {"expected_baseline": -0.1}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaisesRegex(ContractError, r"\(0, 1\)"):
                    _two_arm_protocol(**kwargs)
        for bad in (0, -0.2, 1.5, "0.2"):
            with self.subTest(min_effect=bad):
                with self.assertRaisesRegex(ContractError, "min_effect"):
                    preregister(primary_metric="x", method="m", alpha=0.05,
                                min_effect=bad, sample_size=103,
                                budget=BUDGET)

    def test_a_stored_protocol_with_an_inflated_effect_is_rejected(self):
        protocol = _two_arm_protocol()
        protocol["min_effect"] = 0.05
        with self.assertRaisesRegex(ContractError, "exceeds_min_effect"):
            protocol_required_sample_size(protocol)
        protocol.pop("min_effect")
        with self.assertRaisesRegex(ContractError, "min_effect_invalid"):
            protocol_required_sample_size(protocol)


class OrdinaryFailureAccountingTests(unittest.TestCase):
    def _analysis(self, failed_row):
        report = synthetic_report(103, a_pass=False, e_pass=True,
                                  repositories=20)
        report["per_task"][0]["arms"]["A"] = failed_row
        return analyze_report(
            report, protocol=_powered(), real_agent=True,
            hidden_holdout=True, provenance=eligible_provenance())

    def test_a_timed_out_arm_is_a_failure_not_a_demotion(self):
        for row in (
                {"outcome": "error", "error": "agent_timeout",
                 "budget_exceeded": True, "budget_accounting": "partial"},
                {"outcome": "error",
                 "error": "RuntimeError:real_agent_error_event",
                 "budget_exceeded": False, "budget_accounting": "unverified"},
                {"outcome": "fail", "budget_exceeded": True,
                 "budget_accounting": "partial"}):
            with self.subTest(row=row):
                analysis = self._analysis(row)
                self.assertEqual(
                    analysis["provenance"]["token_accounting"], "verified")
                self.assertEqual(analysis["evidence_class"], CONFIRMATORY)
                self.assertEqual(
                    analysis["provenance"]["token_accounting_rows"][
                        "attested_failure"], 1)

    def test_genuinely_unverifiable_rows_still_demote(self):
        for row in (
                {"outcome": "pass", "budget_exceeded": False,
                 "budget_accounting": "partial"},
                {"outcome": "error", "error": "evaluation:boom",
                 "budget_exceeded": False, "budget_accounting": "partial"},
                {"outcome": "error", "error": "agent_timeout_unterminated",
                 "workspace_retained": True, "budget_exceeded": True,
                 "budget_accounting": "unverified"}):
            with self.subTest(row=row):
                analysis = self._analysis(row)
                self.assertNotEqual(
                    analysis["provenance"]["token_accounting"], "verified")
                self.assertEqual(analysis["evidence_class"], EXPLORATORY)

    def test_codex_agent_meters_tokens_before_failing(self):
        from sis.v3.benchmark import UsageMeter
        from sis.v3.learning_qualification import CodexCliAgent

        def event(event_type, method, summary):
            return SimpleNamespace(event_type=event_type, payload={
                "sdk_method": method, "summary": summary})

        events = [
            event("tool_result", "item.completed", {
                "item_type": "command_execution",
                "token_usage": {"input_tokens": 7, "output_tokens": 3}}),
            event("agent_event", "sis/process_exit",
                  {"cli_exit_status": 137, "timed_out": True}),
        ]

        class Adapter:
            def start_task(self, prompt, workspace_path, **kwargs):
                yield from events

        agent = object.__new__(CodexCliAgent)
        agent._adapter = Adapter()
        agent._model = None
        agent._prompts = {"t1": "prompt"}
        meter = UsageMeter()
        with tempfile.TemporaryDirectory() as temp:
            ctx = SimpleNamespace(task=SimpleNamespace(task_id="t1"),
                                  workspace=Path(temp), guidance=None,
                                  usage_meter=meter)
            with self.assertRaisesRegex(RuntimeError, "real_agent_timeout"):
                agent(ctx)
        self.assertTrue(meter.tokens_verified)
        self.assertTrue(meter.tools_verified)
        self.assertEqual(meter.tokens, 10)


def _powered():
    return preregister(
        primary_metric="paired solved_delta E vs A", method="mcnemar_exact",
        alpha=0.05, min_effect=0.2, sample_size=103, budget=BUDGET)


class NegativeTransferTests(unittest.TestCase):
    def test_negative_transfer_is_measured_and_gates_the_claim(self):
        # 40 wins and 20 losses over 20 repositories: a clear net gain,
        # but E breaks 20 of the baseline's solves.
        rows = []
        for index in range(103):
            repository = f"repo-{index % 20}"
            if index < 40:
                rows.append(_row(f"t{index}", False, True, repository))
            elif index < 60:
                rows.append(_row(f"t{index}", True, False, repository))
            else:
                rows.append(_row(f"t{index}", False, False, repository))
        analysis = analyze_report(
            _report(rows), protocol=_two_arm_protocol(), real_agent=True,
            hidden_holdout=True, arms=("A", "E"),
            provenance=eligible_provenance())
        transfer = analysis["negative_transfer"]
        self.assertTrue(transfer["measured"])
        self.assertEqual(transfer["paired_losses"], 20)
        self.assertTrue(transfer["material"])
        self.assertEqual(analysis["evidence_class"], CONFIRMATORY)
        self.assertNotEqual(analysis["release_gate"], "EFFICACY_SUPPORTED")
        # A preregistered, looser threshold is honored.
        loose = analyze_report(
            _report(rows),
            protocol=_two_arm_protocol(max_negative_transfer=0.25),
            real_agent=True, hidden_holdout=True, arms=("A", "E"),
            provenance=eligible_provenance())
        self.assertFalse(loose["negative_transfer"]["material"])
        self.assertEqual(loose["release_gate"], "EFFICACY_SUPPORTED")

    def test_unpaired_rows_are_not_a_measurement(self):
        report = synthetic_report(103, a_pass=False, e_pass=True,
                                  repositories=20)
        del report["per_task"][5]["arms"]["A"]
        analysis = analyze_report(
            report, protocol=_powered(), real_agent=True,
            hidden_holdout=True, provenance=eligible_provenance())
        self.assertFalse(analysis["negative_transfer"]["measured"])
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)

    def test_misleading_tasks_are_reported(self):
        rows = [_row("t0", True, False, "r0"), _row("t1", True, True, "r1")]
        analysis = analyze_report(
            _report(rows), protocol={"alpha": 0.05, "sample_size": 2},
            real_agent=False, hidden_holdout=True, arms=("A", "E"),
            misleading_tasks={"t0", "t1"})
        self.assertEqual(analysis["negative_transfer"]["misleading_tasks"], 2)
        self.assertEqual(
            analysis["negative_transfer"]["misleading_paired_losses"], 1)

    def test_the_threshold_must_be_a_rate(self):
        with self.assertRaisesRegex(ContractError, "max_negative_transfer"):
            _two_arm_protocol(max_negative_transfer=1.5)


class RepositoryClusteredDecisionTests(unittest.TestCase):
    def test_task_level_significance_alone_is_not_efficacy(self):
        # 20 wins concentrated in two repositories, nothing elsewhere:
        # McNemar on tasks says p < 1e-5, but only two clusters moved.
        rows = []
        for index in range(103):
            repository = f"repo-{index % 20}"
            win = repository in ("repo-0", "repo-1")
            rows.append(_row(f"t{index}", False, win, repository))
        analysis = analyze_report(
            _report(rows), protocol=_two_arm_protocol(), real_agent=True,
            hidden_holdout=True, arms=("A", "E"),
            provenance=eligible_provenance())
        self.assertTrue(analysis["decisive_contrast"]["significant"])
        test = analysis["primary_analysis"]["repository_test"]
        self.assertEqual(test["informative_repositories"], 2)
        self.assertGreater(test["p_value"], 0.05)
        self.assertEqual(analysis["evidence_class"], CONFIRMATORY)
        self.assertEqual(analysis["efficacy_claim"], "no_evidence")
        self.assertEqual(analysis["release_gate"], "NO_EFFICACY_CLAIM")

    def test_sign_flip_p_value_is_exact(self):
        rows = [_row(f"t{i}", False, True, f"r{i}") for i in range(6)]
        test = repository_sign_flip_test(_report(rows))
        self.assertAlmostEqual(test["p_value"], 2 / 64)
        self.assertTrue(test["significant"])
        rows.append(_row("t6", True, False, "r6"))
        test = repository_sign_flip_test(_report(rows))
        # |sum| >= 5 over 7 unit clusters: 2 * (1 + 7) / 128.
        self.assertAlmostEqual(test["p_value"], 16 / 128)

    def test_too_few_holdout_repositories_is_not_confirmatory(self):
        report = synthetic_report(
            103, a_pass=False, e_pass=True,
            repositories=MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES - 1)
        analysis = analyze_report(
            report, protocol=_powered(), real_agent=True,
            hidden_holdout=True, provenance=eligible_provenance())
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)
        self.assertTrue(any("holdout repositories" in item
                            for item in analysis["limitations"]))

    def test_tasks_without_repository_ids_are_not_confirmatory(self):
        report = synthetic_report(103, a_pass=False, e_pass=True)
        analysis = analyze_report(
            report, protocol=_powered(), real_agent=True,
            hidden_holdout=True, provenance=eligible_provenance())
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)
        self.assertNotEqual(analysis["efficacy_claim"], "supported")

    def test_static_guidance_routing_is_not_confirmatory(self):
        report = synthetic_report(103, a_pass=False, e_pass=True,
                                  repositories=20)
        analysis = analyze_report(
            report, protocol=_powered(), real_agent=True,
            hidden_holdout=True,
            provenance=eligible_provenance(guidance_routing="static_bundle"))
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)


class SecondaryContrastTests(unittest.TestCase):
    def test_holm_adjustment(self):
        adjusted = holm_adjust({"x": 0.01, "y": 0.04, "z": 0.03})
        self.assertAlmostEqual(adjusted["x"], 0.03)
        self.assertAlmostEqual(adjusted["z"], 0.06)
        self.assertAlmostEqual(adjusted["y"], 0.06)

    def test_secondary_contrasts_are_holm_corrected_and_labelled(self):
        # E beats B on 6 of 40 tasks: raw p = 0.03125 < 0.05, Holm over
        # three contrasts is 0.09375.
        report = synthetic_report(40, a_pass=False, e_pass=True,
                                  b_pass=True, c_pass=True, d_pass=True)
        for index, row in enumerate(report["per_task"]):
            if index < 6:
                row["arms"]["B"]["outcome"] = "fail"
        analysis = analyze_report(
            report, protocol={"alpha": 0.05, "sample_size": 40},
            real_agent=False, hidden_holdout=True)
        contrast = analysis["integration_vs_components"]["B"]
        self.assertEqual(contrast["role"], "secondary_mechanism_control")
        self.assertEqual(contrast["multiplicity_correction"], "holm")
        self.assertTrue(contrast["significant_unadjusted"])
        self.assertAlmostEqual(contrast["holm_adjusted_p"], 0.09375)
        self.assertFalse(contrast["significant"])
        self.assertEqual(analysis["decisive_contrast"]["role"],
                         "secondary_task_level")


if __name__ == "__main__":
    unittest.main()
