"""Governed evaluation plane + end-to-end campaign (v3.3 M6/M9)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, TaskEnvelopeV1, canonical_digest
from sis.v3.governed_eval import (EvaluationPartition,
                                  assert_partition_disjoint,
                                  compute_metrics, preregister,
                                  protocol_required_sample_size,
                                  required_sample_size, run_candidate_probe,
                                  run_governed_evaluation)

REPO = Path(__file__).resolve().parents[2]


def _forge(document):
    """Re-digest a hand-built protocol document, as an attacker would."""
    normalized = json.loads(
        json.dumps({key: value for key, value in document.items()
                    if key != "protocol_digest"}, sort_keys=True),
        parse_float=lambda value: f"float:{value}")
    return document | {"protocol_digest": canonical_digest(
        "eval_protocol", 1, normalized)}


def _task(task_id, digest):
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest=digest, base_commit="a1b2c3d",
        task_statement_digest="e" * 64, permitted_commands=("pytest",),
        isolation_profile="unverified_local", time_budget_seconds=60,
        token_budget=1000, tool_budget=10, actor_id="t",
        evaluator_task_ref=task_id)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + str(REPO)
    return env


class PartitionTests(unittest.TestCase):
    def test_overlap_and_empty_holdout_rejected(self):
        with self.assertRaises(ContractError):
            assert_partition_disjoint(EvaluationPartition(
                induction=(_task("i", "a" * 64),),
                holdout=(_task("h", "a" * 64),)))
        with self.assertRaisesRegex(ContractError, "holdout"):
            assert_partition_disjoint(EvaluationPartition(
                induction=(_task("i", "a" * 64),)))

    def test_disjoint_partition_passes(self):
        assert_partition_disjoint(EvaluationPartition(
            induction=(_task("i", "a" * 64),),
            development=(_task("d", "b" * 64),),
            holdout=(_task("h", "c" * 64),)))

    def test_unknown_partition_name_rejected(self):
        p = EvaluationPartition(holdout=(_task("h", "c" * 64),))
        with self.assertRaises(ContractError):
            p.by_name("bogus")


class ProtocolTests(unittest.TestCase):
    def test_preregistration_freezes_digest(self):
        p = preregister(primary_metric="paired solved_delta E vs A",
                        method="mcnemar_exact", alpha=0.05,
                        min_effect=1.0, sample_size=required_sample_size(),
                        budget={"wall_seconds": 60})
        self.assertEqual(len(p["protocol_digest"]), 64)
        q = preregister(primary_metric="x", method="m", alpha=0.01,
                        min_effect=1.0,
                        sample_size=required_sample_size(alpha=0.01),
                        budget={"wall_seconds": 60})
        self.assertNotEqual(p["protocol_digest"], q["protocol_digest"])

    def test_sample_size_power_analysis(self):
        n = required_sample_size(0.7, 0.3)
        self.assertIsInstance(n, int)
        self.assertGreaterEqual(n, 4)
        with self.assertRaises(ContractError):
            required_sample_size(0.3, 0.7)

    def test_sample_size_respects_alpha_and_power(self):
        # No silent z substitution: stricter alpha and higher power both
        # increase the required sample.
        base = required_sample_size(0.7, 0.3)
        stricter = required_sample_size(0.7, 0.3, alpha=0.01)
        powered = required_sample_size(0.7, 0.3, power=0.9)
        self.assertGreater(stricter, base)
        self.assertGreater(powered, base)
        for bad in (dict(alpha=0.0), dict(alpha=0.5), dict(alpha=1.0),
                    dict(power=0.0), dict(power=1.0)):
            with self.assertRaises(ContractError):
                required_sample_size(0.7, 0.3, **bad)

    def _powered(self):
        return preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=103, budget={"wall_seconds": 60})

    def test_power_analysis_missing_or_malformed_rejected(self):
        with self.assertRaisesRegex(ContractError, "power_analysis_missing"):
            protocol_required_sample_size(self._powered() | {
                "power_analysis": None})
        with self.assertRaisesRegex(ContractError, "power_analysis_missing"):
            protocol_required_sample_size(
                {"alpha": 0.05, "power_analysis": "opaque"})
        # A diagnostic protocol declares no floor to verify.
        diagnostic = self._diagnostic()
        self.assertNotIn("power_analysis", diagnostic)
        with self.assertRaisesRegex(ContractError, "power_analysis_diagnostic"):
            protocol_required_sample_size(diagnostic)

    def _diagnostic(self):
        return preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=1, powered=False, budget={"wall_seconds": 60})

    def test_diagnostic_marker_cannot_smuggle_a_power_floor(self):
        # A forged mixed document — diagnostic label plus a valid
        # power_analysis — must not become a powered plan for production.
        mixed = self._diagnostic() | {
            "power_analysis": self._powered()["power_analysis"]}
        with self.assertRaisesRegex(ContractError, "power_analysis_diagnostic"):
            protocol_required_sample_size(mixed)

    def test_powered_flag_must_be_a_bool(self):
        for bad in (1, 0, "yes", None):
            with self.assertRaisesRegex(ContractError, "powered"):
                preregister(primary_metric="x", method="m", alpha=0.05,
                            min_effect=1.0, sample_size=1, powered=bad,
                            budget={"wall_seconds": 60})

    def test_powered_plan_below_its_own_floor_is_refused(self):
        # A plan that contradicts its own power target is an authoring
        # error: the declared sample cannot be below the recomputed floor.
        with self.assertRaisesRegex(ContractError, "below the recomputed"):
            preregister(primary_metric="x", method="m", alpha=0.05,
                        min_effect=1.0, sample_size=29,
                        budget={"wall_seconds": 60})
        self.assertEqual(preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=29, expected_baseline=0.7, expected_treatment=0.3,
            budget={"wall_seconds": 60})["power_analysis"]["required_n"], 29)

    def test_underpowered_plan_is_registrable_only_when_declared(self):
        plan = preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=29, allow_underpowered=True,
            budget={"wall_seconds": 60})
        self.assertTrue(plan["power_analysis"]["underpowered_declared"])
        self.assertEqual(plan["power_analysis"]["required_n"], 103)
        self.assertEqual(protocol_required_sample_size(plan), 103)
        # The declaration is inside the digested document, not beside it.
        normalized = json.loads(
            json.dumps({key: value for key, value in plan.items()
                        if key != "protocol_digest"}, sort_keys=True),
            parse_float=lambda value: f"float:{value}")
        self.assertEqual(plan["protocol_digest"],
                         canonical_digest("eval_protocol", 1, normalized))
        undeclared = json.loads(json.dumps(normalized, sort_keys=True))
        del undeclared["power_analysis"]["underpowered_declared"]
        self.assertNotEqual(plan["protocol_digest"],
                            canonical_digest("eval_protocol", 1, undeclared))

    def test_allow_underpowered_flag_is_validated(self):
        with self.assertRaisesRegex(ContractError, "allow_underpowered"):
            preregister(primary_metric="x", method="m", alpha=0.05,
                        min_effect=1.0, sample_size=1, powered=False,
                        allow_underpowered=True,
                        budget={"wall_seconds": 60})
        for bad in (1, 0, "yes", None):
            with self.assertRaisesRegex(ContractError, "allow_underpowered"):
                preregister(primary_metric="x", method="m", alpha=0.05,
                            min_effect=1.0, sample_size=1,
                            allow_underpowered=bad,
                            budget={"wall_seconds": 60})
        with self.assertRaisesRegex(ContractError, "sample_size must be an int"):
            preregister(primary_metric="x", method="m", alpha=0.05,
                        min_effect=1.0, sample_size="29",
                        budget={"wall_seconds": 60})
        with self.assertRaisesRegex(ContractError, "sample_size must be positive"):
            preregister(primary_metric="x", method="m", alpha=0.05,
                        min_effect=1.0, sample_size=0, powered=False,
                        budget={"wall_seconds": 60})

    def test_power_analysis_invalid_values_rejected(self):
        good = self._powered()["power_analysis"]
        for corrupted in (
                {**good, "expected_baseline": "high"},
                {**good, "expected_treatment": None},
                {**good, "power": float("nan")},
                {**good, "power": float("inf")},
                {**good, "expected_baseline": True},
                {k: v for k, v in good.items()
                 if k != "expected_treatment"},
                {**good, "expected_baseline": 0.3,
                 "expected_treatment": 0.7}):
            protocol = self._powered() | {"power_analysis": corrupted}
            with self.assertRaisesRegex(ContractError,
                                        "power_analysis_invalid"):
                protocol_required_sample_size(protocol)
        with self.assertRaisesRegex(ContractError, "power_analysis_invalid"):
            protocol_required_sample_size(
                self._powered() | {"alpha": "0.05"})

    def test_power_analysis_required_n_must_recompute(self):
        good = self._powered()["power_analysis"]
        for forged in (1, 104, 103.0, True, "103", None):
            protocol = self._powered() | {
                "power_analysis": {**good, "required_n": forged}}
            with self.assertRaisesRegex(
                    ContractError, "power_analysis_required_n_mismatch"):
                protocol_required_sample_size(protocol)
        self.assertEqual(
            protocol_required_sample_size(self._powered()), 103)


class _StubHarness:
    """Minimal harness double: returns a fixed report, records the call."""

    def __init__(self, report):
        self._report = report

    def run(self, tasks, agent, *, budget, context_provider, arms):
        return dict(self._report)


class ConformanceTests(unittest.TestCase):
    def _report(self):
        return {"per_task": [], "budget": {"wall_seconds": 60,
                                           "token_budget": 1000,
                                           "tool_budget": 10},
                "solved_counts": {}}

    def _run(self, protocol, n_tasks=1):
        task = _task("h", "c" * 64)
        return run_governed_evaluation(
            _StubHarness(self._report()),
            [(task, Path("/nonexistent"))] * n_tasks,
            object(),
            budget=type("B", (), {"wall_seconds": 60})(),
            context_provider=None,
            protocol=protocol,
            learned_repo_digests=["a" * 64],
            arms=("A", "E"))

    def test_conforming_run_records_conforms_true(self):
        report = self._run(preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=103, arms=("A", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000}), n_tasks=103)
        conf = report["governed"]["conformance"]
        self.assertTrue(conf["conforms"], conf["mismatches"])

    def test_declared_sample_cannot_override_power_floor(self):
        # A hand-built document (correctly re-digested) that declares 29
        # tasks while carrying the 103-task floor must still be flagged:
        # conformance recomputes the floor instead of trusting the plan.
        protocol = _forge(preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=103, arms=("A", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})
            | {"sample_size": 29})
        conf = self._run(protocol, n_tasks=29)["governed"]["conformance"]
        self.assertFalse(conf["conforms"])
        self.assertTrue(any("required=103" in m for m in conf["mismatches"]))
        protocol["power_analysis"]["required_n"] = 1
        conf = self._run(protocol, n_tasks=29)["governed"]["conformance"]
        self.assertIn("power_analysis_required_n_mismatch", conf["mismatches"])

    def test_declared_underpowered_plan_still_reports_the_shortfall(self):
        protocol = preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=29, allow_underpowered=True, arms=("A", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})
        conf = self._run(protocol, n_tasks=29)["governed"]["conformance"]
        self.assertFalse(conf["conforms"])
        self.assertTrue(any("(underpowered)" in m
                            for m in conf["mismatches"]))

    def test_powered_protocol_missing_analysis_is_flagged(self):
        plan = {"primary_metric": "x", "method": "m", "alpha": 0.05,
                "sample_size": 1, "arms": ("A", "E"),
                "budget": {"wall_seconds": 60, "token_budget": 1000}}
        conf = self._run(plan)["governed"]["conformance"]
        self.assertFalse(conf["conforms"])
        self.assertIn("power_analysis_missing", conf["mismatches"])

    def test_diagnostic_plan_conforms_without_power_claim(self):
        protocol = preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=1, powered=False, arms=("A", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})
        conf = self._run(protocol)["governed"]["conformance"]
        self.assertTrue(conf["conforms"], conf["mismatches"])

    def test_mixed_diagnostic_document_is_flagged(self):
        protocol = preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=103, arms=("A", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})
        mixed = protocol | {"analysis_kind": "diagnostic"}
        conf = self._run(mixed)["governed"]["conformance"]
        self.assertFalse(conf["conforms"])
        self.assertIn("power_analysis_diagnostic", conf["mismatches"])

    def test_off_plan_run_is_flagged_not_hidden(self):
        report = self._run(preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=99, allow_underpowered=True, arms=("A", "E"),
            budget={"wall_seconds": 30}))
        conf = report["governed"]["conformance"]
        self.assertFalse(conf["conforms"])
        self.assertTrue(any("budget.wall_seconds" in m
                            for m in conf["mismatches"]))
        self.assertTrue(any("sample_size" in m
                            for m in conf["mismatches"]))


class CandidateProbeTests(unittest.TestCase):
    """Per-candidate qualification probes stay under the governed gates."""

    def _report(self):
        return {"per_task": [], "budget": {"wall_seconds": 60,
                                           "token_budget": 1000,
                                           "tool_budget": 10},
                "solved_counts": {}}

    def _protocol(self):
        return preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=103, arms=("A", "B", "C", "D", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})

    def _probe(self, learned=("a" * 64,)):
        return run_candidate_probe(
            _StubHarness(self._report()),
            [(_task("h", "c" * 64), Path("/nonexistent"))] * 103,
            object(),
            budget=type("B", (), {"wall_seconds": 60})(),
            context_provider=None,
            protocol=self._protocol(),
            learned_repo_digests=list(learned))

    def test_probe_records_conformance_and_skips_arm_comparison(self):
        report = self._probe()
        self.assertEqual(report["governed"]["analysis_mode"],
                         "candidate_probe")
        self.assertEqual(report["governed"]["arms"], ["E"])
        conf = report["governed"]["conformance"]
        self.assertTrue(conf["conforms"], conf["mismatches"])
        self.assertFalse(any(m.startswith("arms:") for m in conf["mismatches"]))

    def test_probe_still_enforces_repository_disjointness(self):
        with self.assertRaisesRegex(ContractError, "overlap"):
            self._probe(learned=("c" * 64,))

    def test_diagnostic_probe_is_useful_but_not_powered(self):
        # A one-task screen honestly declares itself diagnostic: the probe
        # conforms to its plan, but the protocol carries no power floor a
        # production qualification could ever verify.
        protocol = preregister(
            primary_metric="x", method="m", alpha=0.05, min_effect=1.0,
            sample_size=1, powered=False, arms=("A", "B", "C", "D", "E"),
            budget={"wall_seconds": 60, "token_budget": 1000})
        report = run_candidate_probe(
            _StubHarness(self._report()),
            [(_task("h", "c" * 64), Path("/nonexistent"))],
            object(),
            budget=type("B", (), {"wall_seconds": 60})(),
            context_provider=None,
            protocol=protocol,
            learned_repo_digests=["a" * 64])
        conf = report["governed"]["conformance"]
        self.assertTrue(conf["conforms"], conf["mismatches"])
        with self.assertRaisesRegex(ContractError, "power_analysis_diagnostic"):
            protocol_required_sample_size(protocol)


class MetricsTests(unittest.TestCase):
    def _report(self):
        return {"per_task": [
            {"task_id": "t1", "arms": {
                "A": {"outcome": "pass", "wall_seconds": 1.0,
                      "tokens_used": 10, "tools_used": 2},
                "E": {"outcome": "pass", "wall_seconds": 1.0}}},
            {"task_id": "t2", "arms": {
                "A": {"outcome": "fail", "wall_seconds": 2.0},
                "E": {"outcome": "fail", "wall_seconds": 2.0}}},
        ]}

    def test_metrics_math_and_abstention(self):
        m = compute_metrics(
            self._report(),
            served={("t1", "E"): True, ("t2", "E"): False})
        self.assertEqual(m["A"]["solved_task_rate"], 0.5)
        self.assertEqual(m["A"]["failure_rate"], 0.5)
        # The baseline cannot regress against itself.
        self.assertEqual(m["A"]["verified_regression_rate"], 0.0)
        self.assertEqual(m["E"]["verified_regression_rate"], 0.0)
        self.assertEqual(m["A"]["abstention_rate"], 1.0)  # never served
        self.assertEqual(m["E"]["abstention_rate"], 0.5)
        self.assertIsNone(m["E"]["negative_transfer_rate"])
        self.assertEqual(m["A"]["mean_tokens_per_task"], 10.0)
        self.assertIsNone(m["E"]["mean_tokens_per_task"])  # not fabricated
        self.assertEqual(m["A"]["evaluation_integrity_failures"], 0)

    def test_regression_is_relative_to_baseline_solves(self):
        report = self._report()
        report["per_task"][0]["arms"]["E"]["outcome"] = "fail"
        m = compute_metrics(report)
        # t1 was a baseline solve that E lost; t2 was never a baseline solve.
        self.assertEqual(m["E"]["verified_regression_rate"], 1.0)
        self.assertEqual(m["A"]["verified_regression_rate"], 0.0)
        report["per_task"][0]["arms"]["A"]["outcome"] = "fail"
        m = compute_metrics(report)
        self.assertIsNone(m["A"]["verified_regression_rate"])

    def test_paired_rates_and_cost_keys_present(self):
        m = compute_metrics(self._report())
        # t1: both pass -> tie; t2: both fail -> tie. No wins or losses.
        self.assertEqual(m["E"]["paired_win_rate"], 0.0)
        self.assertEqual(m["E"]["paired_loss_rate"], 0.0)
        self.assertIsNone(m["E"]["mean_cost_per_verified_solve"])
        report = self._report()
        report["per_task"][1]["arms"]["E"]["outcome"] = "pass"
        m = compute_metrics(report)
        self.assertEqual(m["E"]["paired_win_rate"], 0.5)
        self.assertEqual(m["E"]["paired_loss_rate"], 0.0)
        self.assertEqual(m["A"]["paired_win_rate"], 0.0)

    def test_negative_transfer_measured(self):
        m = compute_metrics(
            self._report(),
            served={("t2", "E"): True},
            misleading_tasks={"t2"})
        # served a misleading task and it failed -> negative transfer = 1.0
        self.assertEqual(m["E"]["negative_transfer_rate"], 1.0)

    def test_errors_count_as_integrity_failures(self):
        report = self._report()
        report["per_task"][0]["arms"]["A"]["error"] = "boom"
        m = compute_metrics(report)
        self.assertEqual(m["A"]["evaluation_integrity_failures"], 1)


class CampaignCLITests(unittest.TestCase):
    def test_deterministic_campaign_end_to_end(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "out"
            proc = subprocess.run(
                [sys.executable,
                 str(REPO / "tools" / "governed_campaign.py"),
                 "-o", str(out)],
                capture_output=True, text=True, env=_env(), cwd=REPO,
                timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            evidence = json.loads(
                (out / "campaign_evidence.json").read_text())
            self.assertEqual(evidence["kind"], "governed_campaign")
            counts = evidence["evaluation"]["solved_counts"]
            self.assertGreater(counts.get("E", 0), counts.get("A", -1))
            self.assertTrue(evidence["registry"]["qualified"])
            self.assertTrue(evidence["registry"]["audit"])
            # revocation demonstration actually ran: the revoked
            # candidate's lesson text no longer serves
            post = evidence["served_after_revocation"]
            self.assertIsNotNone(post)
            self.assertTrue(all(
                "round_money" not in step for step in post["checks"]))
            self.assertTrue(evidence["skill_bundle"])
            stdout = json.loads(proc.stdout)
            self.assertEqual(len(stdout["digest"]), 64)


if __name__ == "__main__":
    unittest.main()
