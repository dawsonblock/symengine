"""V336-03: benchmark metrics separate candidates from recovery.

The v3.3.4/v3.3.5 tool reported ``rule_recovered = rule is not None``.
On the default non-negative domain the search returns
``absdiff(x[n-2] * x[n-1], -2)``, which matches every generated example
but is a different function, so the tool claimed exact recovery for a
rule its own result called ambiguous.

These regressions pin the repaired semantics: candidate existence,
intended structure, bounded equivalence, holdout accuracy and search
completion are separate metrics, and only ``exact_recovery_verified``
claims the intended rule.
"""
from __future__ import annotations

import argparse
import importlib.util
import unittest
from pathlib import Path

from sis.induction import SearchBudget, induce

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "benchmark_induction", ROOT / "tools" / "benchmark_induction.py")
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)

try:
    import z3  # noqa: F401
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


def _args(**overrides) -> argparse.Namespace:
    fields = dict(
        seed=0,
        train=6,
        dev=3,
        holdout=3,
        input_min=0,
        input_max=9,
        max_candidates=50000,
        max_signature_checks=500_000,
        max_wall_seconds=30.0,
        max_memory_bytes=None,
        max_expression_depth=5,
        equivalence="none",
    )
    fields.update(overrides)
    return argparse.Namespace(**fields)


class StructuralMetricTests(unittest.TestCase):
    def test_commutative_operands_keep_the_intended_structure(self):
        target = benchmark.target_rule(4)
        swapped = {
            "op": "add",
            "args": [
                {"op": "const", "value": 2},
                {"op": "mul", "args": [
                    {"op": "field", "name": "x3"},
                    {"op": "field", "name": "x2"},
                ]},
            ],
        }
        self.assertEqual(
            benchmark.structural_form(target),
            benchmark.structural_form(swapped))

    def test_if_eq_right_operand_is_part_of_the_structure(self):
        base = {
            "op": "if_eq",
            "left": {"op": "field", "name": "x0"},
            "then": {"op": "const", "value": 10},
            "else": {"op": "const", "value": 20},
        }
        first = {**base, "right": {"op": "const", "value": 1}}
        second = {**base, "right": {"op": "const", "value": 2}}
        self.assertNotEqual(
            benchmark.structural_form(first),
            benchmark.structural_form(second))
        self.assertEqual(
            benchmark.structural_form(first),
            benchmark.structural_form({**base, "right": {"op": "const", "value": 1}}))

    def test_observational_equivalent_is_a_different_structure(self):
        target = benchmark.target_rule(2)
        observational = {
            "op": "absdiff",
            "args": [
                {"op": "mul", "args": [
                    {"op": "field", "name": "x0"},
                    {"op": "field", "name": "x1"},
                ]},
                {"op": "const", "value": -2},
            ],
        }
        self.assertNotEqual(
            benchmark.structural_form(target),
            benchmark.structural_form(observational))


class CandidateVersusRecoveryTests(unittest.TestCase):
    def test_perfect_holdout_is_not_exact_recovery(self):
        case = benchmark.run_case(2, _args())
        self.assertTrue(case["candidate_found"])
        self.assertEqual(case["holdout_accuracy"], 1.0)
        self.assertTrue(case["search_complete"])
        self.assertTrue(case["ambiguous"])
        self.assertFalse(case["target_structure_recovered"])
        self.assertFalse(case["equivalence_verified"])
        self.assertFalse(case["exact_recovery_verified"])
        self.assertNotIn("rule_recovered", case)

    def test_structure_alone_is_not_a_proved_rule(self):
        case = benchmark.run_case(
            4, _args(input_min=-9, equivalence="none"))
        self.assertTrue(case["candidate_found"])
        self.assertTrue(case["target_structure_recovered"])
        self.assertFalse(case["equivalence_verified"])
        self.assertFalse(case["exact_recovery_verified"])

    @unittest.skipUnless(HAS_Z3, "bounded equivalence requires z3")
    def test_negative_domain_with_proof_is_exact_recovery(self):
        case = benchmark.run_case(
            4, _args(input_min=-9, equivalence="z3"))
        self.assertTrue(case["candidate_found"])
        self.assertTrue(case["target_structure_recovered"])
        self.assertTrue(case["equivalence_verified"])
        self.assertEqual(
            case["equivalence_scope"], "z3_box:-9..9:all_features")
        self.assertEqual(case["holdout_accuracy"], 1.0)
        self.assertFalse(case["ambiguous"])
        self.assertTrue(case["exact_recovery_verified"])

    @unittest.skipUnless(HAS_Z3, "bounded equivalence requires z3")
    def test_equivalence_of_the_observational_candidate_is_scoped(self):
        case = benchmark.run_case(
            2, _args(equivalence="z3"))
        self.assertTrue(case["candidate_found"])
        self.assertFalse(case["target_structure_recovered"])
        self.assertTrue(case["equivalence_verified"])
        self.assertEqual(
            case["equivalence_scope"], "z3_box:0..9:all_features")
        self.assertTrue(case["ambiguous"])
        self.assertFalse(case["exact_recovery_verified"])


class AdversarialDomainTests(unittest.TestCase):
    @unittest.skipUnless(HAS_Z3, "bounded equivalence requires z3")
    def test_non_equivalent_rule_yields_a_counterexample(self):
        schema = {"x0": "int", "x1": "int"}
        target = benchmark.target_rule(2)
        wrong = {
            "op": "add",
            "args": [target["args"][0], {"op": "const", "value": 3}],
        }
        verified, scope, witness = benchmark.verify_equivalence(
            wrong, target, schema, mode="z3")
        self.assertFalse(verified)
        self.assertEqual(scope, "z3:sat_counterexample")
        self.assertIsInstance(witness, dict)
        self.assertIn("inputs", witness)

    def test_distribution_shift_breaks_the_observational_candidate(self):
        train, dev, _holdout = benchmark.study(
            4, seed=0, train_n=6, dev_n=3, holdout_n=3)
        shifted = [
            {"inputs": {"x0": -1, "x1": -1, "x2": 2, "x3": 3},
             "output": 8},
            {"inputs": {"x0": 0, "x1": 0, "x2": -4, "x3": 2},
             "output": -6},
            {"inputs": {"x0": 1, "x1": 1, "x2": -3, "x3": 3},
             "output": -7},
        ]
        result = induce(
            train, dev=dev, holdout=shifted,
            budget=SearchBudget(max_candidates=50000))
        self.assertEqual(result["status"], "validation_failed")
        self.assertLess(
            result["holdout_passed"], result["holdout_count"])


class ReportSemanticsTests(unittest.TestCase):
    def test_metric_definitions_are_published(self):
        self.assertIn("candidate_found", benchmark.METRIC_DEFINITIONS)
        self.assertIn(
            "exact_recovery_verified", benchmark.METRIC_DEFINITIONS)
        self.assertIn(
            "only",
            benchmark.METRIC_DEFINITIONS["exact_recovery_verified"])


if __name__ == "__main__":
    unittest.main()
