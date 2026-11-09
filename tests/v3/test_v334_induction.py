"""SIS v3.3.4 Phase 4 induction regressions (gate G4).

Covers the four audited gaps:

- G4.1: a shallow rule that fits only the training rows no longer stops
  the search; development data decides whether to deepen, and a sealed
  holdout decides the final status.
- G4.2: candidate, signature-check, wall-clock, memory, and expression
  depth limits are explicit and report completed/truncated/exhausted.
- G4.3: candidate ordering prefers development fit, then lower
  complexity, and never promotes a small-sample coincidence to a
  validated rule.
- G4.4: counterexample-guided refinement uses a labelled oracle when
  one exists and never treats generated probes as ground truth.
"""
from __future__ import annotations

import unittest

from sis.errors import InvalidInput
from sis.expression import evaluate
from sis.induction import SearchBudget, induce


def _deepen_study():
    """Shallow ``a*b`` fits train (c=0); the true rule is ``a*b + c``."""
    train = [{"inputs": {"a": a, "b": b, "c": 0}, "output": a * b}
             for a, b in ((1, 2), (3, 4), (5, 6), (2, 7), (4, 4), (0, 3))]
    dev = [{"inputs": {"a": a, "b": b, "c": 2}, "output": a * b + 2}
           for a, b in ((2, 5), (6, 1), (3, 3))]
    holdout = [{"inputs": {"a": 7, "b": 2, "c": 2}, "output": 16},
               {"inputs": {"a": 1, "b": 9, "c": 2}, "output": 11}]
    return train, dev, holdout


def _ambiguous_study():
    """On b=0, ``a``, ``a+b`` and ``a-b`` are observationally identical."""
    train = [{"inputs": {"a": a, "b": 0}, "output": a} for a in (1, 2, 3, 4)]
    dev = [{"inputs": {"a": a, "b": 0}, "output": a} for a in (5, 6, 7)]
    holdout = [{"inputs": {"a": a, "b": 0}, "output": a} for a in (8, 9)]
    return train, dev, holdout


def _field_study(features, rows=9):
    """``x[n-2] * x[n-1] + 2`` with every other field as a decoy."""
    names = [f"x{i}" for i in range(features)]
    examples = []
    for i in range(rows):
        inputs = {name: (i * 7 + j * 3) % 11 for j, name in enumerate(names)}
        inputs[names[-2]] = i % 9 + 1
        inputs[names[-1]] = (i * 2) % 9 + 1
        examples.append({
            "inputs": inputs,
            "output": inputs[names[-2]] * inputs[names[-1]] + 2,
        })
    return examples[:6], examples[6:]


class BudgetValidationTests(unittest.TestCase):
    """G4.2: every declared limit is validated before search starts."""

    def test_each_limit_is_validated(self):
        for kwargs in (
                {"max_candidates": 99},
                {"max_candidates": 50001},
                {"max_signature_checks": 0},
                {"max_signature_checks": 10_000_001},
                {"max_wall_seconds": 0},
                {"max_wall_seconds": 3601},
                {"max_memory_bytes": 1024},
                {"max_expression_depth": 0},
                {"max_expression_depth": 6},
        ):
            with self.subTest(**kwargs):
                with self.assertRaises(InvalidInput):
                    SearchBudget(**kwargs)

    def test_budget_and_max_candidates_are_exclusive(self):
        train, dev, _holdout = _deepen_study()
        with self.assertRaises(InvalidInput):
            induce(train, dev=dev, max_candidates=200,
                   budget=SearchBudget(max_candidates=200))

    def test_refinement_controls_are_validated(self):
        train, dev, _holdout = _deepen_study()
        with self.assertRaises(InvalidInput):
            induce(train, dev=dev, max_refinement_rounds=-1)
        with self.assertRaises(InvalidInput):
            induce(train, dev=dev, max_refinement_rounds=9)
        with self.assertRaises(InvalidInput):
            induce(train, dev=dev, counterexample_oracle="not-callable")


class EarlyStoppingTests(unittest.TestCase):
    """G4.1: training fit alone is not a reason to stop deepening."""

    def test_development_rejection_deepens_search(self):
        train, dev, holdout = _deepen_study()
        result = induce(train, dev=dev, holdout=holdout)
        self.assertEqual(result["search_depth"], 2)
        self.assertEqual(result["dev_passed"], len(dev))
        self.assertEqual(result["holdout_passed"], len(holdout))
        self.assertNotEqual(result["rule"]["op"], "mul")
        for inputs, expected in (
                ({"a": 3, "b": 7, "c": 5}, 26),
                ({"a": 2, "b": 2, "c": 9}, 13),
                ({"a": 0, "b": 4, "c": 1}, 1),
        ):
            self.assertEqual(evaluate(result["rule"], inputs), expected)

    def test_sealed_holdout_failure_blocks_validation(self):
        train, dev, _holdout = _deepen_study()
        bad_holdout = [
            {"inputs": {"a": 7, "b": 2, "c": 2}, "output": 999},
            {"inputs": {"a": 1, "b": 9, "c": 2}, "output": 11},
        ]
        result = induce(train, dev=dev, holdout=bad_holdout)
        self.assertEqual(result["status"], "validation_failed")
        self.assertTrue(result["holdout_sealed"])
        self.assertLess(result["holdout_passed"], result["holdout_count"])

    def test_legacy_validation_is_not_sealed(self):
        train, dev, _holdout = _deepen_study()
        result = induce(train, dev)
        self.assertFalse(result["holdout_sealed"])
        self.assertIn("not independent", result["verification_scope"])

    def test_partitions_must_be_disjoint(self):
        train, dev, _holdout = _deepen_study()
        with self.assertRaises(InvalidInput):
            induce(train, dev=dev, holdout=dev)

    def test_explicit_dev_without_holdout_reports_no_holdout(self):
        train, dev, _holdout = _deepen_study()
        result = induce(train, dev=dev)
        self.assertEqual(result["holdout_count"], 0)
        self.assertFalse(result["holdout_sealed"])


class BudgetEnforcementTests(unittest.TestCase):
    """G4.2: each limit stops the search with an explicit outcome."""

    def setUp(self):
        self.train, self.dev, self.holdout = _deepen_study()

    def test_signature_check_limit(self):
        result = induce(
            self.train, dev=self.dev, holdout=self.holdout,
            budget=SearchBudget(max_signature_checks=1))
        self.assertEqual(result["search_outcome"], "truncated")
        self.assertIn("max_signature_checks", result["limits_hit"])
        self.assertEqual(result["status"], "search_incomplete")
        self.assertLessEqual(result["signature_checks"], 2)

    def test_wall_clock_limit(self):
        result = induce(
            self.train, dev=self.dev, holdout=self.holdout,
            budget=SearchBudget(max_wall_seconds=1e-9))
        self.assertEqual(result["search_outcome"], "resource_exhausted")
        self.assertIn("max_wall_seconds", result["limits_hit"])
        self.assertEqual(result["status"], "search_incomplete")

    def test_memory_limit(self):
        train, dev = _field_study(16)
        result = induce(
            train, dev=dev,
            budget=SearchBudget(max_memory_bytes=1 << 20))
        self.assertEqual(result["search_outcome"], "resource_exhausted")
        self.assertIn("max_memory_bytes", result["limits_hit"])
        self.assertEqual(result["status"], "search_incomplete")

    def test_expression_depth_limit(self):
        result = induce(
            self.train, dev=self.dev, holdout=self.holdout,
            budget=SearchBudget(max_expression_depth=1))
        self.assertEqual(result["search_outcome"], "truncated")
        self.assertIn("max_expression_depth", result["limits_hit"])
        self.assertEqual(result["status"], "search_incomplete")

    def test_completed_search_reports_no_limits(self):
        result = induce(self.train, dev=self.dev, holdout=self.holdout)
        self.assertEqual(result["search_outcome"], "completed")
        self.assertEqual(result["limits_hit"], [])
        self.assertFalse(result["search_truncated"])
        self.assertEqual(result["budget"]["max_memory_bytes"], None)


class CounterexampleRefinementTests(unittest.TestCase):
    """G4.4: an oracle labels distinguishing inputs; probes never do."""

    def test_oracle_resolves_ambiguity(self):
        train, dev, holdout = _ambiguous_study()
        calls = []

        def oracle(inputs):
            calls.append(inputs)
            return inputs["a"] + inputs["b"]

        result = induce(
            train, dev=dev, holdout=holdout, counterexample_oracle=oracle)
        self.assertGreaterEqual(result["oracle_calls"], 2)
        self.assertGreaterEqual(result["counterexamples_added"], 2)
        self.assertEqual(len(calls), result["oracle_calls"])
        self.assertIsNone(result["distinguishing_probe"])
        self.assertEqual(result["status"], "locally_validated")
        self.assertEqual(
            evaluate(result["rule"], {"a": 4, "b": 3}), 7)

    def test_without_oracle_ambiguity_is_reported(self):
        train, dev, holdout = _ambiguous_study()
        result = induce(train, dev=dev, holdout=holdout)
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNotNone(result["distinguishing_probe"])
        self.assertEqual(result["oracle_calls"], 0)
        self.assertEqual(result["counterexamples_added"], 0)

    def test_oracle_type_mismatch_adds_nothing(self):
        train, dev, holdout = _ambiguous_study()
        result = induce(
            train, dev=dev, holdout=holdout,
            counterexample_oracle=lambda inputs: "wrong-type")
        self.assertEqual(result["oracle_calls"], 1)
        self.assertEqual(result["counterexamples_added"], 0)
        self.assertEqual(result["status"], "ambiguous")


class ScalabilityTests(unittest.TestCase):
    """G4.5: wide feature spaces stay bounded and report honestly."""

    def test_eight_field_rule_recovered(self):
        train, dev = _field_study(8)
        result = induce(train, dev=dev, budget=SearchBudget(
            max_candidates=50000))
        self.assertIsNotNone(result["rule"], result["status"])
        self.assertEqual(result["dev_passed"], len(dev))
        for i in range(6):
            inputs = {f"x{j}": (i + j) % 5 for j in range(8)}
            inputs["x6"] = i + 1
            inputs["x7"] = i + 2
            self.assertEqual(
                evaluate(result["rule"], inputs),
                (i + 1) * (i + 2) + 2)

    def test_wide_budgets_truncate_instead_of_claiming_success(self):
        for features in (32, 64):
            with self.subTest(features=features):
                train, dev = _field_study(features)
                result = induce(
                    train, dev=dev,
                    budget=SearchBudget(
                        max_candidates=500, max_signature_checks=5000))
                self.assertTrue(result["search_truncated"], result["status"])
                self.assertEqual(result["status"], "search_incomplete")
                self.assertTrue(result["limits_hit"])
                self.assertLessEqual(result["candidates_evaluated"], 500)
                self.assertLessEqual(result["signature_checks"], 5001)

    def test_sixty_five_fields_rejected(self):
        inputs = {f"x{i}": 1 for i in range(65)}
        with self.assertRaises(InvalidInput):
            induce([
                {"inputs": inputs, "output": 1},
                {"inputs": {**inputs, "x0": 2}, "output": 1},
                {"inputs": {**inputs, "x0": 3}, "output": 1},
            ])


if __name__ == "__main__":
    unittest.main()
