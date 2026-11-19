"""Review fixes: induction holdout custody, deep ambiguity, 1-row holdout.

- A legacy ``induce(train, validation)`` call splits validation into
  disjoint development and holdout rows; the holdout never reaches
  selection or refinement, and promotion requires a sealed holdout.
- A shallow rule is not declared unambiguous until a rival scan over the
  rest of the search space finds no rival consistent with every labelled
  row.
- A failed one-row holdout is ``validation_failed``, not ``provisional``.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis import induction
from sis.errors import RuleRejected
from sis.induction import induce, legacy_split
from sis.registry import Registry
from sis.validation import canonical

ROOT = Path(__file__).resolve().parents[1]


def _ex(a, b, out):
    return {"inputs": {"a": a, "b": b}, "output": out}


class LegacySplitTests(unittest.TestCase):
    def test_split_is_deterministic_and_disjoint(self):
        rows = [_ex(i, i, 2 * i) for i in range(5)]
        dev, holdout = legacy_split(rows)
        self.assertEqual(dev, rows[:2])
        self.assertEqual(holdout, rows[2:])
        self.assertEqual(legacy_split(rows[:2]), ([], rows[:2]))
        self.assertEqual(legacy_split(rows[:3]), (rows[:1], rows[1:3]))
        self.assertEqual(legacy_split(rows[:1]), ([], rows[:1]))

    def test_holdout_never_reaches_selection_or_refinement(self):
        # Piecewise target: development rows force a refinement round, so
        # the old code fed validation (= holdout) rows into training.
        train = [_ex(1, 3, 3), _ex(2, 5, 5), _ex(4, 7, 7)]
        validation = [_ex(-1, 2, -2), _ex(-3, 4, -4), _ex(-2, -6, 6),
                      _ex(-4, 1, -1)]
        _, holdout = legacy_split(validation)
        holdout_keys = {canonical(row["inputs"]) for row in holdout}
        seen = []
        original = induction._search_once

        def spy(examples, dev, *args, **kwargs):
            seen.append([canonical(row["inputs"])
                         for row in list(examples) + list(dev)])
            return original(examples, dev, *args, **kwargs)

        with mock.patch.object(induction, "_search_once", spy):
            result = induce(train, validation)
        self.assertTrue(seen)
        for keys in seen:
            self.assertFalse(holdout_keys & set(keys))
        self.assertTrue(result["holdout_sealed"])
        self.assertEqual(result["partition_mode"], "legacy_split")
        self.assertEqual(result["holdout_count"], len(holdout))

    def test_quickstart_study_still_promotes(self):
        study = json.loads(
            (ROOT / "examples" / "arithmetic_study.json").read_text())
        result = induce(study["train"], study["validation"],
                        namespace=study["namespace"])
        self.assertEqual(result["status"], "locally_validated")
        self.assertTrue(result["holdout_sealed"])
        with tempfile.TemporaryDirectory() as temp:
            registry = Registry(Path(temp) / "k.sqlite3")
            try:
                promoted = registry.promote(
                    result, train=study["train"],
                    validation=study["validation"])
                self.assertEqual(promoted["status"], "active")
            finally:
                registry.close()

    def test_promotion_requires_a_sealed_holdout(self):
        study = json.loads(
            (ROOT / "examples" / "arithmetic_study.json").read_text())
        result = induce(study["train"], study["validation"],
                        namespace=study["namespace"])
        unsealed = dict(result, holdout_sealed=False)
        with tempfile.TemporaryDirectory() as temp:
            registry = Registry(Path(temp) / "k.sqlite3")
            try:
                with mock.patch.object(induction, "induce",
                                       return_value=unsealed):
                    with self.assertRaisesRegex(RuleRejected, "sealed"):
                        registry.promote(unsealed, train=study["train"],
                                         validation=study["validation"])
                self.assertEqual(registry.list_rules(study["namespace"]), [])
            finally:
                registry.close()


class DeepAmbiguityTests(unittest.TestCase):
    def test_a_depth_two_rival_is_compared(self):
        # Every labelled sum is >= 2, so max(a + b, 2) fits all labels and
        # disagrees with a + b on negative probes.
        train = [_ex(1, 4, 5), _ex(2, 7, 9), _ex(-3, 5, 2), _ex(5, -2, 3),
                 _ex(0, 8, 8)]
        validation = [_ex(4, 9, 13), _ex(1, 1, 2), _ex(11, 3, 14)]
        result = induce(train, validation)
        self.assertEqual(result["rule"]["op"], "add")
        # Selection stops at the first stage with a fitting rule (depth 2);
        # the max(a + b, 2) rival is only reached by the rival scan.
        self.assertEqual(result["rule_depth"], 2)
        self.assertLessEqual(result["search_depth"], 2)
        self.assertEqual(result["status"], "ambiguous")
        self.assertIsNotNone(result["distinguishing_probe"])
        self.assertTrue(result["rival_scan"]["performed"])

    def test_a_refuted_deep_rival_leaves_the_rule_validated(self):
        study = json.loads(
            (ROOT / "examples" / "arithmetic_study.json").read_text())
        result = induce(study["train"], study["validation"])
        self.assertEqual(result["status"], "locally_validated")
        # Learner v2 scans its whole declared space (typed pools up to the
        # cost horizon plus completions), not a fixed depth-2 space.
        self.assertEqual(result["ambiguity_scope"], "full_search_space")
        self.assertTrue(result["rival_scan"]["complete"])


class SingleRowHoldoutTests(unittest.TestCase):
    def test_a_failed_one_row_holdout_is_validation_failed(self):
        train = [_ex(1, 4, 5), _ex(2, 7, 9), _ex(-3, 5, 2)]
        dev = [_ex(5, -2, 3)]
        result = induce(train, dev=dev, holdout=[_ex(0, 8, 99)])
        self.assertEqual(result["status"], "validation_failed")
        passed = induce(train, dev=dev, holdout=[_ex(0, 8, 8)])
        self.assertEqual(passed["status"], "provisional")


if __name__ == "__main__":
    unittest.main()
