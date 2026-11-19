"""Induction corpus: a fixed 15-target subset in CI (learner v2, SIS-FEAT-14).

The full corpus (``examples/induction_corpus``, about sixty targets in six
categories) is run by ``tools/benchmark_induction.py --corpus``; its stored
results are ``evidence/benchmark/induction_corpus_baseline.json`` (engine
before learner v2) and ``induction_corpus_v2.json``. This subset pins the
properties the learner must keep:

- every listed recoverable target is recovered: ``locally_validated`` and
  equal to the oracle on every labelled row and 300 seeded fresh points;
- no target is a false positive (validated but wrong on a fresh point),
  and no distractor is ever ``locally_validated``;
- the committed ``corpus.json`` is exactly what the seeded generators draw,
  and every piecewise split leaves a holdout row on each branch.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "examples" / "induction_corpus"

_SPEC = importlib.util.spec_from_file_location(
    "benchmark_induction", ROOT / "tools" / "benchmark_induction.py")
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)

RECOVERABLE = (
    "lin_3a_2b", "lin_a_2b_m3c_4", "lin_10_minus_a",
    "nl_ab_plus_c", "nl_max_ab",
    "dm_half", "dm_mod3", "dm_div3_plus_b",
    "pw_clamp_offset", "pw_gap_or_double", "pw_flag_select",
    "str_concat", "str_prefix3",
)
DISTRACTORS = ("dis_hash_bool", "dis_noisy_sum")
SUBSET = RECOVERABLE + DISTRACTORS


class CorpusMaterialisationTests(unittest.TestCase):
    def setUp(self):
        self.corpus, self.generator = benchmark.load_corpus(CORPUS)

    def test_committed_corpus_matches_the_seeded_generators(self):
        regenerated = json.loads(json.dumps(self.generator.materialize()))
        self.assertEqual(regenerated, self.corpus)

    def test_six_categories_and_about_sixty_targets(self):
        categories = {t["category"] for t in self.corpus["targets"]}
        self.assertEqual(categories, {"linear", "nonlinear", "divmod",
                                      "piecewise", "string", "distractor"})
        self.assertGreaterEqual(len(self.corpus["targets"]), 60)

    def test_piecewise_splits_cover_every_branch_in_the_holdout(self):
        targets = self.generator.by_name()
        for entry in self.corpus["targets"]:
            if entry["category"] != "piecewise":
                continue
            with self.subTest(target=entry["name"]):
                branch = targets[entry["name"]]["branch"]
                holdout = self.generator.legacy_holdout(entry["validation"])
                self.assertGreaterEqual(len(holdout), 2)
                self.assertEqual({bool(branch(r["inputs"])) for r in holdout},
                                 {True, False})


class CorpusSubsetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = benchmark.run_corpus(CORPUS, names=SUBSET)
        cls.rows = {row["name"]: row for row in report["results"]}
        cls.summary = report["summary"]

    def test_the_subset_ran(self):
        self.assertEqual(set(self.rows), set(SUBSET))

    def test_recoverable_targets_are_recovered(self):
        for name in RECOVERABLE:
            with self.subTest(target=name):
                row = self.rows[name]
                self.assertTrue(row["recovered"], (row["status"], row["rule"],
                                                   row["first_mismatch"]))

    def test_no_false_positives(self):
        for name, row in self.rows.items():
            with self.subTest(target=name):
                self.assertFalse(row["false_positive"], row["first_mismatch"])
        self.assertEqual(self.summary["ALL"]["false_positives"], 0)

    def test_distractors_are_never_validated(self):
        for name in DISTRACTORS:
            with self.subTest(target=name):
                self.assertNotEqual(self.rows[name]["status"], "locally_validated")

    def test_results_carry_the_engine_versions(self):
        from sis.expression import GRAMMAR_VERSION
        from sis.induction import ENGINE_VERSION
        for row in self.rows.values():
            self.assertEqual(row["grammar_version"], GRAMMAR_VERSION)
            self.assertEqual(row["engine_version"], ENGINE_VERSION)


if __name__ == "__main__":
    unittest.main()
