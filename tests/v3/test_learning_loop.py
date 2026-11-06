"""PR-08: observe-learn-verify-reuse loop + M6 repository-disjoint evaluation."""
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.evaluation import assert_repository_disjoint, paired_summary
from sis.v3.learning.pipeline import (observe_strategy_proposals,
                                      observe_structural_proposal)
from sis.v3.learning.strategies import EpisodeEvidence
from sis.v3.procedures import ProcedureStore
from sis.v3.source_change import capture_change

BEFORE = "def scale(a, b):\n    return a - b\n"
AFTER = "def scale(a, b):\n    return a * b\n"


def _envelope(task_id, repo_digest):
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest=repo_digest, base_commit="a1b2c3d",
        task_statement_digest="d" * 64,
        permitted_commands=("pytest",), isolation_profile="unverified_local",
        time_budget_seconds=60, token_budget=1000, tool_budget=10,
        actor_id="actor-1", evaluator_task_ref=None)


class LoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.before, self.after = root / "b", root / "a"
        for d in (self.before, self.after):
            d.mkdir()
            (d / "calc.py").write_text(BEFORE)
        (self.after / "calc.py").write_text(AFTER)
        self.change, _ = capture_change(
            self.before, self.after, attempt_id="att-1",
            worker_identity="w", now="2026-10-24T00:00:00Z")
        self.store = ProcedureStore(root / "store")

    def test_structural_proposal_lands_as_candidate(self):
        digest = observe_structural_proposal(
            self.change, {"calc.py": (BEFORE.encode(), AFTER.encode())},
            semantic_contract_digest="c" * 64,
            independently_verified_receipt_digest="e" * 64,
            store=self.store)
        self.assertIsNotNone(digest)
        candidates = self.store.by_status("candidate")
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].digest, digest)
        self.assertEqual(candidates[0].revision, 1)

    def test_unsupported_change_produces_no_candidate(self):
        (self.after / "calc.py").write_text("x = 1\n")
        change, _ = capture_change(self.before, self.after, attempt_id="a2",
                                   worker_identity="w",
                                   now="2026-10-24T00:00:00Z")
        self.assertIsNone(observe_structural_proposal(
            change, {"calc.py": (BEFORE.encode(), b"x = 1\n")},
            semantic_contract_digest="c" * 64,
            independently_verified_receipt_digest="e" * 64,
            store=self.store))
        self.assertEqual(len(self.store.by_status("candidate")), 0)

    def test_strategy_proposals_require_resolved_receipts(self):
        episodes = [
            EpisodeEvidence("e1", "repo-a", "sig-1", "pass",
                            "1" * 64, ("read_logs",), True),
            EpisodeEvidence("e2", "repo-b", "sig-1", "pass",
                            "2" * 64, ("read_logs",), True),
        ]
        known = {"1" * 64: {}, "2" * 64: {}}
        digests = observe_strategy_proposals(
            episodes, language="python", store=self.store,
            receipt_resolver=lambda d: known.get(d))
        self.assertEqual(len(digests), 1)
        with self.assertRaises(ValueError):
            observe_strategy_proposals(
                episodes, language="python",
                store=ProcedureStore(Path(self.temp.name) / "s2"),
                receipt_resolver=lambda d: None)


class DisjointEvalTests(unittest.TestCase):
    def test_overlap_rejected(self):
        tasks = [_envelope("t1", "a" * 64), _envelope("t2", "b" * 64)]
        with self.assertRaises(ContractError):
            assert_repository_disjoint(["a" * 64], tasks)

    def test_disjoint_passes(self):
        tasks = [_envelope("t1", "a" * 64)]
        assert_repository_disjoint(["b" * 64], tasks)

    def test_empty_eval_set_rejected(self):
        with self.assertRaises(ContractError):
            assert_repository_disjoint([], [])

    def _report(self):
        return {
            "tasks": 4,
            "budget": {"wall_seconds": 60, "token_budget": 1000,
                       "tool_budget": 10},
            "budget_violations": 0,
            "solve_rates": {
                "A": {"solved": 1, "n": 4, "wilson_ci95": ["0", "1"]},
                "D": {"solved": 3, "n": 4, "wilson_ci95": ["0", "1"]},
            },
            "paired": {"D_vs_A": {"wins": 2, "losses": 0, "ties": 2,
                                  "solved_delta": 2,
                                  "mcnemar_exact_p": "0.5"}},
        }

    def test_paired_summary_extracts_decisive_contrast(self):
        summary = paired_summary(self._report())
        self.assertEqual(summary["contrast"]["solved_delta"], 2)
        self.assertEqual(summary["treatment"]["solved"], 3)
        self.assertEqual(summary["baseline"]["solved"], 1)
        self.assertIn("decision_rule", summary)

    def test_missing_arm_rejected(self):
        report = self._report()
        del report["solve_rates"]["D"]
        with self.assertRaises(ContractError):
            paired_summary(report)

    def test_missing_contrast_rejected(self):
        report = self._report()
        del report["paired"]["D_vs_A"]
        with self.assertRaises(ContractError):
            paired_summary(report)


if __name__ == "__main__":
    unittest.main()
