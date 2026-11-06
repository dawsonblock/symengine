"""PR-07: induction must bind to verified capture artifacts and resolved receipts."""
import tempfile
import unittest
from pathlib import Path

from sis.v3.learning.strategies import EpisodeEvidence, induce_strategies
from sis.v3.learning.symbolic import induce_from_source_change
from sis.v3.source_change import capture_change

BEFORE = "def scale(a, b):\n    return a - b\n"
AFTER = "def scale(a, b):\n    return a * b\n"
CONTRACT = "c" * 64
RECEIPT = "e" * 64


class StructuralEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.before, self.after = root / "b", root / "a"
        for d in (self.before, self.after):
            d.mkdir()
            (d / "calc.py").write_text(BEFORE)
        (self.after / "calc.py").write_text(AFTER)
        self.record, _ = capture_change(
            self.before, self.after, attempt_id="att-1",
            worker_identity="w", now="2026-10-24T00:00:00Z")
        self.contents = {"calc.py": (BEFORE.encode(), AFTER.encode())}

    def test_induction_binds_captured_bytes(self):
        change = induce_from_source_change(
            self.record, self.contents,
            semantic_contract_digest=CONTRACT,
            independently_verified_receipt_digest=RECEIPT)
        self.assertIsNotNone(change)
        self.assertEqual(change.old_operator, "Sub")
        self.assertEqual(change.new_operator, "Mult")
        self.assertEqual(change.source_change_digest, self.record.digest)
        self.assertEqual(change.status, "candidate")

    def test_wrong_bytes_rejected(self):
        bad = {"calc.py": (b"forged before", AFTER.encode())}
        with self.assertRaises(ValueError):
            induce_from_source_change(
                self.record, bad, semantic_contract_digest=CONTRACT,
                independently_verified_receipt_digest=RECEIPT)

    def test_multi_file_changes_rejected(self):
        (self.after / "extra.py").write_text("x = 1\n")
        record, _ = capture_change(self.before, self.after, attempt_id="a2",
                                   worker_identity="w",
                                   now="2026-10-24T00:00:00Z")
        with self.assertRaises(ValueError):
            induce_from_source_change(
                record, {**self.contents,
                         "extra.py": (None, b"x = 1\n")},
                semantic_contract_digest=CONTRACT,
                independently_verified_receipt_digest=RECEIPT)

    def test_non_operator_change_returns_none(self):
        (self.after / "calc.py").write_text("x = 1\n")
        record, _ = capture_change(self.before, self.after, attempt_id="a3",
                                   worker_identity="w",
                                   now="2026-10-24T00:00:00Z")
        result = induce_from_source_change(
            record, {"calc.py": (BEFORE.encode(), b"x = 1\n")},
            semantic_contract_digest=CONTRACT,
            independently_verified_receipt_digest=RECEIPT)
        self.assertIsNone(result)


def _episode(repo, outcome="pass", digest=None, verified=True):
    return EpisodeEvidence(
        episode_id="ep-" + repo + outcome,
        repository_id=repo, failure_signature="sig-1", outcome=outcome,
        receipt_digest=digest or hash_d(repo + outcome),
        diagnostic_actions=("read_logs", "run_tests"), verified=verified)


def hash_d(text):
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


class StrategyReceiptResolutionTests(unittest.TestCase):
    def setUp(self):
        self.episodes = [_episode("repo-a"), _episode("repo-b"),
                         _episode("repo-c", outcome="fail")]

    def test_resolver_verifies_each_receipt(self):
        known = {e.receipt_digest for e in self.episodes}
        candidates = induce_strategies(
            self.episodes, receipt_resolver=lambda d: {"ok": True}
            if d in known else None)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].repository_count, 2)

    def test_unresolved_receipt_rejected(self):
        with self.assertRaises(ValueError):
            induce_strategies(
                self.episodes, receipt_resolver=lambda d: None)

    def test_forged_digest_rejected(self):
        episodes = [self.episodes[0],
                    _episode("repo-b", digest="f" * 64)]
        known = {self.episodes[0].receipt_digest}
        with self.assertRaises(ValueError):
            induce_strategies(
                episodes, receipt_resolver=lambda d: {"ok": True}
                if d in known else None)

    def test_legacy_flag_only_path_still_documented(self):
        # Without resolver, verified flag alone admits — weaker contract.
        candidates = induce_strategies(self.episodes)
        self.assertEqual(len(candidates), 1)


if __name__ == "__main__":
    unittest.main()
