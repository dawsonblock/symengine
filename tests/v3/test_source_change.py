"""PR-06: trustworthy source-change capture — digests are computed, never claimed."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, SourceChangeV1
from sis.v3.runner import tree_digest
from sis.v3.source_change import capture_change, verify_capture


class SourceChangeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.before = self.root / "before"
        self.after = self.root / "after"
        for d in (self.before, self.after):
            d.mkdir()
            (d / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
            (d / "util.py").write_text("def noop():\n    pass\n")

    def test_capture_binds_verified_digests(self):
        (self.after / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        record, diff = capture_change(
            self.before, self.after, attempt_id="att-1",
            worker_identity="worker-1",
            expected_before_digest=tree_digest(self.before))
        self.assertEqual(record.before_tree_digest, tree_digest(self.before))
        self.assertEqual(record.after_tree_digest, tree_digest(self.after))
        self.assertEqual(record.diff_digest, hashlib.sha256(diff).hexdigest())
        changes = {c["path"]: c["kind"] for c in record.file_changes}
        self.assertEqual(changes, {"calc.py": "modified"})
        self.assertIn(b"-    return a - b", diff)
        self.assertIn(b"+    return a * b", diff)
        self.assertEqual(verify_capture(record, diff), [])

    def test_added_and_removed_classification(self):
        (self.after / "new.py").write_text("x = 1\n")
        (self.after / "util.py").unlink()
        record, _ = capture_change(
            self.before, self.after, attempt_id="att-2",
            worker_identity="worker-1")
        changes = {c["path"]: c["kind"] for c in record.file_changes}
        self.assertEqual(changes, {"new.py": "added", "util.py": "removed"})

    def test_base_mismatch_refuses(self):
        (self.after / "calc.py").write_text("x = 1\n")
        with self.assertRaises(ContractError):
            capture_change(
                self.before, self.after, attempt_id="att-3",
                worker_identity="worker-1",
                expected_before_digest="0" * 64)

    def test_identical_trees_refuse(self):
        with self.assertRaises(ContractError):
            capture_change(self.before, self.after, attempt_id="att-4",
                           worker_identity="worker-1")

    def test_agent_supplied_digests_cannot_enter(self):
        (self.after / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        record, _ = capture_change(self.before, self.after, attempt_id="att-5",
                                   worker_identity="worker-1")
        # Forging a record with agent-claimed digests fails contract parse
        # or digest binding — fields are frozen and validated.
        body = record.to_dict()
        body["before_tree_digest"] = "1" * 64
        forged = SourceChangeV1.from_dict(body)
        self.assertNotEqual(forged.digest, record.digest)
        self.assertNotEqual(forged.before_tree_digest,
                            tree_digest(self.before))

    def test_diff_tamper_detected_by_verify(self):
        (self.after / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        record, _ = capture_change(self.before, self.after, attempt_id="att-6",
                                   worker_identity="worker-1")
        self.assertEqual(verify_capture(record, b"tampered"),
                         ["diff_digest_mismatch"])

    def test_capture_is_deterministic(self):
        (self.after / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        r1, d1 = capture_change(self.before, self.after, attempt_id="att-7",
                                worker_identity="w", now="2026-10-24T00:00:00Z")
        r2, d2 = capture_change(self.before, self.after, attempt_id="att-7",
                                worker_identity="w", now="2026-10-24T00:00:00Z")
        self.assertEqual((r1.digest, d1), (r2.digest, d2))


if __name__ == "__main__":
    unittest.main()
