"""SIS3-008: source-preserving, digest-locked patch proposals."""
import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError
from sis.v3.patcher import PatchError, propose_edit, verify_proposal


class PatcherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _write(self, name, data: bytes):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def test_unique_span_replaced_rest_preserved(self):
        src = b"# comment\n\ndef f():\r\n    return a - b\r\n\ntail = '\xe2\x98\x83'\n"
        self._write("m.py", src)
        result = propose_edit(
            self.root, "m.py", b"return a - b", b"return a * b",
            proposer_id="p1", purpose="fix operator",
        )
        expected = src.replace(b"return a - b", b"return a * b", 1)
        self.assertEqual(result.patched_content, expected)
        self.assertEqual(
            result.proposal.source_blob_digest, hashlib.sha256(src).hexdigest()
        )
        self.assertIn(b"a - b", result.unified_diff)
        self.assertIn(b"a * b", result.unified_diff)
        ok = verify_proposal(self.root, result.proposal,
                             result.patched_content, result.unified_diff)
        self.assertTrue(ok["ok"], ok)

    def test_nonunique_span_rejected(self):
        self._write("m.py", b"x = a - b\ny = a - b\n")
        with self.assertRaisesRegex(PatchError, "not unique"):
            propose_edit(self.root, "m.py", b"a - b", b"a + b",
                         proposer_id="p", purpose="x")

    def test_missing_span_rejected(self):
        self._write("m.py", b"x = 1\n")
        with self.assertRaisesRegex(PatchError, "not found"):
            propose_edit(self.root, "m.py", b"zzz", b"q",
                         proposer_id="p", purpose="x")

    def test_identity_edit_rejected(self):
        self._write("m.py", b"x = 1\n")
        with self.assertRaisesRegex(PatchError, "identity"):
            propose_edit(self.root, "m.py", b"x = 1", b"x = 1",
                         proposer_id="p", purpose="x")

    def test_path_escape_rejected(self):
        with self.assertRaises(ContractError):
            propose_edit(self.root, "../outside.py", b"a", b"b",
                         proposer_id="p", purpose="x")

    def test_subtree_path_ok(self):
        self._write("pkg/sub/m.py", b"return a - b\n")
        result = propose_edit(self.root, "pkg/sub/m.py", b"a - b", b"a * b",
                              proposer_id="p", purpose="fix")
        self.assertEqual(result.proposal.target_path, "pkg/sub/m.py")

    def test_unicode_and_crlf_preserved(self):
        src = "def f():\r\n    # héllo \r\n    return 1\r\n".encode("utf-8")
        self._write("u.py", src)
        result = propose_edit(self.root, "u.py", b"return 1", b"return 2",
                              proposer_id="p", purpose="x")
        self.assertIn(b"\r\n", result.patched_content)
        self.assertIn("héllo ".encode("utf-8"), result.patched_content)

    def test_verify_detects_source_mismatch(self):
        self._write("m.py", b"return a - b\n")
        result = propose_edit(self.root, "m.py", b"a - b", b"a * b",
                              proposer_id="p", purpose="x")
        self._write("m.py", b"return a - b  # changed\n")
        report = verify_proposal(self.root, result.proposal,
                                 result.patched_content, result.unified_diff)
        self.assertFalse(report["ok"])
        self.assertIn("source_mismatch", report["problems"])

    def test_verify_detects_diff_tamper(self):
        self._write("m.py", b"return a - b\n")
        result = propose_edit(self.root, "m.py", b"a - b", b"a * b",
                              proposer_id="p", purpose="x")
        report = verify_proposal(self.root, result.proposal,
                                 result.patched_content, b"forged diff")
        self.assertFalse(report["ok"])
        self.assertIn("diff_mismatch", report["problems"])


if __name__ == "__main__":
    unittest.main()
