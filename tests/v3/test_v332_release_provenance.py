"""Signed SLSA-style provenance is bound to the exact archive digest."""
from __future__ import annotations

import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

import provenance  # noqa: E402
from sis.v3 import signatures  # noqa: E402


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "release.zip"
        self.archive.write_bytes(b"release-archive-bytes")
        self.seed, self.public = signatures.generate_keypair()
        self.digest = provenance.sha256_file(self.archive)

    def statement(self, **overrides):
        values = {
            "archive_name": self.archive.name,
            "archive_sha256": self.digest,
            "release": "SIS-test",
            "branch": "main",
            "source_commit": "a" * 64,
        }
        values.update(overrides)
        return provenance.build_statement(**values)

    def test_signed_provenance_binds_archive(self):
        envelope = provenance.sign_statement(
            self.statement(), self.seed, "release-key-1")
        statement = provenance.verify_envelope(
            envelope, self.public.hex(), archive_path=self.archive)
        self.assertEqual(statement["subject"][0]["digest"]["sha256"],
                         self.digest)
        self.assertEqual(statement["predicateType"],
                         provenance.PREDICATE_TYPE)

    def test_wrong_archive_fails(self):
        envelope = provenance.sign_statement(
            self.statement(), self.seed, "release-key-1")
        other = self.root / "other.zip"
        other.write_bytes(b"different")
        with self.assertRaisesRegex(ValueError, "does not match"):
            provenance.verify_envelope(
                envelope, self.public.hex(), archive_path=other)

    def test_tampered_payload_fails(self):
        envelope = provenance.sign_statement(
            self.statement(), self.seed, "release-key-1")
        envelope["payload"] = base64.b64encode(
            json.dumps({"tampered": True}).encode()).decode()
        with self.assertRaisesRegex(ValueError, "signature is invalid"):
            provenance.verify_envelope(
                envelope, self.public.hex(), archive_path=self.archive)

    def test_wrong_signer_fails(self):
        envelope = provenance.sign_statement(
            self.statement(), self.seed, "release-key-1")
        _, other_public = signatures.generate_keypair()
        with self.assertRaisesRegex(ValueError, "signature is invalid"):
            provenance.verify_envelope(
                envelope, other_public.hex(), archive_path=self.archive)

    def test_statement_requires_sha256_subject(self):
        with self.assertRaises(ValueError):
            self.statement(archive_sha256="not-a-digest")


if __name__ == "__main__":
    unittest.main()
