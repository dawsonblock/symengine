"""Release CI fails closed; development drift is an explicit policy choice."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import provenance  # noqa: E402
from build_release import write_manifest  # noqa: E402
from sis.v3 import signatures  # noqa: E402


class ReleaseCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "source.py").write_text("VALUE = 1\n")
        write_manifest(self.root)

    def run_check(self, mode, *extra):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_release_ci.py"),
             "--mode", mode, "--source", str(self.root), *extra],
            capture_output=True, text=True,
        )

    def test_matching_inventory_passes_both_modes(self):
        for mode in ("release", "development"):
            self.assertEqual(self.run_check(mode).returncode, 0)

    def test_stale_release_fails_without_rewriting_manifest(self):
        original = (self.root / "RELEASE_SHA256.json").read_bytes()
        (self.root / "source.py").write_text("VALUE = 2\n")
        self.assertNotEqual(self.run_check("release").returncode, 0)
        self.assertEqual((self.root / "RELEASE_SHA256.json").read_bytes(), original)

    def test_extra_untracked_source_fails_release(self):
        (self.root / "new_test.py").write_text("assert True\n")
        self.assertNotEqual(self.run_check("release").returncode, 0)

    def test_missing_source_fails_release(self):
        (self.root / "source.py").unlink()
        self.assertNotEqual(self.run_check("release").returncode, 0)

    def test_development_drift_is_explicitly_not_release_verification(self):
        (self.root / "source.py").write_text("VALUE = 2\n")
        result = self.run_check("development")
        self.assertEqual(result.returncode, 0)
        self.assertIn("not release verification", result.stdout)

    def write_release_manifest(self, test_result):
        release = self.root / "release"
        release.mkdir(exist_ok=True)
        (release / "release_manifest.json").write_text(
            json.dumps({"test_result": test_result}))

    def write_signed_release(self, *, trust_root="production", signed=True,
                             include_isolation=True):
        release = self.root / "release"
        release.mkdir(exist_ok=True)
        archive = release / "SIS-test.zip"
        archive.write_bytes(b"signed release archive")
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        seed, public = signatures.generate_keypair()
        statement = provenance.build_statement(
            archive_name=archive.name, archive_sha256=digest,
            release="SIS-test", branch="test", source_commit="a" * 40)
        envelope = provenance.sign_statement(statement, seed, "release-key")
        (release / "provenance.dsse.json").write_text(
            json.dumps(envelope, sort_keys=True))
        document = {
            "test_result": {
                "source": "evidence", "passed": 10, "failed": 0,
                "errors": 0,
            },
            "archive": {"path": "release/SIS-test.zip", "sha256": digest},
            "provenance": {
                "signed": signed,
                "trust_root": trust_root,
                "path": "release/provenance.dsse.json",
                "subject_sha256": digest,
                "key_id": "release-key",
            },
        }
        if include_isolation:
            document["isolation"] = {
                "external_attestation": {
                    "verified": True,
                    "public_key": "c" * 64,
                    "signer_key_id": "external-isolator",
                }
            }
        (release / "release_manifest.json").write_text(
            json.dumps(document, sort_keys=True))
        return public.hex()

    def test_release_accepts_a_signed_production_seal(self):
        key = self.write_signed_release()
        self.assertEqual(
            self.run_check(
                "release", "--release-public-key", key).returncode, 0)
        self.assertEqual(self.run_check("development").returncode, 0)

    def test_release_refuses_unsigned_provenance(self):
        key = self.write_signed_release(signed=False)
        result = self.run_check("release", "--release-public-key", key)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance is unsigned", result.stderr)

    def test_release_refuses_a_qualification_trust_root(self):
        key = self.write_signed_release(trust_root="qualification-only")
        result = self.run_check("release", "--release-public-key", key)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trust root is not production", result.stderr)

    def test_release_requires_the_release_public_key(self):
        self.write_signed_release()
        result = self.run_check("release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release public key is required", result.stderr)

    def test_release_refuses_a_wrong_release_key(self):
        self.write_signed_release()
        _seed, other = signatures.generate_keypair()
        result = self.run_check(
            "release", "--release-public-key", other.hex())
        self.assertNotEqual(result.returncode, 0)

    def test_release_requires_an_external_isolation_attestation(self):
        key = self.write_signed_release(include_isolation=False)
        result = self.run_check("release", "--release-public-key", key)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no verified external isolation", result.stderr)

    def test_release_refuses_a_different_isolator_key(self):
        key = self.write_signed_release()
        result = self.run_check(
            "release", "--release-public-key", key,
            "--isolator-public-key", "d" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the pinned key", result.stderr)

    def test_release_refuses_operator_entered_counts(self):
        self.write_release_manifest({
            "source": "operator", "passed": 10, "failed": 0})
        result = self.run_check("release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not evidence-backed", result.stderr)

    def test_release_refuses_evidence_with_failures(self):
        self.write_release_manifest({
            "source": "evidence", "passed": 10, "failed": 1, "errors": 0})
        self.assertNotEqual(self.run_check("release").returncode, 0)

    def test_missing_manifest_fails_both_modes(self):
        (self.root / "RELEASE_SHA256.json").unlink()
        for mode in ("release", "development"):
            self.assertNotEqual(self.run_check(mode).returncode, 0)

    def test_malformed_manifest_fails_both_modes(self):
        for body in ("{", json.dumps({"schema": 1, "files": {"../escape": "0" * 64}})):
            (self.root / "RELEASE_SHA256.json").write_text(body)
            for mode in ("release", "development"):
                self.assertNotEqual(self.run_check(mode).returncode, 0)

    def test_workflow_gates_by_event_not_inventory_success(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/') || github.event_name == 'release'", workflow)
        self.assertIn("run: python tools/check_release_ci.py --mode release", workflow)
        self.assertNotIn("if python tools/build_release.py --check", workflow)
