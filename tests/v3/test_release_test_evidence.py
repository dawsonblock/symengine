"""Release qualification consumes executed test evidence, not typed totals."""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import package_release  # noqa: E402
import run_tests  # noqa: E402
import test_evidence  # noqa: E402
from build_release import write_manifest  # noqa: E402
from sis.v3 import signatures  # noqa: E402
from sis.v3.contracts import ExecutionReceiptV1  # noqa: E402
from sis.v3.isolation import issue_attestation_for_receipt  # noqa: E402

COMMIT = "a" * 40
OUTPUT = "1514 passed, 13 skipped in 228.66s\n"


def evidence(**overrides):
    command = [sys.executable, "-m", "pytest", "tests/", "-q"]
    document = {
        "schema_version": 1,
        "kind": "test_evidence",
        "source_commit": COMMIT,
        "dirty": False,
        "command": command,
        "suite": "tests/",
        "python_executable": sys.executable,
        "pytest_version": "8.4.2",
        "pytest_pin": "8.4.2",
        "counts": {"passed": 1514, "failed": 0, "skipped": 13,
                   "errors": 0},
        "exit_status": 0,
        "output": OUTPUT,
        "output_truncated": False,
        "output_sha256": hashlib.sha256(
            OUTPUT.encode("utf-8")).hexdigest(),
    }
    document.update(overrides)
    return document


class TestEvidenceValidationTests(unittest.TestCase):
    def test_a_green_run_of_the_same_tree_is_accepted(self):
        package_release.validate_test_evidence(evidence(), COMMIT)

    def test_another_commit_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "source_commit"):
            package_release.validate_test_evidence(
                evidence(source_commit="b" * 40), COMMIT)

    def test_a_dirty_tree_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "dirty"):
            package_release.validate_test_evidence(
                evidence(dirty=True), COMMIT)

    def test_failed_or_errored_tests_are_rejected(self):
        for counts in ({"passed": 10, "failed": 1, "skipped": 0,
                        "errors": 0},
                       {"passed": 10, "failed": 0, "skipped": 0,
                        "errors": 2}):
            with self.assertRaisesRegex(SystemExit, "reports"):
                package_release.validate_test_evidence(
                    evidence(counts=counts), COMMIT)

    def test_a_nonzero_exit_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "exit_status"):
            package_release.validate_test_evidence(
                evidence(exit_status=1), COMMIT)

    def test_a_different_pytest_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "pinned runner"):
            package_release.validate_test_evidence(
                evidence(pytest_version="8.3.0"), COMMIT)

    def test_a_command_without_pytest_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "does not run pytest"):
            package_release.validate_test_evidence(
                evidence(
                    command=[sys.executable, "-m", "unittest", "tests/",
                             "-q"],
                    python_executable=sys.executable), COMMIT)

    def test_a_fabricated_count_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "counts do not match"):
            package_release.validate_test_evidence(
                evidence(counts={"passed": 999999, "failed": 0,
                                 "skipped": 0, "errors": 0}), COMMIT)

    def test_a_modified_output_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "output digest"):
            package_release.validate_test_evidence(
                evidence(output="1514 passed, 13 skipped in 1.00s\n"),
                COMMIT)

    def test_a_truncated_output_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "truncated"):
            package_release.validate_test_evidence(
                evidence(output_truncated=True), COMMIT)

    def test_extra_pytest_arguments_are_rejected(self):
        command = [sys.executable, "-m", "pytest", "tests/", "-q",
                   "--ignore=tests"]
        with self.assertRaisesRegex(SystemExit, "extra pytest arguments"):
            package_release.validate_test_evidence(
                evidence(command=command,
                         python_executable=sys.executable), COMMIT)

    def test_a_signed_report_verifies_with_the_trusted_key(self):
        seed, public = signatures.generate_keypair()
        signed = test_evidence.sign_evidence(
            evidence(), seed, "ci-runner")
        package_release.validate_test_evidence(
            signed, COMMIT, public_key=public.hex(),
            require_signature=True)

    def test_a_public_key_file_is_accepted(self):
        seed, public = signatures.generate_keypair()
        signed = test_evidence.sign_evidence(
            evidence(), seed, "ci-runner")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ci.pub"
            path.write_text(public.hex() + "\n")
            package_release.validate_test_evidence(
                signed, COMMIT, public_key=str(path),
                require_signature=True)

    def test_a_wrong_key_is_rejected(self):
        seed, _public = signatures.generate_keypair()
        _other_seed, other = signatures.generate_keypair()
        signed = test_evidence.sign_evidence(
            evidence(), seed, "ci-runner")
        with self.assertRaisesRegex(SystemExit, "signature is invalid"):
            package_release.validate_test_evidence(
                signed, COMMIT, public_key=other.hex(),
                require_signature=True)

    def test_a_tampered_signed_report_is_rejected(self):
        seed, public = signatures.generate_keypair()
        signed = test_evidence.sign_evidence(
            evidence(), seed, "ci-runner")
        signed["counts"] = {"passed": 999999, "failed": 0,
                            "skipped": 0, "errors": 0}
        with self.assertRaisesRegex(SystemExit, "signature is invalid"):
            package_release.validate_test_evidence(
                signed, COMMIT, public_key=public.hex(),
                require_signature=True)

    def test_a_signature_is_required_when_requested(self):
        with self.assertRaisesRegex(SystemExit, "public key is required"):
            package_release.validate_test_evidence(
                evidence(), COMMIT, require_signature=True)

    def test_the_cli_refuses_a_missing_required_evidence_file(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/package_release.py"),
             "--status", "TEST", "--require-test-evidence"],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "--require-test-evidence needs --test-evidence", result.stderr)

    def test_load_rejects_a_foreign_document(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.json"
            path.write_text(json.dumps({"kind": "something_else"}))
            with self.assertRaisesRegex(SystemExit, "test_evidence"):
                package_release.load_test_evidence(path)
            path.write_text(json.dumps({"kind": "test_evidence",
                                        "schema_version": 2}))
            with self.assertRaisesRegex(SystemExit, "schema_version"):
                package_release.load_test_evidence(path)


def attestation(**overrides):
    record = {
        "schema_version": 1,
        "kind": "external_isolation_verification",
        "generated_at": "2026-11-14T22:00:00Z",
        "verified": True,
        "reason": "ok",
        "public_key": "c" * 64,
        "image_digest": "a" * 64,
        "receipt_digest": "b" * 64,
        "policy_digest": "d" * 64,
        "required_properties": ["net:denied"],
    }
    record.update(overrides)
    return record


AT = datetime(2026, 11, 14, 22, 10, tzinfo=timezone.utc)


class ExternalAttestationValidationTests(unittest.TestCase):
    def test_a_fresh_bound_attestation_is_accepted(self):
        package_release.validate_external_attestation(
            attestation(),
            expected_image_digest="a" * 64,
            expected_receipt_digest="b" * 64,
            at_time=AT)

    def test_an_expired_attestation_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "window"):
            package_release.validate_external_attestation(
                attestation(), at_time=datetime(
                    2026, 11, 14, 23, 30, tzinfo=timezone.utc))

    def test_a_failed_verification_is_rejected(self):
        for overrides in ({"verified": False},
                          {"reason": "image_mismatch"}):
            with self.assertRaisesRegex(SystemExit, "rejected"):
                package_release.validate_external_attestation(
                    attestation(**overrides), at_time=AT)

    def test_an_image_or_receipt_mismatch_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "image_digest"):
            package_release.validate_external_attestation(
                attestation(), expected_image_digest="e" * 64, at_time=AT)
        with self.assertRaisesRegex(SystemExit, "receipt_digest"):
            package_release.validate_external_attestation(
                attestation(), expected_receipt_digest="e" * 64, at_time=AT)

    def test_missing_properties_or_key_are_rejected(self):
        for overrides in ({"required_properties": []},
                          {"public_key": "not-a-key"}):
            with self.assertRaisesRegex(SystemExit, "rejected"):
                package_release.validate_external_attestation(
                    attestation(**overrides), at_time=AT)

    def test_load_rejects_a_foreign_document(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "attestation.json"
            path.write_text(json.dumps({"kind": "something_else"}))
            with self.assertRaisesRegex(
                    SystemExit, "external_isolation_verification"):
                package_release.load_external_attestation(path)

    def test_the_cli_refuses_a_missing_required_attestation(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/package_release.py"),
             "--status", "TEST", "--passed", "1",
             "--require-external-attestation"],
            capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "--require-external-attestation needs the raw receipt",
            result.stderr)


class PackageIsolationRecordTests(unittest.TestCase):
    def test_raw_isolation_evidence_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            root = base / "repo"
            root.mkdir()
            (root / "source.py").write_text("VALUE = 1\n")
            (root / "tests" / "v3").mkdir(parents=True)
            (root / "tests" / "v3" / "test_candidates.py").write_text(
                "def test_ok():\n    assert True\n")
            (root / "evidence").mkdir()
            write_manifest(root)
            subprocess.run(["git", "-C", str(root), "init", "-q"],
                           check=True)
            subprocess.run(["git", "-C", str(root), "add", "-A"],
                           check=True)
            subprocess.run(
                ["git", "-C", str(root), "-c", "user.name=t",
                 "-c", "user.email=t@e", "commit", "-qm", "init"],
                check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"]
            ).decode().strip()
            output = "1 passed in 0.01s\n"
            evidence = {
                "schema_version": 1,
                "kind": "test_evidence",
                "source_commit": commit,
                "dirty": False,
                "command": [sys.executable, "-m", "pytest", "tests/",
                            "-q"],
                "suite": "tests/",
                "python_executable": sys.executable,
                "pytest_version": "8.4.2",
                "pytest_pin": "8.4.2",
                "counts": {"passed": 1, "failed": 0, "skipped": 0,
                           "errors": 0},
                "exit_status": 0,
                "output": output,
                "output_truncated": False,
                "output_sha256": hashlib.sha256(
                    output.encode("utf-8")).hexdigest(),
            }
            receipt = ExecutionReceiptV1(
                schema_version=1, execution_id="exec-pkg",
                worker_identity="docker-sandbox-v1",
                environment_digest="1" * 64,
                before_tree_digest="2" * 64,
                after_tree_digest="2" * 64,
                command_spec_digest="3" * 64,
                exit_status=0, stdout_digest="4" * 64,
                stderr_digest=None,
                resource_usage={"wall_seconds": 1}, timeout=False,
                security_errors=("isolation:docker_sandbox",))
            iso_seed, iso_public = signatures.generate_keypair()
            issued = datetime.now(timezone.utc)
            attestation = issue_attestation_for_receipt(
                receipt, iso_seed, "iso-key",
                backend="docker_sandbox", policy_digest="5" * 64,
                image_digest="6" * 64, properties=("net:denied",),
                issued_at=issued.isoformat(
                    timespec="seconds").replace("+00:00", "Z"),
                expires_at=(issued + timedelta(hours=1)).isoformat(
                    timespec="seconds").replace("+00:00", "Z"))
            receipt_path = base / "receipt.json"
            attestation_path = base / "attestation.json"
            receipt_path.write_bytes(receipt.canonical_bytes() + b"\n")
            attestation_path.write_bytes(
                attestation.canonical_bytes() + b"\n")
            release_seed, _release_public = signatures.generate_keypair()
            result = package_release.package(
                root, "SIS-test", status="TEST",
                test_evidence=evidence,
                provenance_seed=release_seed,
                provenance_trust_root="qualification-only",
                isolation_receipt=receipt_path,
                isolation_attestation=attestation_path,
                isolator_public_key=iso_public.hex(),
                isolation_image_digest="6" * 64,
                isolation_policy_digest="5" * 64,
                isolation_properties=["net:denied"],
                require_external_attestation=True)
            record = result["release_manifest"]["isolation"][
                "external_attestation"]
            self.assertTrue(record["verified"])
            self.assertEqual(record["verification_mode"],
                             "raw_receipt_and_attestation")
            self.assertTrue(
                (root / "release" / "isolation_verification.json").is_file())
            self.assertTrue(
                (root / "release" / "isolation_receipt.json").is_file())
            self.assertTrue(
                (root / "release" / "isolation_attestation.json").is_file())


class RunTestsParsingTests(unittest.TestCase):
    def test_summary_counts_and_duration_are_parsed(self):
        output = "1514 passed, 13 skipped in 228.66s\n"
        self.assertEqual(
            run_tests._counts(output),
            {"passed": 1514, "failed": 0, "skipped": 13, "errors": 0})
        self.assertEqual(run_tests._duration(output), 228.66)

    def test_error_summary_is_parsed(self):
        output = "2 errors, 40 passed in 1.20s\n"
        counts = run_tests._counts(output)
        self.assertEqual(counts["errors"], 2)
        self.assertEqual(counts["passed"], 40)

    def test_the_pin_comes_from_the_lock_file(self):
        self.assertEqual(run_tests._pinned_version(), "8.4.2")


if __name__ == "__main__":
    unittest.main()
