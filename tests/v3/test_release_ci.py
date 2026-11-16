"""Release CI fails closed; development drift is an explicit policy choice."""
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
import provenance  # noqa: E402
import test_evidence  # noqa: E402
import verify_release  # noqa: E402
from build_release import write_manifest  # noqa: E402
from sis.v3 import signatures  # noqa: E402
from sis.v3.contracts import ExecutionReceiptV1  # noqa: E402
from sis.v3.isolation import issue_attestation_for_receipt  # noqa: E402

COMMIT = "a" * 40
IMAGE = "1" * 64
POLICY = "2" * 64
PROPERTIES = ("net:denied", "fs:root_read_only")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


class ReleaseCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "source.py").write_text("VALUE = 1\n")
        write_manifest(self.root)
        self.release_seed, self.release_public = signatures.generate_keypair()
        self.ci_seed, self.ci_public = signatures.generate_keypair()
        self.isolator_seed, self.isolator_public = signatures.generate_keypair()
        self.release_dir = self.root / "release"
        self.release_dir.mkdir()

    def run_check(self, mode, *extra, env=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_release_ci.py"),
             "--mode", mode, "--source", str(self.root), *extra],
            capture_output=True, text=True, env=env,
        )

    def _build_archive(self):
        archive = self.release_dir / "SIS-test.zip"
        verify_release.build_zip(self.root, archive)
        return archive

    def _sign_provenance(self, archive, *, seed=None, key_id="release-key",
                         archive_name=None, archive_sha256=None):
        digest = archive_sha256 or provenance.sha256_file(archive)
        statement = provenance.build_statement(
            archive_name=archive_name or archive.name,
            archive_sha256=digest,
            release="SIS-test", branch="test", source_commit=COMMIT)
        envelope = provenance.sign_statement(
            statement, seed or self.release_seed, key_id)
        path = self.release_dir / "provenance.dsse.json"
        path.write_text(json.dumps(envelope, sort_keys=True))
        return path

    def _write_evidence(self, *, sign=True, **overrides):
        output = "10 passed, 2 skipped in 1.00s\n"
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
            "counts": {"passed": 10, "failed": 0, "skipped": 2,
                       "errors": 0},
            "exit_status": 0,
            "output": output,
            "output_truncated": False,
            "output_sha256": hashlib.sha256(
                output.encode("utf-8")).hexdigest(),
        }
        document.update(overrides)
        if sign:
            document = test_evidence.sign_evidence(
                document, self.ci_seed, "ci-runner")
        path = self.release_dir / "test_evidence.json"
        digest = test_evidence.write(path, document)
        return path, digest, document

    def _receipt(self, **overrides):
        values = {
            "schema_version": 1,
            "execution_id": "exec-test",
            "worker_identity": "docker-sandbox-v1",
            "environment_digest": "3" * 64,
            "before_tree_digest": "4" * 64,
            "after_tree_digest": "4" * 64,
            "command_spec_digest": "5" * 64,
            "exit_status": 0,
            "stdout_digest": "6" * 64,
            "stderr_digest": None,
            "resource_usage": {"wall_seconds": 1},
            "timeout": False,
            "security_errors": ("isolation:docker_sandbox",),
        }
        values.update(overrides)
        return ExecutionReceiptV1(**values)

    def _write_isolation(self, *, receipt=None, expired=False,
                         seed=None, key_id="external-isolator"):
        receipt = receipt or self._receipt()
        issued = datetime.now(timezone.utc)
        if expired:
            issued -= timedelta(hours=2)
        attestation = issue_attestation_for_receipt(
            receipt, seed or self.isolator_seed, key_id,
            backend="docker_sandbox",
            policy_digest=POLICY,
            image_digest=IMAGE,
            properties=PROPERTIES,
            issued_at=issued.isoformat(
                timespec="seconds").replace("+00:00", "Z"),
            expires_at=(issued + timedelta(hours=1)).isoformat(
                timespec="seconds").replace("+00:00", "Z"))
        receipt_path = self.release_dir / "isolation_receipt.json"
        attestation_path = self.release_dir / "isolation_attestation.json"
        receipt_path.write_text(
            json.dumps(receipt.to_dict(), indent=2, sort_keys=True))
        attestation_path.write_text(
            json.dumps(attestation.to_dict(), indent=2, sort_keys=True))
        return receipt, attestation, receipt_path, attestation_path

    def write_valid_release(self, *, evidence_overrides=None,
                            include_isolation=True):
        archive = self._build_archive()
        digest = provenance.sha256_file(archive)
        self._sign_provenance(archive)
        evidence_path, evidence_digest, evidence_doc = self._write_evidence(
            **(evidence_overrides or {}))
        document = {
            "schema_version": 1,
            "release": "SIS-test",
            "source_commit": COMMIT,
            "test_result": {
                "source": "evidence",
                "command": " ".join(evidence_doc["command"]),
                "passed": evidence_doc["counts"]["passed"],
                "skipped": evidence_doc["counts"]["skipped"],
                "failed": evidence_doc["counts"]["failed"],
                "errors": evidence_doc["counts"]["errors"],
                "evidence": {
                    "path": "release/test_evidence.json",
                    "sha256": evidence_digest,
                    "output_sha256": evidence_doc["output_sha256"],
                },
            },
            "isolation": {"external_attestation": None},
            "archive": {
                "path": "release/SIS-test.zip",
                "sha256": digest,
                "source_files": len(json.loads(
                    (self.root / "RELEASE_SHA256.json").read_text())["files"]),
                "inner_project_dir": self.root.name,
            },
            "provenance": {
                "signed": True,
                "trust_root": "production",
                "path": "release/provenance.dsse.json",
                "subject_sha256": digest,
            },
        }
        if include_isolation:
            receipt, attestation, receipt_path, attestation_path = (
                self._write_isolation())
            document["isolation"]["external_attestation"] = {
                "verified": True,
                "receipt": {
                    "path": "release/isolation_receipt.json",
                    "sha256": hashlib.sha256(
                        receipt_path.read_bytes()).hexdigest(),
                },
                "attestation": {
                    "path": "release/isolation_attestation.json",
                    "sha256": hashlib.sha256(
                        attestation_path.read_bytes()).hexdigest(),
                },
                "receipt_digest": receipt.digest,
                "attestation_digest": attestation.digest,
                "signer_key_id": "external-isolator",
                "public_key": self.isolator_public.hex(),
                "image_digest": IMAGE,
                "policy_digest": POLICY,
                "required_properties": list(PROPERTIES),
                "generated_at": _utcnow(),
            }
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        return document

    def valid_args(self):
        return (
            "--release-public-key", self.release_public.hex(),
            "--test-evidence-public-key", self.ci_public.hex(),
            "--isolator-public-key", self.isolator_public.hex(),
            "--isolation-image-digest", IMAGE,
            "--isolation-policy-digest", POLICY,
            "--isolation-property", PROPERTIES[0],
            "--isolation-property", PROPERTIES[1],
        )

    def test_matching_inventory_passes_development_only(self):
        result = self.run_check("development")
        self.assertEqual(result.returncode, 0)
        self.assertIn("release qualification not performed", result.stdout)
        result = self.run_check("release")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release_manifest.json is missing", result.stderr)

    def test_stale_release_fails_without_rewriting_manifest(self):
        original = (self.root / "RELEASE_SHA256.json").read_bytes()
        (self.root / "source.py").write_text("VALUE = 2\n")
        self.assertNotEqual(self.run_check("release").returncode, 0)
        self.assertEqual(
            (self.root / "RELEASE_SHA256.json").read_bytes(), original)

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

    def test_valid_signed_release_passes(self):
        self.write_valid_release()
        result = self.run_check("release", *self.valid_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("release qualification verified", result.stdout)

    def test_public_key_files_are_accepted(self):
        self.write_valid_release()
        paths = {}
        for name, key in (
                ("release", self.release_public),
                ("ci", self.ci_public),
                ("isolator", self.isolator_public)):
            path = self.release_dir / f"{name}.pub"
            path.write_text(key.hex() + "\n")
            paths[name] = str(path)
        args = list(self.valid_args())
        for flag, name in (
                ("--release-public-key", "release"),
                ("--test-evidence-public-key", "ci"),
                ("--isolator-public-key", "isolator")):
            args[args.index(flag) + 1] = paths[name]
        result = self.run_check("release", *args)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_archive_fails_release(self):
        self.write_valid_release()
        (self.release_dir / "SIS-test.zip").unlink()
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive is missing", result.stderr)

    def test_archive_digest_mismatch_fails_release(self):
        self.write_valid_release()
        archive = self.release_dir / "SIS-test.zip"
        archive.write_bytes(archive.read_bytes() + b"tampered")
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("digest does not match", result.stderr)

    def test_signature_for_a_different_archive_fails_release(self):
        self.write_valid_release()
        archive = self.release_dir / "SIS-test.zip"
        self._sign_provenance(
            archive, archive_name="SIS-other.zip",
            archive_sha256="9" * 64)
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance", result.stderr)

    def test_changed_source_after_archive_fails_source_binding(self):
        self.write_valid_release()
        (self.root / "source.py").write_text("VALUE = 2\n")
        write_manifest(self.root)
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("source binding", result.stderr)

    def test_unsigned_provenance_fails_release(self):
        document = self.write_valid_release()
        document["provenance"]["signed"] = False
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("provenance is unsigned", result.stderr)

    def test_qualification_trust_root_fails_release(self):
        document = self.write_valid_release()
        document["provenance"]["trust_root"] = "qualification-only"
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("trust root is not production", result.stderr)

    def test_missing_release_public_key_fails_release(self):
        self.write_valid_release()
        args = list(self.valid_args())
        index = args.index("--release-public-key")
        del args[index:index + 2]
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release public key is required", result.stderr)

    def test_wrong_release_key_fails_release(self):
        self.write_valid_release()
        _seed, other = signatures.generate_keypair()
        args = list(self.valid_args())
        index = args.index("--release-public-key")
        args[index + 1] = other.hex()
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)

    def test_missing_isolation_fails_release(self):
        self.write_valid_release(include_isolation=False)
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no verified external isolation", result.stderr)

    def test_wrong_isolator_key_fails_release(self):
        self.write_valid_release()
        _seed, other = signatures.generate_keypair()
        args = list(self.valid_args())
        index = args.index("--isolator-public-key")
        args[index + 1] = other.hex()
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolation", result.stderr)

    def test_expired_attestation_fails_release(self):
        self.write_valid_release()
        _receipt, _attestation, receipt_path, attestation_path = (
            self._write_isolation(expired=True))
        document = json.loads(
            (self.release_dir / "release_manifest.json").read_text())
        record = document["isolation"]["external_attestation"]
        record["receipt"]["sha256"] = hashlib.sha256(
            receipt_path.read_bytes()).hexdigest()
        record["attestation"]["sha256"] = hashlib.sha256(
            attestation_path.read_bytes()).hexdigest()
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("attestation", result.stderr)

    def test_receipt_from_another_execution_fails_release(self):
        self.write_valid_release()
        other = self._receipt(command_spec_digest="7" * 64)
        _receipt, _attestation, receipt_path, _attestation_path = (
            self._write_isolation(receipt=other))
        document = json.loads(
            (self.release_dir / "release_manifest.json").read_text())
        document["isolation"]["external_attestation"]["receipt"][
            "sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolation", result.stderr)

    def test_wrong_image_digest_fails_release(self):
        self.write_valid_release()
        args = list(self.valid_args())
        index = args.index("--isolation-image-digest")
        args[index + 1] = "8" * 64
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image_mismatch", result.stderr)

    def test_wrong_policy_digest_fails_release(self):
        self.write_valid_release()
        args = list(self.valid_args())
        index = args.index("--isolation-policy-digest")
        args[index + 1] = "8" * 64
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("policy_mismatch", result.stderr)

    def test_missing_test_evidence_fails_release(self):
        self.write_valid_release()
        (self.release_dir / "test_evidence.json").unlink()
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("test evidence is missing", result.stderr)

    def test_unsigned_test_evidence_fails_release(self):
        self.write_valid_release()
        _path, digest, document = self._write_evidence(sign=False)
        manifest = json.loads(
            (self.release_dir / "release_manifest.json").read_text())
        manifest["test_result"]["evidence"]["sha256"] = digest
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

    def test_fabricated_test_count_fails_release(self):
        self.write_valid_release()
        document = json.loads(
            (self.release_dir / "release_manifest.json").read_text())
        document["test_result"]["passed"] = 999999
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(document, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("count does not match", result.stderr)

    def test_a_command_that_narrows_the_suite_fails_release(self):
        self.write_valid_release()
        _path, digest, document = self._write_evidence(
            command=[sys.executable, "-m", "pytest", "tests/", "-q",
                     "-k", "nothing"])
        manifest = json.loads(
            (self.release_dir / "release_manifest.json").read_text())
        manifest["test_result"]["evidence"]["sha256"] = digest
        manifest["test_result"]["command"] = " ".join(document["command"])
        (self.release_dir / "release_manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True))
        result = self.run_check("release", *self.valid_args())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("extra pytest arguments", result.stderr)

    def test_wrong_test_evidence_key_fails_release(self):
        self.write_valid_release()
        _seed, other = signatures.generate_keypair()
        args = list(self.valid_args())
        index = args.index("--test-evidence-public-key")
        args[index + 1] = other.hex()
        result = self.run_check("release", *args)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signature is invalid", result.stderr)

    def test_workflow_gates_by_event_not_inventory_success(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertIn(
            "if: startsWith(github.ref, 'refs/tags/') ||"
            " github.event_name == 'release'", workflow)
        self.assertIn(
            "tools/check_release_ci.py --mode release", workflow)
        self.assertNotIn("if python tools/build_release.py --check", workflow)

    def test_workflow_provisions_the_gitignored_archive_before_the_gate(self):
        # release/*.zip is gitignored, so a tag checkout has no archive
        # unless CI fetches the release asset first. The gate must stay
        # after the download, and the download must never be treated as
        # trusted input.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("gh release download", workflow)
        self.assertLess(
            workflow.index("gh release download"),
            workflow.index("tools/check_release_ci.py --mode release"))
        self.assertIn("release/SIS-*.zip", workflow)
        for anchor in ("SIS_RELEASE_PUBLIC_KEY", "SIS_TEST_EVIDENCE_PUBLIC_KEY",
                       "SIS_ISOLATOR_PUBLIC_KEY",
                       "SIS_ISOLATION_IMAGE_DIGEST",
                       "SIS_ISOLATION_POLICY_DIGEST",
                       "SIS_ISOLATION_PROPERTIES"):
            self.assertIn(anchor, workflow)

    def test_evidence_job_fails_closed_without_a_signing_key(self):
        # The release-only evidence job used to fall back to an unsigned
        # report, which package_release.py refuses; a missing key is now
        # an explicit configuration error.
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn(
            "SIS_TEST_EVIDENCE_SIGNING_KEY is not configured", workflow)
        for chunk in workflow.split("python tools/run_tests.py")[1:]:
            self.assertIn("--signing-key", chunk[:200])


class ReleasePathTests(unittest.TestCase):
    """Declared release paths must be checked before they are resolved."""

    def _root(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        return Path(temp.name)

    def test_internal_symlinked_file_is_rejected(self):
        from check_release_ci import _release_path
        root = self._root()
        (root / "real.json").write_text("{}")
        (root / "link.json").symlink_to("real.json")
        # resolve() would return the target, so a post-resolve is_symlink()
        # check can never fire; the rule has to see the declared path.
        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            _release_path(root, "link.json", "artifact")
        self.assertEqual(_release_path(root, "real.json", "artifact"),
                         (root / "real.json").resolve())

    def test_internal_symlinked_directory_is_rejected(self):
        from check_release_ci import _release_path
        root = self._root()
        (root / "sub").mkdir()
        (root / "sub" / "real.json").write_text("{}")
        (root / "alias").symlink_to("sub", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "must not be a symlink"):
            _release_path(root, "alias/real.json", "artifact")

    def test_escaping_path_is_rejected(self):
        from check_release_ci import _release_path
        root = self._root()
        outside = root.parent / f"{root.name}-outside.json"
        outside.write_text("{}")
        self.addCleanup(outside.unlink)
        with self.assertRaisesRegex(ValueError, "escapes the release tree"):
            _release_path(root, f"../{outside.name}", "artifact")


if __name__ == "__main__":
    unittest.main()
