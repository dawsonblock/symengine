"""Release qualification consumes executed test evidence, not typed totals."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import package_release  # noqa: E402
import run_tests  # noqa: E402

COMMIT = "a" * 40


def evidence(**overrides):
    document = {
        "schema_version": 1,
        "kind": "test_evidence",
        "source_commit": COMMIT,
        "dirty": False,
        "command": [sys.executable, "-m", "pytest", "tests/", "-q"],
        "pytest_version": "8.4.2",
        "pytest_pin": "8.4.2",
        "counts": {"passed": 1514, "failed": 0, "skipped": 13,
                   "errors": 0},
        "exit_status": 0,
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
                evidence(command=["python3", "-m", "unittest"]), COMMIT)

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
