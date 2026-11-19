"""Shared-custody verdicts need positive evidence; classification uses trusted signals."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.contracts import ExecutionReceiptV1, TaskEnvelopeV1
from sis.v3.evaluation_runtime import (
    RESOURCE_LIMIT,
    TASK_FAIL,
    TASK_PASS,
    check_pytest_report,
    classify_execution,
)
from sis.v3.runner import (
    MARKER_SHARED_CUSTODY,
    LocalSubprocessExecutor,
    tree_digest,
)
from sis.v3.verifier import EvaluationRejected, OutcomeVerifier

PY = sys.executable
NONCE = "a" * 32


def receipt(*, exit_status=0, timeout=False, security_errors=()):
    return ExecutionReceiptV1(
        schema_version=1, execution_id="exec-test",
        worker_identity="worker", environment_digest="0" * 64,
        before_tree_digest="0" * 64, after_tree_digest="0" * 64,
        command_spec_digest="0" * 64, exit_status=exit_status,
        stdout_digest=None, stderr_digest=None,
        resource_usage={"wall_seconds": 1}, timeout=timeout,
        security_errors=tuple(security_errors))


def report_line(nonce=NONCE, **overrides) -> bytes:
    payload = {"collected": 2, "passed": 2, "failed": 0, "errors": 0,
               "skipped": 0, "xfailed": 0, "xpassed": 0,
               "collection_errors": 0, "files": {"acc.py": 2},
               "finished": True, "exitstatus": 0, "returned": 0}
    payload.update(overrides)
    return (b"noise\nSIS_PYTEST_REPORT:" + nonce.encode() + b":"
            + json.dumps(payload).encode() + b"\n2 passed\n")


class ReportCheckTests(unittest.TestCase):
    def check(self, stdout, **kwargs):
        return check_pytest_report(stdout, NONCE, **kwargs)

    def test_complete_pass_is_accepted(self):
        result = self.check(report_line(), expected_files=("acc.py",))
        self.assertTrue(result.ok, result)

    def test_missing_forged_or_incomplete_reports_are_rejected(self):
        cases = {
            "report_missing": b"2 passed\n",
            "report_missing ": report_line(nonce="b" * 32),
            "report_duplicated": report_line() + report_line(),
            "session_not_finished": report_line(finished=False),
            "session_not_successful": report_line(exitstatus=1),
            "no_passing_tests": report_line(
                collected=0, passed=0, files={}),
            "failures_reported": report_line(failed=1, passed=1),
            "tests_without_result": report_line(collected=3),
            "report_malformed": report_line(passed="2"),
        }
        for reason, stdout in cases.items():
            result = self.check(stdout)
            self.assertFalse(result.ok, reason)
            self.assertEqual(result.reason, reason.strip())

    def test_expected_private_files_must_contribute_tests(self):
        self.assertEqual(self.check(
            report_line(files={"acc.py": 1, "<outside>": 1}),
            expected_files=("acc.py",)).reason, "unexpected_tests")
        self.assertEqual(self.check(
            report_line(files={"acc.py": 2}),
            expected_files=("acc.py", "more.py")).reason,
            "expected_tests_not_collected")

    def test_exit_zero_without_a_valid_report_is_a_fail(self):
        missing = self.check(b"")
        self.assertEqual(classify_execution(receipt(), report=missing),
                         TASK_FAIL)
        self.assertEqual(classify_execution(
            receipt(), report=self.check(report_line())), TASK_PASS)

    def test_stderr_text_never_reclassifies(self):
        for text in ("MemoryError", "Killed", "No space left on device",
                     "Too many open files", "Cannot allocate memory",
                     "evaluation_runner_unavailable: pytest"):
            self.assertEqual(classify_execution(
                receipt(exit_status=1), stderr_tail=text), TASK_FAIL, text)
        # Runner-side flags still classify.
        self.assertEqual(classify_execution(receipt(
            exit_status=-9, security_errors=("rlimit:cpu_exceeded",))),
            RESOURCE_LIMIT)


class SharedCustodyVerdictTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            allow_shared_custody=True, executor=self.executor,
            key_dir=self.root / "keys", registry_dir=self.root / "registry")
        self.submission = self.root / "submission"
        self.submission.mkdir()
        self.verifier.register_task(
            actor_role="evaluator", task_id="t", criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "acc.py"),
            files={"acc.py": (
                b"from calc import add\n"
                b"def test_add():\n    assert add(2, 3) == 5\n"
                b"def test_add_more():\n    assert add(1, 1) == 2\n")},
            base_commit="abc1234")
        self.nonce = 0

    def evaluate(self, source: str):
        (self.submission / "calc.py").write_text(source)
        self.nonce += 1
        task = TaskEnvelopeV1(
            schema_version=1, task_id="t",
            repo_snapshot_digest=tree_digest(self.submission),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(b"task").hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref="t")
        return self.verifier.evaluate(
            actor_role="evaluator", task=task,
            submission_dir=self.submission,
            evaluation_nonce=f"n-{self.nonce}")

    def test_correct_submission_passes(self):
        outcome = self.evaluate("def add(a, b):\n    return a + b\n").outcome
        self.assertEqual(outcome, "pass", (
            self.verifier.last_outcome_class,
            self.verifier.last_report_check))

    def test_exit_zero_at_import_is_a_fail(self):
        outcome = self.evaluate(
            "import os\nos._exit(0)\ndef add(a, b):\n    return 0\n")
        self.assertEqual(outcome.outcome, "fail")
        self.assertEqual(self.verifier.last_outcome_class, TASK_FAIL)

    def test_exit_zero_during_a_test_is_a_fail(self):
        outcome = self.evaluate(
            "import os\ndef add(a, b):\n    os._exit(0)\n")
        self.assertEqual(outcome.outcome, "fail")

    def test_printing_a_report_without_the_nonce_is_a_fail(self):
        outcome = self.evaluate(
            "import os\n"
            f"os.write(1, {report_line(nonce='0' * 32)!r})\n"
            "os._exit(0)\n")
        self.assertEqual(outcome.outcome, "fail")

    def test_shared_custody_receipt_is_marked_unqualified(self):
        captured = []
        original = self.executor.run

        def run(*args, **kwargs):
            result = original(*args, **kwargs)
            captured.append(result)
            return result

        with mock.patch.object(self.executor, "run", run):
            self.evaluate("def add(a, b):\n    return a + b\n")
        self.assertIn(MARKER_SHARED_CUSTODY, captured[-1].security_errors)

    def test_tree_changed_between_digest_and_copy_is_rejected(self):
        original = self.executor.prepare

        def prepare(base, **kwargs):
            # The submission changes after the verifier digested it.
            (Path(base) / "calc.py").write_text(
                "def add(a, b):\n    return a + b\n")
            return original(base, **kwargs)

        with mock.patch.object(self.executor, "prepare", prepare):
            with self.assertRaises(EvaluationRejected) as caught:
                self.evaluate("def add(a, b):\n    return 0\n")
        self.assertEqual(caught.exception.reason,
                         "submission_changed_during_evaluation")
        self.assertEqual(self.verifier.issued_receipts(), [])


if __name__ == "__main__":
    unittest.main()
