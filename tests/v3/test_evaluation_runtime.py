"""PR-05: pinned evaluator runtime, outcome taxonomy and sandbox checks."""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ExecutionReceiptV1, TaskEnvelopeV1
from sis.v3.evaluation_runtime import (
    EVALUATOR_BOOTSTRAP_ERROR,
    INFRASTRUCTURE_ERROR,
    RESOURCE_LIMIT,
    SANDBOX_FAILURE,
    TASK_FAIL,
    TASK_PASS,
    TIMEOUT,
    EvaluationRuntimeProfile,
    OUTCOME_CLASSES,
    classify_execution,
)
from sis.v3.runner import (CommandSpec, LocalSubprocessExecutor,
                           ResourceLimits, tree_digest)
from sis.v3.verifier import EvaluationRejected, OutcomeVerifier

PY = sys.executable
POSIX = os.name == "posix"


def receipt(*, exit_status=0, timeout=False, security_errors=()):
    return ExecutionReceiptV1(
        schema_version=1, execution_id="exec-test",
        worker_identity="worker", environment_digest="0" * 64,
        before_tree_digest="0" * 64, after_tree_digest="0" * 64,
        command_spec_digest="0" * 64, exit_status=exit_status,
        stdout_digest=None, stderr_digest=None,
        resource_usage={"wall_seconds": 1}, timeout=timeout,
        security_errors=tuple(security_errors))


class RuntimeProfileTests(unittest.TestCase):
    def test_default_limits_are_calibrated_for_pytest(self):
        self.assertEqual(ResourceLimits().memory_bytes, 2 * 1024 ** 3)
        profile = EvaluationRuntimeProfile()
        self.assertEqual(profile.task_limits.memory_bytes, 2 * 1024 ** 3)
        self.assertEqual(profile.bootstrap_limits.memory_bytes, 2 * 1024 ** 3)
        self.assertIsNone(profile.bootstrap_limits.process_count)

    def test_runtime_digest_binds_pytest_and_limits(self):
        a = EvaluationRuntimeProfile()
        b = EvaluationRuntimeProfile(pytest_version="9.0.0")
        c = EvaluationRuntimeProfile(task_memory_bytes=1 << 30)
        self.assertNotEqual(a.digest, b.digest)
        self.assertNotEqual(a.digest, c.digest)
        self.assertEqual(a.digest, EvaluationRuntimeProfile().digest)

    def test_plugin_policy_is_explicit(self):
        profile = EvaluationRuntimeProfile()
        argv = profile.pytest_argv((PY, "-m", "pytest", "-q"))
        self.assertIn("-p", argv)
        self.assertIn("no:cacheprovider", argv)
        self.assertEqual(profile.environment()[
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD"], "1")
        self.assertEqual(profile.environment()["PYTHONNOUSERSITE"], "1")

    def test_outcome_taxonomy_is_complete(self):
        self.assertEqual(set(OUTCOME_CLASSES), {
            TASK_PASS, TASK_FAIL, EVALUATOR_BOOTSTRAP_ERROR,
            RESOURCE_LIMIT, TIMEOUT, SANDBOX_FAILURE,
            "EVIDENCE_FAILURE", INFRASTRUCTURE_ERROR})

    def test_pinned_runtime_matches_environment(self):
        profile = EvaluationRuntimeProfile()
        record = profile.assert_pinned()
        self.assertEqual(record["pytest_version"], profile.pytest_version)


class ClassificationTests(unittest.TestCase):
    def test_success_is_task_pass(self):
        self.assertEqual(classify_execution(receipt()), TASK_PASS)

    def test_nonzero_is_task_fail(self):
        self.assertEqual(
            classify_execution(receipt(exit_status=1)), TASK_FAIL)

    def test_timeout_is_not_task_fail(self):
        self.assertEqual(
            classify_execution(receipt(timeout=True)), TIMEOUT)

    def test_resource_limit_is_not_task_fail(self):
        self.assertEqual(classify_execution(receipt(
            security_errors=("fs:disk_budget_exceeded",))), RESOURCE_LIMIT)
        self.assertEqual(classify_execution(receipt(
            exit_status=1), stderr_tail="MemoryError"), RESOURCE_LIMIT)
        self.assertEqual(classify_execution(receipt(
            security_errors=("output:stdout_truncated",))), RESOURCE_LIMIT)

    def test_unverified_isolation_can_be_sandbox_failure(self):
        self.assertEqual(classify_execution(
            receipt(security_errors=("isolation:unverified_local",)),
            require_verified_isolation=True), SANDBOX_FAILURE)
        self.assertEqual(classify_execution(
            receipt(security_errors=("isolation:unverified_local",))),
            TASK_PASS)

    def test_external_symlink_is_sandbox_failure(self):
        self.assertEqual(classify_execution(receipt(
            security_errors=("fs:external_symlink",))), SANDBOX_FAILURE)

    def test_infrastructure_error_is_explicit(self):
        self.assertEqual(classify_execution(
            receipt(), infrastructure_error="worker crashed"),
            INFRASTRUCTURE_ERROR)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_bootstrap_probe_succeeds_in_clean_environment(self):
        verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        result = verifier.bootstrap()
        self.assertTrue(result.ok, result)
        self.assertEqual(result.pytest_version,
                         EvaluationRuntimeProfile().pytest_version)

    def test_bootstrap_failure_is_not_a_task_receipt(self):
        verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
            runtime_profile=EvaluationRuntimeProfile(
                pytest_version="0.0.0-not-installed"))
        result = verifier.bootstrap()
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "runtime_pin_mismatch")
        submission = self.root / "submission"
        submission.mkdir()
        (submission / "ok.py").write_text("X = 1\n")
        verifier.register_task(
            actor_role="evaluator", task_id="t-bootstrap",
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py": b"def test_ok():\n    assert True\n"},
            base_commit="abc1234")
        task = TaskEnvelopeV1(
            schema_version=1, task_id="t-bootstrap",
            repo_snapshot_digest=tree_digest(submission),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(b"task").hexdigest(),
            permitted_commands=("pytest",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref="t-bootstrap")
        with self.assertRaises(EvaluationRejected) as caught:
            verifier.evaluate(
                actor_role="evaluator", task=task,
                submission_dir=submission, evaluation_nonce="n-1")
        self.assertEqual(caught.exception.reason,
                         "evaluator_bootstrap_error")
        self.assertEqual(verifier.last_outcome_class,
                         EVALUATOR_BOOTSTRAP_ERROR)
        self.assertEqual(verifier.issued_receipts(), [])


class ReceiptOutcomeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "exec"),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def average(values):\n    return sum(values) / len(values)\n")

    def _task(self, task_id):
        return TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(self.submission),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(b"task").hexdigest(),
            permitted_commands=("pytest",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref=task_id)

    def test_pass_receipt_records_task_pass_class(self):
        task_id = "t-pass"
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py":
                   b"from calc import average\n\n"
                   b"def test_average():\n    assert average([1, 2, 3]) == 2\n"},
            base_commit="abc1234")
        receipt_obj = self.verifier.evaluate(
            actor_role="evaluator", task=self._task(task_id),
            submission_dir=self.submission, evaluation_nonce="n-pass")
        self.assertEqual(receipt_obj.outcome, "pass")
        self.assertEqual(self.verifier.last_outcome_class, TASK_PASS)
        entry = self.verifier._journal[-1]
        self.assertEqual(entry["outcome_class"], TASK_PASS)
        self.assertEqual(entry["runtime_digest"],
                         self.verifier.runtime_profile.digest)
        self.assertIsNotNone(entry["bootstrap_digest"])

    def test_failing_suite_is_task_fail(self):
        task_id = "t-fail"
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py": b"def test_no():\n    assert False\n"},
            base_commit="abc1234")
        receipt_obj = self.verifier.evaluate(
            actor_role="evaluator", task=self._task(task_id),
            submission_dir=self.submission, evaluation_nonce="n-fail")
        self.assertEqual(receipt_obj.outcome, "fail")
        self.assertEqual(self.verifier.last_outcome_class, TASK_FAIL)

    def test_timeout_is_error_not_fail(self):
        task_id = "t-timeout"
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(PY, "-c", "import time; time.sleep(10)"),
            files={}, base_commit="abc1234")
        self.verifier.limits = ResourceLimits(
            wall_seconds=1, cpu_seconds=10, memory_bytes=2 * 1024 ** 3,
            process_count=None)
        receipt_obj = self.verifier.evaluate(
            actor_role="evaluator", task=self._task(task_id),
            submission_dir=self.submission, evaluation_nonce="n-timeout")
        self.assertEqual(receipt_obj.outcome, "error")
        self.assertEqual(self.verifier.last_outcome_class, TIMEOUT)


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "ok.txt").write_text("ok\n")

    def test_protected_path_is_denied_when_seatbelt_available(self):
        executor = LocalSubprocessExecutor(self.root / "exec")
        if executor.network_isolation != "seatbelt_denied":
            self.skipTest("seatbelt is unavailable on this platform")
        secret = self.root / "keys"
        secret.mkdir()
        (secret / "seed").write_text("SECRET")
        executor.protect(secret)
        workspace = executor.prepare(self.base)
        receipt_obj = executor.run(workspace, CommandSpec(
            argv=(PY, "-c", f"print(open({str(secret / 'seed')!r}).read())"),
            limits=ResourceLimits(wall_seconds=10)))
        _, stderr = executor.output(receipt_obj.execution_id)
        self.assertNotEqual(receipt_obj.exit_status, 0)
        self.assertIn(b"Operation not permitted", stderr)
        self.assertNotIn(b"SECRET", stderr)

    def test_network_is_denied_when_seatbelt_available(self):
        executor = LocalSubprocessExecutor(self.root / "exec")
        if executor.network_isolation != "seatbelt_denied":
            self.skipTest("seatbelt is unavailable on this platform")
        workspace = executor.prepare(self.base)
        code = ("import socket; "
                "socket.create_connection(('93.184.216.34', 80), 2)")
        receipt_obj = executor.run(workspace, CommandSpec(
            argv=(PY, "-c", code),
            limits=ResourceLimits(wall_seconds=10)))
        self.assertNotEqual(receipt_obj.exit_status, 0)


if __name__ == "__main__":
    unittest.main()
