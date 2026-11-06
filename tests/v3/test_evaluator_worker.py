"""Evaluator-in-subprocess: signing custody separated from the caller."""
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import TaskEnvelopeV1
from sis.v3.evaluator_worker import EvaluatorWorkerError, evaluate_via_subprocess
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.verifier import OutcomeVerifier, verify_receipt_signature

PY = sys.executable


class EvaluatorWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key_dir = self.root / "keys"
        self.registry_dir = self.root / "registry"
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        # Register the task through a normal verifier; the worker reuses the
        # same registry and key dirs in its own process.
        self.registrar = OutcomeVerifier(
            executor=LocalSubprocessExecutor(self.root / "reg-exec", use_seatbelt=False),
            key_dir=self.key_dir,
            registry_dir=self.registry_dir,
        )
        self.registrar.register_task(
            actor_role="evaluator", task_id="t1", criterion_version="v1",
            argv=(PY, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"},
        )
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )

    def test_subprocess_produces_verifiable_signed_receipt(self):
        result = evaluate_via_subprocess(
            key_dir=self.key_dir, registry_dir=self.registry_dir,
            task=self.task, submission_dir=self.repo,
            evaluation_nonce="sub-nonce-1",
            executor_root=self.root / "work-exec",
        )
        self.assertEqual(result.exit_status, 0)
        self.assertEqual(result.receipt.outcome, "pass")
        pub = self.registrar.public_key_record()
        self.assertEqual(result.receipt.signer_key_id, pub["key_id"])
        self.assertTrue(
            verify_receipt_signature(result.receipt, pub["public_key"])
        )

    def test_unregistered_task_rejected_in_child(self):
        bad = TaskEnvelopeV1.from_dict({
            **self.task.to_dict(), "task_id": "nope",
            "evaluator_task_ref": "nope",
        })
        with self.assertRaisesRegex(EvaluatorWorkerError, "rejected"):
            evaluate_via_subprocess(
                key_dir=self.key_dir, registry_dir=self.registry_dir,
                task=bad, submission_dir=self.repo,
                evaluation_nonce="sub-nonce-2",
            )

    def test_missing_dirs_fail_fast(self):
        with self.assertRaises(EvaluatorWorkerError):
            evaluate_via_subprocess(
                key_dir=self.root / "absent", registry_dir=self.registry_dir,
                task=self.task, submission_dir=self.repo,
                evaluation_nonce="n",
            )


if __name__ == "__main__":
    unittest.main()
