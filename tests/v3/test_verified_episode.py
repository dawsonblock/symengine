"""End-to-end vertical: scripted agent -> executor -> store -> verifier -> replay.

The "agent" here is a deterministic fixture producer, not Codex. This test
exercises the real evidence pipeline (disposable workspace, chained
observations, independent evaluator, signed receipt, replay) so later Codex
integration plugs into a proven loop. No lift claim is made.
"""
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ObservationEventV1, TaskEnvelopeV1, canonical_digest
from sis.v3.episode_store import EpisodeStore
from sis.v3.policy import AuthorizationDenied
from sis.v3.runner import CommandSpec, LocalSubprocessExecutor
from sis.v3.verifier import EvaluationRejected, OutcomeVerifier, verify_receipt_signature


PY = __import__("sys").executable
ACCEPTANCE = (
    b"import calc\n"
    b"assert calc.scale(3, 4) == 12\n"
    b"assert calc.scale(0, 9) == 0\n"
    b"assert calc.scale(-2, 6) == -12\n"
    b"print('acceptance-ok')\n"
)


class VerifiedEpisodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.repo = root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text(
            "def scale(a, b):\n    return a - b\n", encoding="utf-8"
        )
        (self.repo / "TASK.txt").write_text("scale(a, b) must return a * b\n")
        self.agent_executor = LocalSubprocessExecutor(root / "agent-exec", use_seatbelt=False)
        self.eval_executor = LocalSubprocessExecutor(root / "eval-exec", use_seatbelt=False)
        self.store = EpisodeStore(root / "evidence")
        self.anchor_dir = root / "anchor-custody"
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=root / "evaluator-keys",
            registry_dir=root / "evaluator-registry",
        )
        self.verifier.register_task(
            actor_role="evaluator",
            task_id="task-scale-001",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE},
        )
        self.task = TaskEnvelopeV1(
            schema_version=1,
            task_id="task-scale-001",
            repo_snapshot_digest="0" * 64,
            base_commit=None,
            task_statement_digest="1" * 64,
            permitted_commands=("run-tests",),
            isolation_profile="unverified_local",
            time_budget_seconds=300,
            token_budget=10_000,
            tool_budget=50,
            actor_id="agent-session-1",
            evaluator_task_ref="task-scale-001",
        )
        self._seq = 0
        self._prior = None
        self.episode = "episode-scale-1"

    def record(self, event_type, payload, *, actor="agent", artifacts=(), outputs=None):
        event = ObservationEventV1(
            schema_version=1,
            event_id=f"ev-{self.episode}-{self._seq}",
            episode_id=self.episode,
            attempt_id="attempt-1",
            seq=self._seq,
            event_type=event_type,
            timestamp="2026-10-23T12:00:00Z",
            actor=actor,
            inputs_digest=None,
            outputs_digest=outputs,
            artifact_refs=tuple(artifacts),
            prior_event_digest=self._prior,
            idempotency_key=f"key-{self.episode}-{self._seq}",
            payload_digest=canonical_digest("event_payload", 1, payload),
            payload=payload,
        )
        self.store.append_event(event)
        self._seq += 1
        self._prior = event.digest
        return event

    def run_episode(self, fix_source: bytes):
        workspace = self.agent_executor.prepare(self.repo)
        self.record("read", {"target": "calc.py"})
        patched = workspace.path / "calc.py"
        patched.write_bytes(fix_source)
        artifact = self.store.put_artifact(fix_source)
        self.record("edit", {"target": "calc.py", "mechanism": "overwrite"}, artifacts=(artifact,))
        check = self.agent_executor.run(
            workspace,
            CommandSpec(argv=(PY, "-c", "import calc; assert calc.scale(3,4)==12; print('visible-ok')")),
        )
        self.record(
            "test_result",
            {"execution_id": check.execution_id, "exit_status": check.exit_status,
             "trusted": False, "note": "agent-local observation only"},
            outputs=check.digest,
        )
        self.record("completion", {"claim": "fixed"})
        return workspace

    def test_full_pipeline_produces_verified_signed_outcome(self):
        workspace = self.run_episode(b"def scale(a, b):\n    return a * b\n")
        receipt = self.verifier.evaluate(
            actor_role="evaluator",
            task=self.task,
            submission_dir=workspace.path,
            evaluation_nonce="episode-1-attempt-1",
        )
        self.assertEqual(receipt.outcome, "pass")
        self.assertTrue(self.verifier.verify_receipt(receipt))
        public = self.verifier.public_key_record()
        self.assertTrue(verify_receipt_signature(receipt, public["public_key"]))

        report = self.store.verify_episode(self.episode)
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["events"], 4)
        anchor = self.store.anchor_head(self.episode, self.anchor_dir)
        self.assertEqual(anchor["head_digest"], report["head_digest"])

        # Receipt binds the evaluator-measured tree, not the agent's claim.
        from sis.v3.runner import tree_digest

        self.assertEqual(receipt.evaluated_repo_digest, tree_digest(workspace.path))
        self.agent_executor.destroy(workspace)

    def test_buggy_submission_is_signed_fail_not_silent_pass(self):
        workspace = self.run_episode(b"def scale(a, b):\n    return a - b\n")
        receipt = self.verifier.evaluate(
            actor_role="evaluator",
            task=self.task,
            submission_dir=workspace.path,
            evaluation_nonce="episode-bug-1",
        )
        self.assertEqual(receipt.outcome, "fail")
        self.assertTrue(self.verifier.verify_receipt(receipt))
        self.agent_executor.destroy(workspace)

    def test_agent_cannot_self_certify(self):
        workspace = self.run_episode(b"def scale(a, b):\n    return a * b\n")
        with self.assertRaises(AuthorizationDenied):
            self.verifier.evaluate(
                actor_role="agent",
                task=self.task,
                submission_dir=workspace.path,
                evaluation_nonce="nonce-x",
            )
        with self.assertRaisesRegex(EvaluationRejected, "unregistered_task"):
            unregistered = self.task.to_dict()
            unregistered["task_id"] = "task-unknown"
            unregistered["evaluator_task_ref"] = "task-unknown"
            self.verifier.evaluate(
                actor_role="evaluator",
                task=unregistered,
                submission_dir=workspace.path,
                evaluation_nonce="nonce-y",
            )
        self.agent_executor.destroy(workspace)

    def test_agent_reported_success_is_only_an_observation(self):
        """The agent claims success; the stored event is data, not a label."""
        workspace = self.run_episode(b"def scale(a, b):\n    return a * b\n")
        events = self.store.events(self.episode)
        completion = events[-1]
        self.assertEqual(completion.payload["claim"], "fixed")
        self.assertEqual(completion.actor, "agent")
        self.assertFalse(self.store.events(self.episode)[2].payload["trusted"])
        self.agent_executor.destroy(workspace)


if __name__ == "__main__":
    unittest.main()
