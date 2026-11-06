"""SIS3-007: procedure store integrity and deterministic mining."""
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sis.v3.contracts import ContractError, OutcomeReceiptV1, ProcedureRecordV1
from sis.v3.policy import AuthorizationDenied
from sis.v3.procedures import (
    MiningContext,
    ProcedureConflict,
    ProcedureStore,
    ProcedureStoreError,
    failure_signatures,
    mine_candidates,
)


def _record(status="candidate", revision=1, pid="proc-a", failures=("sig-x",)):
    return ProcedureRecordV1(
        schema_version=1,
        procedure_id=pid,
        revision=revision,
        intent="do the thing",
        language="python",
        frameworks=(),
        task_signatures=("sig-task",),
        failure_signatures=failures,
        preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(),
        steps=("step",),
        required_verification=("verify",),
        counterexample_refs=(),
        evidence_refs=("0" * 64,),
        outcome_distribution={"tasks": 1, "successes": 1, "failures": 0, "regressions": 0},
        status=status,
        expires_at=None,
    )


class ProcedureStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = ProcedureStore(Path(self.temp.name) / "catalog")

    def test_add_get_roundtrip(self):
        rec = _record()
        digest = self.store.add(rec)
        self.assertEqual(digest, rec.digest)
        self.assertEqual(self.store.get("proc-a"), rec)

    def test_idempotent_readd(self):
        rec = _record()
        self.assertEqual(self.store.add(rec), self.store.add(rec))

    def test_revision_conflict_rejected(self):
        self.store.add(_record())
        conflicting = replace(_record(), intent="different")
        with self.assertRaises(ProcedureConflict):
            self.store.add(conflicting)

    def test_successor_revision_requires_authority(self):
        """Revision >1 and decision-managed statuses are authority-only writes."""
        self.store.add(_record())
        nxt = replace(_record(), revision=2)  # still "candidate" status
        with self.assertRaisesRegex(ProcedureConflict, "seed_revision_must_be_one"):
            self.store.add(nxt)
        for status in ("evaluated", "qualified", "suspended", "retired"):
            with self.assertRaisesRegex(
                    ProcedureConflict, "status_write_requires_committed_decision"):
                self.store.add(replace(_record(pid="proc-x"), status=status))

    def test_persistence_and_verify(self):
        self.store.add(_record())
        self.store.add(_record(pid="proc-b", status="draft"))
        reloaded = ProcedureStore(self.store.root)
        self.assertEqual(reloaded.get("proc-a").status, "candidate")
        self.assertEqual(reloaded.get("proc-b").status, "draft")
        self.assertTrue(reloaded.verify()["ok"])
        self.assertEqual(
            self.store.catalog_digest(), reloaded.catalog_digest()
        )

    def test_tampered_log_detected(self):
        self.store.add(_record())
        log = Path(self.temp.name) / "catalog" / "procedures.jsonl"
        data = log.read_bytes()
        log.write_bytes(data.replace(b'"candidate"', b'"qualified"', 1))
        with self.assertRaises(ProcedureStoreError):
            ProcedureStore(self.store.root)

    def test_unknown_procedure(self):
        with self.assertRaises(ProcedureStoreError):
            self.store.get("nope")

    def test_catalog_digest_stable(self):
        a, b = _record(pid="proc-a"), _record(pid="proc-b")
        self.store.add(a)
        self.store.add(b)
        first = self.store.catalog_digest()
        fresh = ProcedureStore(Path(self.temp.name) / "c2")
        fresh.add(b)
        fresh.add(a)
        self.assertEqual(first, fresh.catalog_digest())


class MinerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # Real signed receipts from the actual verifier drive the miner.
        import sys
        from sis.v3.runner import LocalSubprocessExecutor
        from sis.v3.verifier import OutcomeVerifier

        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("def scale(a, b):\n    return a * b\n")
        self.eval_executor = LocalSubprocessExecutor(self.root / "eval", use_seatbelt=False)
        self.verifier = OutcomeVerifier(
            executor=self.eval_executor,
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry",
        )
        self.verifier.register_task(
            actor_role="evaluator",
            task_id="t1",
            criterion_version="v1",
            argv=(sys.executable, "acc.py"),
            files={"acc.py": b"import calc; assert calc.scale(3,4)==12\n"},
        )

    def _receipt(self, outcome_dir=None):
        from sis.v3.contracts import TaskEnvelopeV1
        from sis.v3.runner import tree_digest
        import secrets
        task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1",
        )
        return self.verifier.evaluate(
            actor_role="evaluator", task=task,
            submission_dir=outcome_dir or self.repo,
            evaluation_nonce="n-" + secrets.token_hex(6),
        )

    def _events(self):
        from sis.v3.contracts import ObservationEventV1, canonical_digest
        payload = {"summary": {"item_type": "command_execution", "exit_code": 1}}
        return [ObservationEventV1(
            schema_version=1, event_id="e1", episode_id="ep-1", attempt_id="a1",
            seq=0, event_type="tool_result", timestamp="2026-01-01T00:00:00Z",
            actor="agent", inputs_digest=None, outputs_digest=None,
            artifact_refs=(), prior_event_digest=None, idempotency_key="e1",
            payload_digest=canonical_digest("event_payload", 1, payload),
            payload=payload,
        )]

    def test_mine_pass_episode_yields_candidate(self):
        receipt = self._receipt()
        ctx = MiningContext(language="python", toolchain="cpython-3.12",
                            file_paths=("calc.py",))
        candidates = mine_candidates(
            actor_role="learner", episode_id="ep-1", events=self._events(),
            receipt=receipt, context=ctx,
        )
        self.assertEqual(len(candidates), 1)
        rec = candidates[0]
        self.assertEqual(rec.status, "candidate")
        self.assertIn(receipt.digest, rec.evidence_refs)
        self.assertIn("command_execution:exit_1", rec.failure_signatures)
        self.assertEqual(rec.outcome_distribution["successes"], 1)

    def test_mine_fail_episode_marks_counterexample(self):
        buggy = self.root / "buggy"
        buggy.mkdir()
        (buggy / "calc.py").write_text("def scale(a, b):\n    return a - b\n")
        receipt = self._receipt(buggy)
        self.assertEqual(receipt.outcome, "fail")
        ctx = MiningContext(language="python", toolchain="cpython-3.12")
        rec = mine_candidates(
            actor_role="learner", episode_id="ep-1", events=self._events(),
            receipt=receipt, context=ctx,
        )[0]
        self.assertIn(receipt.digest, rec.counterexample_refs)
        self.assertEqual(rec.outcome_distribution["failures"], 1)
        self.assertTrue(rec.contraindications)

    def test_mine_requires_learner_role(self):
        receipt = self._receipt()
        with self.assertRaises(AuthorizationDenied):
            mine_candidates(
                actor_role="agent", episode_id="ep-1", events=self._events(),
                receipt=receipt, context=MiningContext(language="python", toolchain=""),
            )

    def test_mine_rejects_empty_or_foreign_events(self):
        receipt = self._receipt()
        ctx = MiningContext(language="python", toolchain="")
        with self.assertRaises(ContractError):
            mine_candidates(actor_role="learner", episode_id="ep-1", events=[],
                            receipt=receipt, context=ctx)
        event = self._events()[0]
        with self.assertRaises(ContractError):
            mine_candidates(actor_role="learner", episode_id="other", events=[event],
                            receipt=receipt, context=ctx)

    def test_failure_signatures_extraction(self):
        sigs = failure_signatures(self._events())
        self.assertIn("command_execution:exit_1", sigs)


if __name__ == "__main__":
    unittest.main()
