"""PR-01: external authority checkpoints and rollback resistance.

These tests exercise the real publication protocol: a signed checkpoint
is written to independent file custody, serving compares the local
candidate database against it, and a database-only attacker (delete the
last revocation, restore an old file, flip a state column) is detected.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.candidates import (CandidateError, CandidatePublicationPending,
                               CandidateRegistry)
from sis.v3.checkpoints import (
    AuthorityJournal,
    AuthorityStateVerifier,
    CheckpointConflict,
    CheckpointUnavailable,
    CheckpointVerificationError,
    FileAuthorityCheckpointStore,
    GENESIS,
    RollbackDetected,
    sign_checkpoint,
    verify_checkpoint,
)
from sis.v3.contracts import GuidanceRequestV1
from sis.v3.control_plane import SqliteControlPlane
from sis.v3.serving import GovernedServingGateway
from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate

POLICY = "sis-v3.3.1-authority-policy"


def _request() -> GuidanceRequestV1:
    return GuidanceRequestV1(
        schema_version=1, task_id="task-1",
        repo_snapshot_digest="a" * 64, base_commit="abc1234",
        namespace="ns", language="python", toolchain="pytest",
        lockfile_digests={}, task_summary="do the thing",
        failure_signatures=(), present_symbols=(),
        semantic_contract_digest="c" * 64)


class _Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = CandidateStack(self.root / "candidates.db")
        self.addCleanup(self.stack.close)
        self.registry = self.stack.registry
        self.seed, public = signatures.generate_keypair()
        self.key_id = "authority-key-1"
        self.public_hex = public.hex()
        self.store = FileAuthorityCheckpointStore(
            self.root / "independent" / "checkpoints.jsonl",
            trusted_authority_keys={self.key_id: self.public_hex},
            candidate_database_path=self.root / "candidates.db")
        self.verifier = AuthorityStateVerifier(
            self.store,
            trusted_authority_keys={self.key_id: self.public_hex},
            expected_epoch=1, expected_policy_version=POLICY)
        self.registry.bind_checkpoint_verifier(
            self.verifier, production_serving=True)
        self.journal = AuthorityJournal(
            self.registry, self.store, signer_seed=self.seed,
            signer_key_id=self.key_id, issuer_identity="authority",
            authority_epoch=1, policy_version=POLICY)
        self.registry.bind_authority_journal(self.journal)
        self.journal.publish()

    def qualify(self, cid="cand-1", **kwargs):
        candidate = make_candidate(cid=cid, **kwargs)
        self.stack.prepare(candidate)
        self.stack.qualify(candidate)
        return candidate

    def _reopen(self):
        self.stack.close()
        self.stack = CandidateStack(self.root / "candidates.db")
        self.addCleanup(self.stack.close)
        self.registry = self.stack.registry
        self.registry.bind_checkpoint_verifier(
            self.verifier, production_serving=True)
        self.journal = AuthorityJournal(
            self.registry, self.store, signer_seed=self.seed,
            signer_key_id=self.key_id, issuer_identity="authority",
            authority_epoch=1, policy_version=POLICY)
        self.registry.bind_authority_journal(self.journal)
        return self.registry


class PublicationTests(_Fixture):
    def test_publish_anchors_and_verifies(self):
        candidate = self.qualify()
        state = self.registry.authority_state()
        self.assertGreater(state["sequence"], 0)
        self.assertEqual(state["qualified_count"], 1)
        result = self.verifier.verify_local_state(state)
        self.assertTrue(result.ok, result)
        self.assertEqual(result.reason, "ok")
        self.assertEqual(self.registry.state_of(candidate.candidate_id),
                         "qualified")

    def test_publish_is_idempotent(self):
        self.qualify()
        latest = self.store.get_latest()
        again = self.journal.publish()
        self.assertEqual(again.digest, latest.digest)
        self.assertEqual(len(self.store.history()), latest.sequence)

    def test_checkpoint_binds_candidate_revision(self):
        before = self.registry.authority_state()
        self.qualify()
        after = self.registry.authority_state()
        self.assertNotEqual(before["revision_digest"],
                            after["revision_digest"])
        latest = self.store.get_latest()
        self.assertEqual(latest.candidate_revision_digest,
                         after["revision_digest"])
        self.assertEqual(latest.journal_head, after["head"])
        self.assertEqual(latest.journal_sequence, after["sequence"])

    def test_checkpoint_chain_links_previous_digest(self):
        self.qualify("cand-1")
        self.qualify("cand-2")
        history = self.store.history()
        self.assertGreaterEqual(len(history), 3)
        previous = GENESIS
        for sequence, checkpoint in enumerate(history, start=1):
            self.assertEqual(checkpoint.sequence, sequence)
            self.assertEqual(checkpoint.previous_digest, previous)
            previous = checkpoint.digest

    def test_verify_reports_authority_block(self):
        self.qualify()
        report = self.registry.verify()
        self.assertTrue(report["ok"], report["problems"])
        self.assertEqual(report["authority"]["mode"], "checkpoint_verified")
        self.assertTrue(report["authority"]["ok"])

    def test_compare_and_append_rejects_stale_expectation(self):
        latest = self.store.get_latest()
        checkpoint = sign_checkpoint(
            self.seed, schema_version=1, checkpoint_id="cp-race",
            authority_epoch=1, sequence=latest.sequence + 1,
            journal_sequence=latest.journal_sequence,
            previous_digest=latest.digest, journal_head=latest.journal_head,
            candidate_revision_digest=latest.candidate_revision_digest,
            candidate_count=latest.candidate_count,
            qualified_count=latest.qualified_count,
            issuer_identity="authority", policy_version=POLICY,
            issued_at="2026-10-26T00:00:00Z",
            signer_key_id=self.key_id)
        with self.assertRaises(CheckpointConflict):
            self.store.compare_and_append(0, checkpoint)

    def test_compare_and_append_serialises_concurrent_publishers(self):
        latest = self.store.get_latest()
        results = []

        def append(index):
            checkpoint = sign_checkpoint(
                self.seed, schema_version=1,
                checkpoint_id=f"cp-thread-{index}", authority_epoch=1,
                sequence=latest.sequence + 1,
                journal_sequence=latest.journal_sequence,
                previous_digest=latest.digest,
                journal_head=latest.journal_head,
                candidate_revision_digest=latest.candidate_revision_digest,
                candidate_count=latest.candidate_count,
                qualified_count=latest.qualified_count,
                issuer_identity="authority", policy_version=POLICY,
                issued_at="2026-10-26T00:00:00Z",
                signer_key_id=self.key_id)
            try:
                self.store.compare_and_append(latest.sequence, checkpoint)
                results.append("ok")
            except CheckpointConflict:
                results.append("conflict")

        threads = [threading.Thread(target=append, args=(i,))
                   for i in range(2)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), ["conflict", "ok"])
        self.assertEqual(self.store.get_latest().sequence,
                         latest.sequence + 1)


class RollbackAttackTests(_Fixture):
    def _raw(self):
        return sqlite3.connect(str(self.root / "candidates.db"))

    def test_deleted_final_revocation_is_detected(self):
        candidate = self.qualify()
        self.stack.revoke(candidate)
        revoked_state = self.registry.authority_state()
        self.assertEqual(revoked_state["qualified_count"], 0)
        self.stack.close()

        con = self._raw()
        try:
            last = con.execute(
                "SELECT MAX(seq) FROM candidate_transition").fetchone()[0]
            con.execute("DELETE FROM candidate_transition WHERE seq=?", (last,))
            con.execute("UPDATE candidate SET state='qualified'"
                        " WHERE candidate_id=?", (candidate.candidate_id,))
            con.commit()
        finally:
            con.close()

        registry = self._reopen()
        with self.assertRaisesRegex(
                CandidateError, "authority_checkpoint_rejected"):
            registry.get(candidate.candidate_id)
        with self.assertRaisesRegex(
                CandidateError, "authority_checkpoint_rejected"):
            registry.qualified_bases()

    def test_stale_database_restoration_is_detected(self):
        candidate = self.qualify()
        self.stack.close()
        backup = self.root / "candidates.backup.db"
        backup.write_bytes((self.root / "candidates.db").read_bytes())
        # A WAL checkpoint is required for a byte-copy to be complete.
        self._reopen()
        self.stack.revoke(candidate)
        self.stack.close()
        (self.root / "candidates.db").write_bytes(backup.read_bytes())
        for suffix in ("-wal", "-shm"):
            path = Path(str(self.root / "candidates.db") + suffix)
            if path.exists():
                path.unlink()
        registry = self._reopen()
        with self.assertRaisesRegex(
                CandidateError, "authority_checkpoint_rejected"):
            registry.get(candidate.candidate_id)

    def test_qualified_state_column_flip_is_detected(self):
        candidate = make_candidate(cid="cand-flip")
        self.stack.registry.submit(candidate, actor_role="learner")
        self.stack.registry.transition(candidate.candidate_id, "validated",
                                       actor_role="learner")
        self.stack.registry.transition(candidate.candidate_id, "evaluating",
                                       actor_role="evaluator")
        self.stack.close()
        con = self._raw()
        try:
            con.execute("UPDATE candidate SET state='qualified'"
                        " WHERE candidate_id=?", (candidate.candidate_id,))
            con.commit()
        finally:
            con.close()
        registry = self._reopen()
        with self.assertRaisesRegex(CandidateError,
                                    "state_projection_drift"):
            registry.get(candidate.candidate_id)

    def test_reordered_audit_events_are_detected(self):
        self.qualify("cand-1")
        self.qualify("cand-2")
        self.stack.close()
        con = self._raw()
        try:
            rows = con.execute(
                "SELECT seq, entry_digest FROM candidate_transition"
                " ORDER BY seq").fetchall()
            first, second = rows[0], rows[1]
            con.execute("UPDATE candidate_transition SET entry_digest=?"
                        " WHERE seq=?", (second[1], first[0]))
            con.execute("UPDATE candidate_transition SET entry_digest=?"
                        " WHERE seq=?", (first[1], second[0]))
            con.commit()
        finally:
            con.close()
        registry = self._reopen()
        with self.assertRaisesRegex(CandidateError, "audit_chain_tampered"):
            registry.audit()

    def test_journal_head_substitution_is_rejected(self):
        self.qualify()
        local = self.registry.authority_state()
        latest = self.store.get_latest()
        forged = sign_checkpoint(
            self.seed, schema_version=1, checkpoint_id="cp-forged-head",
            authority_epoch=1, sequence=latest.sequence,
            journal_sequence=local["sequence"],
            previous_digest=latest.previous_digest,
            journal_head="f" * 64,
            candidate_revision_digest=local["revision_digest"],
            candidate_count=local["candidate_count"],
            qualified_count=local["qualified_count"],
            issuer_identity="authority", policy_version=POLICY,
            issued_at="2026-10-26T00:00:00Z",
            signer_key_id=self.key_id)
        result = self.verifier.verify_local_state(local, forged)
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "journal_head_mismatch")

    def test_checkpoint_signature_is_verified(self):
        self.qualify()
        latest = self.store.get_latest()
        forged = sign_checkpoint(
            self.seed, schema_version=1, checkpoint_id="cp-x",
            authority_epoch=1, sequence=latest.sequence,
            journal_sequence=latest.journal_sequence,
            previous_digest=latest.previous_digest,
            journal_head=latest.journal_head,
            candidate_revision_digest=latest.candidate_revision_digest,
            candidate_count=latest.candidate_count,
            qualified_count=latest.qualified_count,
            issuer_identity="authority", policy_version=POLICY,
            issued_at=latest.issued_at, signer_key_id=self.key_id)
        self.assertTrue(verify_checkpoint(forged, self.public_hex))
        bad = forged.to_dict()
        bad["signature"] = "0" * 128
        from sis.v3.contracts import AuthorityCheckpointV1
        result = self.verifier.verify_local_state(
            self.registry.authority_state(),
            AuthorityCheckpointV1.from_dict(bad))
        self.assertEqual(result.reason, "checkpoint_signature_invalid")

    def test_replayed_old_epoch_is_rejected(self):
        self.qualify()
        latest = self.store.get_latest()
        other = AuthorityStateVerifier(
            self.store,
            trusted_authority_keys={self.key_id: self.public_hex},
            expected_epoch=2, expected_policy_version=POLICY)
        result = other.verify_local_state(self.registry.authority_state())
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "authority_epoch_mismatch")
        self.assertEqual(latest.authority_epoch, 1)

    def test_tampered_checkpoint_log_fails_closed(self):
        self.qualify()
        path = self.store.path
        lines = path.read_text().splitlines()
        record = json.loads(lines[0])
        record["journal_head"] = "e" * 64
        lines[0] = json.dumps(record, sort_keys=True,
                              separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(CheckpointVerificationError):
            self.store.get_latest()
        result = self.verifier.verify_local_state(
            self.registry.authority_state())
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "checkpoint_unavailable")

    def test_checkpoint_store_must_not_be_the_candidate_database(self):
        with self.assertRaises(CheckpointVerificationError):
            FileAuthorityCheckpointStore(
                self.root / "candidates.db",
                trusted_authority_keys={self.key_id: self.public_hex},
                candidate_database_path=self.root / "candidates.db")


class ServingFailClosedTests(_Fixture):
    def test_production_without_checkpoint_refuses_qualified_reads(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stack = CandidateStack(Path(temp.name) / "c.db")
        self.addCleanup(stack.close)
        candidate = make_candidate(cid="cand-unchecked")
        stack.prepare(candidate)
        stack.qualify(candidate)
        stack.registry._production_serving = True
        with self.assertRaisesRegex(
                CandidateError, "authority_checkpoint_unconfigured"):
            stack.registry.get(candidate.candidate_id)

    def test_production_gateway_abstains_after_rollback(self):
        candidate = self.qualify()
        self.stack.revoke(candidate)
        self.stack.close()
        con = sqlite3.connect(str(self.root / "candidates.db"))
        try:
            last = con.execute(
                "SELECT MAX(seq) FROM candidate_transition").fetchone()[0]
            con.execute("DELETE FROM candidate_transition WHERE seq=?", (last,))
            con.execute("UPDATE candidate SET state='qualified'"
                        " WHERE candidate_id=?", (candidate.candidate_id,))
            con.commit()
        finally:
            con.close()
        registry = self._reopen()
        control = SqliteControlPlane(self.root / "control.db")
        self.addCleanup(control.close)
        gateway = GovernedServingGateway(
            registry, repository_registry=None, production=True,
            control_plane=control)
        guidance = gateway.serve(_request(), repository_id="repo-1")
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")
        # The only text is a non-actionable diagnostic; no candidate
        # instruction survived the failed authority check.
        self.assertEqual(len(guidance.helpful_next_checks), 1)
        self.assertIn("integrity could not be verified",
                      guidance.helpful_next_checks[0])

    def test_serving_still_works_when_checkpoint_matches(self):
        candidate = self.qualify()
        self.stack.revoke(candidate)
        registry = self.registry
        # A revoked candidate is not qualified, but the authority gate
        # must still verify the catalog rather than fail on the
        # revocation itself.
        self.assertEqual(registry.authority_status()["mode"],
                         "checkpoint_verified")
        self.assertEqual(registry.qualified(), [])


class _FailingStore:
    """Wraps a real store and refuses one compare-and-append."""

    def __init__(self, inner):
        self.inner = inner
        self.fail = True

    def get_latest(self):
        return self.inner.get_latest()

    def compare_and_append(self, expected_sequence, checkpoint):
        if self.fail:
            raise CheckpointUnavailable("simulated_outage")
        return self.inner.compare_and_append(expected_sequence, checkpoint)


class InterruptedPublicationTests(_Fixture):
    def test_committed_write_without_checkpoint_denies_serving(self):
        failing = _FailingStore(self.store)
        journal = AuthorityJournal(
            self.registry, failing, signer_seed=self.seed,
            signer_key_id=self.key_id, issuer_identity="authority",
            authority_epoch=1, policy_version=POLICY)
        self.registry.bind_authority_journal(journal)
        candidate = make_candidate(cid="cand-pending")
        with self.assertRaises(CandidatePublicationPending) as caught:
            self.registry.submit(candidate, actor_role="learner")
        self.assertTrue(caught.exception.committed)
        # The row is durable, but it is ahead of the last checkpoint.
        self.assertIsNotNone(
            self.registry.lookup(candidate.candidate_id))
        result = self.verifier.verify_local_state(
            self.registry.authority_state())
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "local_state_unpublished")
        # Recovery republishes the committed state.
        failing.fail = False
        self.registry.bind_authority_journal(self.journal)
        checkpoint = self.registry.publish_pending()
        self.assertEqual(checkpoint.journal_sequence,
                         self.registry.authority_state()["sequence"])
        self.assertTrue(self.verifier.verify_local_state(
            self.registry.authority_state()).ok)

    def test_recover_repairs_interrupted_publication(self):
        failing = _FailingStore(self.store)
        journal = AuthorityJournal(
            self.registry, failing, signer_seed=self.seed,
            signer_key_id=self.key_id, issuer_identity="authority",
            authority_epoch=1, policy_version=POLICY)
        self.registry.bind_authority_journal(journal)
        candidate = make_candidate(cid="cand-recover")
        with self.assertRaises(CandidatePublicationPending):
            self.registry.submit(candidate, actor_role="learner")
        failing.fail = False
        report = journal.recover()
        self.assertEqual(report["action"], "published")
        self.assertTrue(self.verifier.verify_local_state(
            self.registry.authority_state()).ok)

    def test_recover_reports_rollback_without_republishing(self):
        candidate = self.qualify()
        self.stack.revoke(candidate)
        self.stack.close()
        con = sqlite3.connect(str(self.root / "candidates.db"))
        try:
            last = con.execute(
                "SELECT MAX(seq) FROM candidate_transition").fetchone()[0]
            con.execute("DELETE FROM candidate_transition WHERE seq=?", (last,))
            con.execute("UPDATE candidate SET state='qualified'"
                        " WHERE candidate_id=?", (candidate.candidate_id,))
            con.commit()
        finally:
            con.close()
        registry = self._reopen()
        report = self.journal.recover()
        self.assertEqual(report["action"], "rollback_detected")
        with self.assertRaises(RollbackDetected):
            self.journal.publish()

    def test_missing_checkpoint_service_is_not_trusted(self):
        missing = FileAuthorityCheckpointStore(
            self.root / "missing" / "checkpoints.jsonl",
            trusted_authority_keys={self.key_id: self.public_hex})
        verifier = AuthorityStateVerifier(
            missing, trusted_authority_keys={self.key_id: self.public_hex},
            expected_epoch=1, expected_policy_version=POLICY)
        result = verifier.verify_local_state(
            self.registry.authority_state())
        self.assertFalse(result.ok)
        self.assertEqual(result.reason, "checkpoint_missing")


if __name__ == "__main__":
    unittest.main()
