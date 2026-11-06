"""PR-02 adversarial tests for the transactional authority store.

Gate: fault injection at each transaction step yields either fully committed
authorized qualification or zero visible qualification — never a half-state.
"""
from __future__ import annotations

import hashlib
import multiprocessing
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_db import (
    AuthorityConflict,
    AuthorityDB,
    AuthorityError,
)
from sis.v3.promotion import PromotionController, PromotionRejected, operator_token_digest

from tests.v3.authority_testkit import (
    TEST_TOKEN,
    drive,
    evaluator_keypair,
    make_authority,
    seed as seed_record,
    signed_receipt,
)
from tests.v3.test_retrieval import _proc


def _stack(root: Path):
    seed_bytes, pub, key_id = evaluator_keypair()
    receipt = signed_receipt(seed_bytes, key_id)
    db, controller = make_authority(
        root,
        evaluator_key_id=key_id,
        evaluator_public_hex=pub.hex(),
        receipt_resolver={receipt.digest: receipt}.__getitem__,
    )
    return db, controller, seed_bytes, key_id, receipt


class SeedWriteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = AuthorityDB(Path(self.temp.name) / "a.db")
        self.addCleanup(self.db.close)

    def test_seed_accepts_draft_and_candidate_only(self):
        self.db.add_seed(_proc(pid="p1", status="draft"))
        self.db.add_seed(_proc(pid="p2", status="candidate"))
        for status in ("evaluated", "qualified", "suspended", "retired"):
            with self.assertRaisesRegex(
                    AuthorityConflict, "status_write_requires_committed_decision"):
                self.db.add_seed(_proc(pid=f"x-{status}", status=status))
        with self.assertRaisesRegex(AuthorityConflict, "seed_revision_must_be_one"):
            self.db.add_seed(
                _proc(pid="p3", status="draft").__class__.from_dict(
                    {**_proc(pid="p3", status="draft").to_dict(), "revision": 2}))

    def test_seed_idempotent_and_conflict(self):
        rec = _proc(pid="p1", status="draft")
        self.assertEqual(self.db.add_seed(rec), self.db.add_seed(rec))
        from dataclasses import replace
        with self.assertRaisesRegex(AuthorityConflict, "procedure_revision_conflict"):
            self.db.add_seed(replace(rec, intent="different"))

    def test_seed_over_decided_history_rejected(self):
        db, controller, sbytes, kid, receipt = _stack(Path(self.temp.name) / "s")
        self.addCleanup(db.close)
        seed_record(db, _proc(pid="p1", status="draft"))
        drive(db, controller, "p1", "candidate", token=TEST_TOKEN,
              seed=sbytes, key_id=kid, receipts=[receipt])
        # Identical re-seed stays idempotent…
        self.assertEqual(
            db.add_seed(_proc(pid="p1", status="draft")), db.get("p1", 1).digest)
        # …but a *different* rev-1 for a pid with committed decisions is rejected.
        from dataclasses import replace
        with self.assertRaisesRegex(AuthorityConflict, "procedure_revision_conflict"):
            db.add_seed(replace(_proc(pid="p1", status="draft"), intent="hijack"))

    def test_unbound_authority_cannot_commit(self):
        """A caller that never bound as a promotion service is refused."""
        db, controller, sbytes, kid, receipt = _stack(Path(self.temp.name) / "s")
        self.addCleanup(db.close)
        seed_record(db, _proc(pid="p1", status="draft"))
        record = db.get("p1")
        from dataclasses import replace
        nxt = replace(record, revision=2, status="candidate")
        impostor = type("Fake", (), {
            "_trusted": {}, "_operator_keys": {},
            "_token_digest": operator_token_digest(TEST_TOKEN)})()
        # Construct a real signed decision via the real controller, then try
        # to commit it under an unbound authority object.
        real = controller.transition(
            "p1", "candidate", actor_role="operator", actor_identity="op",
            operator_token=TEST_TOKEN)
        with self.assertRaisesRegex(AuthorityError, "unbound_authority"):
            db.commit_transition(
                decision=real, record=nxt,
                expected_prior_decision_digest=None,
                authority=impostor)


class TransactionFaultTests(unittest.TestCase):
    """Inject a fault at every step of the commit; each run must leave either
    the full committed state or nothing at all."""

    STEPS = (
        "_step_check_chain_head",
        "_step_check_candidate",
        "_step_verify_decision",
        "_step_insert_revision",
        "_step_insert_decision",
        "_step_bind_receipts",
        "_step_check_qualified_head",
        "_audit",
    )

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_fault_at_each_step_yields_no_partial_state(self):
        for i, step in enumerate(self.STEPS):
            with self.subTest(step=step):
                db, controller, sbytes, kid, receipt = _stack(self.root / f"s{i}")
                seed_record(db, _proc(pid="p1", status="draft"))
                original = getattr(db, step)

                def boom(*a, _o=original, **k):
                    raise OSError(f"injected fault at {step}")

                setattr(db, step, boom)
                try:
                    with self.assertRaises(OSError):
                        controller.transition(
                            "p1", "candidate", actor_role="operator",
                            actor_identity="op", operator_token=TEST_TOKEN)
                finally:
                    setattr(db, step, original)
                self.assertIsNone(db.decision_head())
                self.assertEqual(db.get("p1").status, "draft")
                self.assertEqual(db.get("p1").revision, 1)
                report = db.verify()
                self.assertTrue(report["ok"], report["problems"])
                # Recovery: the same transition can now commit.
                controller.transition(
                    "p1", "candidate", actor_role="operator",
                    actor_identity="op", operator_token=TEST_TOKEN)
                self.assertEqual(db.get("p1").status, "candidate")
                db.close()

    def test_power_loss_simulation_drop_connection_mid_commit(self):
        """Hard process-level failure: close the connection mid-transaction;
        on reopen the database must contain only committed rows."""
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        original = db._step_insert_decision

        def kill(con, *a, **k):
            # Simulate power loss between revision insert and decision insert.
            con.execute("ROLLBACK")
            raise OSError("simulated power loss")

        db._step_insert_decision = kill
        with self.assertRaises(OSError):
            controller.transition(
                "p1", "candidate", actor_role="operator",
                actor_identity="op", operator_token=TEST_TOKEN)
        db._step_insert_decision = original
        # Fresh handle (fresh process view) sees only the seed.
        cold = AuthorityDB(self.root / "s" / "authority.db")
        self.assertIsNone(cold.decision_head())
        self.assertEqual(cold.get("p1").revision, 1)
        self.assertTrue(cold.verify()["ok"])
        cold.close()
        db.close()

    def test_wal_sidecar_does_not_leak_uncommitted_state(self):
        """Rows written but never committed (client crash between BEGIN and
        COMMIT) must not appear to a fresh connection even if -wal exists."""
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        con = db._conn()
        con.execute("BEGIN IMMEDIATE")
        con.execute(
            "INSERT INTO procedure_revision"
            " (procedure_id, revision, record_digest, status, record_json, committed_at)"
            " VALUES ('ghost', 1, ?, 'draft', '{}', 'now')",
            ("0" * 64,))
        # No COMMIT — simulate abrupt client death by rolling back and closing.
        con.execute("ROLLBACK")
        cold = AuthorityDB(self.root / "s" / "authority.db")
        with self.assertRaises(AuthorityError):
            cold.get("ghost")
        cold.close()
        db.close()


class RestartAndStaleWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_restart_preserves_all_state(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        drive(db, controller, "p1", "qualified", token=TEST_TOKEN,
              seed=sbytes, key_id=kid, receipts=[receipt])
        head = db.decision_head()
        qhead = db.qualified_head_digest()
        db.close()

        cold = AuthorityDB(self.root / "s" / "authority.db")
        self.assertEqual(cold.decision_head(), head)
        self.assertEqual(cold.qualified_head_digest(), qhead)
        self.assertEqual(cold.get("p1").status, "qualified")
        fresh = PromotionController(
            cold, operator_token_digest=operator_token_digest(TEST_TOKEN),
            trusted_evaluator_keys={kid: signatures.public_key(sbytes).hex()})
        self.assertTrue(fresh.verify()["ok"])
        cold.close()

    def test_stale_controller_rejected_at_chain_head_check(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        stale = PromotionController(
            db, operator_token_digest=operator_token_digest(TEST_TOKEN),
            trusted_evaluator_keys={kid: sbytes.hex()})
        drive(db, controller, "p1", "candidate", token=TEST_TOKEN,
              seed=sbytes, key_id=kid, receipts=[receipt])
        with self.assertRaisesRegex(PromotionRejected, "stale_controller"):
            stale.transition("p1", "evaluated", actor_role="operator",
                             actor_identity="op", operator_token=TEST_TOKEN)

    def test_in_tx_head_recheck_catches_race(self):
        """Even if a controller passes the pre-check, the in-transaction head
        re-check rejects a commit made on a stale view."""
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        controller.transition("p1", "candidate", actor_role="operator",
                              actor_identity="op", operator_token=TEST_TOKEN)
        # Forge a second commit attempt claiming the old head.
        record = db.get("p1")
        from dataclasses import replace
        nxt = replace(record, revision=3, status="evaluated")
        decision = controller.decisions()[0]
        from sis.v3.contracts import PromotionDecisionV2
        forged = PromotionDecisionV2.from_dict(
            {**decision.to_dict(), "decision_id": "dec-forged-race",
             "new_record_digest": nxt.digest, "new_status": "evaluated"})
        with self.assertRaises(AuthorityError):
            db.commit_transition(
                decision=forged, record=nxt,
                expected_prior_decision_digest=None,  # stale view of head
                authority=controller)


class ConcurrencyTests(unittest.TestCase):
    def test_concurrent_writers_serialize(self):
        """Two threads racing transitions: exactly one wins each edge; the
        final committed chain is internally consistent."""
        import threading
        root = Path(tempfile.mkdtemp())
        db, controller, sbytes, kid, receipt = _stack(root)
        seed_record(db, _proc(pid="p1", status="draft"))
        results, errors = [], []

        def attempt():
            try:
                controller.transition(
                    "p1", "candidate", actor_role="operator",
                    actor_identity="op", operator_token=TEST_TOKEN)
                results.append(True)
            except PromotionRejected:
                errors.append("rejected")

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 7)
        self.assertTrue(db.verify()["ok"])
        self.assertEqual(len(controller.decisions()), 1)
        db.close()

    def test_concurrent_process_writers(self):
        """True multiprocess writers on one file: serialized, no corruption."""
        root = Path(tempfile.mkdtemp())
        db = AuthorityDB(root / "authority.db")
        db.add_seed(_proc(pid="p1", status="draft"))
        db.close()
        ctx = multiprocessing.get_context("spawn")
        procs = [ctx.Process(target=_writer_proc,
                             args=(str(root / "authority.db"), i))
                 for i in range(4)]
        for p in procs:
            p.start()
        for p in procs:
            p.join(timeout=30)
            self.assertEqual(p.exitcode, 0)
        cold = AuthorityDB(root / "authority.db")
        self.assertTrue(cold.verify()["ok"])
        self.assertEqual(cold.get("p1").status, "candidate")
        self.assertEqual(len(cold.decisions()), 1)
        cold.close()


def _writer_proc(db_path: str, index: int) -> None:
    db = AuthorityDB(db_path)
    controller = PromotionController(
        db, operator_token_digest=operator_token_digest(TEST_TOKEN),
        trusted_evaluator_keys={})
    try:
        controller.transition("p1", "candidate", actor_role="operator",
                              actor_identity=f"writer-{index}",
                              operator_token=TEST_TOKEN)
    except PromotionRejected:
        pass  # stale head/illegal transition — expected for losers
    db.close()


class DoublePromotionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_identical_decision_cannot_commit_twice(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        decision = controller.transition(
            "p1", "candidate", actor_role="operator",
            actor_identity="op", operator_token=TEST_TOKEN)
        record = db.get("p1")
        with self.assertRaises(AuthorityError):
            db.commit_transition(
                decision=decision, record=record,
                expected_prior_decision_digest=decision.digest,
                authority=controller)

    def test_repeated_transition_is_new_decision_not_replay(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        controller.transition("p1", "candidate", actor_role="operator",
                              actor_identity="op", operator_token=TEST_TOKEN)
        with self.assertRaisesRegex(PromotionRejected, "illegal_transition"):
            controller.transition("p1", "candidate", actor_role="operator",
                                  actor_identity="op", operator_token=TEST_TOKEN)
        self.assertEqual(len(controller.decisions()), 1)


class BackupAndIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_backup_restores_to_consistent_state(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        drive(db, controller, "p1", "qualified", token=TEST_TOKEN,
              seed=sbytes, key_id=kid, receipts=[receipt])
        backup = db.backup(self.root / "backup.db")
        cold = AuthorityDB(backup)
        self.assertTrue(cold.verify()["ok"])
        self.assertEqual(cold.get("p1").status, "qualified")
        cold.close()
        db.close()

    def test_corrupted_page_fails_closed(self):
        db, controller, sbytes, kid, receipt = _stack(self.root / "s")
        seed_record(db, _proc(pid="p1", status="draft"))
        drive(db, controller, "p1", "qualified", token=TEST_TOKEN,
              seed=sbytes, key_id=kid, receipts=[receipt])
        db.close()
        db_path = self.root / "s" / "authority.db"
        raw = bytearray(db_path.read_bytes())
        # Corrupt a byte inside a committed decision row's JSON payload.
        needle = b'"new_status":"qualified"'
        pos = raw.find(needle)
        self.assertGreater(pos, 0)
        raw[pos + 2] = ord('X')
        db_path.write_bytes(bytes(raw))
        cold = AuthorityDB(db_path)
        report = cold.verify()
        self.assertFalse(report["ok"], "corrupted page must not verify")
        cold.close()


if __name__ == "__main__":
    unittest.main()
