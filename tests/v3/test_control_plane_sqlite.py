"""SQLite control-plane invariant coverage (default profile).

These tests port the control-plane invariants of
``test_control_plane_postgres.py`` to the default SQLite profile: one
database file, ``BEGIN IMMEDIATE`` write serialization standing in for
the PostgreSQL advisory lock, and two ``SqliteControlPlane`` instances
on the same file standing in for two replicas. Within a single host and
a single filesystem this is the production deployment shape, so the
serialization guarantees are exercised for real — the racing threads
contend on the actual file lock, not a stub.

Scope is deliberately narrow: this file is NOT PostgreSQL validation and
must never be reported as such. SQLite file locking cannot cover the
multi-host case — separate machines opening the same logical control
plane need a shared transactional store. A multi-host deployment must
still run ``test_control_plane_postgres.py`` against
``SIS_POSTGRES_DSN`` before claiming cross-replica replay protection.
"""
from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path

from sis.v3.control_plane import ControlPlaneError, SqliteControlPlane
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture


class SqliteControlPlaneInvariantTests(unittest.TestCase):
    """Single-file equivalents of the PostgreSQL replica invariants."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = Path(self._tmp.name) / "plane.db"
        self.plane = SqliteControlPlane(self.db_path)
        self.addCleanup(self.plane.close)

    def values(self, nonce="nonce-sqlite-1", digest="c" * 64):
        return dict(
            nonce=nonce, session_digest="b" * 64,
            expires_at="2030-01-01T00:00:00Z", task_id="task-sqlite",
            repository_id="repo-sqlite", guidance_digest=digest,
            decision="advisory", snapshot_digest="d" * 64)

    def _head_value(self, sequence, **overrides):
        value = {
            "sequence": sequence,
            "checkpoint_digest": "a" * 64,
            "journal_head": "b" * 64,
            "revocation_head": "0" * 64,
            "supersession_head": "0" * 64,
            "custody_entry_count": 0,
            "updated_at": "2026-10-27T00:00:00Z",
        }
        value.update(overrides)
        return value

    def test_sqlite_concurrent_replicas_produce_one_commit(self):
        # Port of PostgresControlPlaneTests
        # .test_concurrent_replicas_produce_one_commit: four instances on
        # one file race the same nonce; the UNIQUE constraint inside the
        # serialized write transaction must admit exactly one.
        results = []
        barrier = threading.Barrier(4)

        def race():
            plane = SqliteControlPlane(self.db_path)
            try:
                barrier.wait(timeout=10)
                results.append(
                    plane.commit_authorization(**self.values()))
            except ControlPlaneError as exc:
                results.append(exc.reason)
            except BaseException as exc:
                results.append(exc)
            finally:
                plane.close()

        threads = [threading.Thread(target=race) for _ in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        self.assertFalse(any(thread.is_alive() for thread in threads),
                         "a racing replica never finished")
        committed = [item for item in results if isinstance(item, dict)]
        rejected = [item for item in results
                    if item == "session_nonce_replayed"]
        self.assertEqual(len(committed), 1, results)
        self.assertEqual(len(rejected), 3, results)

    def test_sqlite_outcome_binds_to_receipt(self):
        # Port of .test_outcome_binds_to_receipt: one outcome row per
        # authorization; the second record attempt fails closed.
        receipt = self.plane.commit_authorization(**self.values())
        self.plane.record_outcome(
            authorization_id=receipt["authorization_id"],
            task_id="task-sqlite", served_digest="c" * 64,
            receipt_digest="e" * 64, outcome="pass")
        outcome = self.plane.outcome(receipt["authorization_id"])
        self.assertEqual(outcome["outcome"], "pass")
        with self.assertRaisesRegex(ControlPlaneError,
                                    "outcome_already_recorded"):
            self.plane.record_outcome(
                authorization_id=receipt["authorization_id"],
                task_id="task-sqlite", served_digest="c" * 64,
                receipt_digest="e" * 64, outcome="pass")

    def test_sqlite_two_replicas_share_one_serving_decision(self):
        # Port of .test_two_replicas_share_one_serving_decision: two
        # gateways backed by two plane instances on one file must not
        # both consume the session nonce.
        fixture = ProductionFixture(Path(self._tmp.name) / "fixture")
        self.addCleanup(fixture.close)
        latest = fixture.store.get_latest()
        head = {
            "sequence": latest.sequence,
            "checkpoint_digest": latest.digest,
            "journal_head": latest.journal_head,
            "revocation_head": latest.revocation_head,
            "supersession_head": latest.supersession_head,
            "custody_entry_count": latest.custody_entry_count,
            "updated_at": latest.issued_at,
        }
        shared_path = Path(self._tmp.name) / "shared-plane.db"
        first_plane = SqliteControlPlane(shared_path)
        second_plane = SqliteControlPlane(shared_path)
        self.addCleanup(first_plane.close)
        self.addCleanup(second_plane.close)
        first_plane.advance_authority_head(head)

        def gateway(plane):
            return GovernedServingGateway(
                fixture.registry,
                repository_registry=fixture.repo_registry,
                production=True,
                execution_identity_authority=fixture.identity_authority,
                control_plane=plane)

        identity = fixture.identity()
        first = gateway(first_plane).serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        second = gateway(second_plane).serve(
            _request(), repository_id="repo-1",
            execution_identity=identity)
        self.assertEqual(first.decision, "advisory")
        self.assertEqual(second.decision, "abstain")
        self.assertEqual(second.reason_code, "catalog_unavailable")

    def test_sqlite_authorization_rejects_head_revoked_before_commit(self):
        # Port of .test_authorization_rejects_head_revoked_before_commit:
        # a witnessed head superseded between serve and commit must
        # reject the authorization.
        seed = self._head_value(1)
        self.plane.advance_authority_head(seed)
        self.plane.advance_authority_head(
            self._head_value(2, checkpoint_digest="e" * 64))
        with self.assertRaisesRegex(ControlPlaneError,
                                    "authority_head_stale"):
            self.plane.commit_authorization(
                **self.values(nonce="nonce-sqlite-stale"),
                expected_head=seed)

    def test_sqlite_commit_serializes_against_head_advance(self):
        # Port of .test_commit_serializes_against_head_advance. SQLite
        # has no advisory lock; the equivalent guarantee is that BEGIN
        # IMMEDIATE holds the file write lock for the whole transaction,
        # so a concurrent head advance must block until the commit that
        # read the witnessed head finishes.
        seed = self._head_value(1)
        self.plane.advance_authority_head(seed)
        pause, resume = threading.Event(), threading.Event()
        # Both instances are created before the race: a SqliteControlPlane
        # constructor writes schema, so building one while the pausing
        # plane holds the write lock would block this thread and let the
        # pausing plane's resume timeout expire before the race starts.
        serving = _PausingSqlitePlane(self.db_path, pause, resume)
        revocation = SqliteControlPlane(self.db_path)
        self.addCleanup(serving.close)
        self.addCleanup(revocation.close)
        outcome = {}

        def commit():
            try:
                outcome["receipt"] = serving.commit_authorization(
                    **self.values(nonce="nonce-sqlite-race-commit"),
                    expected_head=seed)
            except BaseException as exc:
                outcome["error"] = exc

        advanced = threading.Event()

        def advance():
            try:
                revocation.advance_authority_head(
                    self._head_value(2, checkpoint_digest="e" * 64))
            except BaseException as exc:
                outcome["advance_error"] = exc
            else:
                advanced.set()

        thread = threading.Thread(target=commit)
        advancer = threading.Thread(target=advance)
        thread.start()
        try:
            self.assertTrue(pause.wait(10), "commit never read the head")
            advancer.start()
            self.assertFalse(
                advanced.wait(0.75),
                "a revocation published while an authorization held the "
                "write lock")
        finally:
            resume.set()
        thread.join(15)
        advancer.join(15)
        self.assertFalse(thread.is_alive(), "commit thread never finished")
        self.assertFalse(advancer.is_alive(),
                         "advance thread never finished")
        self.assertIn("receipt", outcome, outcome)
        self.assertEqual(
            self.plane.authority_head()["sequence"], 2)

    def test_sqlite_concurrent_head_advance_never_regresses(self):
        # Port of .test_concurrent_head_advance_never_regresses: the
        # check-then-upsert inside the serialized write transaction must
        # leave the head at the highest committed sequence even when a
        # lower advance stalls mid-transaction.
        seed = self._head_value(1)
        self.plane.advance_authority_head(seed)
        pause, resume = threading.Event(), threading.Event()
        # Same construction-order requirement as the commit race above.
        lower = _PausingSqlitePlane(self.db_path, pause, resume)
        higher = SqliteControlPlane(self.db_path)
        self.addCleanup(lower.close)
        self.addCleanup(higher.close)
        results = {}

        def advance_lower():
            try:
                lower.advance_authority_head(
                    self._head_value(2, checkpoint_digest="e" * 64))
                results["lower"] = "committed"
            except BaseException as exc:
                results["lower"] = exc

        higher_done = threading.Event()

        def advance_higher():
            try:
                higher.advance_authority_head(
                    self._head_value(3, checkpoint_digest="f" * 64))
                results["higher"] = "committed"
            except BaseException as exc:
                results["higher"] = exc
            else:
                higher_done.set()

        thread = threading.Thread(target=advance_lower)
        advancer = threading.Thread(target=advance_higher)
        thread.start()
        try:
            self.assertTrue(pause.wait(10),
                          "lower advance never read the head")
            advancer.start()
            self.assertFalse(
                higher_done.wait(0.75),
                "higher advance committed while a lower advance held "
                "the write lock")
        finally:
            resume.set()
        thread.join(15)
        advancer.join(15)
        self.assertFalse(thread.is_alive(),
                         "lower advance thread never finished")
        self.assertFalse(advancer.is_alive(),
                         "higher advance thread never finished")
        self.assertEqual(results.get("lower"), "committed", results)
        self.assertEqual(results.get("higher"), "committed", results)
        self.assertEqual(self.plane.authority_head()["sequence"], 3,
                         results)


class _PausingSqlitePlane(SqliteControlPlane):
    """Pauses after its first head read, still inside the write
    transaction, so tests can interleave a second instance's work."""

    def __init__(self, path, pause, resume):
        super().__init__(path)
        self._pause = pause
        self._resume = resume
        self._paused = False

    def _head(self, con):
        value = super()._head(con)
        if not self._paused:
            self._paused = True
            self._pause.set()
            self._resume.wait(10)
        return value


if __name__ == "__main__":
    unittest.main()
