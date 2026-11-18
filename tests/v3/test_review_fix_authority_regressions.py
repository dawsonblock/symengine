"""Regressions for the serving/authority review findings.

Each class names the finding it pins down. The production stack is the
same ``ProductionFixture`` the v3.3.2 security suite uses.
"""
from __future__ import annotations

import http.client
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis.server import create_server
from sis.v3 import nonce_store, signatures
from sis.v3.bootstrap import BootstrapError, build_v3_runtime, build_v3_service
from sis.v3.checkpoints import RollbackDetected
from sis.v3.control_plane import (SCHEMA_VERSION, ControlPlaneError,
                                  PostgresControlPlane, SqliteControlPlane)
from sis.v3.evidence_custody import EvidenceCustodyError, EvidenceCustodyStore
from sis.v3.promotion import PromotionRejected
from sis.v3.serving import GovernedServingGateway
from tests.v3.authority_testkit import TEST_TOKEN, drive
from tests.v3.authority_testkit import seed as seed_record
from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_authority_db import _stack as _authority_stack
from tests.v3.test_execution_identity_custody import ProductionFixture
from tests.v3.test_retrieval import _proc
from tests.v3.test_v332_security_regressions import _grant_writeback

TOKEN = "v3-serving-token-for-review-fix-tests-0001"


class _Production(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(_grant_writeback, self.temp.name)
        self.root = Path(self.temp.name)
        self.fx = ProductionFixture(self.root / "stack")
        self.addCleanup(self.fx.close)

    def gateway(self, **kwargs):
        return GovernedServingGateway(
            self.fx.registry, repository_registry=self.fx.repo_registry,
            production=True,
            execution_identity_authority=self.fx.identity_authority,
            control_plane=self.fx.control_plane, **kwargs)

    def serve(self, nonce, gateway=None):
        return (gateway or self.gateway()).serve(
            _request(), repository_id="repo-1",
            execution_identity=self.fx.identity(session_nonce=nonce))

    def revoke(self, digest, kind):
        return self.fx.custody.revoke(
            digest, kind=kind, reason="review regression",
            seed=self.fx.custody_seed, key_id=self.fx.custody_key)


# ---------------------------------------------------------------------- #
# Finding 1: custody revocation of candidate/decision digest at serve time
# ---------------------------------------------------------------------- #
class CustodyCandidateRevocationTests(_Production):
    def _basis(self):
        (cand, basis), = self.fx.registry.qualified_bases()
        return cand, basis

    def test_baseline_serves_advisory(self):
        self.assertEqual(self.serve("n-base").decision, "advisory")

    def test_custody_revocation_of_candidate_and_decision_suppresses(self):
        # The original repro: neither digest is reached by the
        # certificate dependency walk, and the client sends no
        # revoked_digests. Serving must still suppress the candidate.
        cand, basis = self._basis()
        self.revoke(cand.digest, "candidate")
        self.revoke(basis["decision_digest"], "evidence")
        self.fx.publish()
        self.assertEqual(
            self.fx.custody.status(self.fx.certificate.digest), "active")
        guidance = self.serve("n-both")
        self.assertNotEqual(guidance.decision, "advisory")
        self.assertNotIn("do the thing",
                         " ".join(guidance.helpful_next_checks))

    def test_candidate_digest_revocation_alone_is_audited(self):
        cand, _ = self._basis()
        self.revoke(cand.digest, "candidate")
        self.fx.publish()
        audit = []
        guidance = self.serve("n-cand", self.gateway(audit_sink=audit.append))
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(audit[-1]["rejections"],
                         [{"candidate_id": cand.candidate_id,
                           "reason": "revoked"}])

    def test_decision_digest_revocation_alone_is_audited(self):
        cand, basis = self._basis()
        self.revoke(basis["decision_digest"], "evidence")
        self.fx.publish()
        audit = []
        guidance = self.serve("n-dec", self.gateway(audit_sink=audit.append))
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(audit[-1]["rejections"][0]["reason"],
                         "evidence_revoked")

    def test_supersession_of_candidate_digest_suppresses(self):
        cand, _ = self._basis()
        self.fx.custody.supersede(
            cand.digest, "f" * 64, reason="replaced",
            seed=self.fx.custody_seed, key_id=self.fx.custody_key)
        self.fx.publish()
        self.assertEqual(self.serve("n-sup").decision, "abstain")

    def test_client_supplied_set_is_still_honoured(self):
        cand, _ = self._basis()
        guidance = self.gateway().serve(
            _request(), repository_id="repo-1",
            revoked_digests=frozenset({cand.digest}),
            execution_identity=self.fx.identity(session_nonce="n-client"))
        self.assertEqual(guidance.decision, "abstain")


# ---------------------------------------------------------------------- #
# Finding 2: AuthorityDB reads must not observe uncommitted revisions
# ---------------------------------------------------------------------- #
class AuthorityDBReadIsolationTests(unittest.TestCase):
    def test_read_during_rolled_back_commit_sees_committed_state(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db, controller, sbytes, kid, receipt = _authority_stack(
            Path(temp.name) / "s")
        self.addCleanup(db.close)
        seed_record(db, _proc(pid="p1", status="draft"))
        inserted = threading.Event()
        release = threading.Event()
        original = db._step_insert_decision

        def stall_then_fail(con, *args, **kwargs):
            # The revision row is already inserted on the shared
            # connection; hold the transaction open, then roll back.
            inserted.set()
            release.wait(10)
            raise OSError("injected failure after revision insert")

        db._step_insert_decision = stall_then_fail
        self.addCleanup(setattr, db, "_step_insert_decision", original)
        writer_error = []

        def writer():
            try:
                controller.transition(
                    "p1", "candidate", actor_role="operator",
                    actor_identity="op", operator_token=TEST_TOKEN)
            except Exception as exc:  # noqa: BLE001
                writer_error.append(exc)

        seen = []
        writer_thread = threading.Thread(target=writer)
        writer_thread.start()
        self.assertTrue(inserted.wait(10))
        reader = threading.Thread(target=lambda: seen.append(
            (db.get("p1").revision, len(db.decisions()),
             db.qualified_head_digest())))
        reader.start()
        time.sleep(0.2)  # an unlocked read would complete here
        release.set()
        writer_thread.join(10)
        reader.join(10)
        self.assertTrue(writer_error)
        self.assertEqual(seen[0][0], 1)
        self.assertEqual(seen[0][1], 0)
        self.assertEqual(db.get("p1").revision, 1)


# ---------------------------------------------------------------------- #
# Finding 3: custody logs must extend the checkpointed heads
# ---------------------------------------------------------------------- #
class CustodyExtensionTests(_Production):
    def test_truncated_revocation_log_padded_with_supersessions(self):
        self.revoke("1" * 64, "receipt")
        self.revoke("2" * 64, "receipt")
        checkpoint = self.fx.publish()
        self.assertEqual(checkpoint.custody_entry_count, 2)
        path = self.fx.custody.root / "revocations.jsonl"
        lines = path.read_bytes().splitlines(keepends=True)
        path.write_bytes(lines[0])
        # A second writer (fresh process) restores the combined count
        # with supersessions; only per-log extension can tell.
        other = EvidenceCustodyStore(
            self.fx.custody.root,
            trusted_revocation_keys=dict(self.fx.custody._keys))
        for target in ("3" * 64, "4" * 64):
            other.supersede(target, "5" * 64, reason="pad",
                            seed=self.fx.custody_seed,
                            key_id=self.fx.custody_key)
        self.assertEqual(
            self.fx.custody.authority_snapshot()["custody_entry_count"], 3)
        with self.assertRaisesRegex(RollbackDetected,
                                    "revocation_history_not_extended"):
            self.fx.publish()
        self.assertEqual(self.fx.store.get_latest().digest,
                         checkpoint.digest)

    def test_honest_extension_publishes(self):
        self.revoke("1" * 64, "receipt")
        first = self.fx.publish()
        self.fx.custody.supersede(
            "3" * 64, "5" * 64, reason="ok", seed=self.fx.custody_seed,
            key_id=self.fx.custody_key)
        self.revoke("2" * 64, "receipt")
        second = self.fx.publish()
        self.assertEqual(second.custody_entry_count, 3)
        self.assertGreater(second.sequence, first.sequence)
        self.assertEqual(
            self.fx.registry.verify_custody_extends(
                revocation_head=first.revocation_head,
                supersession_head=first.supersession_head,
                custody_entry_count=first.custody_entry_count),
            {"revocation_count": 1, "supersession_count": 0})

    def test_append_onto_truncated_log_is_refused(self):
        self.revoke("1" * 64, "receipt")
        self.revoke("2" * 64, "receipt")
        path = self.fx.custody.root / "revocations.jsonl"
        path.write_bytes(path.read_bytes().splitlines(keepends=True)[0])
        with self.assertRaisesRegex(EvidenceCustodyError,
                                    "revocation_log_truncated"):
            self.revoke("6" * 64, "receipt")


# ---------------------------------------------------------------------- #
# Finding 4: one withdrawn candidate must not take down the catalog
# ---------------------------------------------------------------------- #
class PerCandidateExclusionTests(unittest.TestCase):
    def test_expired_candidate_is_excluded_individually(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stack = CandidateStack(Path(temp.name) / "c.db")
        self.addCleanup(stack.close)
        healthy = make_candidate(cid="healthy")
        stack.prepare(healthy)
        stack.qualify(healthy)
        expiring = make_candidate(cid="expiring")
        stack.prepare(expiring)
        receipt = stack.receipt(task_id="task-exp")
        stack.evidence_authority._fixed_now = "2020-01-01T00:00:00Z"
        evidence = stack.evidence_authority.issue(
            seed=stack.eval_seed, candidate=expiring,
            receipt_refs=[receipt.digest],
            evaluation_protocol_digest=stack.protocol, partition="holdout",
            signer_key_id=stack.eval_key, expires_at="2020-01-02T00:00:00Z")
        decision = stack.decision(
            expiring, "evaluating", "qualified",
            receipt_refs=(receipt.digest,), evidence_refs=(evidence.digest,))
        stack.registry.qualify(
            expiring.candidate_id, actor_role="operator",
            actor_identity="test-operator", receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        self.assertEqual(len(stack.registry.qualified()), 2)
        stack.evidence_authority._fixed_now = "2020-01-03T00:00:00Z"
        rejections = []
        bases = stack.registry.qualified_bases(rejections)
        self.assertEqual([c.candidate_id for c, _ in bases], ["healthy"])
        self.assertEqual(rejections[0]["candidate_id"], "expiring")
        self.assertIn("evidence_expired", rejections[0]["reason"])

    def test_tampered_row_still_fails_whole_catalog(self):
        from sis.v3.candidates import CandidateError
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        stack = CandidateStack(Path(temp.name) / "c.db")
        self.addCleanup(stack.close)
        cand = make_candidate(cid="flip")
        stack.registry.submit(cand, actor_role="learner")
        stack.registry._conn().execute(
            "UPDATE candidate SET state='qualified' WHERE candidate_id=?",
            (cand.candidate_id,))
        with self.assertRaisesRegex(CandidateError, "state_projection_drift"):
            stack.registry.qualified_bases([])


# ---------------------------------------------------------------------- #
# Finding 5: one evaluator receipt backs at most one outcome
# ---------------------------------------------------------------------- #
def _commit(plane, nonce, digest="c" * 64):
    return plane.commit_authorization(
        nonce=nonce, session_digest="b" * 64,
        expires_at="2030-01-01T00:00:00Z", task_id="task-1",
        repository_id="repo-1", guidance_digest=digest,
        decision="advisory", snapshot_digest="d" * 64)


class _FakePsycopg:
    """psycopg stand-in backed by SQLite, to exercise the Postgres SQL."""

    def __init__(self, path):
        self.path = str(path)

    def connect(self, dsn, connect_timeout=10):
        return _FakePgConnection(self.path)


class _FakePgConnection:
    def __init__(self, path):
        self._con = sqlite3.connect(path, isolation_level=None, timeout=15)
        self._con.execute("BEGIN IMMEDIATE")

    def execute(self, sql, params=()):
        if "pg_advisory_xact_lock" in sql:
            return self._con.execute("SELECT ?", params)
        return self._con.execute(sql.replace("%s", "?"), params)

    def commit(self):
        self._con.execute("COMMIT")

    def rollback(self):
        self._con.execute("ROLLBACK")

    def close(self):
        self._con.close()


def _fake_postgres(path):
    plane = PostgresControlPlane.__new__(PostgresControlPlane)
    with mock.patch.dict("sys.modules", {"psycopg": _FakePsycopg(path)}):
        PostgresControlPlane.__init__(plane, "postgresql://fake")
    return plane


class OutcomeReceiptUniquenessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _planes(self):
        sqlite_plane = SqliteControlPlane(self.root / "plane.db")
        self.addCleanup(sqlite_plane.close)
        return {"sqlite": sqlite_plane,
                "postgres": _fake_postgres(self.root / "pg.db")}

    def test_receipt_cannot_back_two_authorizations(self):
        for name, plane in self._planes().items():
            with self.subTest(profile=name):
                first = _commit(plane, f"{name}-n1")
                second = _commit(plane, f"{name}-n2")
                plane.record_outcome(
                    authorization_id=first["authorization_id"],
                    task_id="task-1", served_digest="c" * 64,
                    receipt_digest="e" * 64, outcome="pass")
                with self.assertRaisesRegex(ControlPlaneError,
                                            "outcome_receipt_reused"):
                    plane.record_outcome(
                        authorization_id=second["authorization_id"],
                        task_id="task-1", served_digest="c" * 64,
                        receipt_digest="e" * 64, outcome="pass")
                with self.assertRaisesRegex(ControlPlaneError,
                                            "outcome_already_recorded"):
                    plane.record_outcome(
                        authorization_id=first["authorization_id"],
                        task_id="task-1", served_digest="c" * 64,
                        receipt_digest="f" * 64, outcome="pass")
                self.assertIsNone(plane.outcome(second["authorization_id"]))
                self.assertEqual(plane.schema_version(), SCHEMA_VERSION)

    def test_v2_database_upgrades_with_unique_index(self):
        path = self.root / "v2.db"
        SqliteControlPlane(path).close()
        con = sqlite3.connect(str(path))
        con.execute("DROP INDEX guidance_outcome_receipt_digest")
        con.execute("UPDATE schema_meta SET version=2")
        con.commit()
        con.close()
        plane = SqliteControlPlane(path)
        self.addCleanup(plane.close)
        self.assertEqual(plane.schema_version(), SCHEMA_VERSION)
        indexes = {row[1] for row in plane._con.execute(
            "PRAGMA index_list(guidance_outcome)")}
        self.assertIn("guidance_outcome_receipt_digest", indexes)

    def test_v2_database_with_reused_receipts_fails_closed(self):
        path = self.root / "dup.db"
        SqliteControlPlane(path).close()
        con = sqlite3.connect(str(path))
        con.execute("DROP INDEX guidance_outcome_receipt_digest")
        con.execute("UPDATE schema_meta SET version=2")
        for auth in ("a1", "a2"):
            con.execute(
                "INSERT INTO guidance_outcome VALUES (?,?,?,?,?,?)",
                (auth, "task-1", "c" * 64, "e" * 64, "pass", "now"))
        con.commit()
        con.close()
        with self.assertRaisesRegex(ControlPlaneError,
                                    "control_plane_outcome_receipt_reused"):
            SqliteControlPlane(path)

    def test_gateway_without_control_plane_refuses_reuse(self):
        stack_temp = tempfile.TemporaryDirectory()
        self.addCleanup(stack_temp.cleanup)
        stack = CandidateStack(Path(stack_temp.name) / "c.db")
        self.addCleanup(stack.close)
        gateway = GovernedServingGateway(
            stack.registry, repository_registry=None,
            receipt_authority=lambda digest: SimpleNamespace(
                task_id="task-1", outcome="pass"))
        gateway._served["task-1"] = "c" * 64
        gateway._served["task-2"] = "c" * 64
        gateway.record_outcome(task_id="task-1", served_digest="c" * 64,
                               receipt_digest="e" * 64, outcome="pass")
        gateway._receipt_authority = lambda digest: SimpleNamespace(
            task_id="task-2", outcome="pass")
        with self.assertRaisesRegex(ValueError, "outcome_receipt_reused"):
            gateway.record_outcome(task_id="task-2", served_digest="c" * 64,
                                   receipt_digest="e" * 64, outcome="pass")


# ---------------------------------------------------------------------- #
# Finding 6: token-mode operator authorization is per-decision verifiable
# ---------------------------------------------------------------------- #
class OperatorTokenMacTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        (self.db, self.controller, self.sbytes, self.kid,
         self.receipt) = _authority_stack(Path(temp.name) / "s")
        self.addCleanup(self.db.close)
        seed_record(self.db, _proc(pid="p1", status="draft"))

    def test_token_authorization_is_a_per_decision_mac(self):
        drive(self.db, self.controller, "p1", "evaluated", token=TEST_TOKEN,
              seed=self.sbytes, key_id=self.kid, receipts=[self.receipt])
        auths = [d.operator_authorization for d in self.db.decisions()]
        self.assertEqual(len(auths), 2)
        self.assertTrue(all(a.startswith("operator_token_hmac:")
                            for a in auths))
        self.assertNotEqual(auths[0], auths[1])
        self.assertTrue(self.controller.verify()["ok"])
        self.assertTrue(
            self.controller.verify(operator_token=TEST_TOKEN)["ok"])
        report = self.controller.verify(
            operator_token="a-different-operator-token-0000")
        self.assertFalse(report["ok"])
        self.assertTrue(any("operator_token_mac_invalid" in p
                            for p in report["problems"]))

    def test_live_commit_refuses_legacy_constant(self):
        legacy = "operator_token_sha256:" + self.controller._token_digest
        with mock.patch.object(type(self.controller), "_authorize_operator",
                               return_value=legacy):
            with self.assertRaisesRegex(
                    PromotionRejected, "operator_authorization_legacy_token"):
                self.controller.transition(
                    "p1", "candidate", actor_role="operator",
                    actor_identity="op", operator_token=TEST_TOKEN)

    def test_legacy_rows_still_replay(self):
        from sis.v3.promotion import verify_decision_v2
        drive(self.db, self.controller, "p1", "candidate", token=TEST_TOKEN,
              seed=self.sbytes, key_id=self.kid, receipts=[self.receipt])
        decision = self.db.decisions()[0]
        legacy = decision.__class__.from_dict({
            **decision.to_dict(),
            "operator_authorization":
                "operator_token_sha256:" + self.controller._token_digest})
        self.assertEqual(verify_decision_v2(
            legacy, {}, set(), trusted={}, operator_keys={},
            token_digest=self.controller._token_digest), [])
        self.assertIn("operator_authorization_legacy_token",
                      verify_decision_v2(
                          legacy, {}, set(), trusted={}, operator_keys={},
                          token_digest=self.controller._token_digest,
                          allow_legacy_token=False))


# ---------------------------------------------------------------------- #
# Finding 7: schema-version race and leaked nonce-store connections
# ---------------------------------------------------------------------- #
class SchemaRaceAndConnectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_losing_schema_insert_race_is_tolerated(self):
        plane = SqliteControlPlane(self.root / "race.db")
        self.addCleanup(plane.close)

        class LateReader:
            """First version read misses the row another replica wrote."""

            def __init__(self, con):
                self.con = con
                self.misses = 1

            def execute(self, sql, params=()):
                if sql.startswith("SELECT version") and self.misses:
                    self.misses -= 1
                    return SimpleNamespace(fetchone=lambda: None)
                return self.con.execute(sql, params)

        with plane._transaction() as con:
            plane._ensure_schema_version(LateReader(con))
        self.assertEqual(plane.schema_version(), SCHEMA_VERSION)

    def test_nonce_store_closes_every_connection(self):
        opened = []
        real_connect = sqlite3.connect

        def tracking(*args, **kwargs):
            con = real_connect(*args, **kwargs)
            opened.append(con)
            return con

        envelope = SimpleNamespace(signer_key_id="k", nonce="n",
                                   digest="d" * 64)
        with mock.patch.object(nonce_store.sqlite3, "connect", tracking), \
                mock.patch.object(nonce_store, "verify_envelope",
                                  return_value=True):
            store = nonce_store.OutcomeNonceStore(self.root / "n.db")
            store.verify_and_consume(envelope, registry=None)
            with self.assertRaises(nonce_store.NonceAlreadyConsumed):
                store.verify_and_consume(envelope, registry=None)
        self.assertEqual(len(opened), 3)
        for con in opened:
            with self.assertRaises(sqlite3.ProgrammingError):
                con.execute("SELECT 1")


# ---------------------------------------------------------------------- #
# Finding 8: production composition root and `sis serve --v3-config`
# ---------------------------------------------------------------------- #
class BootstrapTests(_Production):
    def config(self) -> Path:
        fx = self.fx
        stack = fx.cert.stack
        cert = fx.cert
        root = self.root / "deploy"
        root.mkdir()
        fx.repo_registry.dump(root / "repos.jsonl")
        (root / "api-keys.json").write_text(json.dumps({TOKEN: "agent-1"}))
        pub = lambda seed: signatures.public_key(seed).hex()  # noqa: E731
        config = {
            "candidate_database": str(stack.registry.path),
            "custody_root": str(fx.custody.root),
            "custody_revocation_keys": dict(fx.custody._keys),
            "checkpoint_store": str(fx.store.path),
            "authority_keys": {fx.authority_key: pub(fx.authority_seed)},
            "authority_epoch": 1,
            "authority_policy_version": "sis-v3.3.1-authority-policy",
            "control_plane": str(fx.control_plane.path),
            "repository_registry": "repos.jsonl",
            "repository_registry_public_key": pub(fx.repo_seed),
            "execution_identity_keys": {fx.identity_key: pub(fx.identity_seed)},
            "evaluator_keys": {stack.eval_key: stack.eval_public_hex},
            "operator_keys": {stack.op_key: pub(stack.op_seed)},
            "certificate_keys": {cert.cert_key: pub(cert.cert_seed)},
            "delivery_keys": {cert.harness_key: pub(cert.harness_seed)},
            "evaluation_protocol": cert.protocol,
            "qualification_policy": cert.policy.to_dict(),
            "api_keys_file": "api-keys.json",
        }
        path = root / "v3.json"
        path.write_text(json.dumps(config))
        return path

    def payload(self, nonce):
        return {"request": _request().to_dict(), "repository_id": "repo-1",
                "execution_identity":
                    self.fx.identity(session_nonce=nonce).to_dict()}

    def post(self, port, body):
        raw = json.dumps(body).encode()
        con = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        try:
            con.request("POST", "/v3/guidance", body=raw, headers={
                "Authorization": f"Bearer {TOKEN}",
                "Content-Type": "application/json",
                "Content-Length": str(len(raw))})
            response = con.getresponse()
            return response.status, json.loads(response.read())
        finally:
            con.close()

    def test_composed_service_serves_over_http_and_honours_custody(self):
        service = build_v3_service(self.config())
        self.addCleanup(service.gateway._candidates.close)
        self.addCleanup(service.gateway.control_plane.close)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SIS_V3_ONLY", None)
            httpd = create_server("127.0.0.1", 0,
                                  db_path=str(self.root / "legacy.db"),
                                  v3_service=service)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        status, body = self.post(port, self.payload("boot-1"))
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "advisory")
        self.assertIsNotNone(body["authorization"])
        # A custody revocation of the candidate digest, published by the
        # authority process, is honoured by the composed replica.
        (cand, _), = self.fx.registry.qualified_bases()
        self.revoke(cand.digest, "candidate")
        self.fx.publish()
        status, body = self.post(port, self.payload("boot-2"))
        self.assertEqual(status, 200)
        self.assertEqual(body["decision"], "abstain")

    def test_missing_requirement_fails_closed(self):
        config = json.loads(self.config().read_text())
        del config["custody_revocation_keys"]
        with self.assertRaisesRegex(BootstrapError,
                                    "v3_config_missing:custody_revocation_keys"):
            build_v3_runtime(config, base_dir=self.root / "deploy")

    def test_unanchored_authority_refuses_to_start(self):
        path = self.config()
        config = json.loads(path.read_text())
        config["authority_epoch"] = 2
        with self.assertRaisesRegex(BootstrapError, "v3_authority_not_ready"):
            build_v3_runtime(config, base_dir=path.parent)

    def test_cli_serve_rejects_bad_v3_config(self):
        from sis.cli import main
        bad = self.root / "bad.json"
        bad.write_text(json.dumps({"candidate_database": "x"}))
        with mock.patch("sis.cli.serve") as serve:
            code = main(["--db", str(self.root / "legacy.db"), "serve",
                         "--v3-config", str(bad)])
        self.assertEqual(code, 2)
        serve.assert_not_called()

    def test_cli_serve_passes_composed_service(self):
        from sis.cli import main
        path = self.config()
        with mock.patch("sis.cli.serve") as serve:
            code = main(["--db", str(self.root / "legacy.db"), "serve",
                         "--port", "0", "--v3-config", str(path)])
        self.assertEqual(code, 0)
        service = serve.call_args.kwargs["v3_service"]
        self.addCleanup(service.gateway._candidates.close)
        self.addCleanup(service.gateway.control_plane.close)
        self.assertTrue(service.health()["checks"]["authority"]["ok"])


if __name__ == "__main__":
    unittest.main()
