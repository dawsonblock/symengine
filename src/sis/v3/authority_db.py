"""Transactional authority datastore (v3.1-alpha, PR-02).

``AuthorityDB`` is the single durable home for procedure revisions and the
signed decisions that produce them. It replaces the legacy two-file JSONL
write-ahead pattern with one SQLite database (WAL mode, ``synchronous=FULL``)
so a decision and its materialized revision become visible atomically —
committed together or not at all (invariant I-2).

Write paths:

- ``add_seed(record)`` — intake for new ``draft``/``candidate`` records at
  revision 1 only. Seed writes can never mint decision-managed state
  (``evaluated``/``qualified``/``suspended``/``retired``).
- ``commit_transition(...)`` — the promotion service's only write. Inside one
  ``BEGIN IMMEDIATE`` transaction it re-checks the chain head, re-verifies the
  decision's signatures and transition legality against replayed state,
  enforces the decision-to-record digest binding, inserts the revision, the
  decision, receipt bindings and an audit row, then verifies the resulting
  qualified head against the signed expectation before ``COMMIT``.
- ``_import_committed_decision(...)`` — migration-only importer used by
  ``tools/migrate_authority.py``; records provenance ``migrated`` in the audit
  trail and applies the same binding rules.

A Python object graph is not a security boundary: the ``authority`` argument
must be a ``PromotionController`` that bound itself via ``_bind_authority``,
but the real isolation is the deployment boundary — candidate writers run in
a different process/service identity that cannot reach this object. All read
methods see only committed state; verification is fail-closed on corrupt
pages, broken hash links, unauthorized revisions or projection drift.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
import threading
import weakref
from datetime import datetime, timezone
from pathlib import Path

from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ProcedureRecordV1,
    PromotionDecisionV1,
    PromotionDecisionV2,
    RevocationV1,
    ScopeGrantV1,
    canonical_digest,
    loads_json,
)

_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEED_STATUSES = frozenset({"draft", "candidate"})
_DECISION_STATUSES = frozenset({"evaluated", "qualified", "suspended", "retired"})
_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS procedure_revision (
    procedure_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    record_json TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    PRIMARY KEY (procedure_id, revision)
);
CREATE TABLE IF NOT EXISTS signed_promotion_decision (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    decision_id TEXT NOT NULL UNIQUE,
    decision_digest TEXT NOT NULL UNIQUE,
    decision_json TEXT NOT NULL,
    prior_decision_digest TEXT,
    candidate_digest TEXT NOT NULL,
    new_record_digest TEXT REFERENCES procedure_revision(record_digest),
    prior_status TEXT NOT NULL,
    new_status TEXT NOT NULL,
    provenance TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipt_binding (
    decision_id TEXT NOT NULL REFERENCES signed_promotion_decision(decision_id),
    receipt_digest TEXT NOT NULL,
    task_id TEXT,
    evaluated_repo_digest TEXT,
    PRIMARY KEY (decision_id, receipt_digest)
);
CREATE TABLE IF NOT EXISTS scope_grant (
    grant_id TEXT PRIMARY KEY,
    grant_digest TEXT NOT NULL UNIQUE,
    grant_json TEXT NOT NULL,
    procedure_revision_digest TEXT NOT NULL
        REFERENCES procedure_revision(record_digest),
    source_registry_id TEXT NOT NULL,
    source_family_id TEXT NOT NULL,
    target_registry_id TEXT,
    target_family_id TEXT,
    signer_key_id TEXT NOT NULL,
    expires_at TEXT,
    committed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS grant_receipt_binding (
    grant_id TEXT NOT NULL REFERENCES scope_grant(grant_id),
    receipt_digest TEXT NOT NULL,
    task_id TEXT,
    evaluated_repo_digest TEXT,
    receipt_json TEXT NOT NULL,
    PRIMARY KEY (grant_id, receipt_digest)
);
CREATE TABLE IF NOT EXISTS revocation (
    digest TEXT NOT NULL,
    kind TEXT NOT NULL,
    reason TEXT,
    actor_identity TEXT,
    revocation_json TEXT NOT NULL DEFAULT '',
    committed_at TEXT NOT NULL,
    PRIMARY KEY (digest, kind)
);
CREATE TABLE IF NOT EXISTS nonce_consumption (
    signer TEXT NOT NULL,
    nonce TEXT NOT NULL,
    digest TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    PRIMARY KEY (signer, nonce)
);
CREATE TABLE IF NOT EXISTS audit_event (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantined_revision (
    quarantine_id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    record_json TEXT NOT NULL,
    quarantined_at TEXT NOT NULL
);
"""


class AuthorityError(RuntimeError):
    """The authority datastore cannot complete an operation."""


class AuthorityConflict(AuthorityError):
    """A write conflicts with already-committed authorized state."""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _check_digest(value, name):
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")


class AuthorityDB:
    """Single-writer transactional store for authorized procedure state."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._authorities: "weakref.WeakSet" = weakref.WeakSet()
        try:
            self._con = sqlite3.connect(
                str(self.path), isolation_level=None, timeout=15.0,
                check_same_thread=False,
            )
            con = self._con
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA busy_timeout=15000")
            con.executescript(_SCHEMA)
            con.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at, description)"
                " VALUES (?, ?, ?)",
                (_SCHEMA_VERSION, _utcnow(), "authority_db initial schema"),
            )
        except sqlite3.Error as exc:
            raise AuthorityError(f"authority_db_open_failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    # lifecycle
    # ------------------------------------------------------------------ #
    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                try:
                    self._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                self._con.close()
                self._con = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _conn(self) -> sqlite3.Connection:
        if self._con is None:
            raise AuthorityError("authority_db_closed")
        return self._con

    def backup(self, target: str | Path) -> Path:
        """Online consistent backup via the SQLite backup API."""
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, sqlite3.connect(str(target)) as dest:
            self._conn().backup(dest)
        return target

    # ------------------------------------------------------------------ #
    # authority binding
    # ------------------------------------------------------------------ #
    def _bind_authority(self, controller) -> None:
        """Register a promotion service allowed to call ``commit_transition``.

        In-process hygiene only: the real isolation boundary is that candidate
        writers run under a different process/service identity that never
        receives this object (see docs/v3/V2_BASELINE.md, invariant I-1).
        """
        self._authorities.add(controller)

    def _require_authority(self, authority) -> None:
        if authority not in self._authorities:
            raise AuthorityError("unbound_authority: caller is not a bound promotion service")

    # ------------------------------------------------------------------ #
    # intake (restricted repository interface — seed writes only)
    # ------------------------------------------------------------------ #
    def add_seed(self, record: ProcedureRecordV1) -> str:
        """Persist a new draft/candidate revision-1 record; idempotent on identical."""
        if not isinstance(record, ProcedureRecordV1):
            record = ProcedureRecordV1.from_dict(record)
        if record.status not in _SEED_STATUSES:
            raise AuthorityConflict(
                "status_write_requires_committed_decision",
            )
        if record.revision != 1:
            raise AuthorityConflict("seed_revision_must_be_one")
        with self._lock:
            con = self._conn()
            row = con.execute(
                "SELECT record_digest FROM procedure_revision"
                " WHERE procedure_id=? AND revision=?",
                (record.procedure_id, record.revision),
            ).fetchone()
            if row is not None:
                if row[0] == record.digest:
                    return record.digest
                raise AuthorityConflict("procedure_revision_conflict")
            if con.execute(
                "SELECT 1 FROM procedure_revision WHERE procedure_id=?",
                (record.procedure_id,),
            ).fetchone() is not None:
                raise AuthorityConflict("seed_after_decisions")
            con.execute("BEGIN IMMEDIATE")
            try:
                con.execute(
                    "INSERT INTO procedure_revision"
                    " (procedure_id, revision, record_digest, status, record_json, committed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (record.procedure_id, record.revision, record.digest,
                     record.status, record.canonical_bytes().decode("utf-8"), _utcnow()),
                )
                self._audit(con, "seed_committed", {
                    "procedure_id": record.procedure_id,
                    "record_digest": record.digest,
                })
                con.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise AuthorityConflict(f"seed_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise
            return record.digest

    # ------------------------------------------------------------------ #
    # committed decision writes (authority service only)
    # ------------------------------------------------------------------ #
    def commit_transition(
        self,
        *,
        decision: PromotionDecisionV2,
        record: ProcedureRecordV1,
        expected_prior_decision_digest: str | None,
        expected_new_qualified_head: str | None = None,
        receipts=(),
        authority=None,
        provenance: str = "live",
    ) -> None:
        """Atomically commit a verified decision and its materialized revision.

        Either every row lands or none do. ``expected_prior_decision_digest``
        is checked *inside* the write transaction so a stale writer can never
        interleave. The decision is re-verified (signatures, transition
        legality, head arithmetic) against replayed committed state; a forged
        or tampered decision object cannot pass this gate even if it was never
        seen by the controller.
        """
        self._require_authority(authority)
        if not isinstance(decision, PromotionDecisionV2):
            raise AuthorityError("committed decision must be a PromotionDecisionV2")
        if not isinstance(record, ProcedureRecordV1):
            record = ProcedureRecordV1.from_dict(record)
        if decision.new_record_digest != record.digest:
            raise AuthorityConflict("decision_record_digest_mismatch")
        if decision.new_status != record.status:
            raise AuthorityConflict("decision_record_status_mismatch")

        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                self._step_check_chain_head(con, expected_prior_decision_digest)
                self._step_check_candidate(con, decision, record)
                existing = con.execute(
                    "SELECT 1 FROM signed_promotion_decision WHERE decision_digest=?",
                    (decision.digest,),
                ).fetchone()
                if existing is not None:
                    con.execute("ROLLBACK")
                    raise AuthorityConflict("decision_already_committed")
                self._step_verify_decision(con, decision, authority)
                self._step_insert_revision(con, record)
                self._step_insert_decision(con, decision, expected_prior_decision_digest, provenance)
                self._step_bind_receipts(con, decision, receipts)
                self._step_check_qualified_head(con, decision, expected_new_qualified_head)
                self._audit(con, "decision_committed", {
                    "decision_id": decision.decision_id,
                    "decision_digest": decision.digest,
                    "new_status": decision.new_status,
                    "new_record_digest": decision.new_record_digest,
                    "provenance": provenance,
                })
                con.execute("COMMIT")
            except AuthorityError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise AuthorityConflict(f"commit_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise

    # ---- transaction steps; each is individually fault-injectable ---- #
    def _step_check_chain_head(self, con, expected_prior) -> None:
        row = con.execute(
            "SELECT decision_digest FROM signed_promotion_decision ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        disk_head = row[0] if row else None
        if disk_head != expected_prior:
            raise AuthorityConflict(
                f"stale_decision_head: expected {expected_prior}, disk has {disk_head}"
            )

    def _step_check_candidate(self, con, decision, record) -> None:
        row = con.execute(
            "SELECT record_digest, status, revision FROM procedure_revision"
            " WHERE procedure_id=? ORDER BY revision DESC LIMIT 1",
            (record.procedure_id,),
        ).fetchone()
        if row is None:
            raise AuthorityConflict("candidate_missing")
        digest, status, revision = row
        if digest != decision.candidate_digest:
            raise AuthorityConflict("candidate_digest_mismatch")
        if status != decision.prior_status:
            raise AuthorityConflict("prior_status_mismatch")
        if revision + 1 != record.revision:
            raise AuthorityConflict("revision_not_successor")

    def _step_verify_decision(self, con, decision, authority) -> None:
        """Re-verify signatures and transition legality against committed state."""
        from .promotion import verify_decision_v2  # deferred: promotion imports this module

        statuses, qualified = self._replayed_state(con)
        problems = verify_decision_v2(
            decision,
            statuses,
            qualified,
            trusted=authority._trusted,
            operator_keys=authority._operator_keys,
            token_digest=authority._token_digest,
        )
        if problems:
            raise AuthorityConflict(
                "decision_rejected: " + ",".join(problems[:5])
            )

    def _step_insert_revision(self, con, record) -> None:
        con.execute(
            "INSERT INTO procedure_revision"
            " (procedure_id, revision, record_digest, status, record_json, committed_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (record.procedure_id, record.revision, record.digest,
             record.status, record.canonical_bytes().decode("utf-8"), _utcnow()),
        )

    def _step_insert_decision(self, con, decision, prior_digest, provenance) -> None:
        con.execute(
            "INSERT INTO signed_promotion_decision"
            " (decision_id, decision_digest, decision_json, prior_decision_digest,"
            "  candidate_digest, new_record_digest, prior_status, new_status,"
            "  provenance, committed_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (decision.decision_id, decision.digest,
             decision.canonical_bytes().decode("utf-8"), prior_digest,
             decision.candidate_digest, decision.new_record_digest,
             decision.prior_status, decision.new_status, provenance, _utcnow()),
        )

    def _step_bind_receipts(self, con, decision, receipts) -> None:
        for receipt in receipts:
            if receipt.digest not in set(decision.receipt_refs):
                raise AuthorityConflict("receipt_not_bound_by_decision")
            con.execute(
                "INSERT INTO receipt_binding"
                " (decision_id, receipt_digest, task_id, evaluated_repo_digest)"
                " VALUES (?, ?, ?, ?)",
                (decision.decision_id, receipt.digest,
                 receipt.task_id, receipt.evaluated_repo_digest),
            )

    def _step_check_qualified_head(self, con, decision, expected_new_head) -> None:
        actual = self._qualified_head(con)
        if decision.new_qualified_head is not None and decision.new_qualified_head != actual:
            raise AuthorityConflict(
                "qualified_head_divergence: declared head does not match committed state"
            )
        if expected_new_head is not None and expected_new_head != actual:
            raise AuthorityConflict(
                "qualified_head_divergence: expected head does not match committed state"
            )

    def _audit(self, con, event_type: str, payload: dict) -> None:
        con.execute(
            "INSERT INTO audit_event (event_type, payload_json, committed_at) VALUES (?, ?, ?)",
            (event_type, _canonical(payload), _utcnow()),
        )

    # ------------------------------------------------------------------ #
    # nonce admission (atomic once-only consumption)
    # ------------------------------------------------------------------ #
    def try_consume_nonce(self, signer: str, nonce: str, digest: str) -> None:
        """Atomically record one-time receipt admission; raises on replay."""
        _check_digest(digest, "digest")
        with self._lock:
            try:
                self._conn().execute(
                    "INSERT INTO nonce_consumption (signer, nonce, digest, consumed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (signer, nonce, digest, _utcnow()),
                )
            except sqlite3.IntegrityError as exc:
                raise AuthorityConflict("nonce_replayed") from exc

    # ------------------------------------------------------------------ #
    # migration import (tools/migrate_authority.py only)
    # ------------------------------------------------------------------ #
    def _import_committed_decision(
        self, *, decision, record, expected_prior_decision_digest, receipts=(),
        authority, source="legacy-jsonl",
    ) -> None:
        """Import an already-signed legacy decision + its materialized record.

        Used only by the migration tool inside its reconciliation pass; the
        same binding and head rules apply. ``record`` may be ``None`` for V1
        legacy decisions which carry no bound revision.
        """
        self._require_authority(authority)
        if not isinstance(decision, (PromotionDecisionV1, PromotionDecisionV2)):
            raise AuthorityError("decision must be a PromotionDecision record")
        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                self._step_check_chain_head(con, expected_prior_decision_digest)
                if record is not None:
                    self._step_check_candidate(con, decision, record)
                if isinstance(decision, PromotionDecisionV2):
                    self._step_verify_decision(con, decision, authority)
                    if record is None:
                        raise AuthorityConflict("v2_decision_without_record")
                if record is not None:
                    existing = con.execute(
                        "SELECT 1 FROM procedure_revision WHERE record_digest=?",
                        (record.digest,),
                    ).fetchone()
                    if existing is None:
                        self._step_insert_revision(con, record)
                con.execute(
                    "INSERT INTO signed_promotion_decision"
                    " (decision_id, decision_digest, decision_json, prior_decision_digest,"
                    "  candidate_digest, new_record_digest, prior_status, new_status,"
                    "  provenance, committed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (decision.decision_id, decision.digest,
                     canonical_json_bytes(decision), expected_prior_decision_digest,
                     decision.candidate_digest,
                     getattr(decision, "new_record_digest", None),
                     decision.prior_status, decision.new_status,
                     f"migrated:{source}", _utcnow()),
                )
                self._step_bind_receipts(con, decision, receipts)
                if isinstance(decision, PromotionDecisionV2):
                    self._step_check_qualified_head(con, decision, None)
                self._audit(con, "decision_migrated", {
                    "decision_id": decision.decision_id,
                    "decision_digest": decision.digest,
                    "source": source,
                })
                con.execute("COMMIT")
            except AuthorityError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise AuthorityConflict(f"import_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise

    def quarantine(self, *, source: str, reason: str, record) -> None:
        """Park an unreconciled record; it never becomes servable state."""
        payload = record.canonical_bytes().decode("utf-8") if isinstance(
            record, ProcedureRecordV1) else str(record)
        with self._lock:
            self._conn().execute(
                "INSERT INTO quarantined_revision (source, reason, record_json, quarantined_at)"
                " VALUES (?, ?, ?, ?)",
                (source, reason, payload, _utcnow()),
            )

    # ------------------------------------------------------------------ #
    # scope grants and revocations (authority service only)
    # ------------------------------------------------------------------ #
    def commit_scope_grant(
        self, *, grant: ScopeGrantV1, receipts=(), authority, verifier=None,
    ) -> None:
        """Atomically commit a signed scope grant.

        One ``BEGIN IMMEDIATE`` transaction re-verifies the grant (via the
        mandatory ``verifier`` callable — normally
        ``ScopeGrantAuthority.verify``), binds the granted procedure
        revision, consumes the grant nonce (replay is an atomic conflict),
        and inserts the grant plus its evidence receipt bindings.
        """
        self._require_authority(authority)
        if not isinstance(grant, ScopeGrantV1):
            raise AuthorityError("grant must be a ScopeGrantV1")
        if verifier is None:
            raise AuthorityError("grant_verifier_required")
        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                problems = verifier(grant)
                if problems:
                    raise AuthorityConflict(
                        "grant_rejected: " + ",".join(problems[:5]))
                if con.execute(
                    "SELECT 1 FROM procedure_revision WHERE record_digest=?",
                    (grant.procedure_revision_digest,),
                ).fetchone() is None:
                    raise AuthorityConflict("grant_revision_missing")
                if con.execute(
                    "SELECT 1 FROM scope_grant"
                    " WHERE grant_id=? OR grant_digest=?",
                    (grant.grant_id, grant.digest),
                ).fetchone() is not None:
                    raise AuthorityConflict("grant_already_committed")
                bound = set()
                for receipt in receipts:
                    if receipt.digest not in set(grant.evidence_receipt_refs):
                        raise AuthorityConflict("receipt_not_bound_by_grant")
                    bound.add(receipt.digest)
                missing = set(grant.evidence_receipt_refs) - bound
                if missing:
                    raise AuthorityConflict(
                        "grant_evidence_incomplete: "
                        + ",".join(sorted(d[:12] for d in missing)))
                con.execute(
                    "INSERT INTO nonce_consumption"
                    " (signer, nonce, digest, consumed_at) VALUES (?, ?, ?, ?)",
                    (grant.signer_key_id, grant.grant_nonce, grant.digest,
                     _utcnow()),
                )
                con.execute(
                    "INSERT INTO scope_grant"
                    " (grant_id, grant_digest, grant_json,"
                    "  procedure_revision_digest, source_registry_id,"
                    "  source_family_id, target_registry_id, target_family_id,"
                    "  signer_key_id, expires_at, committed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (grant.grant_id, grant.digest,
                     grant.canonical_bytes().decode("utf-8"),
                     grant.procedure_revision_digest, grant.source_registry_id,
                     grant.source_family_id, grant.target_registry_id,
                     grant.target_family_id, grant.signer_key_id,
                     grant.expires_at, _utcnow()),
                )
                for receipt in receipts:
                    con.execute(
                        "INSERT INTO grant_receipt_binding"
                        " (grant_id, receipt_digest, task_id,"
                        "  evaluated_repo_digest, receipt_json)"
                        " VALUES (?, ?, ?, ?, ?)",
                        (grant.grant_id, receipt.digest, receipt.task_id,
                         receipt.evaluated_repo_digest,
                         receipt.canonical_bytes().decode("utf-8")),
                    )
                self._audit(con, "scope_grant_committed", {
                    "grant_id": grant.grant_id,
                    "grant_digest": grant.digest,
                    "procedure_revision_digest": grant.procedure_revision_digest,
                })
                con.execute("COMMIT")
            except AuthorityError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                if "nonce_consumption" in str(exc):
                    raise AuthorityConflict("grant_nonce_replayed") from exc
                raise AuthorityConflict(f"grant_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise

    def scope_grants(
        self, procedure_revision_digest: str | None = None
    ) -> list[ScopeGrantV1]:
        """Committed grants, optionally filtered to one procedure revision."""
        if procedure_revision_digest is not None:
            rows = self._conn().execute(
                "SELECT grant_json FROM scope_grant"
                " WHERE procedure_revision_digest=? ORDER BY grant_id",
                (procedure_revision_digest,),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT grant_json FROM scope_grant ORDER BY grant_id"
            ).fetchall()
        return [ScopeGrantV1.from_dict(loads_json(r[0])) for r in rows]

    def receipts_for_grant(self, grant_id: str) -> list[OutcomeReceiptV1]:
        """Evidence receipts bound to a committed grant (serve-time recheck)."""
        rows = self._conn().execute(
            "SELECT receipt_json FROM grant_receipt_binding WHERE grant_id=?"
            " ORDER BY receipt_digest",
            (grant_id,),
        ).fetchall()
        return [OutcomeReceiptV1.from_dict(loads_json(r[0])) for r in rows]

    def commit_revocation(
        self, *, revocation: RevocationV1, authority, verifier=None,
    ) -> None:
        """Atomically commit a signed ``RevocationV1``.

        The mandatory ``verifier`` (normally ``RevocationAuthority.verify``)
        re-runs inside the write transaction; unsigned or forged revocations
        never land. ``(target, kind)`` uniqueness is enforced — a second
        revocation of the same target is a conflict, not silent state.
        """
        self._require_authority(authority)
        if not isinstance(revocation, RevocationV1):
            raise AuthorityError("revocation must be a RevocationV1")
        if verifier is None:
            raise AuthorityError("revocation_verifier_required")
        target = (revocation.target_digest
                  if revocation.target_digest is not None
                  else revocation.target_id)
        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                if not verifier(revocation):
                    raise AuthorityConflict("revocation_rejected")
                con.execute(
                    "INSERT INTO revocation"
                    " (digest, kind, reason, actor_identity,"
                    "  revocation_json, committed_at)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (target, revocation.kind, revocation.reason,
                     revocation.actor_identity,
                     revocation.canonical_bytes().decode("utf-8"),
                     _utcnow()),
                )
                self._audit(con, "revocation_committed", {
                    "revocation_id": revocation.revocation_id,
                    "kind": revocation.kind,
                    "target": target,
                    "actor_identity": revocation.actor_identity,
                })
                con.execute("COMMIT")
            except AuthorityError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise AuthorityConflict("revocation_already_committed") from exc
            except Exception:
                _safe_rollback(con)
                raise

    def revocations(self, kind: str | None = None) -> list[RevocationV1]:
        """Committed signed revocations; undecodable rows fail closed."""
        if kind is not None:
            rows = self._conn().execute(
                "SELECT revocation_json FROM revocation WHERE kind=?"
                " ORDER BY digest",
                (kind,),
            ).fetchall()
        else:
            rows = self._conn().execute(
                "SELECT revocation_json FROM revocation ORDER BY digest"
            ).fetchall()
        out = []
        for (body,) in rows:
            if not body:
                raise AuthorityError("undecodable_revocation")
            out.append(RevocationV1.from_dict(loads_json(body)))
        return out

    def quarantined(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT source, reason, record_json, quarantined_at"
            " FROM quarantined_revision ORDER BY quarantine_id"
        ).fetchall()
        return [{"source": s, "reason": r, "record_json": j, "quarantined_at": t}
                for s, r, j, t in rows]

    # ------------------------------------------------------------------ #
    # read model — same contract as ProcedureStore
    # ------------------------------------------------------------------ #
    def _latest_rows(self):
        return self._conn().execute(
            "SELECT r.procedure_id, r.revision, r.record_digest, r.record_json"
            " FROM procedure_revision r"
            " JOIN (SELECT procedure_id, MAX(revision) AS rev"
            "       FROM procedure_revision GROUP BY procedure_id) m"
            " ON r.procedure_id = m.procedure_id AND r.revision = m.rev"
            " ORDER BY r.procedure_id"
        ).fetchall()

    @staticmethod
    def _parse(row) -> ProcedureRecordV1:
        record = ProcedureRecordV1.from_dict(loads_json(row[3]))
        if record.digest != row[2]:
            raise AuthorityError("stored_record_digest_mismatch")
        return record

    def get(self, procedure_id: str, revision: int | None = None) -> ProcedureRecordV1:
        if revision is None:
            row = self._conn().execute(
                "SELECT procedure_id, revision, record_digest, record_json"
                " FROM procedure_revision WHERE procedure_id=?"
                " ORDER BY revision DESC LIMIT 1",
                (procedure_id,),
            ).fetchone()
        else:
            row = self._conn().execute(
                "SELECT procedure_id, revision, record_digest, record_json"
                " FROM procedure_revision WHERE procedure_id=? AND revision=?",
                (procedure_id, revision),
            ).fetchone()
        if row is None:
            raise AuthorityError("unknown_procedure" if revision is None else "unknown_revision")
        return self._parse(row)

    def by_status(self, status: str) -> list[ProcedureRecordV1]:
        return [rec for rec in (self._parse(r) for r in self._latest_rows())
                if rec.status == status]

    def all_latest(self) -> list[ProcedureRecordV1]:
        return [self._parse(r) for r in self._latest_rows()]

    def catalog_digest(self) -> str:
        return canonical_digest("procedure_catalog", 1, {
            "head": sorted(rec.digest for rec in self.all_latest()),
        })

    def _qualified_head(self, con) -> str:
        rows = con.execute(
            "SELECT r.record_digest FROM procedure_revision r"
            " JOIN (SELECT procedure_id, MAX(revision) AS rev"
            "       FROM procedure_revision GROUP BY procedure_id) m"
            " ON r.procedure_id = m.procedure_id AND r.revision = m.rev"
            " WHERE r.status='qualified'"
        ).fetchall()
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r[0] for r in rows),
        })

    def qualified_head_digest(self) -> str:
        return self._qualified_head(self._conn())

    def decisions(self) -> list:
        rows = self._conn().execute(
            "SELECT decision_json FROM signed_promotion_decision ORDER BY seq"
        ).fetchall()
        out = []
        for (body,) in rows:
            parsed = loads_json(body)
            if "new_record_digest" in parsed:
                out.append(PromotionDecisionV2.from_dict(parsed))
            else:
                out.append(PromotionDecisionV1.from_dict(parsed))
        return out

    def decision_head(self) -> str | None:
        row = self._conn().execute(
            "SELECT decision_digest FROM signed_promotion_decision ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def _replayed_state(self, con):
        """Fold committed decisions into (statuses, qualified) maps."""
        statuses: dict[str, str] = {}
        qualified: set[str] = set()
        for row in con.execute(
            "SELECT decision_json FROM signed_promotion_decision ORDER BY seq"
        ).fetchall():
            parsed = loads_json(row[0])
            if "new_record_digest" not in parsed:
                continue  # legacy V1: history only
            if parsed["prior_status"] == "qualified":
                qualified.discard(parsed["candidate_digest"])
            if parsed["new_status"] == "qualified":
                qualified.add(parsed["new_record_digest"])
            statuses[parsed["new_record_digest"]] = parsed["new_status"]
            statuses.pop(parsed["candidate_digest"], None)
        return statuses, qualified

    def audit_trail(self) -> list[dict]:
        rows = self._conn().execute(
            "SELECT seq, event_type, payload_json, committed_at FROM audit_event ORDER BY seq"
        ).fetchall()
        return [{"seq": s, "event_type": t, "payload": loads_json(p), "committed_at": c}
                for s, t, p, c in rows]

    # ------------------------------------------------------------------ #
    # integrity verification (fail closed)
    # ------------------------------------------------------------------ #
    def verify(self) -> dict:
        """Replay the database; every digest, link and authorization must hold."""
        problems: list[str] = []
        try:
            con = self._conn()
            integrity = con.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                problems.append(f"sqlite_integrity:{integrity[:80]}")
        except sqlite3.Error as exc:
            return {"ok": False, "problems": [f"sqlite_error:{exc}"], "entries": 0, "head": None}

        revisions = 0
        decided_digests: set[str] = set()
        try:
            per_pid: dict[str, list[int]] = {}
            rows = con.execute(
                "SELECT procedure_id, revision, record_digest, status, record_json"
                " FROM procedure_revision ORDER BY procedure_id, revision"
            ).fetchall()
            for pid, rev, digest, status, body in rows:
                revisions += 1
                try:
                    record = ProcedureRecordV1.from_dict(loads_json(body))
                except ContractError:
                    problems.append(f"undecodable_revision:{pid}@{rev}")
                    continue
                if record.digest != digest:
                    problems.append(f"record_digest_mismatch:{pid}@{rev}")
                if record.status != status:
                    problems.append(f"record_status_mismatch:{pid}@{rev}")
                per_pid.setdefault(pid, []).append(rev)
            for pid, revs in per_pid.items():
                if revs != list(range(1, max(revs) + 1)):
                    problems.append(f"noncontiguous_revisions:{pid}")

            prev_digest = None
            count = 0
            for seq, did, digest, body, prior in con.execute(
                "SELECT seq, decision_id, decision_digest, decision_json, prior_decision_digest"
                " FROM signed_promotion_decision ORDER BY seq"
            ).fetchall():
                count += 1
                try:
                    parsed = loads_json(body)
                    decision = (PromotionDecisionV2.from_dict(parsed)
                                if "new_record_digest" in parsed
                                else PromotionDecisionV1.from_dict(parsed))
                except ContractError:
                    problems.append(f"undecodable_decision_at_{seq}")
                    continue
                if decision.digest != digest or decision.decision_id != did:
                    problems.append(f"decision_digest_mismatch_at_{seq}")
                if prior != prev_digest:
                    problems.append(f"chain_conflict_at_{seq}")
                prev_digest = digest
                if isinstance(decision, PromotionDecisionV2):
                    decided_digests.add(decision.new_record_digest)

            # A committed decision and its materialized revision are visible
            # together or not at all: enforce in both directions.
            for pid, rev, digest, status, _body in rows:
                if rev == 1 and status not in _SEED_STATUSES:
                    problems.append(f"unauthorized_seed_status:{pid}@{rev}")
                elif rev > 1 and digest not in decided_digests:
                    problems.append(f"revision_without_decision:{pid}@{rev}")
            existing = {d for _, _, d, _, _ in rows}
            for d in decided_digests - existing:
                problems.append(f"decision_without_revision:{d[:16]}")

            grant_revision_digests = set()
            for grant_id, grant_digest, body, rev_digest in con.execute(
                "SELECT grant_id, grant_digest, grant_json,"
                " procedure_revision_digest FROM scope_grant"
            ).fetchall():
                try:
                    grant = ScopeGrantV1.from_dict(loads_json(body))
                except ContractError:
                    problems.append(f"undecodable_scope_grant:{grant_id}")
                    continue
                if grant.digest != grant_digest:
                    problems.append(f"scope_grant_digest_mismatch:{grant_id}")
                grant_revision_digests.add(rev_digest)
            for d in grant_revision_digests - existing:
                problems.append(f"grant_revision_missing:{d[:16]}")

            for digest, kind, body in con.execute(
                "SELECT digest, kind, revocation_json FROM revocation"
            ).fetchall():
                try:
                    rev = RevocationV1.from_dict(loads_json(body))
                except ContractError:
                    problems.append(f"undecodable_revocation:{digest[:16]}")
                    continue
                if rev.kind != kind:
                    problems.append(f"revocation_kind_mismatch:{digest[:16]}")
                expected_target = (rev.target_digest
                                   if rev.target_digest is not None
                                   else rev.target_id)
                if expected_target != digest:
                    problems.append(f"revocation_target_mismatch:{digest[:16]}")
        except sqlite3.Error as exc:
            problems.append(f"sqlite_error:{exc}")
            prev_digest = None
            count = 0
        return {
            "ok": not problems,
            "problems": problems,
            "revisions": revisions,
            "entries": count,
            "head": prev_digest,
        }


def canonical_json_bytes(record) -> str:
    return record.canonical_bytes().decode("utf-8")


def _canonical(payload: dict) -> str:
    from .contracts import canonical_json
    return canonical_json(payload).decode("utf-8")


def _safe_rollback(con) -> None:
    """ROLLBACK if a transaction is still active — tolerate faulted drivers."""
    try:
        if con.in_transaction:
            con.execute("ROLLBACK")
    except sqlite3.Error:
        pass
