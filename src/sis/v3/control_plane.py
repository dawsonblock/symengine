"""Shared control plane for cross-process serving authority.

The v3.3.1 serving gateway kept replay state in a process-local set and
outcome bindings in a process-local dict. Neither survives a restart and
neither is shared by replicas, so one signed session could authorize one
decision per process and two replicas could both accept the same nonce.

This module provides the transactional substrate:

- ``session_nonce`` is the uniqueness constraint replay protection needs.
  ``commit_authorization`` inserts the nonce and the decision receipt in
  one transaction, so exactly one racing replica wins.
- ``authorization_receipt`` is the durable decision record. A guidance
  outcome can only be attached to a receipt this control plane issued.
- ``guidance_outcome`` replaces the in-memory ``_served`` map.
- ``authority_head`` records the witnessed authority snapshot a decision
  was committed against, so a stale snapshot cannot be committed after a
  revocation publication advanced the head.

Two deployment profiles share the same interface:

- SQLite (``SqliteControlPlane``) for single-host development and tests.
- PostgreSQL (``PostgresControlPlane``) for multi-process production,
  where ``INSERT ... ON CONFLICT`` plus a real transaction provides the
  cross-replica serialization point. SQLite WAL must not be shared
  across hosts over a network filesystem.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_NONCE = 256
_MAX_ID = 256
_DECISIONS = frozenset({"recommend", "advisory", "abstain"})
_OUTCOMES = frozenset({"pass", "fail", "partial", "error"})

SCHEMA_VERSION = 2

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS schema_meta (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        version INTEGER NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS session_nonce (
        nonce TEXT PRIMARY KEY,
        session_digest TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        reserved_at TEXT NOT NULL,
        authorization_id TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS authorization_receipt (
        authorization_id TEXT PRIMARY KEY,
        nonce TEXT NOT NULL UNIQUE,
        task_id TEXT NOT NULL,
        repository_id TEXT,
        guidance_digest TEXT NOT NULL,
        decision TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL,
        requester TEXT,
        committed_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS guidance_outcome (
        authorization_id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL,
        served_digest TEXT NOT NULL,
        receipt_digest TEXT NOT NULL,
        outcome TEXT NOT NULL,
        recorded_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS authority_head (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        sequence INTEGER NOT NULL,
        checkpoint_digest TEXT NOT NULL,
        journal_head TEXT NOT NULL,
        revocation_head TEXT NOT NULL,
        supersession_head TEXT NOT NULL,
        custody_entry_count INTEGER NOT NULL,
        updated_at TEXT NOT NULL
    )""",
)


class ControlPlaneError(RuntimeError):
    """A durable control-plane operation failed closed."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    # Microsecond precision keeps "latest authorization for task" ordered
    # even when a task is served twice within one wall-clock second.
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds").replace("+00:00", "Z")


def _identifier(value, name: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not (isinstance(value, str) and 0 < len(value) <= _MAX_ID):
        raise ControlPlaneError(f"{name}_invalid")
    return value


def _digest(value, name: str) -> str:
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ControlPlaneError(f"{name}_invalid")
    return value


def _nonce(value) -> str:
    if not (isinstance(value, str) and 0 < len(value) <= _MAX_NONCE):
        raise ControlPlaneError("session_nonce_invalid")
    return value


class ControlPlane(Protocol):
    """Durable authority operations shared by every serving replica."""

    def commit_authorization(
        self,
        *,
        nonce: str,
        session_digest: str,
        expires_at: str,
        task_id: str,
        repository_id: str | None,
        guidance_digest: str,
        decision: str,
        snapshot_digest: str,
        requester: str | None = None,
        expected_head: dict | None = None,
        committed_at: str | None = None,
    ) -> dict: ...

    def authorization(self, authorization_id: str) -> dict | None: ...

    def authorization_for_nonce(self, nonce: str) -> dict | None: ...

    def authorization_for_task(self, task_id: str) -> dict | None: ...

    def record_outcome(
        self,
        *,
        authorization_id: str,
        task_id: str,
        served_digest: str,
        receipt_digest: str,
        outcome: str,
        requester: str | None = None,
        recorded_at: str | None = None,
    ) -> dict: ...

    def outcome(self, authorization_id: str) -> dict | None: ...

    def advance_authority_head(self, head: dict) -> dict: ...

    def authority_head(self) -> dict | None: ...

    def schema_version(self) -> int: ...

    def close(self) -> None: ...


def _validate_head(head: dict) -> dict:
    if not isinstance(head, dict):
        raise ControlPlaneError("authority_head_invalid")
    sequence = head.get("sequence")
    if type(sequence) is not int or sequence < 1:
        raise ControlPlaneError("authority_head_sequence_invalid")
    return {
        "sequence": sequence,
        "checkpoint_digest": _digest(
            head.get("checkpoint_digest"), "checkpoint_digest"),
        "journal_head": _digest(head.get("journal_head"), "journal_head"),
        "revocation_head": _digest(
            head.get("revocation_head"), "revocation_head"),
        "supersession_head": _digest(
            head.get("supersession_head"), "supersession_head"),
        "custody_entry_count": head.get("custody_entry_count"),
        "updated_at": head.get("updated_at") or _utcnow(),
    }


class _SqlControlPlane:
    """Shared validation and head-conflict rules for both backends."""

    placeholder = "?"

    def _has_column(self, con, table: str, column: str) -> bool:
        if self.placeholder == "?":
            return any(row[1] == column for row in con.execute(
                f"PRAGMA table_info({table})"))
        return con.execute(
            "SELECT 1 FROM information_schema.columns"
            f" WHERE table_schema=current_schema()"
            f" AND table_name={self.placeholder}"
            f" AND column_name={self.placeholder}",
            (table, column)).fetchone() is not None

    def _ensure_schema_version(self, con) -> None:
        row = con.execute(
            "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        if row is None:
            con.execute(
                "INSERT INTO schema_meta (singleton, version)"
                f" VALUES (1, {self.placeholder})",
                (SCHEMA_VERSION,))
            return
        version = row[0]
        if type(version) is not int:
            raise ControlPlaneError("control_plane_schema_invalid")
        if version > SCHEMA_VERSION:
            raise ControlPlaneError(
                "control_plane_schema_too_new",
                f"database={version} supported={SCHEMA_VERSION}")
        if version < SCHEMA_VERSION:
            if version < 2:
                # v1 -> v2: outcome submissions must bind the requester
                # that the original authorization was committed for.
                if not self._has_column(
                        con, "authorization_receipt", "requester"):
                    con.execute(
                        "ALTER TABLE authorization_receipt"
                        " ADD COLUMN requester TEXT")
            con.execute(
                "UPDATE schema_meta SET version="
                f"{self.placeholder} WHERE singleton=1",
                (SCHEMA_VERSION,))

    def _check_expected_head(self, current: dict | None,
                             expected: dict | None) -> None:
        if expected is None:
            return
        if current is None:
            # Production commits compare against a witnessed head. An
            # empty head table means no checkpoint was ever published
            # through this control plane, so there is nothing to compare
            # the decision against.
            raise ControlPlaneError("authority_head_uninitialized")
        for key in ("sequence", "checkpoint_digest", "journal_head",
                    "revocation_head", "supersession_head",
                    "custody_entry_count"):
            if expected.get(key) != current.get(key):
                raise ControlPlaneError(
                    "authority_head_stale",
                    f"{key}: expected={expected.get(key)!r}"
                    f" current={current.get(key)!r}")

    def _validate_commit(self, *, nonce, session_digest, expires_at,
                         task_id, repository_id, guidance_digest,
                         decision, snapshot_digest, requester) -> dict:
        if decision not in _DECISIONS:
            raise ControlPlaneError("decision_invalid")
        return {
            "nonce": _nonce(nonce),
            "session_digest": _digest(session_digest, "session_digest"),
            "expires_at": _identifier(expires_at, "expires_at"),
            "task_id": _identifier(task_id, "task_id"),
            "repository_id": _identifier(
                repository_id, "repository_id", optional=True),
            "guidance_digest": _digest(guidance_digest, "guidance_digest"),
            "decision": _identifier(decision, "decision"),
            "snapshot_digest": _digest(snapshot_digest, "snapshot_digest"),
            "requester": _identifier(
                requester, "requester", optional=True),
        }

    @staticmethod
    def _receipt_row(row, columns) -> dict | None:
        if row is None:
            return None
        return dict(zip(columns, row))

    @staticmethod
    def _head_row(row) -> dict | None:
        if row is None:
            return None
        keys = ("singleton", "sequence", "checkpoint_digest", "journal_head",
                "revocation_head", "supersession_head",
                "custody_entry_count", "updated_at")
        value = dict(zip(keys, row))
        value.pop("singleton", None)
        return value


class SqliteControlPlane(_SqlControlPlane):
    """Single-host durable control plane (SQLite, transactional).

    Suitable for development and single-host production. It is *not* the
    distributed qualification target: do not place the database on a
    network filesystem and expect cross-host atomicity.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        try:
            self._con.execute("PRAGMA journal_mode=WAL")
            self._con.execute("PRAGMA synchronous=FULL")
            self._con.execute("PRAGMA busy_timeout=15000")
            with self._lock:
                for statement in _SCHEMA:
                    self._con.execute(statement)
            with self._transaction() as con:
                self._ensure_schema_version(con)
        except BaseException:
            con, self._con = self._con, None
            try:
                con.close()
            except sqlite3.Error:
                pass
            raise

    def schema_version(self) -> int:
        with self._transaction() as con:
            row = con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        return row[0] if row is not None else 0

    def _transaction(self):
        return _SqliteTransaction(self._con, self._lock)

    def commit_authorization(self, *, nonce, session_digest, expires_at,
                             task_id, repository_id, guidance_digest,
                             decision, snapshot_digest, requester=None,
                             expected_head=None,
                             committed_at=None) -> dict:
        values = self._validate_commit(
            nonce=nonce, session_digest=session_digest,
            expires_at=expires_at, task_id=task_id,
            repository_id=repository_id, guidance_digest=guidance_digest,
            decision=decision, snapshot_digest=snapshot_digest,
            requester=requester)
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            existing = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (values["nonce"],)).fetchone()
            if existing is not None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (?,?,?,?,?)",
                (values["nonce"], values["session_digest"],
                 values["expires_at"], committed_at or _utcnow(),
                 authorization_id))
            con.execute(
                "INSERT INTO authorization_receipt"
                " (authorization_id, nonce, task_id, repository_id,"
                "  guidance_digest, decision, snapshot_digest, requester,"
                "  committed_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (authorization_id, values["nonce"], values["task_id"],
                 values["repository_id"], values["guidance_digest"],
                 values["decision"], values["snapshot_digest"],
                 values["requester"], committed_at or _utcnow()))
        return self.authorization(authorization_id)

    def authorization(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, nonce, task_id, repository_id,"
                " guidance_digest, decision, snapshot_digest, requester,"
                " committed_at"
                " FROM authorization_receipt WHERE authorization_id=?",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "nonce", "task_id", "repository_id",
            "guidance_digest", "decision", "snapshot_digest", "requester",
            "committed_at"))

    def authorization_for_nonce(self, nonce: str) -> dict | None:
        _nonce(nonce)
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=?",
                (nonce,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def authorization_for_task(self, task_id: str) -> dict | None:
        _identifier(task_id, "task_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM authorization_receipt"
                " WHERE task_id=? ORDER BY committed_at DESC,"
                " authorization_id DESC LIMIT 1", (task_id,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def record_outcome(self, *, authorization_id, task_id, served_digest,
                       receipt_digest, outcome, requester=None,
                       recorded_at=None) -> dict:
        _identifier(authorization_id, "authorization_id")
        _identifier(task_id, "task_id")
        _digest(served_digest, "served_digest")
        _digest(receipt_digest, "receipt_digest")
        if outcome not in _OUTCOMES:
            raise ControlPlaneError("outcome_invalid")
        with self._transaction() as con:
            receipt = con.execute(
                "SELECT task_id, guidance_digest, requester"
                " FROM authorization_receipt"
                " WHERE authorization_id=?", (authorization_id,)).fetchone()
            if receipt is None:
                raise ControlPlaneError("authorization_unknown")
            if receipt[0] != task_id:
                raise ControlPlaneError("authorization_task_mismatch")
            if receipt[1] != served_digest:
                raise ControlPlaneError("served_guidance_unknown")
            if receipt[2] != requester:
                raise ControlPlaneError("outcome_requester_mismatch")
            existing = con.execute(
                "SELECT 1 FROM guidance_outcome WHERE authorization_id=?",
                (authorization_id,)).fetchone()
            if existing is not None:
                raise ControlPlaneError("outcome_already_recorded")
            con.execute(
                "INSERT INTO guidance_outcome"
                " (authorization_id, task_id, served_digest, receipt_digest,"
                "  outcome, recorded_at) VALUES (?,?,?,?,?,?)",
                (authorization_id, task_id, served_digest, receipt_digest,
                 outcome, recorded_at or _utcnow()))
        return self.outcome(authorization_id)

    def outcome(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, task_id, served_digest,"
                " receipt_digest, outcome, recorded_at"
                " FROM guidance_outcome WHERE authorization_id=?",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "task_id", "served_digest", "receipt_digest",
            "outcome", "recorded_at"))

    def _head(self, con) -> dict | None:
        row = con.execute(
            "SELECT singleton, sequence, checkpoint_digest, journal_head,"
            " revocation_head, supersession_head, custody_entry_count,"
            " updated_at FROM authority_head WHERE singleton=1").fetchone()
        return self._head_row(row)

    def authority_head(self) -> dict | None:
        with self._transaction() as con:
            return self._head(con)

    def advance_authority_head(self, head: dict) -> dict:
        values = _validate_head(head)
        if type(values["custody_entry_count"]) is not int or \
                values["custody_entry_count"] < 0:
            raise ControlPlaneError("custody_entry_count_invalid")
        with self._transaction() as con:
            current = self._head(con)
            if current is not None:
                if values["sequence"] < current["sequence"]:
                    raise ControlPlaneError("authority_head_rollback")
                if values["sequence"] == current["sequence"]:
                    if all(values[key] == current[key] for key in (
                            "checkpoint_digest", "journal_head",
                            "revocation_head", "supersession_head",
                            "custody_entry_count")):
                        return current
                    raise ControlPlaneError("authority_head_conflict")
                if values["custody_entry_count"] < \
                        current["custody_entry_count"]:
                    raise ControlPlaneError("custody_entry_count_regression")
            con.execute(
                "INSERT INTO authority_head"
                " (singleton, sequence, checkpoint_digest, journal_head,"
                "  revocation_head, supersession_head, custody_entry_count,"
                "  updated_at) VALUES (1,?,?,?,?,?,?,?)"
                " ON CONFLICT(singleton) DO UPDATE SET"
                " sequence=excluded.sequence,"
                " checkpoint_digest=excluded.checkpoint_digest,"
                " journal_head=excluded.journal_head,"
                " revocation_head=excluded.revocation_head,"
                " supersession_head=excluded.supersession_head,"
                " custody_entry_count=excluded.custody_entry_count,"
                " updated_at=excluded.updated_at",
                (values["sequence"], values["checkpoint_digest"],
                 values["journal_head"], values["revocation_head"],
                 values["supersession_head"],
                 values["custody_entry_count"], values["updated_at"]))
        return self.authority_head()

    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                self._con.close()


class _SqliteTransaction:
    def __init__(self, con, lock) -> None:
        self._con = con
        self._lock = lock

    def __enter__(self):
        self._lock.acquire()
        try:
            self._con.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as error:
            self._lock.release()
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        except BaseException:
            self._lock.release()
            raise
        return self._con

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._con.execute("COMMIT")
            else:
                self._con.execute("ROLLBACK")
        except sqlite3.Error as error:
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        finally:
            self._lock.release()
        if exc_type is not None and issubclass(exc_type, sqlite3.Error):
            raise ControlPlaneError(
                "control_plane_unavailable", str(exc)) from exc
        return False


class PostgresControlPlane(_SqlControlPlane):
    """Multi-process production control plane (PostgreSQL).

    Uniqueness constraints plus a single transaction provide the
    cross-replica serialization point. The signing/custody principals are
    expected to be separate database roles in a real deployment.
    """

    placeholder = "%s"

    # Transaction-scoped advisory lock that serializes authorization
    # commits with authority-head advancement across replicas. A row lock
    # cannot cover the uninitialized case, where no authority_head row
    # exists yet and SELECT ... FOR UPDATE locks nothing.
    _AUTHORITY_LOCK_KEY = 0x5349535F41555448

    def __init__(self, dsn: str, *, connect_timeout: int = 10) -> None:
        if not isinstance(dsn, str) or not dsn:
            raise ControlPlaneError("postgres_dsn_required")
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise ControlPlaneError("postgres_driver_missing") from exc
        self._psycopg = psycopg
        self._dsn = dsn
        self._connect_timeout = connect_timeout
        self._lock = threading.RLock()
        with self._transaction() as con:
            for statement in _SCHEMA:
                con.execute(statement)
        with self._transaction() as con:
            self._ensure_schema_version(con)

    def schema_version(self) -> int:
        with self._transaction() as con:
            row = con.execute(
                "SELECT version FROM schema_meta WHERE singleton=1").fetchone()
        return row[0] if row is not None else 0

    def _transaction(self):
        return _PostgresTransaction(
            self._psycopg, self._dsn, self._connect_timeout, self._lock)

    def _lock_authority(self, con) -> None:
        """Serialize this transaction against every other authority writer.

        READ COMMITTED alone lets a serving transaction verify a head,
        have a revocation publish and commit, and then still write an
        authorization receipt against the stale head. Holding one
        cluster-wide advisory lock for the whole transaction closes that
        window and also orders concurrent head advancements.
        """
        con.execute("SELECT pg_advisory_xact_lock(%s)",
                    (self._AUTHORITY_LOCK_KEY,))

    def commit_authorization(self, *, nonce, session_digest, expires_at,
                             task_id, repository_id, guidance_digest,
                             decision, snapshot_digest, requester=None,
                             expected_head=None,
                             committed_at=None) -> dict:
        values = self._validate_commit(
            nonce=nonce, session_digest=session_digest,
            expires_at=expires_at, task_id=task_id,
            repository_id=repository_id, guidance_digest=guidance_digest,
            decision=decision, snapshot_digest=snapshot_digest,
            requester=requester)
        authorization_id = "auth-" + secrets.token_hex(16)
        with self._transaction() as con:
            self._lock_authority(con)
            current = self._head(con)
            self._check_expected_head(current, expected_head)
            inserted = con.execute(
                "INSERT INTO session_nonce"
                " (nonce, session_digest, expires_at, reserved_at,"
                "  authorization_id) VALUES (%s,%s,%s,%s,%s)"
                " ON CONFLICT (nonce) DO NOTHING RETURNING nonce",
                (values["nonce"], values["session_digest"],
                 values["expires_at"], committed_at or _utcnow(),
                 authorization_id)).fetchone()
            if inserted is None:
                raise ControlPlaneError("session_nonce_replayed")
            con.execute(
                "INSERT INTO authorization_receipt"
                " (authorization_id, nonce, task_id, repository_id,"
                "  guidance_digest, decision, snapshot_digest, requester,"
                "  committed_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (authorization_id, values["nonce"], values["task_id"],
                 values["repository_id"], values["guidance_digest"],
                 values["decision"], values["snapshot_digest"],
                 values["requester"], committed_at or _utcnow()))
        return self.authorization(authorization_id)

    def authorization(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, nonce, task_id, repository_id,"
                " guidance_digest, decision, snapshot_digest, requester,"
                " committed_at"
                " FROM authorization_receipt WHERE authorization_id=%s",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "nonce", "task_id", "repository_id",
            "guidance_digest", "decision", "snapshot_digest", "requester",
            "committed_at"))

    def authorization_for_nonce(self, nonce: str) -> dict | None:
        _nonce(nonce)
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM session_nonce WHERE nonce=%s",
                (nonce,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def authorization_for_task(self, task_id: str) -> dict | None:
        _identifier(task_id, "task_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id FROM authorization_receipt"
                " WHERE task_id=%s ORDER BY committed_at DESC,"
                " authorization_id DESC LIMIT 1", (task_id,)).fetchone()
        return self.authorization(row[0]) if row is not None else None

    def record_outcome(self, *, authorization_id, task_id, served_digest,
                       receipt_digest, outcome, requester=None,
                       recorded_at=None) -> dict:
        _identifier(authorization_id, "authorization_id")
        _identifier(task_id, "task_id")
        _digest(served_digest, "served_digest")
        _digest(receipt_digest, "receipt_digest")
        if outcome not in _OUTCOMES:
            raise ControlPlaneError("outcome_invalid")
        with self._transaction() as con:
            receipt = con.execute(
                "SELECT task_id, guidance_digest, requester"
                " FROM authorization_receipt"
                " WHERE authorization_id=%s", (authorization_id,)).fetchone()
            if receipt is None:
                raise ControlPlaneError("authorization_unknown")
            if receipt[0] != task_id:
                raise ControlPlaneError("authorization_task_mismatch")
            if receipt[1] != served_digest:
                raise ControlPlaneError("served_guidance_unknown")
            if receipt[2] != requester:
                raise ControlPlaneError("outcome_requester_mismatch")
            inserted = con.execute(
                "INSERT INTO guidance_outcome"
                " (authorization_id, task_id, served_digest, receipt_digest,"
                "  outcome, recorded_at) VALUES (%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (authorization_id) DO NOTHING RETURNING"
                " authorization_id",
                (authorization_id, task_id, served_digest, receipt_digest,
                 outcome, recorded_at or _utcnow())).fetchone()
            if inserted is None:
                raise ControlPlaneError("outcome_already_recorded")
        return self.outcome(authorization_id)

    def outcome(self, authorization_id: str) -> dict | None:
        _identifier(authorization_id, "authorization_id")
        with self._transaction() as con:
            row = con.execute(
                "SELECT authorization_id, task_id, served_digest,"
                " receipt_digest, outcome, recorded_at"
                " FROM guidance_outcome WHERE authorization_id=%s",
                (authorization_id,)).fetchone()
        return self._receipt_row(row, (
            "authorization_id", "task_id", "served_digest", "receipt_digest",
            "outcome", "recorded_at"))

    def _head(self, con) -> dict | None:
        row = con.execute(
            "SELECT singleton, sequence, checkpoint_digest, journal_head,"
            " revocation_head, supersession_head, custody_entry_count,"
            " updated_at FROM authority_head WHERE singleton=1").fetchone()
        return self._head_row(row)

    def authority_head(self) -> dict | None:
        with self._transaction() as con:
            return self._head(con)

    def advance_authority_head(self, head: dict) -> dict:
        values = _validate_head(head)
        if type(values["custody_entry_count"]) is not int or \
                values["custody_entry_count"] < 0:
            raise ControlPlaneError("custody_entry_count_invalid")
        with self._transaction() as con:
            self._lock_authority(con)
            current = self._head(con)
            if current is not None:
                if values["sequence"] < current["sequence"]:
                    raise ControlPlaneError("authority_head_rollback")
                if values["sequence"] == current["sequence"]:
                    if all(values[key] == current[key] for key in (
                            "checkpoint_digest", "journal_head",
                            "revocation_head", "supersession_head",
                            "custody_entry_count")):
                        return current
                    raise ControlPlaneError("authority_head_conflict")
                if values["custody_entry_count"] < \
                        current["custody_entry_count"]:
                    raise ControlPlaneError("custody_entry_count_regression")
            updated = con.execute(
                "INSERT INTO authority_head"
                " (singleton, sequence, checkpoint_digest, journal_head,"
                "  revocation_head, supersession_head, custody_entry_count,"
                "  updated_at) VALUES (1,%s,%s,%s,%s,%s,%s,%s)"
                " ON CONFLICT (singleton) DO UPDATE SET"
                " sequence=excluded.sequence,"
                " checkpoint_digest=excluded.checkpoint_digest,"
                " journal_head=excluded.journal_head,"
                " revocation_head=excluded.revocation_head,"
                " supersession_head=excluded.supersession_head,"
                " custody_entry_count=excluded.custody_entry_count,"
                " updated_at=excluded.updated_at"
                " WHERE authority_head.sequence < excluded.sequence",
                (values["sequence"], values["checkpoint_digest"],
                 values["journal_head"], values["revocation_head"],
                 values["supersession_head"],
                 values["custody_entry_count"], values["updated_at"]))
            if updated.rowcount != 1:
                # The conditional update refused to move the head
                # backwards even though the pre-read said it could.
                raise ControlPlaneError("authority_head_rollback")
        return self.authority_head()

    def close(self) -> None:
        return None


class _PostgresTransaction:
    def __init__(self, psycopg, dsn, timeout, lock) -> None:
        self._psycopg = psycopg
        self._dsn = dsn
        self._timeout = timeout
        self._lock = lock
        self._con = None

    def __enter__(self):
        self._lock.acquire()
        try:
            self._con = self._psycopg.connect(
                self._dsn, connect_timeout=self._timeout)
            return self._con
        except Exception as error:
            self._lock.release()
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        except BaseException:
            self._lock.release()
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                self._con.commit()
            else:
                self._con.rollback()
        except Exception as error:
            raise ControlPlaneError(
                "control_plane_unavailable", str(error)) from error
        finally:
            self._con.close()
            self._lock.release()
        if exc_type is not None and issubclass(exc_type, Exception) and \
                not issubclass(exc_type, ControlPlaneError):
            raise ControlPlaneError(
                "control_plane_unavailable", str(exc)) from exc
        return False


def open_control_plane(location: str | Path, *,
                       postgres_dsn: str | None = None) -> ControlPlane:
    """Open the configured profile: ``postgresql://`` DSN or SQLite path."""
    if postgres_dsn is not None:
        return PostgresControlPlane(postgres_dsn)
    if isinstance(location, str) and location.startswith(
            ("postgresql://", "postgres://")):
        return PostgresControlPlane(location)
    return SqliteControlPlane(str(location).removeprefix("sqlite:///"))


__all__ = [
    "ControlPlane",
    "ControlPlaneError",
    "PostgresControlPlane",
    "SqliteControlPlane",
    "open_control_plane",
]
