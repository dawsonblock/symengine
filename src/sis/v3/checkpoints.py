"""External, signed authority checkpoints (SIS v3.3.1, PR-01).

The candidate registry's hash chain proves that its *current* rows are
internally consistent. It cannot prove that no row was deleted: an
attacker with write access to the candidate SQLite file can remove the
final revocation transition and restore the ``qualified`` state column,
and the remaining chain still verifies. Nothing inside that database can
witness the missing event.

This module supplies the missing witness. The trusted authority process
publishes a signed :class:`AuthorityCheckpointV1` to a store that lives
in different custody from the candidate database. A checkpoint binds:

- the authority epoch and a monotonic publication sequence;
- the previous checkpoint digest (an append-only chain);
- the local transition-journal sequence and head;
- a digest over every candidate's current state (including the serving
  state, so a qualified-column rewrite is visible);
- the issuer, policy version and signature.

Serving fails closed unless the local database exactly matches the latest
checkpoint. A restored or rolled-back database is older than the
checkpoint; a database with an unpublished transition is ahead of it.
Neither may serve.

The reference backend is an append-only file with an OS file lock and
atomic replacement. It must be deployed on storage the candidate-database
principal cannot write (a different service identity, host or volume).
A second table in the same SQLite database is explicitly *not* an
independent backend and must never be configured as one.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol, runtime_checkable

from . import signatures
from .contracts import (
    AuthorityCheckpointV1,
    ContractError,
    canonical_digest,
    canonical_json,
    loads_json,
)

CHECKPOINT_DOMAIN = b"sis-v3:authority_checkpoint:1\0"
GENESIS = "0" * 64
_HEX = re.compile(r"^[0-9a-f]{64}$")
_MAX_LINE = 64 * 1024

try:  # POSIX advisory locks; the deployment target is Linux/macOS.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


class CheckpointError(RuntimeError):
    """Base class for checkpoint failures."""


class CheckpointUnavailable(CheckpointError):
    """The checkpoint service cannot be read; serving must fail closed."""


class CheckpointConflict(CheckpointError):
    """A compare-and-append lost a race or observed a divergent state."""


class CheckpointVerificationError(CheckpointError):
    """A checkpoint is malformed, unsigned, or not on the trusted chain."""


class RollbackDetected(CheckpointError):
    """Local authority state is older than, or diverged from, the checkpoint."""


@dataclass(frozen=True)
class VerificationResult:
    """Outcome of comparing local authority state with a checkpoint."""

    ok: bool
    reason: str = "ok"
    detail: str = ""
    checkpoint_sequence: int | None = None
    checkpoint_journal_sequence: int | None = None
    local_journal_sequence: int | None = None
    checkpoint_digest: str | None = None
    journal_head: str | None = None
    candidate_revision_digest: str | None = None
    revocation_head: str | None = None
    supersession_head: str | None = None
    custody_entry_count: int | None = None

    def require_ok(self) -> "VerificationResult":
        if not self.ok:
            raise RollbackDetected(f"{self.reason}: {self.detail}".strip())
        return self

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "detail": self.detail,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_journal_sequence": self.checkpoint_journal_sequence,
            "local_journal_sequence": self.local_journal_sequence,
            "checkpoint_digest": self.checkpoint_digest,
            "journal_head": self.journal_head,
            "candidate_revision_digest": self.candidate_revision_digest,
            "revocation_head": self.revocation_head,
            "supersession_head": self.supersession_head,
            "custody_entry_count": self.custody_entry_count,
        }


def _check_digest(value, name):
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")


def _wire_projection(body: dict) -> dict:
    """Drop custody fields when they carry no history.

    Keeps the signed bytes identical to v3.3.1 for checkpoints without a
    custody witness, so existing signatures and digest chains survive the
    upgrade. Once a revocation is witnessed, the fields are signed.
    """
    if (body.get("revocation_head") == GENESIS
            and body.get("supersession_head") == GENESIS
            and body.get("custody_entry_count", 0) == 0):
        for name in ("revocation_head", "supersession_head",
                     "custody_entry_count"):
            body.pop(name, None)
    return body


def checkpoint_body(checkpoint: AuthorityCheckpointV1 | dict) -> bytes:
    """Canonical, domain-separated bytes signed by the authority key."""
    body = checkpoint.to_dict() if isinstance(
        checkpoint, AuthorityCheckpointV1) else dict(checkpoint)
    body.pop("signature", None)
    return CHECKPOINT_DOMAIN + canonical_json(_wire_projection(body))


def sign_checkpoint(seed: bytes, **fields) -> AuthorityCheckpointV1:
    """Sign an unsigned checkpoint body with the authority's Ed25519 key."""
    fields.setdefault("schema_version", 1)
    fields.setdefault("revocation_head", GENESIS)
    fields.setdefault("supersession_head", GENESIS)
    fields.setdefault("custody_entry_count", 0)
    unsigned = {k: v for k, v in fields.items() if k != "signature"}
    signature = signatures.sign(seed, checkpoint_body(unsigned)).hex()
    return AuthorityCheckpointV1.from_dict(
        {**unsigned, "signature": signature})


def verify_checkpoint(checkpoint: AuthorityCheckpointV1, public_hex: str) -> bool:
    """Verify one checkpoint signature against a trusted authority key."""
    try:
        return signatures.verify(
            bytes.fromhex(checkpoint.signature),
            checkpoint_body(checkpoint),
            bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


@runtime_checkable
class AuthorityCheckpointStore(Protocol):
    """Independent, compare-and-append checkpoint storage."""

    def get_latest(self) -> AuthorityCheckpointV1 | None: ...

    def compare_and_append(
        self,
        expected_sequence: int,
        checkpoint: AuthorityCheckpointV1,
    ) -> None: ...


@contextmanager
def _exclusive_lock(lock_path: Path, *, timeout: float = 10.0):
    """Advisory exclusive lock with a bounded wait.

    A lock file next to the checkpoint log serialises publishers. It is
    only a concurrency primitive; custody separation is what prevents an
    attacker from rewriting the log.
    """
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    deadline = time.monotonic() + timeout
    try:
        if fcntl is not None:
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise CheckpointUnavailable("checkpoint_store_locked")
                    time.sleep(0.05)
        yield
    finally:
        if fcntl is not None:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                pass
        os.close(fd)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        os.chmod(path, 0o600)
        try:
            dir_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass


class FileAuthorityCheckpointStore:
    """Append-only signed checkpoint log in independent file custody.

    The file is a sequence of canonical JSON checkpoint records. Reads
    verify the signature and the previous-digest chain end to end; a
    truncated, reordered or rewritten log fails closed instead of
    returning a plausible-looking head.
    """

    independent_custody = True

    def __init__(
        self,
        path: str | Path,
        *,
        trusted_authority_keys: dict[str, str],
        candidate_database_path: str | Path | None = None,
    ) -> None:
        if not trusted_authority_keys:
            raise CheckpointVerificationError("trusted_authority_keys_required")
        self._keys: dict[str, str] = {}
        for key_id, public_hex in trusted_authority_keys.items():
            if not (isinstance(public_hex, str)
                    and _HEX.fullmatch(public_hex)):
                raise CheckpointVerificationError(
                    "authority_public_key_must_be_sha256_hex")
            self._keys[key_id] = public_hex
        self.path = Path(path)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._thread_lock = threading.RLock()
        if candidate_database_path is not None:
            db = Path(candidate_database_path).resolve()
            if self.path.resolve() == db:
                raise CheckpointVerificationError(
                    "checkpoint_store_must_not_be_candidate_database")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._cache: list[AuthorityCheckpointV1] | None = None

    # ------------------------------------------------------------------ #
    # read path
    # ------------------------------------------------------------------ #
    def _load(self) -> list[AuthorityCheckpointV1]:
        if not self.path.exists():
            return []
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise CheckpointUnavailable("checkpoint_store_unreadable") from exc
        if len(raw) > 8 * 1024 * 1024:
            raise CheckpointUnavailable("checkpoint_store_too_large")
        records: list[AuthorityCheckpointV1] = []
        previous = GENESIS
        epoch = 0
        for position, line in enumerate(raw.splitlines()):
            if not line.strip():
                continue
            if len(line) > _MAX_LINE:
                raise CheckpointVerificationError(
                    f"checkpoint_line_too_large:{position}")
            try:
                record = AuthorityCheckpointV1.from_dict(loads_json(line))
            except (ContractError, ValueError) as exc:
                raise CheckpointVerificationError(
                    f"checkpoint_malformed:{position}") from exc
            public_hex = self._keys.get(record.signer_key_id)
            if public_hex is None or not verify_checkpoint(record, public_hex):
                raise CheckpointVerificationError(
                    f"checkpoint_signature_invalid:{position}")
            expected_sequence = len(records) + 1
            if record.sequence != expected_sequence:
                raise CheckpointVerificationError(
                    f"checkpoint_sequence_discontinuity:{position}")
            if record.previous_digest != previous:
                raise CheckpointVerificationError(
                    f"checkpoint_chain_broken:{position}")
            if record.authority_epoch < epoch:
                raise CheckpointVerificationError(
                    f"checkpoint_epoch_regression:{position}")
            epoch = record.authority_epoch
            previous = record.digest
            records.append(record)
        return records

    def _records(self) -> list[AuthorityCheckpointV1]:
        with self._thread_lock:
            self._cache = self._load()
            return list(self._cache)

    def get_latest(self) -> AuthorityCheckpointV1 | None:
        records = self._records()
        return records[-1] if records else None

    def history(self) -> tuple[AuthorityCheckpointV1, ...]:
        return tuple(self._records())

    # ------------------------------------------------------------------ #
    # write path
    # ------------------------------------------------------------------ #
    def compare_and_append(
        self,
        expected_sequence: int,
        checkpoint: AuthorityCheckpointV1,
    ) -> None:
        if type(expected_sequence) is not int or expected_sequence < 0:
            raise CheckpointConflict("expected_sequence_invalid")
        if not isinstance(checkpoint, AuthorityCheckpointV1):
            raise CheckpointConflict("checkpoint_required")
        public_hex = self._keys.get(checkpoint.signer_key_id)
        if public_hex is None or not verify_checkpoint(checkpoint, public_hex):
            raise CheckpointVerificationError("checkpoint_signature_invalid")
        with self._thread_lock, _exclusive_lock(self._lock_path):
            records = self._load()
            latest = records[-1] if records else None
            current_sequence = latest.sequence if latest is not None else 0
            if expected_sequence != current_sequence:
                raise CheckpointConflict(
                    f"expected_sequence:{expected_sequence}"
                    f" actual:{current_sequence}")
            if checkpoint.sequence != current_sequence + 1:
                raise CheckpointConflict(
                    f"checkpoint_sequence:{checkpoint.sequence}"
                    f" expected:{current_sequence + 1}")
            if latest is None:
                if checkpoint.previous_digest != GENESIS:
                    raise CheckpointConflict("checkpoint_genesis_mismatch")
                if checkpoint.authority_epoch < 1:
                    raise CheckpointConflict("checkpoint_epoch_invalid")
            else:
                if checkpoint.previous_digest != latest.digest:
                    raise CheckpointConflict("checkpoint_previous_mismatch")
                if checkpoint.authority_epoch < latest.authority_epoch:
                    raise CheckpointConflict("checkpoint_epoch_regression")
                if (checkpoint.journal_sequence < latest.journal_sequence):
                    raise CheckpointConflict("checkpoint_journal_regression")
                if (checkpoint.journal_sequence == latest.journal_sequence
                        and checkpoint.journal_head != latest.journal_head):
                    raise CheckpointConflict("checkpoint_journal_substitution")
                if (checkpoint.signer_key_id != latest.signer_key_id
                        and checkpoint.authority_epoch
                        <= latest.authority_epoch):
                    # A new signing key must open a new authority epoch;
                    # otherwise a compromised old key could rotate itself
                    # without an explicit epoch transition.
                    raise CheckpointConflict(
                        "checkpoint_signer_rotation_requires_new_epoch")
                if (checkpoint.custody_entry_count
                        < latest.custody_entry_count):
                    raise CheckpointConflict(
                        "checkpoint_custody_regression")
                if (checkpoint.custody_entry_count
                        == latest.custody_entry_count
                        and (checkpoint.revocation_head
                             != latest.revocation_head
                             or checkpoint.supersession_head
                             != latest.supersession_head)):
                    raise CheckpointConflict(
                        "checkpoint_custody_substitution")
            payload = b"".join(
                record.canonical_bytes() + b"\n"
                for record in (*records, checkpoint))
            _atomic_write(self.path, payload)
            self._cache = [*records, checkpoint]

    def verify(self) -> dict:
        records = self._records()
        return {
            "ok": True,
            "path": str(self.path),
            "entries": len(records),
            "sequence": records[-1].sequence if records else 0,
            "head": records[-1].digest if records else GENESIS,
            "authority_epoch": records[-1].authority_epoch if records else None,
        }


class AuthorityStateVerifier:
    """Compare a local candidate registry against the trusted checkpoint."""

    def __init__(
        self,
        store: AuthorityCheckpointStore,
        *,
        trusted_authority_keys: dict[str, str],
        expected_epoch: int,
        expected_policy_version: str,
        max_checkpoint_age_seconds: int | None = None,
        clock=_utcnow,
    ) -> None:
        if not trusted_authority_keys:
            raise CheckpointVerificationError("trusted_authority_keys_required")
        if type(expected_epoch) is not int or expected_epoch < 1:
            raise CheckpointVerificationError("expected_epoch_invalid")
        self.store = store
        self._keys = dict(trusted_authority_keys)
        self.expected_epoch = expected_epoch
        self.expected_policy_version = expected_policy_version
        self.max_checkpoint_age_seconds = max_checkpoint_age_seconds
        self._clock = clock

    def latest_checkpoint(self) -> AuthorityCheckpointV1 | None:
        return self.store.get_latest()

    def verify_local_state(
        self,
        local_state: dict,
        checkpoint: AuthorityCheckpointV1 | None = None,
    ) -> VerificationResult:
        try:
            cp = checkpoint if checkpoint is not None else self.store.get_latest()
        except CheckpointError as exc:
            return VerificationResult(
                ok=False, reason="checkpoint_unavailable", detail=str(exc),
                local_journal_sequence=_local_sequence(local_state))
        local_sequence = _local_sequence(local_state)
        if cp is None:
            return VerificationResult(
                ok=False, reason="checkpoint_missing",
                detail="no independently stored checkpoint exists",
                local_journal_sequence=local_sequence)
        public_hex = self._keys.get(cp.signer_key_id)
        if public_hex is None or not verify_checkpoint(cp, public_hex):
            return VerificationResult(
                ok=False, reason="checkpoint_signature_invalid",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if cp.authority_epoch != self.expected_epoch:
            return VerificationResult(
                ok=False, reason="authority_epoch_mismatch",
                detail=f"expected {self.expected_epoch} got {cp.authority_epoch}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if cp.policy_version != self.expected_policy_version:
            return VerificationResult(
                ok=False, reason="policy_version_mismatch",
                detail=f"expected {self.expected_policy_version}"
                       f" got {cp.policy_version}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if self.max_checkpoint_age_seconds is not None:
            age = _age_seconds(cp.issued_at, self._clock())
            if age is None:
                return VerificationResult(
                    ok=False, reason="checkpoint_timestamp_invalid",
                    checkpoint_sequence=cp.sequence,
                    checkpoint_journal_sequence=cp.journal_sequence,
                    local_journal_sequence=local_sequence,
                    checkpoint_digest=cp.digest)
            if age > self.max_checkpoint_age_seconds:
                return VerificationResult(
                    ok=False, reason="checkpoint_stale",
                    detail=f"age={age}s limit={self.max_checkpoint_age_seconds}s",
                    checkpoint_sequence=cp.sequence,
                    checkpoint_journal_sequence=cp.journal_sequence,
                    local_journal_sequence=local_sequence,
                    checkpoint_digest=cp.digest)
        if local_sequence is None:
            return VerificationResult(
                ok=False, reason="local_state_unreadable",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                checkpoint_digest=cp.digest)
        if local_sequence < cp.journal_sequence:
            return VerificationResult(
                ok=False, reason="local_state_stale",
                detail=f"local={local_sequence} checkpoint={cp.journal_sequence}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if local_sequence > cp.journal_sequence:
            return VerificationResult(
                ok=False, reason="local_state_unpublished",
                detail=f"local={local_sequence} checkpoint={cp.journal_sequence}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if local_state.get("head") != cp.journal_head:
            return VerificationResult(
                ok=False, reason="journal_head_mismatch",
                detail="local journal head differs from the checkpoint",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if local_state.get("revision_digest") != cp.candidate_revision_digest:
            return VerificationResult(
                ok=False, reason="candidate_revision_mismatch",
                detail="candidate state differs from the checkpoint",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if local_state.get("candidate_count") != cp.candidate_count:
            return VerificationResult(
                ok=False, reason="candidate_count_mismatch",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        if local_state.get("qualified_count") != cp.qualified_count:
            return VerificationResult(
                ok=False, reason="qualified_count_mismatch",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest)
        # Custody is the revocation witness. A checkpoint that names a
        # non-genesis head must be matched by the local custody state;
        # restoring an older custody directory is a rollback, not an
        # acceptable "no revocations" state.
        local_revocation = local_state.get("revocation_head")
        local_supersession = local_state.get("supersession_head")
        local_custody_count = local_state.get("custody_entry_count")
        witnessed = (cp.revocation_head != GENESIS
                     or cp.supersession_head != GENESIS
                     or cp.custody_entry_count > 0)
        if witnessed and (local_revocation is None
                          or local_supersession is None
                          or local_custody_count is None):
            return VerificationResult(
                ok=False, reason="custody_witness_missing",
                detail="checkpoint names custody history but local custody"
                       " state is unavailable",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest,
                revocation_head=cp.revocation_head,
                supersession_head=cp.supersession_head,
                custody_entry_count=cp.custody_entry_count)
        if local_custody_count is not None and \
                cp.custody_entry_count > local_custody_count:
            return VerificationResult(
                ok=False, reason="custody_entry_count_regression",
                detail=f"local={local_custody_count}"
                       f" checkpoint={cp.custody_entry_count}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest,
                revocation_head=cp.revocation_head,
                supersession_head=cp.supersession_head,
                custody_entry_count=cp.custody_entry_count)
        if local_revocation is not None and \
                local_revocation != cp.revocation_head:
            return VerificationResult(
                ok=False, reason="revocation_head_mismatch",
                detail="local custody revocation head differs from the"
                       " checkpoint",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest,
                revocation_head=cp.revocation_head,
                supersession_head=cp.supersession_head,
                custody_entry_count=cp.custody_entry_count)
        if local_supersession is not None and \
                local_supersession != cp.supersession_head:
            return VerificationResult(
                ok=False, reason="supersession_head_mismatch",
                detail="local custody supersession head differs from the"
                       " checkpoint",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest,
                revocation_head=cp.revocation_head,
                supersession_head=cp.supersession_head,
                custody_entry_count=cp.custody_entry_count)
        if local_custody_count is not None and \
                local_custody_count != cp.custody_entry_count:
            return VerificationResult(
                ok=False, reason="custody_entry_count_mismatch",
                detail=f"local={local_custody_count}"
                       f" checkpoint={cp.custody_entry_count}",
                checkpoint_sequence=cp.sequence,
                checkpoint_journal_sequence=cp.journal_sequence,
                local_journal_sequence=local_sequence,
                checkpoint_digest=cp.digest,
                revocation_head=cp.revocation_head,
                supersession_head=cp.supersession_head,
                custody_entry_count=cp.custody_entry_count)
        return VerificationResult(
            ok=True, checkpoint_sequence=cp.sequence,
            checkpoint_journal_sequence=cp.journal_sequence,
            local_journal_sequence=local_sequence,
            checkpoint_digest=cp.digest,
            journal_head=cp.journal_head,
            candidate_revision_digest=cp.candidate_revision_digest,
            revocation_head=cp.revocation_head,
            supersession_head=cp.supersession_head,
            custody_entry_count=cp.custody_entry_count)


class AuthorityJournal:
    """Trusted publication protocol for the candidate journal.

    The authority process owns the signing key. It anchors the current
    local state, publishes a new checkpoint when the local journal has
    advanced, and refuses to publish when the local state is older than
    (or diverges from) the checkpoint. Publication is idempotent and
    crash-recoverable: a crash after the database commit but before the
    checkpoint append leaves the local state ahead, which serving denies
    until ``recover()`` republishes it.
    """

    def __init__(
        self,
        registry,
        store: AuthorityCheckpointStore,
        *,
        signer_seed: bytes,
        signer_key_id: str,
        issuer_identity: str,
        authority_epoch: int,
        policy_version: str,
        clock=_utcnow,
        control_plane=None,
    ) -> None:
        if len(signer_seed) != 32:
            raise CheckpointVerificationError("signer_seed_must_be_32_bytes")
        if type(authority_epoch) is not int or authority_epoch < 1:
            raise CheckpointVerificationError("authority_epoch_invalid")
        self.registry = registry
        self.store = store
        self._seed = bytes(signer_seed)
        self.signer_key_id = signer_key_id
        self.issuer_identity = issuer_identity
        self.authority_epoch = authority_epoch
        self.policy_version = policy_version
        self._clock = clock
        self._control_plane = control_plane
        self._lock = threading.RLock()

    def _advance(self, checkpoint: AuthorityCheckpointV1) -> None:
        """Record the witnessed head in the shared control plane.

        The signed checkpoint file is the independent rollback witness;
        the control plane row is the serialization point authorization
        commits compare against.
        """
        if self._control_plane is None:
            return
        self._control_plane.advance_authority_head({
            "sequence": checkpoint.sequence,
            "checkpoint_digest": checkpoint.digest,
            "journal_head": checkpoint.journal_head,
            "revocation_head": checkpoint.revocation_head,
            "supersession_head": checkpoint.supersession_head,
            "custody_entry_count": checkpoint.custody_entry_count,
            "updated_at": checkpoint.issued_at,
        })

    def _signed(self, *, sequence: int, previous_digest: str,
                journal_sequence: int, journal_head: str,
                revision_digest: str, candidate_count: int,
                qualified_count: int, revocation_head: str,
                supersession_head: str,
                custody_entry_count: int) -> AuthorityCheckpointV1:
        return sign_checkpoint(
            self._seed,
            schema_version=1,
            checkpoint_id="cp-" + secrets.token_hex(12),
            authority_epoch=self.authority_epoch,
            sequence=sequence,
            journal_sequence=journal_sequence,
            previous_digest=previous_digest,
            journal_head=journal_head,
            candidate_revision_digest=revision_digest,
            candidate_count=candidate_count,
            qualified_count=qualified_count,
            revocation_head=revocation_head,
            supersession_head=supersession_head,
            custody_entry_count=custody_entry_count,
            issuer_identity=self.issuer_identity,
            policy_version=self.policy_version,
            issued_at=self._clock(),
            signer_key_id=self.signer_key_id,
        )

    def publish(self) -> AuthorityCheckpointV1:
        """Publish a checkpoint for the current local state (idempotent)."""
        with self._lock:
            local = self.registry.authority_state()
            latest = self.store.get_latest()
            if latest is None:
                checkpoint = self._signed(
                    sequence=1, previous_digest=GENESIS,
                    journal_sequence=local["sequence"],
                    journal_head=local["head"],
                    revision_digest=local["revision_digest"],
                    candidate_count=local["candidate_count"],
                    qualified_count=local["qualified_count"],
                    revocation_head=local["revocation_head"],
                    supersession_head=local["supersession_head"],
                    custody_entry_count=local["custody_entry_count"])
                try:
                    self.store.compare_and_append(0, checkpoint)
                except CheckpointConflict:
                    latest = self.store.get_latest()
                    if latest is not None and self._matches(latest, local):
                        self._advance(latest)
                        return latest
                    raise
                self._advance(checkpoint)
                return checkpoint
            if local["sequence"] < latest.journal_sequence:
                raise RollbackDetected(
                    "local_state_stale:"
                    f"local={local['sequence']}"
                    f" checkpoint={latest.journal_sequence}")
            if local["sequence"] == latest.journal_sequence:
                if local["head"] != latest.journal_head:
                    raise RollbackDetected(
                        "journal_head_substitution:"
                        "local head differs from the checkpoint")
                if local["revision_digest"] != latest.candidate_revision_digest:
                    raise RollbackDetected(
                        "candidate_revision_mismatch:"
                        "local candidate state differs from the checkpoint")
                if (local["revocation_head"] == latest.revocation_head
                        and local["supersession_head"]
                        == latest.supersession_head
                        and local["custody_entry_count"]
                        == latest.custody_entry_count):
                    self._advance(latest)
                    return latest
                # Custody advanced (revocation/supersession) without a
                # candidate transition. That still needs a new witnessed
                # head, otherwise the revocation is not anchored. The
                # monotonic checks below make a rollback fail closed.
            # Local state is ahead. It may only be published if it still
            # contains the checkpointed head at the checkpointed sequence:
            # an attacker who rewrote history cannot extend it.
            anchor = self.registry.journal_head_at(latest.journal_sequence)
            if anchor != latest.journal_head:
                raise RollbackDetected(
                    "checkpoint_anchor_missing:"
                    f"sequence={latest.journal_sequence}")
            checkpoint = self._signed(
                sequence=latest.sequence + 1,
                previous_digest=latest.digest,
                journal_sequence=local["sequence"],
                journal_head=local["head"],
                revision_digest=local["revision_digest"],
                candidate_count=local["candidate_count"],
                qualified_count=local["qualified_count"],
                revocation_head=local["revocation_head"],
                supersession_head=local["supersession_head"],
                custody_entry_count=local["custody_entry_count"])
            try:
                self.store.compare_and_append(latest.sequence, checkpoint)
            except CheckpointConflict:
                current = self.store.get_latest()
                if current is not None and self._matches(current, local):
                    self._advance(current)
                    return current
                raise
            self._advance(checkpoint)
            return checkpoint

    @staticmethod
    def _matches(checkpoint: AuthorityCheckpointV1, local: dict) -> bool:
        return (
            checkpoint.journal_sequence == local["sequence"]
            and checkpoint.journal_head == local["head"]
            and checkpoint.candidate_revision_digest
            == local["revision_digest"]
            and checkpoint.candidate_count == local["candidate_count"]
            and checkpoint.qualified_count == local["qualified_count"]
            and checkpoint.revocation_head == local["revocation_head"]
            and checkpoint.supersession_head == local["supersession_head"]
            and checkpoint.custody_entry_count
            == local["custody_entry_count"]
        )

    def recover(self) -> dict:
        """Repair an interrupted publication or report a rollback.

        A crash between the database commit and the checkpoint append is
        recoverable: the local journal is ahead and still contains the
        checkpointed head. A rollback is not recoverable by this process.
        """
        with self._lock:
            local = self.registry.authority_state()
            latest = self.store.get_latest()
            if latest is None:
                checkpoint = self.publish()
                return {"action": "anchored", "sequence": checkpoint.sequence,
                        "journal_sequence": checkpoint.journal_sequence}
            if local["sequence"] < latest.journal_sequence:
                return {"action": "rollback_detected",
                        "local_sequence": local["sequence"],
                        "checkpoint_journal_sequence": latest.journal_sequence}
            if local["sequence"] == latest.journal_sequence:
                if local["head"] != latest.journal_head or \
                        local["revision_digest"] != latest.candidate_revision_digest:
                    return {"action": "diverged",
                            "local_sequence": local["sequence"],
                            "checkpoint_journal_sequence": latest.journal_sequence}
                if (local["revocation_head"] == latest.revocation_head
                        and local["supersession_head"]
                        == latest.supersession_head
                        and local["custody_entry_count"]
                        == latest.custody_entry_count):
                    return {"action": "idempotent",
                            "sequence": latest.sequence,
                            "journal_sequence": latest.journal_sequence}
            try:
                checkpoint = self.publish()
            except RollbackDetected as exc:
                return {"action": "rollback_detected",
                        "detail": str(exc),
                        "local_sequence": local["sequence"],
                        "checkpoint_journal_sequence":
                            latest.journal_sequence}
            return {"action": "published", "sequence": checkpoint.sequence,
                    "journal_sequence": checkpoint.journal_sequence}

    def verify_serving_state(
        self, verifier: AuthorityStateVerifier
    ) -> VerificationResult:
        return verifier.verify_local_state(self.registry.authority_state())


def _local_sequence(local_state: dict) -> int | None:
    value = local_state.get("sequence") if isinstance(local_state, dict) else None
    return value if type(value) is int and value >= 0 else None


def _age_seconds(issued_at: str, now: str) -> int | None:
    try:
        def parse(value):
            raw = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        return max(0, int((parse(now) - parse(issued_at)).total_seconds()))
    except (TypeError, ValueError):
        return None


def revision_digest(candidates: list[dict]) -> str:
    """Digest the full candidate state projection (id, record, state)."""
    return canonical_digest("candidate_revision", 1, {
        "candidates": [
            {"candidate_id": item["candidate_id"],
             "candidate_digest": item["candidate_digest"],
             "state": item["state"]}
            for item in sorted(candidates, key=lambda i: i["candidate_id"])
        ],
    })


def checkpoint_store_digest(store: AuthorityCheckpointStore) -> str:
    """Identity of the configured checkpoint backend (for release evidence)."""
    latest = store.get_latest()
    return canonical_digest("checkpoint_store", 1, {
        "kind": type(store).__name__,
        "latest": latest.digest if latest is not None else None,
    })


def hash_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


__all__ = [
    "AuthorityCheckpointStore",
    "AuthorityJournal",
    "AuthorityStateVerifier",
    "CheckpointConflict",
    "CheckpointError",
    "CheckpointUnavailable",
    "CheckpointVerificationError",
    "FileAuthorityCheckpointStore",
    "GENESIS",
    "RollbackDetected",
    "VerificationResult",
    "checkpoint_body",
    "checkpoint_store_digest",
    "hash_file",
    "revision_digest",
    "sign_checkpoint",
    "verify_checkpoint",
]
