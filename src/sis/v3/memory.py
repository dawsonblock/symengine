"""Experience-memory subsystem (SIS v3.3, milestone 2).

ReasoningBank-style episodic memory, rebuilt inside the v3 trust model:

- Ingestion accepts only schema-validated ``ExperienceRecordV1`` JSON —
  no pickle, no caller-asserted verification flags. The record carries
  digest references to the verified outcome receipt and the execution
  trace; large artifacts stay outside the record.
- Induction produces ``CandidateV1`` records of type
  ``experience_memory`` — *candidates*, never qualified truth. Facts
  (observed) and hypotheses (model-inferred) are stored separately and
  only facts may serve as evidence handles downstream.
- ``UNIQUE(episode_id, task_fingerprint)`` dedup means replaying the same
  episode can never masquerade as independent attempts.
- Retrieval gates on trusted repository scope, applicability predicates
  (the same allowlisted kinds as procedure retrieval), counterexample
  suppression, score threshold and a deterministic token budget — and
  abstains instead of guessing. Unqualified memory never reaches this
  function: callers pass only registry-qualified candidates.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import signatures
from .candidates import content_digest
from .contracts import (CandidateV1, ContractError, ExperienceRecordV1,
                        ExperienceRecordV2, canonical_json, loads_json)
from .memory_witness import MemoryWitness, WitnessError
from .retrieval import (RetrievalContext, precondition_holds,
                        suppression_match)

_SIGNATURE_DOMAIN = b"sis-v3:experience_record_v2:1\0"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS experience (
    experience_id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL,
    task_fingerprint TEXT NOT NULL,
    repository_registry_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE (episode_id, task_fingerprint)
);
CREATE TABLE IF NOT EXISTS memory_chain (
    seq INTEGER PRIMARY KEY,
    record_digest TEXT NOT NULL UNIQUE,
    prev_head TEXT NOT NULL,
    head TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    signature TEXT NOT NULL
);
"""

_CHAIN_DOMAIN = "sis-v3-memory-chain:"
_CHAIN_DOMAIN_BYTES = _CHAIN_DOMAIN.encode("utf-8")


def _chain_head(prev_head: str, record_digest: str, seq: int) -> str:
    return hashlib.sha256(
        (_CHAIN_DOMAIN + prev_head + ":" + record_digest + ":" + str(seq))
        .encode("utf-8")).hexdigest()


def _sign_chain_entry(seed: bytes, payload: Mapping) -> str:
    return signatures.sign(
        seed, _CHAIN_DOMAIN_BYTES + canonical_json(payload)).hex()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class MemoryError(RuntimeError):
    """The memory store cannot complete an operation."""


class DuplicateEpisode(MemoryError):
    """The same episode + task fingerprint was already ingested."""


_PRODUCTION_CONTROLS = (
    "require_signed_records",
    "require_evaluator_evidence",
    "require_chain_signature",
    "require_witness",
    "require_registered_task",
)

_PROFILE_MODES = ("development", "production")


@dataclass(frozen=True)
class MemoryTrustProfile:
    """Explicit development/production memory trust configuration (3.1).

    Development keeps legacy rows readable and makes every trust
    decision caller-visible: nothing is reported as trusted. Production
    requires signed V2 records, evaluator evidence bound to a
    registered task, a custodian-signed chain, and an external witness;
    a store that cannot meet those requirements refuses to construct
    rather than silently downgrading.

    A profile is a closed enumeration, not a bag of caller-chosen flags:
    a production profile must enable every control, a development
    profile must enable none, and any other name or partial combination
    fails construction. ``trust_status`` additionally checks that the
    store still holds the controls the profile claims, so renaming or
    rewriting the profile object cannot manufacture trust.
    """

    name: str
    require_signed_records: bool
    require_evaluator_evidence: bool
    require_chain_signature: bool
    require_witness: bool
    require_registered_task: bool

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or self.name not in _PROFILE_MODES:
            raise ContractError(f"unknown_memory_trust_profile:{self.name}")
        flags = tuple(getattr(self, control)
                      for control in _PRODUCTION_CONTROLS)
        if any(type(flag) is not bool for flag in flags):
            raise ContractError(
                "memory_trust_profile_flags_must_be_boolean")
        expected = self.name == "production"
        if any(flag != expected for flag in flags):
            raise ContractError(
                "production_profile_requires_every_trust_control"
                if expected else
                "development_profile_cannot_enable_trust_controls")

    @property
    def production_trust(self) -> bool:
        """Whether this profile claims the full production contract."""
        return self.name == "production" and all(
            getattr(self, control) for control in _PRODUCTION_CONTROLS)

    @classmethod
    def development(cls) -> "MemoryTrustProfile":
        return cls(
            name="development",
            require_signed_records=False,
            require_evaluator_evidence=False,
            require_chain_signature=False,
            require_witness=False,
            require_registered_task=False,
        )

    @classmethod
    def production(cls) -> "MemoryTrustProfile":
        return cls(
            name="production",
            require_signed_records=True,
            require_evaluator_evidence=True,
            require_chain_signature=True,
            require_witness=True,
            require_registered_task=True,
        )


def sign_experience_record(unsigned: Mapping, seed: bytes) -> str:
    """Sign a V2 experience body (all fields except ``signature``)."""
    return signatures.sign(
        seed, _SIGNATURE_DOMAIN + canonical_json(unsigned)).hex()


def issue_experience_record(
    seed: bytes,
    key_id: str,
    **fields,
) -> ExperienceRecordV2:
    """Issue a signed ``ExperienceRecordV2`` under an evaluator key."""
    unsigned = {**fields, "schema_version": 1, "signer_key_id": key_id}
    signature = sign_experience_record(unsigned, seed)
    return ExperienceRecordV2.from_dict({**unsigned, "signature": signature})


def verify_experience_signature(
    record: ExperienceRecordV2 | Mapping,
    public_key_hex: str,
) -> bool:
    """Check a V2 record's signature against a trusted public key."""
    try:
        parsed = (record if isinstance(record, ExperienceRecordV2)
                  else ExperienceRecordV2.from_dict(record))
    except (ContractError, TypeError, KeyError):
        return False
    if not isinstance(public_key_hex, str):
        return False
    try:
        public = bytes.fromhex(public_key_hex)
    except ValueError:
        return False
    if not signatures.is_valid_public_key(public):
        return False
    unsigned = parsed.to_dict()
    unsigned.pop("signature")
    return signatures.verify(
        bytes.fromhex(parsed.signature),
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
        public)


def _parse_record(raw: bytes) -> ExperienceRecordV1 | ExperienceRecordV2:
    """Dispatch on the signed V2 shape; everything else parses as V1."""
    value = loads_json(raw)
    if isinstance(value, dict) and "signature" in value:
        return ExperienceRecordV2.from_dict(value)
    return ExperienceRecordV1.from_dict(value)


class MemoryStore:
    """Durable, deduplicating store of verified experience records.

    The store holds evidence-pointers only: it never executes, never
    interprets content as instructions, and never grants authority.

    With ``trusted_signer_keys`` configured the store only accepts and
    serves evaluator-signed ``ExperienceRecordV2`` rows, re-verifying the
    signature on every read so a database writer that edits both
    ``record_json`` and ``record_digest`` is detected — the row-local
    digest is an integrity checksum, never a provenance signature.
    Trusted reads additionally require the exact record being returned
    to own a chain entry, checked per record in one statement rather
    than inferred from a store-wide chain/table scan.
    Without trusted keys rows are read as untrusted legacy data: V1
    records carry no signature at all and can never be promoted to
    verified evidence through this store.

    Stores created before the ``memory_chain`` table existed hold
    unchained rows: trusted-mode access raises ``memory_unmigrated``
    until ``repair_chain`` backfills the chain (or ``rebuild=True``
    rewrites a corrupt one). ``verify_chain`` failures report their
    cause through ``last_chain_failure``.

    ``profile`` selects the explicit trust configuration.
    ``MemoryTrustProfile.production()`` requires trusted signer keys, a
    custodian chain key, an external :class:`MemoryWitness` stored
    outside this database's directory, and an evaluator ``verifier``;
    every read then re-checks lineage, and every write advances the
    witness. ``MemoryTrustProfile.development()`` is the default and
    keeps legacy behavior, but reports every record as untrusted.
    """

    def __init__(self, path: str | Path, *,
                 trusted_signer_keys: dict[str, str] | None = None,
                 chain_key: tuple[bytes, str] | None = None,
                 profile: MemoryTrustProfile | None = None,
                 witness: MemoryWitness | None = None,
                 verifier=None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._signer_keys = (dict(trusted_signer_keys)
                             if trusted_signer_keys is not None else None)
        self._chain_key = chain_key
        self._profile = profile or MemoryTrustProfile.development()
        if not isinstance(self._profile, MemoryTrustProfile):
            raise ContractError("profile must be a MemoryTrustProfile")
        if self._profile.require_signed_records and not self._signer_keys:
            raise ContractError("production_requires_trusted_signer_keys")
        if self._profile.require_chain_signature and self._chain_key is None:
            raise ContractError("production_requires_chain_key")
        if self._profile.require_witness and witness is None:
            raise ContractError("production_requires_witness")
        if self._profile.require_evaluator_evidence and verifier is None:
            raise ContractError("production_requires_verifier")
        if self._profile.require_registered_task and not callable(
                getattr(verifier, "registered_task", None)):
            raise ContractError(
                "production_requires_registered_task_verifier")
        if witness is not None:
            if not isinstance(witness, MemoryWitness):
                raise ContractError("witness must be a MemoryWitness")
            store_path = self.path.resolve()
            witness_path = witness.path.resolve()
            if (witness_path == store_path
                    or witness_path.is_relative_to(store_path.parent)):
                raise ContractError("witness_must_live_outside_store_directory")
        self._witness = witness
        self._verifier = verifier
        self._chain_failure: str | None = None
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=FULL")
        self._con.executescript(_SCHEMA)

    @property
    def trust_configured(self) -> bool:
        return self._signer_keys is not None

    @property
    def _production_controls_present(self) -> bool:
        """Whether every control a production profile claims is configured."""
        return (bool(self._signer_keys)
                and self._chain_key is not None
                and self._witness is not None
                and self._verifier is not None)

    @property
    def _chain_enforced(self) -> bool:
        """Whether chain integrity gates reads and writes."""
        return self._signer_keys is not None or self._chain_key is not None

    def _require_membership(self, record) -> None:
        """Require this exact record to be a member of the chain.

        ``_chain_state`` proves a store-wide invariant — the chain covers
        exactly the rows present — at the instant it runs. That is not
        the same as proving the record a caller is about to trust owns a
        chain entry, and it cannot bind a row that appears between the
        invariant check and the row read. One statement joins the
        experience row to its chain entry, so both are read from the same
        snapshot; a record that was never ingested, whose row was removed,
        or whose stored digest differs from the object presented fails
        closed. Membership is not provenance: the signature and lineage
        checks still decide whether the member is trusted.
        """
        row = self._conn().execute(
            "SELECT 1 FROM experience e"
            " JOIN memory_chain c ON c.record_digest = e.record_digest"
            " WHERE e.experience_id=? AND e.record_digest=?",
            (record.experience_id, record.digest)).fetchone()
        if row is None:
            raise MemoryError(f"experience_unchained:{record.experience_id}")

    def _record_integrity(self, record) -> None:
        """Fail closed on rows a database writer could have forged."""
        if self._profile.production_trust and not self._production_controls_present:
            raise MemoryError("trust_controls_not_configured")
        if self._signer_keys is None:
            return
        if not isinstance(record, ExperienceRecordV2):
            raise MemoryError("experience_untrusted: legacy_v1_record")
        public_hex = self._signer_keys.get(record.signer_key_id)
        if public_hex is None:
            raise MemoryError("experience_untrusted: unknown_signer")
        if not verify_experience_signature(record, public_hex):
            raise MemoryError("experience_tampered")
        if self._profile.require_evaluator_evidence:
            self._verify_lineage(record)

    def _verify_lineage(self, record) -> None:
        """Require the authenticated outcome/execution/task lineage."""
        if self._verifier is None:
            raise MemoryError("production_verifier_required")
        try:
            verify_experience_evidence(
                record, self._verifier,
                require_registered_task=self._profile.require_registered_task)
        except MemoryError:
            raise
        except (RuntimeError, ContractError) as exc:
            raise MemoryError(f"experience_evidence_rejected:{exc}") from exc

    def trust_status(self, record) -> str:
        """Classify a record as ``trusted`` or name the failed condition.

        Development stores never report trust: local persistence is not
        evidence. Production reports trust only when the profile claims
        the full contract *and* the store still holds every control that
        contract depends on — signer keys, chain key, witness and
        evaluator verifier — before the chain, witness, record signature
        and evaluation lineage checks run.
        """
        if not isinstance(record, (ExperienceRecordV1, ExperienceRecordV2)):
            return "untrusted:not_an_experience_record"
        if not self._profile.production_trust:
            return "untrusted:development_profile"
        if not self._production_controls_present:
            return "untrusted:trust_controls_not_configured"
        try:
            self._require_chain()
            self._require_membership(record)
            self._record_integrity(record)
        except MemoryError as exc:
            return f"untrusted:{exc}"
        return "trusted"

    def is_trusted(self, record) -> bool:
        return self.trust_status(record) == "trusted"

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
            raise MemoryError("memory_store_closed")
        return self._con

    def ingest(self, record, *,
               evidence_check=None) -> str:
        """Store a verified experience; identical re-ingest is idempotent.

        A different record for the same ``(episode_id, task_fingerprint)``
        is a conflict — repeated or mutated copies of an episode cannot
        masquerade as independent evidence.

        ``evidence_check(record)`` is the trust-boundary hook: production
        ingestion must pass ``verify_experience_evidence`` bound to the
        evaluator, so a record cannot claim a receipt it does not have.
        It runs before any write and fails closed.
        """
        if not isinstance(record, (ExperienceRecordV1, ExperienceRecordV2)):
            record = (ExperienceRecordV2.from_dict(record)
                      if isinstance(record, Mapping) and "signature" in record
                      else ExperienceRecordV1.from_dict(record))
        self._record_integrity(record)
        if evidence_check is not None and not evidence_check(record):
            raise MemoryError("experience_evidence_rejected")
        with self._lock:
            self._require_chain()
            con = self._conn()
            row = con.execute(
                "SELECT record_digest FROM experience WHERE experience_id=?",
                (record.experience_id,),
            ).fetchone()
            if row is not None:
                if row[0] == record.digest:
                    return record.digest
                raise DuplicateEpisode("experience_id_conflict")
            dup = con.execute(
                "SELECT record_digest FROM experience"
                " WHERE episode_id=? AND task_fingerprint=?",
                (record.episode_id, record.task_fingerprint),
            ).fetchone()
            if dup is not None:
                if dup[0] == record.digest:
                    return record.digest
                raise DuplicateEpisode(
                    "episode_replay: episode+fingerprint already recorded")
            try:
                con.execute("BEGIN IMMEDIATE")
                con.execute(
                    "INSERT INTO experience"
                    " (experience_id, episode_id, task_fingerprint,"
                    "  repository_registry_id, record_digest, record_json,"
                    "  outcome, captured_at) VALUES (?,?,?,?,?,?,?,?)",
                    (record.experience_id, record.episode_id,
                     record.task_fingerprint, record.repository_registry_id,
                     record.digest,
                     record.canonical_bytes().decode("utf-8"),
                     record.outcome, record.captured_at))
                self._append_chain(con, record.digest)
                con.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise DuplicateEpisode(f"ingest_conflict: {exc}") from exc
            except BaseException:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
            self._advance_witness()
            return record.digest

    def _append_chain(self, con: sqlite3.Connection,
                      record_digest: str) -> None:
        """Append one entry to the append-only integrity chain.

        Each head commits to the previous head, the record digest and its
        monotonic sequence position. With ``chain_key`` configured the
        entry is signed by the memory custodian key, so a database writer
        cannot extend or rewrite the chain; without it the chain still
        detects mid-history edits but a writer could recompute heads —
        callers should pin ``head_digest()`` externally to catch rewinds.
        """
        last = con.execute(
            "SELECT seq, head FROM memory_chain ORDER BY seq DESC"
            " LIMIT 1").fetchone()
        seq = 1 if last is None else last[0] + 1
        prev_head = "" if last is None else last[1]
        head = _chain_head(prev_head, record_digest, seq)
        signer_key_id = ""
        signature = ""
        if self._chain_key is not None:
            seed, signer_key_id = self._chain_key
            signature = _sign_chain_entry(seed, {
                "seq": seq, "record_digest": record_digest,
                "prev_head": prev_head, "head": head,
                "signer_key_id": signer_key_id})
        con.execute(
            "INSERT INTO memory_chain"
            " (seq, record_digest, prev_head, head, signer_key_id,"
            "  signature) VALUES (?,?,?,?,?,?)",
            (seq, record_digest, prev_head, head,
             signer_key_id, signature))

    def head_digest(self) -> str | None:
        """The current chain head, or ``None`` for an empty store.

        Pin this externally (verifier journal, candidate custody, ops
        monitoring) — a restored older snapshot yields a different head,
        so a pinned head is the rewind witness the chain alone cannot be.
        """
        row = self._conn().execute(
            "SELECT head FROM memory_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    @property
    def last_chain_failure(self) -> str | None:
        """Reason of the most recent failed chain check, else ``None``."""
        return self._chain_failure

    def _chain_state(self) -> tuple[str, str]:
        """Classify the chain/table pair: ``ok``, ``unmigrated``, ``corrupt``.

        ``ok`` — chain is contiguous, internally consistent, signed where
        required, and covers exactly the experience rows present.
        ``unmigrated`` — the chain itself is valid but at least one
        experience row was never chained (a store predating the chain,
        or rows appended by an untrusted write); ``repair_chain`` fixes
        this without rewriting integrity history.
        ``corrupt`` — broken contiguity/linkage, a failed signature, or a
        chained digest with no matching row: integrity history itself is
        in doubt and repair requires ``rebuild=True``.
        """
        entries = self._conn().execute(
            "SELECT seq, record_digest, prev_head, head, signer_key_id,"
            " signature FROM memory_chain ORDER BY seq").fetchall()
        public = None
        if self._chain_key is not None:
            try:
                public = signatures.public_key(self._chain_key[0])
            except (ValueError, TypeError):
                return "corrupt", "chain_key_invalid"
        prev_head = ""
        seen: set[str] = set()
        for i, (seq, record_digest, p_head, head, key_id, sig) in \
                enumerate(entries, start=1):
            if seq != i or p_head != prev_head:
                return "corrupt", "chain_not_contiguous"
            if head != _chain_head(prev_head, record_digest, seq):
                return "corrupt", "head_recompute_mismatch"
            if self._chain_key is not None:
                if key_id != self._chain_key[1]:
                    # Entries predating key adoption are unsigned, not
                    # forged — but they still cannot verify, so adopting
                    # a custodian key mid-stream requires a rebuild.
                    if not key_id and not sig:
                        return "corrupt", "unsigned_entries"
                    return "corrupt", "signer_mismatch"
                try:
                    signature = bytes.fromhex(sig)
                except ValueError:
                    return "corrupt", "signature_malformed"
                if not signatures.verify(
                        signature,
                        _CHAIN_DOMAIN_BYTES + canonical_json({
                            "seq": seq, "record_digest": record_digest,
                            "prev_head": p_head, "head": head,
                            "signer_key_id": key_id}), public):
                    return "corrupt", "signature_invalid"
            seen.add(record_digest)
            prev_head = head
        rows = {r[0] for r in self._conn().execute(
            "SELECT record_digest FROM experience").fetchall()}
        if rows == seen:
            return "ok", ""
        if seen <= rows:
            return "unmigrated", "unchained_rows"
        return "corrupt", "row_deleted_or_digest_rewritten"

    def _chain_position(self) -> tuple[int, str | None]:
        """The current chain sequence and head; ``(0, None)`` when empty."""
        row = self._conn().execute(
            "SELECT seq, head FROM memory_chain ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (0, None) if row is None else (row[0], row[1])

    def _verify_witness(self) -> None:
        """Require the store's chain position to match the external witness."""
        if self._witness is None:
            return
        sequence, head = self._chain_position()
        try:
            self._witness.verify_against(
                sequence=sequence, memory_head_digest=head)
        except WitnessError as exc:
            self._chain_failure = f"witness:{exc.reason}"
            raise MemoryError(
                f"memory_witness_invalid:{exc.reason}") from exc

    def _advance_witness(self) -> None:
        """Record the current chain position in the external witness."""
        if self._witness is None:
            return
        sequence, head = self._chain_position()
        try:
            self._witness.advance(
                sequence=sequence, memory_head_digest=head)
        except WitnessError as exc:
            raise MemoryError(
                f"memory_witness_advance_failed:{exc.reason}") from exc

    def reconcile_witness(self) -> int | None:
        """Advance a stale witness to the current verified chain head.

        Operator action for the crash window between the database commit
        and the witness append. Refuses unless the chain itself verifies,
        and cannot re-anchor a database that is behind the witness — that
        is a detected rollback, not a stale witness.
        """
        if self._witness is None:
            return None
        with self._lock:
            state, reason = self._chain_state()
            if state != "ok":
                self._chain_failure = reason
                raise MemoryError(f"memory_chain_invalid:{reason}")
            self._advance_witness()
            return self._chain_position()[0]

    def _require_chain(self) -> None:
        """Fail reads and writes on a corrupt or un-migrated chain.

        Enforced whenever a trust root is configured — record signer keys
        or the chain custodian key — so chain integrity gates the path
        even where per-record signature checks are not configured. When
        an external witness is configured, the store's position must
        match it before any read or write proceeds.
        """
        if self._signer_keys is None and self._chain_key is None:
            self._verify_witness()
            return
        state, reason = self._chain_state()
        self._chain_failure = None if state == "ok" else reason
        if state == "corrupt":
            raise MemoryError(f"memory_chain_invalid:{reason}")
        if state == "unmigrated":
            raise MemoryError("memory_unmigrated")
        self._verify_witness()

    def verify_chain(self, *, expected_head: str | None = None) -> bool:
        """Re-validate the whole integrity chain and row consistency.

        Catches mid-history row deletion or rewrite (the chain commits
        every record digest in order), forged entries (signature check,
        when ``chain_key`` signatures are used), chain/experience table
        divergence, and — via ``expected_head`` — snapshot rewinds. On
        ``False`` the machine-readable cause is in ``last_chain_failure``.
        """
        state, reason = self._chain_state()
        self._chain_failure = None if state == "ok" else reason
        if state != "ok":
            return False
        if expected_head is not None \
                and self.head_digest() != expected_head:
            self._chain_failure = "expected_head_mismatch"
            return False
        try:
            self._verify_witness()
        except MemoryError:
            return False
        return True

    def repair_chain(self, *, rebuild: bool = False) -> int:
        """Backfill chain entries for unchained rows (migration path).

        Rows already covered by a valid chain prefix are kept; every
        unchained experience row is appended in original insertion order
        and signed when ``chain_key`` is configured. Chaining attests a
        row's membership in the store, never its provenance — per-record
        signature checks on read are unchanged. Returns the number of
        entries appended.

        Refuses on a corrupt existing chain: rewriting broken integrity
        evidence requires the explicit ``rebuild=True`` operator
        decision, which deletes the chain and re-commits every row.
        Rebuild only after the experience table itself has been verified
        trustworthy, then pin ``head_digest()`` externally.

        A production store refuses to chain legacy or untrusted rows —
        membership in a trusted chain is not provenance — and a rebuild
        over an existing witness requires a fresh witness epoch under
        the separate witness authority.
        """
        if (rebuild and self._witness is not None
                and self._witness.latest() is not None):
            raise MemoryError("memory_witness_rebuild_requires_new_epoch")
        with self._lock:
            con = self._conn()
            appended = 0
            try:
                con.execute("BEGIN IMMEDIATE")
                state, reason = self._chain_state()
                if state == "corrupt":
                    if not rebuild:
                        raise MemoryError(
                            f"memory_chain_corrupt:{reason}")
                    con.execute("DELETE FROM memory_chain")
                last = con.execute(
                    "SELECT seq, head FROM memory_chain ORDER BY seq DESC"
                    " LIMIT 1").fetchone()
                seq = 1 if last is None else last[0] + 1
                prev_head = "" if last is None else last[1]
                chained = {r[0] for r in con.execute(
                    "SELECT record_digest FROM memory_chain").fetchall()}
                rows = con.execute(
                    "SELECT record_digest FROM experience ORDER BY rowid"
                ).fetchall()
                if self._profile.require_signed_records:
                    for (raw,) in con.execute(
                            "SELECT record_json FROM experience"):
                        self._record_integrity(_parse_record(raw.encode("utf-8")))
                for (record_digest,) in rows:
                    if record_digest in chained:
                        continue
                    head = _chain_head(prev_head, record_digest, seq)
                    signer_key_id = ""
                    signature = ""
                    if self._chain_key is not None:
                        seed, signer_key_id = self._chain_key
                        signature = _sign_chain_entry(seed, {
                            "seq": seq, "record_digest": record_digest,
                            "prev_head": prev_head, "head": head,
                            "signer_key_id": signer_key_id})
                    con.execute(
                        "INSERT INTO memory_chain"
                        " (seq, record_digest, prev_head, head,"
                        "  signer_key_id, signature)"
                        " VALUES (?,?,?,?,?,?)",
                        (seq, record_digest, prev_head, head,
                         signer_key_id, signature))
                    prev_head = head
                    seq += 1
                    appended += 1
                con.execute("COMMIT")
            except BaseException:
                if con.in_transaction:
                    con.execute("ROLLBACK")
                raise
            self._chain_failure = None
            self._advance_witness()
            return appended

    def get(self, experience_id: str):
        row = self._conn().execute(
            "SELECT record_json, record_digest FROM experience"
            " WHERE experience_id=?", (experience_id,),
        ).fetchone()
        if row is None:
            raise MemoryError("experience_missing")
        self._require_chain()
        record = _parse_record(row[0].encode("utf-8"))
        if record.digest != row[1]:
            raise MemoryError(f"experience_tampered:{experience_id}")
        if self._chain_enforced:
            self._require_membership(record)
        self._record_integrity(record)
        return record

    def by_outcome(self, outcome: str) -> list:
        self._require_chain()
        rows = self._conn().execute(
            "SELECT record_json, record_digest FROM experience"
            " WHERE outcome=? ORDER BY experience_id", (outcome,),
        ).fetchall()
        out = []
        for raw, digest in rows:
            record = _parse_record(raw.encode("utf-8"))
            if record.digest != digest:
                raise MemoryError("experience_tampered")
            if self._chain_enforced:
                self._require_membership(record)
            self._record_integrity(record)
            out.append(record)
        return out


def verify_experience_evidence(record, verifier, *,
                               require_registered_task: bool = False) -> bool:
    """Bind an experience record to the authenticated evaluation lineage.

    Resolves ``outcome_receipt_digest`` through the evaluator's own
    receipt journal, verifies its signature against the trusted key
    registry, then compares the record's claimed task, repository
    snapshot, attempt and execution against the resolved artifact — an
    authentic receipt for a *different* task, repository or attempt can
    no longer back this experience. The resolved artifact must itself
    hash to ``outcome_receipt_digest``; a resolver returning some other
    valid receipt fails closed instead of being trusted on its say-so.

    The resolved artifact may be an ``OutcomeReceiptV1`` or
    ``OutcomeReceiptV2`` (task, repo and outcome bound; V2 also binds the
    execution receipt, worker and sandbox policy, and V1 execution is
    corroborated through the verifier's ``execution_digest_for`` journal
    lookup) or an ``OutcomeEnvelopeV2`` (which additionally binds the
    attempt and the execution receipt in the signed body). The stock
    ``OutcomeVerifier.verify_receipt`` authenticates signed outcome
    receipts; envelope artifacts verify through a verifier extended to
    accept them. When neither artifact
    nor journal can authenticate the claimed
    ``execution_receipt_digest``, the check fails closed.

    ``ExperienceRecordV1`` lacks every lineage field, so it is readable
    as legacy/untrusted memory only and is rejected here.

    ``require_registered_task`` additionally requires the outcome to
    point at a task the evaluator registered and at the exact suite
    commitment that registration recorded, closing the
    experience → outcome → execution → registered-task chain.
    """
    if isinstance(record, ExperienceRecordV1):
        raise MemoryError("experience_legacy_unverifiable")
    if not isinstance(record, ExperienceRecordV2):
        raise ContractError(
            "evidence check requires an ExperienceRecordV2")
    artifact = verifier.load_receipt(record.outcome_receipt_digest)
    # Defense in depth: never let a storage resolver's choice of artifact
    # stand in for the one this record names. A receipt that is valid
    # under its own digest is still not evidence for a different one.
    if getattr(artifact, "digest", None) != record.outcome_receipt_digest:
        raise MemoryError("experience_receipt_digest_mismatch")
    if not verifier.verify_receipt(artifact):
        raise MemoryError("experience_receipt_unauthenticated")
    if getattr(artifact, "outcome", None) != record.outcome:
        raise MemoryError("experience_outcome_mismatch")
    if getattr(artifact, "task_id", None) != record.task_id:
        raise MemoryError("experience_task_mismatch")
    if require_registered_task:
        lookup = getattr(verifier, "registered_task", None)
        if not callable(lookup):
            raise MemoryError("experience_task_registration_unverifiable")
        registration = lookup(record.task_id)
        if registration is None:
            raise MemoryError("experience_task_unregistered")
        commitment = getattr(artifact, "test_suite_commitment", None)
        if (commitment is not None
                and getattr(registration, "suite_commitment", None) != commitment):
            raise MemoryError("experience_protocol_mismatch")
    if getattr(artifact, "evaluated_repo_digest", None) != record.repo_snapshot_digest:
        raise MemoryError("experience_repo_mismatch")
    attempt = getattr(artifact, "attempt_id", None)
    if attempt is not None and attempt != record.attempt_id:
        raise MemoryError("experience_attempt_mismatch")
    execution = getattr(artifact, "execution_receipt_digest", None)
    if execution is None:
        resolver = getattr(verifier, "execution_digest_for", None)
        if callable(resolver):
            execution = resolver(record.outcome_receipt_digest)
    if execution is None:
        raise MemoryError("experience_execution_unverifiable")
    if execution != record.execution_receipt_digest:
        raise MemoryError("experience_execution_mismatch")
    return True


def induce_candidate(record, *,
                     candidate_id: str | None = None,
                     generator_identity: str = "sis-v3-memory-induction",
                     repository_scope: dict | None = None,
                     now: str | None = None) -> CandidateV1:
    """Distill a verified experience into an ``experience_memory`` candidate.

    The lesson becomes payload text; observed facts and inferred
    hypotheses stay separated — hypotheses are carried for evaluation
    but are never silently promoted to accepted causal truth.
    """
    if not isinstance(record, (ExperienceRecordV1, ExperienceRecordV2)):
        raise ContractError("induce requires an ExperienceRecordV1/V2")
    payload = {
        "lesson": record.lesson,
        "facts": list(record.facts),
        "hypotheses": list(record.hypotheses),
        "outcome": record.outcome,
        "failure_category": record.failure_category or "",
        "task_category": record.task_category,
        "outcome_receipt_digest": record.outcome_receipt_digest,
        "trace_digest": record.trace_digest,
    }
    if isinstance(record, ExperienceRecordV2):
        payload.update({
            "task_id": record.task_id,
            "attempt_id": record.attempt_id,
            "repo_snapshot_digest": record.repo_snapshot_digest,
            "execution_receipt_digest": record.execution_receipt_digest,
        })
    cid = candidate_id or (
        "mem-" + record.experience_id.replace(" ", "-")[:32])
    return CandidateV1(
        schema_version=1,
        candidate_id=cid,
        candidate_type="experience_memory",
        content_digest=content_digest("experience_memory", payload),
        parent_candidate_ids=(),
        source_episode_ids=(record.episode_id,),
        generator_identity=generator_identity,
        target_agent="any",
        target_task_family=record.task_category,
        repository_scope=dict(repository_scope) if repository_scope
        else {"kind": "registry_id",
              "value": record.repository_registry_id},
        applicability_predicate=tuple(record.applicability),
        known_counterexamples=tuple(record.counterexamples),
        payload=payload,
        created_at=now or _utcnow(),
    )


@dataclass(frozen=True)
class RetrievedMemory:
    candidate: CandidateV1
    score: int


def retrieve_memories(
    candidates: list[CandidateV1],
    context: RetrievalContext,
    *,
    min_score: int = 10,
    token_budget: int = 600,
    limit: int = 5,
    on_suppress=None,
    trust_check=None,
    on_reject=None,
) -> tuple[RetrievedMemory, ...]:
    """Select applicable, trustworthy memory candidates; abstain via empty.

    The three decisions are separate and ordered, and a later decision
    can never rescue an earlier failure:

    1. *Trustworthy* — ``trust_check(candidate)`` must return true when
       supplied. Without it the pool is treated as caller-vouched;
       callers that have not already filtered by trust must pass one.
    2. *Applicable* — every applicability predicate holds against the
       caller-supplied context.
    3. *Useful* — no known counterexample appears in the task context,
       the deterministic score meets ``min_score``, and the candidate
       fits the token budget and limit.

    Ranking is deterministic: matched-gate count, then content digest.
    Exact-duplicate lessons are deduplicated by ``content_digest``.

    ``on_suppress(candidate, counterexample)`` is an audit hook invoked
    for every candidate a counterexample suppresses — paraphrase-tolerant
    matching deliberately over-fires toward suppression, so deployments
    that care about recall should record these decisions rather than let
    them stay silent. ``on_reject(candidate, stage, detail)`` reports
    every candidate a hard gate removes, with ``stage`` one of
    ``untrusted``, ``inapplicable``, ``suppressed`` or ``low_score``.
    """
    if type(min_score) is not int or min_score < 0:
        raise ContractError("min_score must be a nonnegative integer")
    if type(token_budget) is not int or token_budget < 1:
        raise ContractError("token_budget must be a positive integer")
    if type(limit) is not int or not 1 <= limit <= 32:
        raise ContractError("limit must be in [1,32]")
    if on_suppress is not None and not callable(on_suppress):
        raise ContractError("on_suppress must be callable")
    if trust_check is not None and not callable(trust_check):
        raise ContractError("trust_check must be callable")
    if on_reject is not None and not callable(on_reject):
        raise ContractError("on_reject must be callable")

    def reject(cand, stage: str, detail: str) -> None:
        if on_reject is not None:
            on_reject(cand, stage, detail)

    context_text = " ".join(sorted(
        context.failure_signatures | context.symbols_present
        | context.files_present)).lower()
    scored: list[RetrievedMemory] = []
    seen_digests: set[str] = set()
    for cand in candidates:
        if cand.candidate_type != "experience_memory":
            continue
        if cand.content_digest in seen_digests:
            continue
        if trust_check is not None and not trust_check(cand):
            reject(cand, "untrusted", "the memory is not trusted evidence")
            continue
        if any(not precondition_holds(cond, context)
               for cond in cand.applicability_predicate):
            reject(cand, "inapplicable", "an applicability predicate failed")
            continue
        suppressed_by = next(
            (cx for cx in cand.known_counterexamples
             if isinstance(cx, str)
             and suppression_match(context_text, cx)),
            None)
        if suppressed_by is not None:
            if on_suppress is not None:
                on_suppress(cand, suppressed_by)
            reject(cand, "suppressed", suppressed_by)
            continue
        matched = sum(1 for cond in cand.applicability_predicate
                      if precondition_holds(cond, context))
        score = matched * 10 + len(cand.source_episode_ids)
        if score < min_score:
            reject(cand, "low_score", f"{score} < {min_score}")
            continue
        scored.append(RetrievedMemory(candidate=cand, score=score))
        seen_digests.add(cand.content_digest)

    scored.sort(key=lambda m: (-m.score, m.candidate.digest))
    picked: list[RetrievedMemory] = []
    spent = 0
    for item in scored:
        cost = max(1, len(item.candidate.payload.get("lesson", "")) // 4)
        if len(picked) >= limit or spent + cost > token_budget:
            continue
        picked.append(item)
        spent += cost
    return tuple(picked)
