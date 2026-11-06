"""Typed, governed candidate registry (SIS v3.3, milestone 3).

One registry for every learnable artifact type: symbolic procedures,
diagnostic strategies, experience memories, skill instructions/bundles and
prompt variants. ``CandidateV1`` records are immutable and
content-addressed; mutable evaluation state lives only in this store.

State machine (spec):

    PROPOSED -> VALIDATED -> EVALUATING -> REJECTED
                                        -> INCONCLUSIVE
                                        -> QUALIFIED -> REVOKED

Every transition is role-gated through ``policy.require_permission`` and
committed inside one ``BEGIN IMMEDIATE`` transaction with an audit row —
a transition and its audit entry land together or not at all.

Two signed artifacts are required for serving state, not just a role
string:

- ``evaluating -> qualified`` needs at least one operator-signed
  ``CandidateDecisionV1`` *and* at least one evaluator-signed
  ``CandidateEvidenceV1`` binding the cited pass receipts to this exact
  candidate (record digest + content digest + holdout partition +
  protocol). A pass receipt for an unrelated task or candidate is not a
  qualification handle.
- ``qualified -> revoked`` needs an operator-signed decision for that
  exact edge.

Decisions and evidence are stored durably in this registry and
re-authenticated on every serving read. The state column is never
trusted: reads fold the hash-chained transition log, require the column
to match that projection, and require every serving-state transition to
be backed by the signed artifacts it cites. A direct SQL flip to
``qualified`` fails closed instead of serving.

Audit rows are hash-chained (``prev_digest`` → ``entry_digest``) inside
the same transaction and re-verified end-to-end on every ``audit()``
read — rewritten, reordered or deleted history fails closed, the same
tamper-evidence model as the v3.2 authority journal.
"""
from __future__ import annotations

import json as _json
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .candidate_authority import (QUALIFICATION_PARTITION,
                                  CandidateAuthorityError)
from .checkpoints import (AuthorityJournal, AuthorityStateVerifier,
                          revision_digest)
from .contracts import (CandidateDecisionV1, CandidateEvidenceV1,
                        CandidateV1, ContractError,
                        EvaluationCertificateV1, canonical_digest,
                        loads_json)
from .evaluation_certificate import (CertificateError,
                                     QualificationPolicy,
                                     QualificationValidator)
from .evidence_custody import (EvidenceCustodyError, EvidenceCustodyStore,
                               OfflineEvidencePolicy)
from .policy import require_permission

_HEX = re.compile(r"^[0-9a-f]{64}$")

CANDIDATE_TYPES = frozenset({
    "symbolic_procedure", "diagnostic_strategy", "experience_memory",
    "skill_instruction", "skill_bundle", "prompt_variant",
})
STATES = ("proposed", "validated", "evaluating", "rejected",
          "inconclusive", "qualified", "revoked")
SERVING_STATES = frozenset({"qualified", "revoked"})

_EDGES = {
    "proposed": frozenset({"validated", "rejected"}),
    "validated": frozenset({"evaluating", "rejected"}),
    "evaluating": frozenset({"qualified", "rejected", "inconclusive"}),
    "inconclusive": frozenset(),
    "rejected": frozenset(),
    "qualified": frozenset({"revoked"}),
    "revoked": frozenset(),
}

_TRANSITION_ROLE = {
    ("proposed", "validated"): ("candidate:write",),
    ("proposed", "rejected"): ("outcome:evaluate", "promotion:approve"),
    ("validated", "evaluating"): ("outcome:evaluate",),
    ("validated", "rejected"): ("outcome:evaluate", "promotion:approve"),
    ("evaluating", "qualified"): ("promotion:approve",),
    ("evaluating", "rejected"): ("outcome:evaluate",),
    ("evaluating", "inconclusive"): ("outcome:evaluate",),
    ("qualified", "revoked"): ("promotion:approve",),
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate (
    candidate_id TEXT PRIMARY KEY,
    candidate_digest TEXT NOT NULL UNIQUE,
    candidate_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_transition (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    actor_identity TEXT NOT NULL,
    receipt_refs_json TEXT NOT NULL,
    evidence_refs_json TEXT NOT NULL DEFAULT '[]',
    decision_digest TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL,
    committed_at TEXT NOT NULL,
    prev_digest TEXT NOT NULL DEFAULT '',
    entry_digest TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS candidate_decision (
    decision_digest TEXT PRIMARY KEY,
    decision_json TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    decision_nonce TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    UNIQUE(signer_key_id, decision_nonce)
);
CREATE TABLE IF NOT EXISTS candidate_evidence (
    evidence_digest TEXT PRIMARY KEY,
    evidence_json TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    stored_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS candidate_certificate (
    certificate_digest TEXT PRIMARY KEY,
    certificate_json TEXT NOT NULL,
    candidate_id TEXT NOT NULL UNIQUE,
    signer_key_id TEXT NOT NULL,
    evidence_class TEXT NOT NULL,
    stored_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS registry_migration (
    migration TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    entries INTEGER NOT NULL,
    detail TEXT NOT NULL
);
"""

_GENESIS = "0" * 64


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def content_digest(candidate_type: str, payload) -> str:
    """Domain-separated digest over the typed payload (helper for builders)."""
    return canonical_digest("candidate_content", 1,
                            {"type": candidate_type, "payload": payload})


def _check_digest(value, name):
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")


class CandidateError(RuntimeError):
    """The candidate registry cannot complete an operation."""


class CandidateConflict(CandidateError):
    """A write conflicts with committed state or an illegal transition."""


class CandidatePublicationPending(CandidateError):
    """A committed transition has not reached the independent checkpoint.

    The database write is durable; the authoritative checkpoint is not.
    Serving fails closed until the trusted authority publishes or
    recovers. Retrying the transition is wrong (it is already committed);
    call ``CandidateRegistry.publish_pending()`` instead.
    """

    committed = True


def _permitted(role: str, action: str) -> bool:
    try:
        require_permission(role, action)
        return True
    except Exception:
        return False


def _entry_digest(seq, candidate_id, from_state, to_state,
                  actor_identity, receipt_refs_json, evidence_refs_json,
                  decision_digest, note, committed_at, prev_digest) -> str:
    """Domain-separated digest over one audit row plus its chain link."""
    return canonical_digest("candidate_audit", 1, {
        "seq": seq,
        "candidate_id": candidate_id,
        "from_state": from_state,
        "to_state": to_state,
        "actor_identity": actor_identity,
        "receipt_refs": _refs(receipt_refs_json),
        "evidence_refs": _refs(evidence_refs_json),
        "decision_digest": decision_digest,
        "note": note,
        "committed_at": committed_at,
        "prev_digest": prev_digest,
    })


def _legacy_entry_digest(seq, candidate_id, from_state, to_state,
                         actor_identity, receipt_refs_json, note,
                         committed_at, prev_digest) -> str:
    """Digest of a row sealed before evidence/decision fields existed.

    Only used to prove a pre-migration chain was intact before it is
    resealed; it must never be used to seal a new row.
    """
    return canonical_digest("candidate_audit", 1, {
        "seq": seq,
        "candidate_id": candidate_id,
        "from_state": from_state,
        "to_state": to_state,
        "actor_identity": actor_identity,
        "receipt_refs": _refs(receipt_refs_json),
        "note": note,
        "committed_at": committed_at,
        "prev_digest": prev_digest,
    })


def _refs(raw):
    """Decode a stored ref list; malformed JSON is registry corruption."""
    try:
        value = _json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise CandidateError("audit_row_malformed") from exc
    if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value):
        raise CandidateError("audit_row_malformed")
    return value


class CandidateRegistry:
    """Single-writer transactional store for governed learning candidates.

    ``expected_evaluation_protocol_digest`` optionally pins every
    qualification evidence binding to the preregistered protocol; a
    mismatch is refused at qualification and re-detected at serve time.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        receipt_authority=None,
        evidence_authority=None,
        decision_authority=None,
        expected_evaluation_protocol_digest: str | None = None,
        checkpoint_verifier: AuthorityStateVerifier | None = None,
        authority_journal: AuthorityJournal | None = None,
        production_serving: bool = False,
        qualification_policy: QualificationPolicy | None = None,
        qualification_validator: QualificationValidator | None = None,
        certificate_resolver=None,
        delivery_resolver=None,
        evidence_custody: EvidenceCustodyStore | None = None,
        require_evidence_custody: bool = False,
        offline_evidence_policy: OfflineEvidencePolicy | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Independent evaluator boundary: a callable that resolves a receipt
        # digest and raises unless its signature authenticates.
        self._receipt_authority = receipt_authority
        # Signed-artifact boundaries. Evidence binds receipts to a
        # candidate; decisions bind the exact serving-state edge. Both are
        # re-authenticated on read, never trusted from the database alone.
        self._evidence_authority = evidence_authority
        self._decision_authority = decision_authority
        if expected_evaluation_protocol_digest is not None:
            _check_digest(expected_evaluation_protocol_digest,
                          "expected_evaluation_protocol_digest")
        self._expected_protocol = expected_evaluation_protocol_digest
        # Independent authority witness. A local-only database is not
        # rollback resistant, so production serving refuses to read a
        # qualified state without a verifier.
        self._checkpoint_verifier = checkpoint_verifier
        self._authority_journal: AuthorityJournal | None = None
        self._production_serving = bool(production_serving)
        self._last_publication_error = ""
        # Production qualification is certificate-gated. A registry
        # without a policy can still hold demonstration evidence, but it
        # is explicitly not production-qualified.
        self._qualification_policy = qualification_policy
        self._qualification_validator = qualification_validator
        self._certificate_resolver = certificate_resolver
        self._delivery_resolver = delivery_resolver
        if qualification_policy is not None and qualification_validator is None:
            raise CandidateError("qualification_validator_required")
        if qualification_validator is not None and \
                qualification_policy is None:
            raise CandidateError("qualification_policy_required")
        self._evidence_custody = evidence_custody
        self._require_evidence_custody = bool(require_evidence_custody)
        self._offline_evidence_policy = offline_evidence_policy
        if self._require_evidence_custody and evidence_custody is None:
            raise CandidateError("evidence_custody_required")
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        con = self._con
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA synchronous=FULL")
        con.execute("PRAGMA foreign_keys=ON")
        con.execute("PRAGMA busy_timeout=15000")
        con.executescript(_SCHEMA)
        try:
            self._migrate(con)
        except Exception:
            # A refused migration (e.g. a broken pre-migration chain) must
            # not leak the connection the registry just opened.
            con.close()
            self._con = None
            raise
        if authority_journal is not None:
            self.bind_authority_journal(authority_journal)

    def bind_authority_journal(self, journal: AuthorityJournal) -> None:
        """Attach the trusted publisher that anchors this registry."""
        if journal.registry is not self:
            raise CandidateError("authority_journal_registry_mismatch")
        self._authority_journal = journal

    def bind_checkpoint_verifier(
        self, verifier: AuthorityStateVerifier, *,
        production_serving: bool = False,
    ) -> None:
        """Attach the independent checkpoint verifier used for serving."""
        self._checkpoint_verifier = verifier
        self._production_serving = bool(production_serving)

    def bind_evidence_custody(
        self, custody: EvidenceCustodyStore, *,
        require: bool = False,
        offline_policy: OfflineEvidencePolicy | None = None,
        delivery_resolver=None,
    ) -> None:
        """Attach durable evidence custody used for qualification/serving."""
        self._evidence_custody = custody
        self._require_evidence_custody = bool(require)
        self._offline_evidence_policy = offline_policy
        if delivery_resolver is not None:
            self._delivery_resolver = delivery_resolver

    @property
    def last_publication_error(self) -> str:
        return self._last_publication_error

    @property
    def qualification_mode(self) -> str:
        """``production`` only when a certificate policy is enforced."""
        return "production" if self._qualification_policy is not None \
            else "demonstration"

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
            raise CandidateError("candidate_registry_closed")
        return self._con

    @contextmanager
    def _read(self):
        """Consistent read snapshot under the writer lock."""
        with self._lock:
            con = self._conn()
            con.execute("BEGIN")
            try:
                yield con
            except Exception:
                _safe_rollback(con)
                raise
            else:
                try:
                    con.execute("COMMIT")
                except sqlite3.Error:
                    pass

    # ------------------------------------------------------------------ #
    # intake — learners only; a submission can never mint elevated state
    # ------------------------------------------------------------------ #
    def submit(self, candidate: CandidateV1, *, actor_role: str) -> str:
        """Persist a new candidate at PROPOSED; idempotent on identical."""
        require_permission(actor_role, "candidate:write")
        if not isinstance(candidate, CandidateV1):
            candidate = CandidateV1.from_dict(candidate)
        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                # Never build new history on a tampered projection.
                self._project(con)
                row = con.execute(
                    "SELECT candidate_digest, state FROM candidate WHERE candidate_id=?",
                    (candidate.candidate_id,),
                ).fetchone()
                if row is not None:
                    if row[0] == candidate.digest:
                        con.execute("COMMIT")
                        return candidate.digest
                    raise CandidateConflict("candidate_id_conflict")
                con.execute(
                    "INSERT INTO candidate"
                    " (candidate_id, candidate_digest, candidate_json, state, created_at)"
                    " VALUES (?, ?, ?, 'proposed', ?)",
                    (candidate.candidate_id, candidate.digest,
                     candidate.canonical_bytes().decode("utf-8"), _utcnow()))
                self._audit(con, candidate.candidate_id, "", "proposed",
                            actor_role, (), (), "", "submitted")
                con.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise CandidateConflict(f"submit_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise
            self._publish_after_commit()
            return candidate.digest

    # ------------------------------------------------------------------ #
    # governed transitions
    # ------------------------------------------------------------------ #
    def transition(self, candidate_id: str, target: str, *,
                   actor_role: str, actor_identity: str = "",
                   receipt_refs=(), evidence_refs=(),
                   decision_ref: str | None = None,
                   certificate_ref: str | None = None,
                   note: str = "") -> None:
        """Move ``candidate_id`` along a legal edge; role-gated + audited.

        QUALIFIED requires ``promotion:approve``, at least one bound pass
        receipt, at least one authenticated evidence binding that names
        this candidate, and an operator-signed decision for the exact
        edge. REVOKED requires an operator-signed decision as well.
        Every check is re-evaluated inside the write transaction so stale
        readers cannot interleave, and the decision nonce is consumed in
        the same transaction so it can never be replayed.
        """
        if target not in STATES:
            raise ContractError(f"unknown candidate state: {target}")
        refs = tuple(dict.fromkeys(receipt_refs or ()))
        erefs = tuple(dict.fromkeys(evidence_refs or ()))
        for ref in refs:
            _check_digest(ref, "receipt_refs[]")
        for ref in erefs:
            _check_digest(ref, "evidence_refs[]")
        if decision_ref is not None:
            _check_digest(decision_ref, "decision_ref")
        if certificate_ref is not None:
            _check_digest(certificate_ref, "certificate_ref")

        with self._lock:
            con = self._conn()
            con.execute("BEGIN IMMEDIATE")
            try:
                states, _ = self._project(con)
                row = con.execute(
                    "SELECT candidate_digest, candidate_json, state"
                    " FROM candidate WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if row is None:
                    raise CandidateConflict("candidate_missing")
                record = self._row_to_record(row[:2])
                current = states.get(candidate_id, "")
                if target not in _EDGES[current]:
                    raise CandidateConflict(
                        f"illegal_transition:{current}->{target}")
                actions = _TRANSITION_ROLE[(current, target)]
                if not any(_permitted(actor_role, a) for a in actions):
                    raise CandidateConflict(
                        f"role_denied:{actor_role} cannot {current}->{target}")
                if target == "qualified" and not refs:
                    raise CandidateConflict(
                        "qualification_requires_bound_receipts")
                if target == "qualified" and not erefs:
                    raise CandidateConflict(
                        "qualification_requires_evidence_binding")
                if target == "qualified" and decision_ref is None:
                    raise CandidateConflict(
                        "qualification_requires_decision")
                if target == "revoked" and decision_ref is None:
                    raise CandidateConflict(
                        "revocation_requires_decision")
                if target != "qualified" and erefs:
                    raise CandidateConflict(
                        "evidence_only_for_qualification")
                if target == "qualified" and \
                        self._qualification_policy is not None and \
                        certificate_ref is None:
                    raise CandidateConflict(
                        "qualification_requires_evaluation_certificate")
                if certificate_ref is not None and \
                        (target != "qualified"
                         or self._qualification_policy is None):
                    raise CandidateConflict(
                        "certificate_only_for_production_qualification")
                needs_decision = target in {"qualified", "revoked"} or \
                    decision_ref is not None
                if needs_decision and not actor_identity:
                    raise CandidateConflict(
                        "actor_identity_required_for_decision")

                if target == "qualified":
                    self._authenticate_receipts(refs)
                    if self._expected_protocol is None:
                        raise CandidateConflict(
                            "qualification_requires_expected_protocol")
                    self._authenticate_evidence(record, erefs, refs, con)
                if certificate_ref is not None:
                    self._authenticate_certificate(
                        record, refs, erefs, certificate_ref, con)
                decision = None
                if needs_decision:
                    decision = self._authenticate_decision(
                        record, current, target, refs, erefs,
                        actor_identity, decision_ref, con)

                con.execute(
                    "UPDATE candidate SET state=? WHERE candidate_id=?",
                    (target, candidate_id))
                self._audit(
                    con, candidate_id, current, target,
                    actor_identity or actor_role, refs, erefs,
                    decision.digest if decision is not None else "", note)
                con.execute("COMMIT")
            except CandidateError:
                _safe_rollback(con)
                raise
            except sqlite3.IntegrityError as exc:
                _safe_rollback(con)
                raise CandidateConflict(f"transition_conflict: {exc}") from exc
            except Exception:
                _safe_rollback(con)
                raise
            self._publish_after_commit()

    def _publish_after_commit(self) -> None:
        """Anchor a committed write in independent authority storage.

        The database commit is already durable. If publication fails the
        registry is ahead of the checkpoint and serving must fail closed;
        callers get a distinct "committed but pending" error so they do
        not mistake it for a rolled-back transition.
        """
        if self._authority_journal is None:
            return
        try:
            self._authority_journal.publish()
        except Exception as exc:
            self._last_publication_error = f"{type(exc).__name__}: {exc}"
            raise CandidatePublicationPending(
                "authority_publication_pending:"
                f"{self._last_publication_error}") from exc
        self._last_publication_error = ""

    def publish_pending(self):
        """Publish the current local state after an interrupted write."""
        if self._authority_journal is None:
            raise CandidateError("authority_journal_unconfigured")
        checkpoint = self._authority_journal.publish()
        self._last_publication_error = ""
        return checkpoint

    # ------------------------------------------------------------------ #
    # authority state — the independently witnessed projection
    # ------------------------------------------------------------------ #
    def _authority_state(self, con) -> dict:
        states, _ = self._project(con)
        tail = con.execute(
            "SELECT seq, entry_digest FROM candidate_transition"
            " ORDER BY seq DESC LIMIT 1").fetchone()
        rows = con.execute(
            "SELECT candidate_id, candidate_digest, state"
            " FROM candidate ORDER BY candidate_id").fetchall()
        revision = revision_digest([
            {"candidate_id": cid, "candidate_digest": digest,
             "state": states.get(cid, state)}
            for cid, digest, state in rows])
        custody = {
            "revocation_head": _GENESIS,
            "supersession_head": _GENESIS,
            "custody_entry_count": 0,
        }
        if self._evidence_custody is not None:
            try:
                snapshot = self._evidence_custody.authority_snapshot()
            except EvidenceCustodyError as exc:
                raise CandidateError(
                    f"evidence_custody_unavailable:{exc.reason}") from exc
            custody.update({
                "revocation_head": snapshot["revocation_head"],
                "supersession_head": snapshot["supersession_head"],
                "custody_entry_count": snapshot["custody_entry_count"],
            })
        return {
            "sequence": tail[0] if tail is not None else 0,
            "head": tail[1] if tail is not None else _GENESIS,
            "revision_digest": revision,
            "candidate_count": len(rows),
            "qualified_count": sum(
                1 for cid, _, _ in rows
                if states.get(cid) == "qualified"),
            **custody,
        }

    def authority_state(self) -> dict:
        """Journal sequence/head plus a digest over every candidate state."""
        with self._read() as con:
            return self._authority_state(con)

    def journal_head_at(self, sequence: int) -> str | None:
        """Return the sealed head at ``sequence`` (0 is genesis)."""
        if type(sequence) is not int or sequence < 0:
            raise ContractError("journal sequence must be nonnegative")
        if sequence == 0:
            return _GENESIS
        with self._read() as con:
            self._project(con)
            row = con.execute(
                "SELECT entry_digest FROM candidate_transition WHERE seq=?",
                (sequence,)).fetchone()
            return row[0] if row is not None else None

    def _authority_gate(self, con=None) -> dict:
        """Fail closed unless local state matches the trusted checkpoint."""
        if self._checkpoint_verifier is None:
            if self._production_serving:
                raise CandidateError("authority_checkpoint_unconfigured")
            return {
                "ok": True,
                "mode": "uncheckpointed_development",
                "reason": "no_independent_checkpoint_configured",
            }
        local = self._authority_state(con) if con is not None \
            else self.authority_state()
        result = self._checkpoint_verifier.verify_local_state(local)
        if not result.ok:
            raise CandidateError(
                "authority_checkpoint_rejected:" + result.reason)
        return {"ok": True, "mode": "checkpoint_verified",
                **result.as_dict()}

    def authority_status(self) -> dict:
        """Current authority verification result (raises when it fails)."""
        with self._read() as con:
            return self._authority_gate(con)

    def seed_authority_head(self, control_plane) -> dict:
        """Anchor a fresh control plane to the latest signed checkpoint.

        Used on upgrade/recovery: the checkpoint file is the independent
        witness, so the shared head row may be reconstructed from it
        after verifying the local candidate and custody state.
        """
        if self._checkpoint_verifier is None:
            raise CandidateError("authority_checkpoint_unconfigured")
        checkpoint = self._checkpoint_verifier.latest_checkpoint()
        if checkpoint is None:
            raise CandidateError("authority_checkpoint_missing")
        result = self._checkpoint_verifier.verify_local_state(
            self.authority_state(), checkpoint)
        if not result.ok:
            raise CandidateError(
                "authority_checkpoint_rejected:" + result.reason)
        return control_plane.advance_authority_head({
            "sequence": checkpoint.sequence,
            "checkpoint_digest": checkpoint.digest,
            "journal_head": checkpoint.journal_head,
            "revocation_head": checkpoint.revocation_head,
            "supersession_head": checkpoint.supersession_head,
            "custody_entry_count": checkpoint.custody_entry_count,
            "updated_at": checkpoint.issued_at,
        })

    def qualify(self, candidate_id: str, *,
                actor_role: str, actor_identity: str = "",
                receipt_refs, evidence_refs=(),
                decision_ref: str | None = None,
                certificate_ref: str | None = None,
                note: str = "") -> None:
        """Explicit qualification — decision, evidence, and (production)
        a candidate-specific evaluation certificate."""
        self.transition(candidate_id, "qualified", actor_role=actor_role,
                        actor_identity=actor_identity,
                        receipt_refs=receipt_refs,
                        evidence_refs=evidence_refs,
                        decision_ref=decision_ref,
                        certificate_ref=certificate_ref, note=note)

    def revoke(self, candidate_id: str, *,
               actor_role: str, actor_identity: str = "",
               decision_ref: str | None = None, note: str = "") -> None:
        self.transition(candidate_id, "revoked", actor_role=actor_role,
                        actor_identity=actor_identity,
                        decision_ref=decision_ref, note=note)

    def _authenticate_receipts(self, refs) -> None:
        """Require every cited receipt to resolve as an authentic pass."""
        if self._receipt_authority is None:
            raise CandidateConflict(
                "qualification_requires_receipt_authority")
        for ref in refs:
            try:
                receipt = self._receipt_authority(ref)
            except CandidateError:
                raise
            except Exception as exc:
                raise CandidateConflict(
                    f"receipt_rejected:{ref[:12]}") from exc
            if receipt is None or getattr(receipt, "outcome", None) != "pass":
                raise CandidateConflict(
                    f"qualification_requires_pass_receipt:{ref[:12]}")
            if self._evidence_custody is not None:
                try:
                    self._evidence_custody.put(receipt)
                except EvidenceCustodyError as exc:
                    raise CandidateConflict(
                        f"evidence_custody_rejected:{exc.reason}") from exc

    def _authenticate_evidence(self, record, erefs, refs, con) -> None:
        """Every cited binding must authenticate and name this candidate."""
        if self._evidence_authority is None:
            raise CandidateConflict(
                "qualification_requires_evidence_authority")
        covered: set[str] = set()
        for ref in erefs:
            try:
                evidence = self._evidence_authority.resolve(ref)
            except CandidateAuthorityError as exc:
                raise CandidateConflict(
                    f"evidence_rejected:{exc.reason}") from exc
            except Exception as exc:
                raise CandidateConflict(
                    f"evidence_rejected:{ref[:12]}") from exc
            try:
                self._evidence_authority.check(
                    evidence, candidate=record, receipt_refs=refs,
                    partition=QUALIFICATION_PARTITION)
            except CandidateAuthorityError as exc:
                raise CandidateConflict(
                    f"evidence_rejected:{exc.reason}") from exc
            if self._expected_protocol is not None and \
                    evidence.evaluation_protocol_digest != self._expected_protocol:
                raise CandidateConflict("evidence_protocol_mismatch")
            covered.update(evidence.receipt_refs)
            self._store_evidence(con, evidence)
            if self._evidence_custody is not None:
                try:
                    self._evidence_custody.put(evidence)
                except EvidenceCustodyError as exc:
                    raise CandidateConflict(
                        f"evidence_custody_rejected:{exc.reason}") from exc
        if not set(refs) <= covered:
            raise CandidateConflict("evidence_receipt_not_bound")

    def _authenticate_decision(self, record, current, target, refs, erefs,
                               actor_identity, decision_ref, con):
        if self._decision_authority is None:
            raise CandidateConflict("decision_authority_required")
        try:
            decision = self._decision_authority.resolve(decision_ref)
        except CandidateAuthorityError as exc:
            raise CandidateConflict(
                f"decision_rejected:{exc.reason}") from exc
        except Exception as exc:
            raise CandidateConflict(
                f"decision_rejected:{decision_ref[:12]}") from exc
        try:
            self._decision_authority.check(
                decision, candidate=record, from_state=current,
                to_state=target, receipt_refs=refs, evidence_refs=erefs,
                actor_identity=actor_identity)
        except CandidateAuthorityError as exc:
            raise CandidateConflict(
                f"decision_rejected:{exc.reason}") from exc
        self._store_decision(con, decision)
        return decision

    @staticmethod
    def _store_decision(con, decision: CandidateDecisionV1) -> None:
        try:
            con.execute(
                "INSERT INTO candidate_decision"
                " (decision_digest, decision_json, signer_key_id,"
                "  decision_nonce, consumed_at) VALUES (?, ?, ?, ?, ?)",
                (decision.digest,
                 decision.canonical_bytes().decode("utf-8"),
                 decision.signer_key_id, decision.decision_nonce, _utcnow()))
        except sqlite3.IntegrityError as exc:
            raise CandidateConflict("decision_replayed") from exc

    @staticmethod
    def _store_evidence(con, evidence: CandidateEvidenceV1) -> None:
        con.execute(
            "INSERT OR IGNORE INTO candidate_evidence"
            " (evidence_digest, evidence_json, candidate_id,"
            "  signer_key_id, stored_at) VALUES (?, ?, ?, ?, ?)",
            (evidence.digest, evidence.canonical_bytes().decode("utf-8"),
             evidence.candidate_id, evidence.signer_key_id, _utcnow()))

    def _authenticate_certificate(self, record, refs, erefs, certificate_ref,
                                  con) -> EvaluationCertificateV1:
        """Require a signed, policy-conforming certificate for this candidate."""
        if self._certificate_resolver is None:
            raise CandidateConflict("certificate_resolver_required")
        try:
            certificate = self._certificate_resolver(certificate_ref)
        except CertificateError as exc:
            raise CandidateConflict(
                f"certificate_rejected:{exc.reason}") from exc
        except Exception as exc:
            raise CandidateConflict(
                f"certificate_rejected:{certificate_ref[:12]}") from exc
        if not isinstance(certificate, EvaluationCertificateV1):
            raise CandidateConflict("certificate_rejected:wrong_type")
        if certificate.digest != certificate_ref:
            raise CandidateConflict("certificate_rejected:digest_mismatch")
        validation = self._qualification_validator.validate(
            certificate, record)
        if not validation.ok:
            raise CandidateConflict(
                "certificate_rejected:" + ",".join(validation.failures))
        certificate_receipts = {
            item["receipt_digest"]
            for item in certificate.individual_task_receipts}
        if set(refs) != certificate_receipts:
            raise CandidateConflict("certificate_receipt_mismatch")
        if self._evidence_custody is not None:
            try:
                self._evidence_custody.put(certificate)
                if self._delivery_resolver is None:
                    raise CandidateConflict("delivery_resolver_required")
                for item in certificate.individual_task_receipts:
                    attestation = self._delivery_resolver(
                        item["attestation_digest"])
                    if attestation.digest != item["attestation_digest"] or \
                            attestation.delivery_digest != item["delivery_digest"]:
                        raise CandidateConflict(
                            "delivery_attestation_digest_mismatch")
                    self._evidence_custody.put(attestation)
                self._evidence_custody.link(
                    certificate.digest,
                    candidate_digest=record.digest,
                    receipts=refs, evidence=erefs,
                    deliveries=tuple(
                        item["attestation_digest"]
                        for item in certificate.individual_task_receipts))
            except EvidenceCustodyError as exc:
                raise CandidateConflict(
                    f"evidence_custody_rejected:{exc.reason}") from exc
        elif self._require_evidence_custody:
            raise CandidateConflict("evidence_custody_required")
        self._store_certificate(con, certificate)
        return certificate

    @staticmethod
    def _store_certificate(con, certificate: EvaluationCertificateV1) -> None:
        con.execute(
            "INSERT OR REPLACE INTO candidate_certificate"
            " (certificate_digest, certificate_json, candidate_id,"
            "  signer_key_id, evidence_class, stored_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (certificate.digest,
             certificate.canonical_bytes().decode("utf-8"),
             certificate.candidate_id, certificate.signer_key_id,
             certificate.evidence_class, _utcnow()))

    @staticmethod
    def _load_certificate(con, candidate_id: str) -> EvaluationCertificateV1:
        row = con.execute(
            "SELECT certificate_digest, certificate_json"
            " FROM candidate_certificate WHERE candidate_id=?",
            (candidate_id,)).fetchone()
        if row is None:
            raise CandidateError(f"certificate_missing:{candidate_id}")
        try:
            certificate = EvaluationCertificateV1.from_dict(
                loads_json(row[1].encode("utf-8")))
        except ContractError as exc:
            raise CandidateError(
                f"certificate_tampered:{candidate_id}") from exc
        if certificate.digest != row[0]:
            raise CandidateError(f"certificate_tampered:{candidate_id}")
        return certificate

    def _migrate(self, con) -> None:
        """Seal legacy audit rows and add signed-artifact columns.

        Rows written before the chain existed are sealed over their
        current content — backfill makes them verifiable, it cannot
        prove they were not already altered. A legacy qualified row has
        no decision/evidence, so the projection marks it unbacked and
        serving fails closed until it is re-qualified with signed
        artifacts.

        A database that is *already* chained under the previous digest
        domain is resealed only after that chain verifies end-to-end
        against the old domain. Resealing an unverified chain would
        launder tampering performed before the upgrade, so a broken
        pre-migration chain refuses to open instead. Every reseal is
        recorded in ``registry_migration`` and reported by ``verify()``.
        """
        cols = {row[1] for row in con.execute(
            "PRAGMA table_info(candidate_transition)")}
        wanted = {"prev_digest", "entry_digest", "evidence_refs_json",
                  "decision_digest"}
        missing = wanted - cols
        if not missing:
            return
        chained = {"prev_digest", "entry_digest"} <= cols
        selected = [
            "seq", "candidate_id", "from_state", "to_state",
            "actor_identity", "receipt_refs_json", "note", "committed_at",
        ]
        if chained:
            selected += ["prev_digest", "entry_digest"]
        if "evidence_refs_json" not in missing:
            selected.append("evidence_refs_json")
        if "decision_digest" not in missing:
            selected.append("decision_digest")
        con.execute("BEGIN IMMEDIATE")
        try:
            rows = con.execute(
                "SELECT " + ", ".join(selected)
                + " FROM candidate_transition ORDER BY seq").fetchall()
            if chained:
                self._verify_pre_migration_chain(rows)
            for col in sorted(missing):
                default = "'[]'" if col == "evidence_refs_json" else "''"
                con.execute(
                    f"ALTER TABLE candidate_transition"
                    f" ADD COLUMN {col} TEXT NOT NULL DEFAULT {default}")
            prev = _GENESIS
            for row in rows:
                values = dict(zip(selected, row))
                erefs_json = values.get("evidence_refs_json", "[]")
                decision_digest = values.get("decision_digest", "")
                digest = _entry_digest(
                    values["seq"], values["candidate_id"],
                    values["from_state"], values["to_state"],
                    values["actor_identity"], values["receipt_refs_json"],
                    erefs_json, decision_digest, values["note"],
                    values["committed_at"], prev)
                con.execute(
                    "UPDATE candidate_transition SET prev_digest=?,"
                    " entry_digest=? WHERE seq=?", (prev, digest,
                                                    values["seq"]))
                prev = digest
            con.execute(
                "INSERT OR REPLACE INTO registry_migration"
                " (migration, applied_at, entries, detail) VALUES (?, ?, ?, ?)",
                ("chain-reseal-v1", _utcnow(), len(rows),
                 "resealed_pre_migration_chain" if chained
                 else "backfilled_pre_chain_rows"))
            con.execute("COMMIT")
        except Exception:
            _safe_rollback(con)
            raise

    @staticmethod
    def _verify_pre_migration_chain(rows) -> None:
        """Prove a pre-migration chain is intact before resealing it."""
        prev = _GENESIS
        for row in rows:
            values = dict(zip(
                ("seq", "candidate_id", "from_state", "to_state",
                 "actor_identity", "receipt_refs_json", "note",
                 "committed_at", "prev_digest", "entry_digest"), row[:10]))
            if values["prev_digest"] != prev:
                raise CandidateError(
                    "audit_chain_tampered:pre_migration_link_at_"
                    + str(values["seq"]))
            expected = _legacy_entry_digest(
                values["seq"], values["candidate_id"], values["from_state"],
                values["to_state"], values["actor_identity"],
                values["receipt_refs_json"], values["note"],
                values["committed_at"], values["prev_digest"])
            if values["entry_digest"] != expected:
                raise CandidateError(
                    "audit_chain_tampered:pre_migration_row_at_"
                    + str(values["seq"]))
            prev = values["entry_digest"]


    def _audit(self, con, candidate_id, from_state, to_state,
               actor_identity, receipt_refs, evidence_refs,
               decision_digest, note) -> None:
        refs_json = _json.dumps(list(receipt_refs), sort_keys=True)
        erefs_json = _json.dumps(list(evidence_refs), sort_keys=True)
        at = _utcnow()
        row = con.execute(
            "SELECT COALESCE(MAX(seq), 0) FROM candidate_transition"
        ).fetchone()
        seq = row[0] + 1
        tail = con.execute(
            "SELECT entry_digest FROM candidate_transition"
            " ORDER BY seq DESC LIMIT 1").fetchone()
        prev = tail[0] if tail is not None and tail[0] else _GENESIS
        digest = _entry_digest(
            seq, candidate_id, from_state, to_state, actor_identity,
            refs_json, erefs_json, decision_digest, note, at, prev)
        con.execute(
            "INSERT INTO candidate_transition"
            " (seq, candidate_id, from_state, to_state, actor_identity,"
            "  receipt_refs_json, evidence_refs_json, decision_digest,"
            "  note, committed_at, prev_digest, entry_digest)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (seq, candidate_id, from_state, to_state, actor_identity,
             refs_json, erefs_json, decision_digest, note, at, prev, digest))

    # ------------------------------------------------------------------ #
    # state projection — the state column is never trusted
    # ------------------------------------------------------------------ #
    def _project(self, con=None) -> tuple[dict[str, str], dict[str, str]]:
        """Fold the audit chain and verify the committed state columns.

        Structural checks only: chain integrity, legal edge continuity,
        column agreement, and the presence of the signed-artifact rows a
        serving-state transition cites. Signature/binding checks live in
        ``_verify_serving_basis`` so writers can append without needing
        evaluator custody. Serving transitions that cannot be backed —
        legacy rows with no decision digest, or rows whose cited
        decision/evidence is absent — are returned as ``unbacked`` with
        a reason. They are excluded from serving but stay writable, so a
        takedown under a signed decision remains possible; reads of the
        affected candidate fail closed through ``_verify_serving_basis``.
        """
        con = con or self._conn()
        rows = con.execute(
            "SELECT seq, candidate_id, from_state, to_state,"
            " actor_identity, receipt_refs_json, evidence_refs_json,"
            " decision_digest, note, committed_at, prev_digest, entry_digest"
            " FROM candidate_transition ORDER BY seq").fetchall()
        self._verify_chain(rows)
        states: dict[str, str] = {}
        unbacked: dict[str, str] = {}
        for (seq, cid, frm, to, actor, refs, erefs, dd,
             note, at, prev, dg) in rows:
            current = states.get(cid, "")
            if frm != current:
                raise CandidateError(
                    f"state_projection_invalid:link_at_{seq}")
            if current == "":
                if to != "proposed":
                    raise CandidateError(
                        f"state_projection_invalid:first_edge_at_{seq}")
            elif to not in _EDGES.get(current, frozenset()):
                raise CandidateError(
                    f"state_projection_invalid:edge_at_{seq}")
            if to in SERVING_STATES:
                if not dd:
                    unbacked[cid] = "state_not_decision_backed"
                else:
                    # A decision-backed serving transition supersedes an
                    # earlier unbacked one (e.g. remediating a legacy
                    # qualification by revoking it under a signed decision).
                    unbacked.pop(cid, None)
                    if con.execute(
                        "SELECT 1 FROM candidate_decision WHERE decision_digest=?",
                        (dd,),
                    ).fetchone() is None:
                        unbacked[cid] = "decision_missing"
                    elif to == "qualified":
                        refs_list = _refs(erefs)
                        if not refs_list:
                            unbacked[cid] = "state_not_evidence_backed"
                        elif any(
                            con.execute(
                                "SELECT 1 FROM candidate_evidence"
                                " WHERE evidence_digest=?", (ref,),
                            ).fetchone() is None
                            for ref in refs_list
                        ):
                            unbacked[cid] = "evidence_missing"
            states[cid] = to
        candidate_rows = con.execute(
            "SELECT candidate_id, state FROM candidate").fetchall()
        known = {cid for cid, _ in candidate_rows}
        for cid in states:
            if cid not in known:
                raise CandidateError(f"candidate_row_missing:{cid}")
        for cid, state in candidate_rows:
            if states.get(cid, "") != state:
                raise CandidateError(f"state_projection_drift:{cid}")
        return states, unbacked

    def _verify_serving_basis(self, candidate_id: str, state: str,
                              con) -> dict:
        """Authenticate the signed artifacts behind a serving state."""
        if self._decision_authority is None or self._evidence_authority is None:
            raise CandidateError("serving_integrity_unavailable")
        edge = "qualified" if state == "qualified" else "revoked"
        row = con.execute(
            "SELECT candidate_digest, candidate_json FROM candidate"
            " WHERE candidate_id=?", (candidate_id,)).fetchone()
        if row is None:
            raise CandidateError("candidate_missing")
        record = self._row_to_record(row)
        trow = con.execute(
            "SELECT actor_identity, receipt_refs_json, evidence_refs_json,"
            " decision_digest FROM candidate_transition"
            " WHERE candidate_id=? AND to_state=? ORDER BY seq DESC LIMIT 1",
            (candidate_id, edge)).fetchone()
        if trow is None:
            raise CandidateError(f"state_not_decision_backed:{candidate_id}")
        actor, refs_json, erefs_json, dd = trow
        refs = tuple(_refs(refs_json))
        erefs = tuple(_refs(erefs_json))
        decision = self._load_decision(con, dd)
        try:
            self._decision_authority.check(
                decision, candidate=record,
                from_state="evaluating" if edge == "qualified" else "qualified",
                to_state=edge, receipt_refs=refs, evidence_refs=erefs,
                actor_identity=actor)
        except CandidateAuthorityError as exc:
            raise CandidateError(
                f"decision_not_authenticated:{exc.reason}") from exc
        if edge != "qualified":
            return {"decision_digest": dd, "receipt_refs": refs,
                    "evidence_refs": erefs}
        if self._expected_protocol is None:
            # Qualification requires a pinned protocol; a serving replica
            # that cannot state the expected protocol cannot verify the
            # evidence it is about to serve.
            raise CandidateError("serving_protocol_unpinned")
        covered: set[str] = set()
        for ref in erefs:
            evidence = self._load_evidence(con, ref)
            try:
                self._evidence_authority.check(
                    evidence, candidate=record, receipt_refs=refs,
                    partition=QUALIFICATION_PARTITION)
            except CandidateAuthorityError as exc:
                raise CandidateError(
                    f"evidence_not_authenticated:{exc.reason}") from exc
            if evidence.evaluation_protocol_digest != self._expected_protocol:
                raise CandidateError("evidence_protocol_mismatch")
            covered.update(evidence.receipt_refs)
        if not set(refs) <= covered:
            raise CandidateError("evidence_receipt_not_bound")
        basis = {"decision_digest": dd, "receipt_refs": refs,
                 "evidence_refs": erefs}
        if self._qualification_policy is not None:
            certificate = self._load_certificate(con, candidate_id)
            validation = self._qualification_validator.validate(
                certificate, record)
            if not validation.ok:
                raise CandidateError(
                    "certificate_rejected:"
                    + ",".join(validation.failures))
            certificate_receipts = {
                item["receipt_digest"]
                for item in certificate.individual_task_receipts}
            if certificate_receipts != set(refs):
                raise CandidateError("certificate_receipt_mismatch")
            basis["certificate_digest"] = certificate.digest
            if self._evidence_custody is not None:
                try:
                    status = self._evidence_custody.status(
                        certificate.digest)
                except EvidenceCustodyError as exc:
                    raise CandidateError(
                        f"evidence_custody_unavailable:{exc.reason}") from exc
                if status != "active":
                    raise CandidateError(f"evidence_{status}")
                basis["evidence_custody"] = status
            elif self._require_evidence_custody:
                raise CandidateError("evidence_custody_unconfigured")
        return basis

    @staticmethod
    def _load_decision(con, digest: str) -> CandidateDecisionV1:
        row = con.execute(
            "SELECT decision_json FROM candidate_decision"
            " WHERE decision_digest=?", (digest,)).fetchone()
        if row is None:
            raise CandidateError(f"decision_missing:{digest[:12]}")
        try:
            decision = CandidateDecisionV1.from_dict(
                loads_json(row[0].encode("utf-8")))
        except ContractError as exc:
            raise CandidateError(
                f"decision_tampered:{digest[:12]}") from exc
        if decision.digest != digest:
            raise CandidateError(f"decision_tampered:{digest[:12]}")
        return decision

    @staticmethod
    def _load_evidence(con, digest: str) -> CandidateEvidenceV1:
        row = con.execute(
            "SELECT evidence_json FROM candidate_evidence"
            " WHERE evidence_digest=?", (digest,)).fetchone()
        if row is None:
            raise CandidateError(f"evidence_missing:{digest[:12]}")
        try:
            evidence = CandidateEvidenceV1.from_dict(
                loads_json(row[0].encode("utf-8")))
        except ContractError as exc:
            raise CandidateError(
                f"evidence_tampered:{digest[:12]}") from exc
        if evidence.digest != digest:
            raise CandidateError(f"evidence_tampered:{digest[:12]}")
        return evidence

    # ------------------------------------------------------------------ #
    # reads — digest + state projection re-verified; corrupt rows fail closed
    # ------------------------------------------------------------------ #
    def _row_to_record(self, row) -> CandidateV1:
        record = CandidateV1.from_dict(loads_json(row[1].encode("utf-8")))
        if record.digest != row[0]:
            raise CandidateError(
                f"candidate_tampered:{record.candidate_id}")
        return record

    def get(self, candidate_id: str) -> tuple[CandidateV1, str]:
        with self._read() as con:
            states, unbacked = self._project(con)
            row = con.execute(
                "SELECT candidate_digest, candidate_json FROM candidate"
                " WHERE candidate_id=?", (candidate_id,),
            ).fetchone()
            if row is None or candidate_id not in states:
                raise CandidateError("candidate_missing")
            record = self._row_to_record(row)
            state = states[candidate_id]
            if state == "qualified":
                if candidate_id in unbacked:
                    raise CandidateError(
                        f"{unbacked[candidate_id]}:{candidate_id}")
                self._authority_gate(con)
                self._verify_serving_basis(candidate_id, state, con)
            return record, state

    def lookup(self, candidate_id: str) -> tuple[CandidateV1, str] | None:
        """Return the record and state, or ``None`` when the id is unknown.

        Only an absent id is ``None``; a catalog that fails verification
        still raises, so ingestion cannot mistake tampering for novelty.
        """
        try:
            return self.get(candidate_id)
        except CandidateError as exc:
            if str(exc) == "candidate_missing":
                return None
            raise

    def by_state(self, state: str) -> list[CandidateV1]:
        if state not in STATES:
            raise ContractError(f"unknown candidate state: {state}")
        if state == "qualified":
            return [cand for cand, _ in self.qualified_bases()]
        with self._read() as con:
            states, _ = self._project(con)
            rows = con.execute(
                "SELECT candidate_id, candidate_digest, candidate_json"
                " FROM candidate ORDER BY candidate_id").fetchall()
            return [self._row_to_record(r[1:]) for r in rows
                    if states.get(r[0]) == state]

    def qualified(self) -> list[CandidateV1]:
        return [cand for cand, _ in self.qualified_bases()]

    def qualified_bases(self) -> list[tuple[CandidateV1, dict]]:
        """Qualified records with their authenticated basis, in one fold.

        Serving needs both the record and the signed handles behind it
        (revocation checks). Folding once avoids re-verifying the whole
        catalog and every signature once per candidate.
        """
        with self._read() as con:
            states, unbacked = self._project(con)
            stale = sorted(cid for cid, folded in states.items()
                           if folded == "qualified" and cid in unbacked)
            if stale:
                cid = stale[0]
                raise CandidateError(f"{unbacked[cid]}:{cid}")
            self._authority_gate(con)
            rows = con.execute(
                "SELECT candidate_id, candidate_digest, candidate_json"
                " FROM candidate ORDER BY candidate_id").fetchall()
            return [
                (self._row_to_record(r[1:]),
                 self._verify_serving_basis(r[0], "qualified", con))
                for r in rows if states.get(r[0]) == "qualified"]

    def state_of(self, candidate_id: str) -> str:
        return self.get(candidate_id)[1]

    def serving_basis(self, candidate_id: str) -> dict:
        """Signed handles behind a qualified candidate (for revocation checks)."""
        with self._read() as con:
            states, unbacked = self._project(con)
            state = states.get(candidate_id)
            if state != "qualified" or candidate_id in unbacked:
                raise CandidateError("candidate_not_qualified")
            self._authority_gate(con)
            return self._verify_serving_basis(candidate_id, state, con)

    def check_offline_serving(self, *, offline: bool, now=None) -> dict:
        """Apply the configured offline/revocation-freshness policy."""
        if self._evidence_custody is None:
            if self._require_evidence_custody or offline:
                raise CandidateError("evidence_custody_unconfigured")
            return {"ok": True, "mode": "custody_unconfigured"}
        if self._offline_evidence_policy is None:
            if offline:
                raise CandidateError("offline_evidence_policy_required")
            return {"ok": True, "mode": "online"}
        try:
            return self._evidence_custody.check_offline_serving(
                self._offline_evidence_policy, offline=offline, now=now)
        except EvidenceCustodyError as exc:
            raise CandidateError(f"evidence_custody_rejected:{exc.reason}") \
                from exc

    @property
    def has_evidence_custody(self) -> bool:
        return self._evidence_custody is not None

    def evidence_custody_snapshot(self) -> dict:
        """Current custody heads (genesis when custody is unconfigured)."""
        if self._evidence_custody is None:
            return {
                "revocation_head": _GENESIS,
                "supersession_head": _GENESIS,
                "revocation_count": 0,
                "supersession_count": 0,
                "custody_entry_count": 0,
            }
        try:
            return self._evidence_custody.authority_snapshot()
        except EvidenceCustodyError as exc:
            raise CandidateError(
                f"evidence_custody_unavailable:{exc.reason}") from exc

    def evidence_custody_status(self, digest: str) -> str:
        if self._evidence_custody is None:
            raise CandidateError("evidence_custody_unconfigured")
        try:
            return self._evidence_custody.status(digest)
        except EvidenceCustodyError as exc:
            raise CandidateError(
                f"evidence_custody_unavailable:{exc.reason}") from exc

    def certificate_for(self, candidate_id: str) -> EvaluationCertificateV1:
        """Return the stored certificate for a qualified candidate.

        The certificate is re-parsed and re-digested; a tampered row
        fails closed. Signature/policy validation happens on serving.
        """
        with self._read() as con:
            return self._load_certificate(con, candidate_id)

    def audit(self, candidate_id: str | None = None) -> list[dict]:
        """Return the transition log after verifying the hash chain."""
        with self._read() as con:
            rows = con.execute(
                "SELECT seq, candidate_id, from_state, to_state,"
                " actor_identity, receipt_refs_json, evidence_refs_json,"
                " decision_digest, note, committed_at,"
                " prev_digest, entry_digest"
                " FROM candidate_transition ORDER BY seq").fetchall()
            # The chain is only meaningful end-to-end: verify the full log,
            # then filter — a filtered read must never skip verification.
            self._verify_chain(rows)
            out = []
            for (seq, cid, frm, to, actor, refs, erefs, dd,
                 note, at, prev, dg) in rows:
                if candidate_id is not None and cid != candidate_id:
                    continue
                out.append({
                    "seq": seq, "candidate_id": cid, "from_state": frm,
                    "to_state": to, "actor_identity": actor,
                    "receipt_refs": _refs(refs),
                    "evidence_refs": _refs(erefs),
                    "decision_digest": dd, "note": note,
                    "committed_at": at, "entry_digest": dg})
            return out

    def verify(self) -> dict:
        """Replay the whole catalog: chain, projection, serving basis."""
        with self._read() as con:
            rows = con.execute(
                "SELECT entry_digest FROM candidate_transition"
                " ORDER BY seq").fetchall()
            head = rows[-1][0] if rows else _GENESIS
            migrations = [
                {"migration": migration, "applied_at": at,
                 "entries": entries, "detail": detail}
                for migration, at, entries, detail in con.execute(
                    "SELECT migration, applied_at, entries, detail"
                    " FROM registry_migration ORDER BY migration")]
            problems: list[str] = []
            try:
                states, unbacked = self._project(con)
            except CandidateError as exc:
                return {"ok": False, "entries": len(rows), "head": head,
                        "problems": [str(exc)], "migrations": migrations}
            for cid in sorted(unbacked):
                problems.append(f"{unbacked[cid]}:{cid}")
            for cid, state in states.items():
                if state in SERVING_STATES and cid not in unbacked:
                    try:
                        self._verify_serving_basis(cid, state, con)
                    except CandidateError as exc:
                        problems.append(str(exc))
            try:
                authority = self._authority_gate(con)
            except CandidateError as exc:
                authority = {"ok": False, "reason": str(exc)}
                problems.append(str(exc))
            custody = None
            if self._evidence_custody is not None:
                custody = self._evidence_custody.verify()
                if not custody["ok"]:
                    problems.append("evidence_custody_integrity")
            return {"ok": not problems, "entries": len(rows),
                    "head": head, "problems": problems,
                    "migrations": migrations, "authority": authority,
                    "qualification_mode": self.qualification_mode,
                    "evidence_custody": custody}

    @staticmethod
    def _verify_chain(rows) -> None:
        prev = _GENESIS
        for (seq, cid, frm, to, actor, refs, erefs, dd,
             note, at, p, dg) in rows:
            if p != prev:
                raise CandidateError(
                    f"audit_chain_tampered:link_at_{seq}")
            expected = _entry_digest(seq, cid, frm, to, actor, refs, erefs,
                                     dd, note, at, p)
            if dg != expected or not _HEX.fullmatch(dg):
                raise CandidateError(
                    f"audit_chain_tampered:row_at_{seq}")
            prev = dg


def _safe_rollback(con) -> None:
    try:
        con.execute("ROLLBACK")
    except sqlite3.Error:
        pass
