"""Signed evidence bindings and transition decisions for candidates.

The candidate registry could authenticate a receipt but not its
relationship to a candidate, and it gated serving-state changes on a
caller-supplied role string. This module supplies the two missing signed
artifacts:

- ``CandidateEvidenceV1`` — the evaluator attests that a set of outcome
  receipts came from evaluating one *exact* candidate on a declared
  partition under a declared protocol. A pass receipt for some other
  task, repository or candidate is not a qualification handle.
- ``CandidateDecisionV1`` — the operator authorizes one *exact*
  candidate transition, binding the candidate record digest, the edge,
  the evidence handles and the actor identity.

Both use the same Ed25519 primitives as the v3.2 authority stack. The
registry authenticates them at write *and* read time: a database writer
who flips a state column or rewrites the audit chain cannot mint serving
authority without the corresponding key.

The registry consumes an authority object through two methods —
``resolve(digest)`` (fetch + authenticate, raising
``CandidateAuthorityError``) and ``check(record, ...)`` (authenticate and
bind to the exact candidate/edge). The classes below are the reference
implementation; deployments may substitute durable-custody equivalents
as long as they preserve those semantics.
"""
from __future__ import annotations

import hashlib
import re
import secrets
from collections.abc import Mapping
from datetime import datetime, timezone

from . import signatures
from .contracts import (
    CandidateDecisionV1,
    CandidateEvidenceV1,
    CandidateV1,
    ContractError,
    canonical_json,
)
from .policy import require_permission

_EVIDENCE_DOMAIN = b"sis-v3:candidate_evidence:1\0"
_DECISION_DOMAIN = b"sis-v3:candidate_decision:1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_PARTITIONS = frozenset({"development", "holdout", "monitoring"})
QUALIFICATION_PARTITION = "holdout"


class CandidateAuthorityError(RuntimeError):
    """A signed candidate artifact is missing, forged, stale, or unbound."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Lexicographic comparison is wrong for the timestamps the contracts
    accept: ``2026-10-25T10:00:00+05:00`` precedes ``2026-10-25T08:00:00Z``
    in time but sorts after it as text, and a fractional second sorts
    before the trailing ``Z``. Expiry is compared as instants, never as
    strings.
    """
    if not isinstance(value, str) or not value:
        raise CandidateAuthorityError("timestamp_invalid")
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise CandidateAuthorityError("timestamp_invalid") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _expired(expires_at: str | None, now: str) -> bool:
    return expires_at is not None and _instant(expires_at) <= _instant(now)


def _check_lifetime(issued_at: str, expires_at: str | None) -> None:
    try:
        expired = expires_at is not None and \
            _instant(expires_at) <= _instant(issued_at)
    except CandidateAuthorityError as exc:
        raise ContractError(
            "issued_at/expires_at must be ISO-8601 timestamps") from exc
    if expired:
        raise ContractError("expires_at must be later than issued_at")


def _body(record, domain: bytes) -> bytes:
    unsigned = {k: v for k, v in record.to_dict().items() if k != "signature"}
    return domain + canonical_json(unsigned)


def _check_digest(value, name) -> None:
    if not (isinstance(value, str) and _HEX.fullmatch(value)):
        raise ContractError(f"{name} must be a lowercase SHA-256 digest")


def _as_candidate(candidate) -> CandidateV1:
    if not isinstance(candidate, CandidateV1):
        candidate = CandidateV1.from_dict(candidate)
    return candidate


class CandidateEvidenceAuthority:
    """Issues and verifies evaluator-signed candidate evidence bindings."""

    def __init__(
        self,
        *,
        trusted_evaluator_keys: Mapping[str, str],
        revoked_evaluator_keys=frozenset(),
        now: str | None = None,
    ) -> None:
        self._trusted = dict(trusted_evaluator_keys)
        self._revoked = set(revoked_evaluator_keys)
        self._fixed_now = now
        # Process-lifetime resolution store; a durable-custody deployment
        # replaces it rather than growing it without bound.
        self._journal: dict[str, CandidateEvidenceV1] = {}

    # ---- issuance (evaluator custody) --------------------------------- #
    def issue(
        self,
        *,
        seed: bytes,
        candidate,
        receipt_refs,
        evaluation_protocol_digest: str,
        partition: str = QUALIFICATION_PARTITION,
        evaluator_identity: str = "sis-v3-evaluator",
        outcome: str = "pass",
        issued_at: str | None = None,
        expires_at: str | None = None,
        evidence_id: str | None = None,
        signer_key_id: str | None = None,
        actor_role: str = "evaluator",
    ) -> CandidateEvidenceV1:
        """Mint a signed binding of ``receipt_refs`` to one candidate."""
        require_permission(actor_role, "outcome:sign")
        candidate = _as_candidate(candidate)
        refs = tuple(dict.fromkeys(receipt_refs or ()))
        if not refs:
            raise ContractError("evidence requires at least one receipt")
        for ref in refs:
            _check_digest(ref, "receipt_refs[]")
        _check_digest(evaluation_protocol_digest,
                      "evaluation_protocol_digest")
        if partition not in _PARTITIONS:
            raise ContractError(f"unsupported evidence partition: {partition}")
        key_id = self._signer(signer_key_id, "no_trusted_evaluator_key")
        issued = issued_at or self._now()
        _check_lifetime(issued, expires_at)
        content = {
            "schema_version": 1,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.digest,
            "content_digest": candidate.content_digest,
            "receipt_refs": list(refs),
            "evaluation_protocol_digest": evaluation_protocol_digest,
            "partition": partition,
            "outcome": outcome,
            "evaluator_identity": evaluator_identity,
            "issued_at": issued,
            "expires_at": expires_at,
            "signer_key_id": key_id,
        }
        eid = evidence_id or (
            "cev-" + hashlib.sha256(
                canonical_json(content)).hexdigest()[:16])
        unsigned = {**content, "evidence_id": eid}
        evidence = CandidateEvidenceV1.from_dict({
            **unsigned,
            "signature": signatures.sign(
                seed, _EVIDENCE_DOMAIN + canonical_json(unsigned)).hex(),
        })
        self.authenticate(evidence)
        self._journal[evidence.digest] = evidence
        return evidence

    # ---- verification -------------------------------------------------- #
    def authenticate(self, evidence: CandidateEvidenceV1 | Mapping,
                     *, now: str | None = None) -> CandidateEvidenceV1:
        if not isinstance(evidence, CandidateEvidenceV1):
            evidence = CandidateEvidenceV1.from_dict(evidence)
        public = self._trusted.get(evidence.signer_key_id)
        if public is None:
            raise CandidateAuthorityError("evidence_signer_untrusted")
        if evidence.signer_key_id in self._revoked:
            raise CandidateAuthorityError("evidence_signer_revoked")
        try:
            valid = signatures.verify(
                bytes.fromhex(evidence.signature),
                _body(evidence, _EVIDENCE_DOMAIN),
                bytes.fromhex(public))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise CandidateAuthorityError("evidence_signature_invalid")
        if _expired(evidence.expires_at, now or self._now()):
            raise CandidateAuthorityError("evidence_expired")
        return evidence

    def resolve(self, digest: str) -> CandidateEvidenceV1:
        evidence = self._journal.get(digest)
        if evidence is None:
            raise CandidateAuthorityError("evidence_missing")
        return self.authenticate(evidence)

    def check(
        self,
        evidence: CandidateEvidenceV1 | Mapping,
        *,
        candidate,
        receipt_refs=None,
        partition: str = QUALIFICATION_PARTITION,
        now: str | None = None,
    ) -> CandidateEvidenceV1:
        """Authenticate and bind one evidence record to ``candidate``."""
        candidate = _as_candidate(candidate)
        evidence = self.authenticate(evidence, now=now)
        if evidence.candidate_digest != candidate.digest:
            raise CandidateAuthorityError("evidence_candidate_digest_mismatch")
        if evidence.content_digest != candidate.content_digest:
            raise CandidateAuthorityError("evidence_content_digest_mismatch")
        if evidence.candidate_id != candidate.candidate_id:
            raise CandidateAuthorityError("evidence_candidate_id_mismatch")
        if evidence.partition != partition:
            raise CandidateAuthorityError(
                f"evidence_partition_not_{partition}")
        if evidence.outcome != "pass":
            raise CandidateAuthorityError("evidence_outcome_not_pass")
        if receipt_refs is not None and not (
                set(receipt_refs) <= set(evidence.receipt_refs)):
            raise CandidateAuthorityError("evidence_receipt_not_bound")
        return evidence

    def revoke_signer(self, key_id: str) -> None:
        self._revoked.add(key_id)

    def _signer(self, signer_key_id: str | None, missing: str) -> str:
        """Resolve the signing key; an ambiguous trust set is refused."""
        if signer_key_id is not None:
            return signer_key_id
        if len(self._trusted) == 1:
            return next(iter(self._trusted))
        raise CandidateAuthorityError(
            missing if not self._trusted else "signer_key_id_required")

    def _now(self) -> str:
        return self._fixed_now or _utcnow()


class CandidateDecisionAuthority:
    """Issues and verifies operator-signed candidate transition decisions."""

    def __init__(
        self,
        *,
        trusted_operator_keys: Mapping[str, str],
        revoked_operator_keys=frozenset(),
        now: str | None = None,
    ) -> None:
        self._trusted = dict(trusted_operator_keys)
        self._revoked = set(revoked_operator_keys)
        self._fixed_now = now
        # Process-lifetime resolution store; a durable-custody deployment
        # replaces it rather than growing it without bound.
        self._journal: dict[str, CandidateDecisionV1] = {}

    # ---- issuance (operator custody) ---------------------------------- #
    def issue(
        self,
        *,
        seed: bytes,
        candidate,
        from_state: str,
        to_state: str,
        actor_identity: str,
        receipt_refs=(),
        evidence_refs=(),
        decision_nonce: str | None = None,
        issued_at: str | None = None,
        expires_at: str | None = None,
        decision_id: str | None = None,
        signer_key_id: str | None = None,
        actor_role: str = "operator",
    ) -> CandidateDecisionV1:
        """Mint a signed authorization for one exact candidate edge."""
        require_permission(actor_role, "promotion:approve")
        candidate = _as_candidate(candidate)
        receipts = tuple(dict.fromkeys(receipt_refs or ()))
        evidence = tuple(dict.fromkeys(evidence_refs or ()))
        for ref in receipts + evidence:
            _check_digest(ref, "decision refs[]")
        key_id = self._signer(signer_key_id, "no_trusted_operator_key")
        nonce = decision_nonce or secrets.token_hex(16)
        issued = issued_at or self._now()
        _check_lifetime(issued, expires_at)
        did = decision_id or ("cdec-" + hashlib.sha256(
            canonical_json({
                "candidate_digest": candidate.digest,
                "from_state": from_state,
                "to_state": to_state,
                "receipt_refs": list(receipts),
                "evidence_refs": list(evidence),
                "actor_identity": actor_identity,
                "decision_nonce": nonce,
            })).hexdigest()[:16])
        unsigned = {
            "schema_version": 1,
            "decision_id": did,
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.digest,
            "content_digest": candidate.content_digest,
            "from_state": from_state,
            "to_state": to_state,
            "receipt_refs": list(receipts),
            "evidence_refs": list(evidence),
            "actor_identity": actor_identity,
            "decision_nonce": nonce,
            "issued_at": issued,
            "expires_at": expires_at,
            "signer_key_id": key_id,
        }
        decision = CandidateDecisionV1.from_dict({
            **unsigned,
            "signature": signatures.sign(
                seed, _DECISION_DOMAIN + canonical_json(unsigned)).hex(),
        })
        self.authenticate(decision)
        self._journal[decision.digest] = decision
        return decision

    # ---- verification -------------------------------------------------- #
    def authenticate(self, decision: CandidateDecisionV1 | Mapping,
                     *, now: str | None = None) -> CandidateDecisionV1:
        if not isinstance(decision, CandidateDecisionV1):
            decision = CandidateDecisionV1.from_dict(decision)
        public = self._trusted.get(decision.signer_key_id)
        if public is None:
            raise CandidateAuthorityError("decision_signer_untrusted")
        if decision.signer_key_id in self._revoked:
            raise CandidateAuthorityError("decision_signer_revoked")
        try:
            valid = signatures.verify(
                bytes.fromhex(decision.signature),
                _body(decision, _DECISION_DOMAIN),
                bytes.fromhex(public))
        except (ValueError, TypeError):
            valid = False
        if not valid:
            raise CandidateAuthorityError("decision_signature_invalid")
        if _expired(decision.expires_at, now or self._now()):
            raise CandidateAuthorityError("decision_expired")
        return decision

    def resolve(self, digest: str) -> CandidateDecisionV1:
        decision = self._journal.get(digest)
        if decision is None:
            raise CandidateAuthorityError("decision_missing")
        return self.authenticate(decision)

    def check(
        self,
        decision: CandidateDecisionV1 | Mapping,
        *,
        candidate,
        from_state: str,
        to_state: str,
        receipt_refs=(),
        evidence_refs=(),
        actor_identity: str | None = None,
        now: str | None = None,
    ) -> CandidateDecisionV1:
        """Authenticate and bind one decision to the exact pending edge."""
        candidate = _as_candidate(candidate)
        decision = self.authenticate(decision, now=now)
        if decision.candidate_digest != candidate.digest:
            raise CandidateAuthorityError("decision_candidate_digest_mismatch")
        if decision.content_digest != candidate.content_digest:
            raise CandidateAuthorityError("decision_content_digest_mismatch")
        if decision.candidate_id != candidate.candidate_id:
            raise CandidateAuthorityError("decision_candidate_id_mismatch")
        if decision.from_state != from_state or decision.to_state != to_state:
            raise CandidateAuthorityError("decision_edge_mismatch")
        if set(decision.receipt_refs) != set(receipt_refs or ()):
            raise CandidateAuthorityError("decision_receipts_mismatch")
        if set(decision.evidence_refs) != set(evidence_refs or ()):
            raise CandidateAuthorityError("decision_evidence_mismatch")
        if actor_identity is not None and \
                decision.actor_identity != actor_identity:
            raise CandidateAuthorityError("decision_actor_mismatch")
        return decision

    def revoke_signer(self, key_id: str) -> None:
        self._revoked.add(key_id)

    def _signer(self, signer_key_id: str | None, missing: str) -> str:
        """Resolve the signing key; an ambiguous trust set is refused."""
        if signer_key_id is not None:
            return signer_key_id
        if len(self._trusted) == 1:
            return next(iter(self._trusted))
        raise CandidateAuthorityError(
            missing if not self._trusted else "signer_key_id_required")

    def _now(self) -> str:
        return self._fixed_now or _utcnow()
