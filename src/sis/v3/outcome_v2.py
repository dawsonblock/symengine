"""OutcomeEnvelopeV2 issuance and verification (SIS3-131).

The envelope binds the full evaluation context — task, attempt, after-tree,
environment, test-suite commitment, execution receipt, outcome, issuance and
expiry — under one domain-separated Ed25519 signature. Verification checks
the pinned key registry for the exact ``outcome_signing`` purpose, key
validity windows, a revocation set, nonce replay, and expiry. Envelopes are
signed only with evaluator-custodied keys; this module never accepts a
signature produced in the agent process.
"""
from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from . import signatures
from .contracts import ContractError, OutcomeEnvelopeV2, canonical_json
from .verifier import EvaluatorKeyStore

_SIGNATURE_DOMAIN = b"sis-v3:outcome_envelope:1\0"
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


class EnvelopeRejected(RuntimeError):
    """An envelope failed verification."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(
        ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    # Naive timestamps are treated as UTC so comparisons never mix awareness.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class TrustedKey:
    """One pinned evaluator key with its declared purpose and validity window."""

    public_key: str
    purpose: str = "outcome_signing"
    valid_from: str | None = None
    valid_until: str | None = None


class TrustedKeyRegistry:
    """Pinned evaluator keys; callers freeze this set per deployment."""

    def __init__(self, keys: Mapping[str, TrustedKey | Mapping] | None = None) -> None:
        self._keys: dict[str, TrustedKey] = {}
        for key_id, entry in (keys or {}).items():
            if isinstance(entry, TrustedKey):
                self._keys[key_id] = entry
            else:
                self._keys[key_id] = TrustedKey(**entry)

    def add(self, key_id: str, key: TrustedKey) -> None:
        if key_id in self._keys and self._keys[key_id] != key:
            raise EnvelopeRejected("trusted_key_conflict", key_id)
        self._keys[key_id] = key

    def get(self, key_id: str) -> TrustedKey | None:
        return self._keys.get(key_id)


def issue_envelope(
    *,
    keystore: EvaluatorKeyStore,
    task_id: str,
    attempt_id: str,
    evaluated_repo_digest: str,
    environment_digest: str,
    test_suite_commitment: str,
    execution_receipt_digest: str,
    criterion_version: str,
    outcome: str,
    nonce: str | None = None,
    expires_at: str | None = None,
    regression_evidence: tuple[str, ...] = (),
) -> OutcomeEnvelopeV2:
    """Sign a V2 envelope with the evaluator-custodied key."""
    unsigned = {
        "schema_version": 1,
        "envelope_id": "env-" + secrets.token_hex(12),
        "evaluator_identity": "sis-v3-evaluator",
        "task_id": task_id,
        "attempt_id": attempt_id,
        "evaluated_repo_digest": evaluated_repo_digest,
        "environment_digest": environment_digest,
        "test_suite_commitment": test_suite_commitment,
        "execution_receipt_digest": execution_receipt_digest,
        "criterion_version": criterion_version,
        "outcome": outcome,
        "regression_evidence": list(regression_evidence),
        "nonce": nonce or "nonce-" + secrets.token_hex(12),
        "issued_at": _utcnow(),
        "expires_at": expires_at,
        "key_purpose": "outcome_signing",
        "signer_key_id": keystore.key_id,
    }
    signature = signatures.sign(
        keystore._seed or keystore.load_or_create()[0],
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
    ).hex()
    return OutcomeEnvelopeV2.from_dict({**unsigned, "signature": signature})


def verify_envelope(
    envelope: OutcomeEnvelopeV2 | Mapping,
    registry: TrustedKeyRegistry,
    *,
    revoked_keys: frozenset[str] | set[str] = frozenset(),
    seen_nonces: set[str] | None = None,
    at_time: str | None = None,
) -> bool:
    """Fail-closed envelope verification; returns False on any violation."""
    try:
        env = envelope if isinstance(envelope, OutcomeEnvelopeV2) else OutcomeEnvelopeV2.from_dict(envelope)
    except ContractError:
        return False
    key = registry.get(env.signer_key_id)
    if key is None or key.purpose != "outcome_signing":
        return False
    if env.signer_key_id in revoked_keys:
        return False
    try:
        now = _parse(at_time) if at_time else datetime.now(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ContractError("at_time must be an ISO-8601 timestamp") from exc
    try:
        issued = _parse(env.issued_at)
        if key.valid_from and issued < _parse(key.valid_from):
            return False
        if key.valid_until and issued > _parse(key.valid_until):
            return False
        if env.expires_at and now > _parse(env.expires_at):
            return False
    except (ValueError, TypeError):
        return False
    if seen_nonces is not None and env.nonce in seen_nonces:
        return False
    unsigned = env.to_dict()
    unsigned.pop("signature")
    return signatures.verify(
        bytes.fromhex(env.signature),
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
        bytes.fromhex(key.public_key),
    )
