"""Signed isolation attestation (SIS v3.3.3, trust boundary repair).

The local subprocess backend is development-only: it reports factual
capability markers and can never qualify its own containment. Production
classification instead requires an :class:`IsolationAttestationV1` signed
by an independently trusted isolator key that binds the executor backend,
worker identity, sandbox policy and image digests, the command spec, the
workspace input tree, and the exact execution receipt it describes.

``verify_isolation_attestation`` re-checks every binding against the
receipt at hand: an attestation issued for another command, worker, tree,
nonce, policy or receipt does not verify, and neither does an expired or
untrusted signature. Callers feed the boolean verdict to
``classify_execution(production=True, isolation_attested=...)`` — the
receipt's own markers are never consulted as evidence of isolation.
"""
from __future__ import annotations

import secrets
from collections.abc import Mapping
from datetime import datetime, timezone

from . import signatures
from .contracts import (
    ContractError,
    IsolationAttestationV1,
    canonical_json,
)

_SIGNATURE_DOMAIN = b"sis-v3:isolation_attestation:1\0"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def issue_attestation(
    seed: bytes,
    key_id: str,
    *,
    backend: str,
    worker_identity: str,
    policy_digest: str,
    image_digest: str,
    command_spec_digest: str,
    workspace_input_digest: str,
    execution_receipt_digest: str,
    properties: tuple[str, ...] | list[str],
    attestation_id: str | None = None,
    nonce: str | None = None,
    issued_at: str | None = None,
    expires_at: str | None = None,
) -> IsolationAttestationV1:
    """Sign an attestation over one execution's containment facts."""
    unsigned = {
        "schema_version": 1,
        "attestation_id": attestation_id or "att-" + secrets.token_hex(12),
        "backend": backend,
        "worker_identity": worker_identity,
        "policy_digest": policy_digest,
        "image_digest": image_digest,
        "command_spec_digest": command_spec_digest,
        "workspace_input_digest": workspace_input_digest,
        "execution_receipt_digest": execution_receipt_digest,
        "properties": list(properties),
        "issued_at": issued_at or _utcnow(),
        "expires_at": expires_at,
        "nonce": nonce or "nonce-" + secrets.token_hex(12),
        "signer_key_id": key_id,
    }
    signature = signatures.sign(
        seed, _SIGNATURE_DOMAIN + canonical_json(unsigned)).hex()
    return IsolationAttestationV1.from_dict({**unsigned, "signature": signature})


def verify_isolation_attestation(
    attestation: IsolationAttestationV1 | Mapping,
    receipt,
    *,
    trusted_keys: Mapping[str, str],
    allowed_backends=(),
    required_policy_digest: str | None = None,
    at_time: str | None = None,
) -> bool:
    """Fail-closed attestation check; returns False on any violation.

    ``trusted_keys`` maps isolator signer key IDs to public-key hex.
    ``allowed_backends`` is the deployment's executor allowlist — a signed
    attestation for a non-allowlisted backend (including this local
    subprocess) never verifies. ``required_policy_digest`` pins the
    expected sandbox policy when the deployment has one.
    """
    try:
        att = (attestation if isinstance(attestation, IsolationAttestationV1)
               else IsolationAttestationV1.from_dict(attestation))
    except (ContractError, TypeError, KeyError):
        return False
    public_hex = trusted_keys.get(att.signer_key_id)
    if public_hex is None:
        return False
    try:
        public = bytes.fromhex(public_hex)
    except ValueError:
        return False
    if not signatures.is_valid_public_key(public):
        return False
    if allowed_backends and att.backend not in allowed_backends:
        return False
    if (required_policy_digest is not None
            and att.policy_digest != required_policy_digest):
        return False
    try:
        now = _parse(at_time) if at_time else datetime.now(timezone.utc)
        if att.expires_at is not None and now > _parse(att.expires_at):
            return False
        if _parse(att.issued_at) > now:
            return False
    except (ValueError, TypeError):
        return False
    if (att.execution_receipt_digest != getattr(receipt, "digest", None)
            or att.command_spec_digest != getattr(receipt, "command_spec_digest", None)
            or att.workspace_input_digest != getattr(receipt, "before_tree_digest", None)
            or att.worker_identity != getattr(receipt, "worker_identity", None)):
        return False
    unsigned = att.to_dict()
    unsigned.pop("signature")
    return signatures.verify(
        bytes.fromhex(att.signature),
        _SIGNATURE_DOMAIN + canonical_json(unsigned),
        public,
    )
