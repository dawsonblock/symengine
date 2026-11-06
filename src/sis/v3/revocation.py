"""Signed revocations (v3.1-alpha, PR-04).

``RevocationV1`` records are minted under revocation-custody keys and
committed transactionally to the authority store. Kinds:

- ``record``  — deny a specific procedure revision digest at serving.
- ``receipt`` — revoke evidence; citing qualified records are cascade-
  suspended through signed decisions, and grants whose
  ``evidence_receipt_refs`` include it stop permitting.
- ``grant``   — revoke a committed ``ScopeGrantV1`` by digest.
- ``signer``  — revoke a grant/registry signer key id; every object it
  signed stops verifying.

Committed rows are consulted on every request, so revocation takes effect
without restarting the serving boundary.
"""
from __future__ import annotations

from collections.abc import Mapping

from . import signatures
from .contracts import RevocationV1, canonical_json
from .policy import require_permission
from .procedures import _utcnow

_REVOCATION_DOMAIN = b"sis-v3:revocation:1\0"


def unsigned_revocation(
    *,
    revocation_id: str,
    kind: str,
    target_digest: str | None = None,
    target_id: str | None = None,
    reason: str = "",
    actor_identity: str,
    issued_at: str,
    signer_key_id: str,
) -> dict:
    return {
        "schema_version": 1,
        "revocation_id": revocation_id,
        "kind": kind,
        "target_digest": target_digest,
        "target_id": target_id,
        "reason": reason,
        "actor_identity": actor_identity,
        "issued_at": issued_at,
        "signer_key_id": signer_key_id,
        "signature": "",
    }


def sign_revocation(seed: bytes, unsigned: dict) -> RevocationV1:
    body = _REVOCATION_DOMAIN + canonical_json(
        {k: v for k, v in unsigned.items() if k != "signature"})
    return RevocationV1.from_dict({
        **unsigned,
        "signature": signatures.sign(seed, body).hex(),
    })


def verify_revocation_signature(
    revocation: RevocationV1, trusted_signers: Mapping[str, str]
) -> bool:
    public = trusted_signers.get(revocation.signer_key_id)
    if public is None:
        return False
    unsigned = {k: v for k, v in revocation.to_dict().items()
                if k != "signature"}
    try:
        body = _REVOCATION_DOMAIN + canonical_json(unsigned)
        return signatures.verify(
            bytes.fromhex(revocation.signature), body, bytes.fromhex(public))
    except (ValueError, TypeError):
        return False


class RevocationAuthority:
    """Issues and verifies signed revocations under operator custody."""

    def __init__(self, *, trusted_signers: Mapping[str, str]) -> None:
        self._signers = dict(trusted_signers)

    def issue(
        self,
        *,
        actor_role: str,
        seed: bytes,
        revocation_id: str,
        kind: str,
        target_digest: str | None = None,
        target_id: str | None = None,
        reason: str = "",
        actor_identity: str,
        signer_key_id: str | None = None,
        issued_at: str | None = None,
    ) -> RevocationV1:
        require_permission(actor_role, "promotion:approve")
        key_id = signer_key_id or next(iter(self._signers), None)
        if key_id is None:
            raise ValueError("no_trusted_revocation_signer")
        unsigned = unsigned_revocation(
            revocation_id=revocation_id, kind=kind,
            target_digest=target_digest, target_id=target_id,
            reason=reason, actor_identity=actor_identity,
            issued_at=issued_at or _utcnow(), signer_key_id=key_id)
        revocation = sign_revocation(seed, unsigned)
        if not self.verify(revocation):
            raise ValueError("issued revocation failed self-verification")
        return revocation

    def verify(self, revocation: RevocationV1) -> bool:
        return verify_revocation_signature(revocation, self._signers)
