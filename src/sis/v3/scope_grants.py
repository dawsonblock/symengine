"""Signed scope grants for cross-namespace guidance (v3.1-alpha, PR-03).

``ScopeGrantV1`` binds one *specific* procedure revision to a transfer
target (a registry repository or a whole family). Grants are signed by a
trusted grant-signing key, verified against the ``RepositoryRegistry`` at
both issuance and every serving decision, and their nonces are consumed
atomically inside the authority store transaction — replay is impossible.

Policy:

- Repository-local scope is the default and needs no grant.
- A grant is required for family or cross-repository eligibility, must be
  unexpired, correctly signed, registry-resolvable on both ends, and backed
  by transfer evidence from *genuinely distinct* registry identities —
  comparing tree digests alone is not sufficient.
- A grant binds the exact qualified revision digest; a later revision
  inherits nothing.
"""
from __future__ import annotations

import re
from collections.abc import Mapping

from . import signatures
from .contracts import (
    ContractError,
    OutcomeReceiptV1,
    ScopeGrantV1,
    canonical_json,
)
from .policy import require_permission
from .repository_registry import RepositoryRegistry

_GRANT_DOMAIN = b"sis-v3:scope_grant:1\0"
_MAX_NONCE = 128


class ScopeGrantError(RuntimeError):
    """A scope grant cannot be issued or verified."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def unsigned_grant(
    *,
    grant_id: str,
    procedure_revision_digest: str,
    source_registry_id: str,
    source_family_id: str,
    target_registry_id: str | None = None,
    target_family_id: str | None = None,
    allowed_use: str = "guidance",
    evaluator_protocol_digest: str,
    evidence_receipt_refs: tuple[str, ...] | list[str],
    expires_at: str | None,
    grant_nonce: str,
    signer_key_id: str,
) -> dict:
    return {
        "schema_version": 1,
        "grant_id": grant_id,
        "procedure_revision_digest": procedure_revision_digest,
        "source_registry_id": source_registry_id,
        "source_family_id": source_family_id,
        "target_registry_id": target_registry_id,
        "target_family_id": target_family_id,
        "allowed_use": allowed_use,
        "evaluator_protocol_digest": evaluator_protocol_digest,
        "evidence_receipt_refs": list(evidence_receipt_refs),
        "expires_at": expires_at,
        "grant_nonce": grant_nonce,
        "signer_key_id": signer_key_id,
        "signature": "",
    }


def sign_grant(seed: bytes, unsigned: dict) -> ScopeGrantV1:
    body = _GRANT_DOMAIN + canonical_json(
        {k: v for k, v in unsigned.items() if k != "signature"})
    return ScopeGrantV1.from_dict({
        **unsigned,
        "signature": signatures.sign(seed, body).hex(),
    })


def verify_grant_signature(
    grant: ScopeGrantV1, trusted_signers: Mapping[str, str]
) -> bool:
    public = trusted_signers.get(grant.signer_key_id)
    if public is None:
        return False
    unsigned = {k: v for k, v in grant.to_dict().items() if k != "signature"}
    try:
        body = _GRANT_DOMAIN + canonical_json(unsigned)
        return signatures.verify(
            bytes.fromhex(grant.signature), body, bytes.fromhex(public))
    except (ValueError, TypeError):
        return False


class ScopeGrantAuthority:
    """Issues and verifies signed scope grants against the trusted registry.

    ``trusted_signers`` maps grant-signing key IDs to Ed25519 public keys;
    those keys live in operator custody, never in agent-controlled request
    data. ``revoked_signers``/``revoked_grants`` are honored at verify time
    so invalidation is visible without restarting the process.
    """

    def __init__(
        self,
        registry: RepositoryRegistry,
        *,
        trusted_signers: Mapping[str, str],
        revoked_signers=frozenset(),
        revoked_grants=frozenset(),
        min_transfer_receipts: int = 2,
        now: str | None = None,
    ) -> None:
        if type(min_transfer_receipts) is not int or min_transfer_receipts < 2:
            raise ContractError("min_transfer_receipts must be at least 2")
        self.registry = registry
        self._signers = dict(trusted_signers)
        self._revoked_signers = set(revoked_signers)
        self._revoked_grants = set(revoked_grants)
        self._min_receipts = min_transfer_receipts

    # ---- issuance (operator path; commits go through the authority store) ---- #
    def issue(
        self,
        *,
        actor_role: str,
        seed: bytes,
        record,
        source_registry_id: str,
        target_registry_id: str | None = None,
        target_family_id: str | None = None,
        allowed_use: str = "guidance",
        evaluator_protocol_digest: str,
        evidence_receipts=(),
        expires_at: str | None = None,
        grant_nonce: str,
        grant_id: str | None = None,
        signer_key_id: str | None = None,
    ) -> ScopeGrantV1:
        """Mint a signed grant after full policy verification.

        ``record`` is the qualified procedure revision the grant binds to;
        ``evidence_receipts`` are already-verified ``OutcomeReceiptV1``
        objects whose evaluated trees must resolve to distinct registry
        identities including the grant's source repository.
        """
        require_permission(actor_role, "promotion:approve")
        key_id = signer_key_id or self._default_signer()
        if key_id is None:
            raise ScopeGrantError("no_trusted_signer")
        unsigned = unsigned_grant(
            grant_id=grant_id or "grant-" + grant_nonce,
            procedure_revision_digest=record.digest,
            source_registry_id=source_registry_id,
            source_family_id=self._require_identity(source_registry_id).family_id,
            target_registry_id=target_registry_id,
            target_family_id=target_family_id,
            allowed_use=allowed_use,
            evaluator_protocol_digest=evaluator_protocol_digest,
            evidence_receipt_refs=tuple(r.digest for r in evidence_receipts),
            expires_at=expires_at,
            grant_nonce=grant_nonce,
            signer_key_id=key_id,
        )
        grant = sign_grant(seed, unsigned)
        problems = self.verify(grant, receipts=evidence_receipts,
                               record=record)
        if problems:
            raise ScopeGrantError("grant_policy_rejected", ",".join(problems))
        return grant

    # ---- verification (repeatable; used at issue and at every serve) ---- #
    def verify(
        self,
        grant: ScopeGrantV1,
        *,
        receipts=(),
        record=None,
        now: str | None = None,
        revoked=frozenset(),
        revoked_signers=frozenset(),
    ) -> list[str]:
        """Return a list of problems; empty means the grant is valid.

        ``revoked`` carries committed revocation targets — grant digests
        and receipt digests — so a committed revocation stops the grant
        without touching this authority's in-memory sets. ``revoked_signers``
        carries revoked signer key ids.
        """
        problems: list[str] = []
        if grant.grant_id in self._revoked_grants or grant.digest in revoked:
            problems.append("grant_revoked")
        if grant.signer_key_id in self._revoked_signers or \
                grant.signer_key_id in revoked_signers:
            problems.append("signer_revoked")
        if set(grant.evidence_receipt_refs) & set(revoked):
            problems.append("evidence_revoked")
        if not verify_grant_signature(grant, self._signers):
            problems.append("grant_signature_invalid")
        source = self.registry.resolve(grant.source_registry_id)
        if source is None:
            problems.append("source_identity_unknown")
        elif source.family_id != grant.source_family_id:
            problems.append("source_family_mismatch")
        if grant.target_registry_id is not None:
            target = self.registry.resolve(grant.target_registry_id)
            if target is None:
                problems.append("target_identity_unknown")
            elif target.registry_id == grant.source_registry_id:
                problems.append("self_grant")  # same-identity grant is meaningless
        elif grant.target_family_id is None:
            problems.append("missing_target")
        if now is None:
            from .procedures import _utcnow
            now = _utcnow()
        if grant.expires_at is not None and grant.expires_at <= now:
            problems.append("grant_expired")
        if record is not None and grant.procedure_revision_digest != record.digest:
            problems.append("revision_mismatch")
        # Transfer evidence must come from genuinely distinct registry
        # identities — never tree-digest comparison alone.
        resolved = set()
        for receipt in receipts:
            if not isinstance(receipt, OutcomeReceiptV1):
                problems.append("evidence_malformed")
                continue
            identity = self.registry.identity_by_tree(receipt.evaluated_repo_digest)
            if identity is None:
                problems.append("evidence_identity_unknown")
                continue
            resolved.add(identity.registry_id)
        if len(resolved) < self._min_receipts:
            problems.append("insufficient_transfer_evidence")
        elif grant.source_registry_id not in resolved:
            problems.append("source_not_in_evidence")
        if grant.target_registry_id is not None and \
                grant.target_registry_id not in resolved:
            problems.append("target_not_in_evidence")
        return problems

    def permits(
        self,
        record,
        *,
        owner_identity: str | None,
        requester: str,
        grants,
        receipts_for=None,
        now: str | None = None,
        revoked=frozenset(),
        revoked_signers=frozenset(),
    ) -> bool:
        """True iff a committed, currently-valid grant allows ``requester``.

        ``grants`` is the committed grant list from the authority store;
        ``receipts_for`` optionally resolves evidence receipt digests to
        receipt objects for transfer-evidence rechecks. ``revoked`` /
        ``revoked_signers`` carry committed revocation targets (grant and
        receipt digests, signer key ids). Repository-local access is
        handled by the caller and never requires a grant.
        """
        requester_id = self.registry.resolve(requester)
        if requester_id is None:
            return False
        for grant in grants:
            if grant.procedure_revision_digest != record.digest:
                continue
            if owner_identity is not None and \
                    grant.source_registry_id != owner_identity:
                continue
            receipts = receipts_for(grant) if receipts_for else ()
            if self.verify(grant, receipts=receipts, record=record, now=now,
                           revoked=revoked, revoked_signers=revoked_signers):
                continue
            if grant.target_registry_id == requester_id.registry_id:
                return True
            if grant.target_family_id is not None and \
                    grant.target_family_id == requester_id.family_id:
                return True
        return False

    def revoke_signer(self, key_id: str) -> None:
        self._revoked_signers.add(key_id)

    def revoke_grant(self, grant_id: str) -> None:
        self._revoked_grants.add(grant_id)

    def _default_signer(self) -> str | None:
        return next(iter(self._signers), None)

    def _require_identity(self, registry_id: str):
        identity = self.registry.resolve(registry_id)
        if identity is None:
            raise ScopeGrantError("identity_unknown", registry_id)
        return identity
