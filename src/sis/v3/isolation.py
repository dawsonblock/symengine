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
untrusted signature. Production classification goes through
``sis.v3.evaluation_runtime.classify_production_execution``, which takes
the attestation itself; ``classify_execution`` no longer accepts a
caller-supplied verdict, and ``production=True`` always fails closed. The
receipt's own markers are never consulted as evidence of isolation.

The ``nonce`` is a uniqueness tag bound into the signed body, not a
freshness challenge: replay resistance comes from binding the attestation
to ``execution_receipt_digest``, so a captured attestation only ever
describes the one execution it was issued for.

No in-tree backend or signer produces attestations — issuance belongs to
an independently trusted isolator, so production execution stays closed
until one exists.
"""
from __future__ import annotations

import re
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from . import signatures
from .contracts import (
    ContractError,
    IsolationAttestationV1,
    canonical_digest,
    canonical_json,
)

_SIGNATURE_DOMAIN = b"sis-v3:isolation_attestation:1\0"
_DIGEST = re.compile(r"[0-9a-f]{64}")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse(ts: str) -> datetime:
    parsed = datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


@dataclass(frozen=True)
class ProductionIsolationPolicy:
    """Mandatory containment contract for production evaluation (2.1).

    Every field is required. There is no permissive default: a policy
    with no allowed backend, no trusted isolator key, no pinned policy
    or image digest, or no required containment property refuses to
    construct. The policy digest binds the allowlist, trust root, pinned
    digests, required properties and freshness rules, so a verifier can
    name the exact contract it enforced.
    """

    allowed_backends: frozenset[str]
    trusted_keys: Mapping[str, str]
    required_policy_digest: str
    required_image_digest: str
    required_properties: frozenset[str]
    revoked_keys: frozenset[str] = frozenset()
    require_expiry: bool = True
    max_attestation_age_seconds: int | None = 3600

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_backends, frozenset) or not self.allowed_backends:
            raise ContractError("allowed_backends must be a non-empty frozenset")
        for backend in self.allowed_backends:
            if not isinstance(backend, str) or not backend:
                raise ContractError(
                    "allowed_backends entries must be non-empty strings")
        if not isinstance(self.trusted_keys, Mapping) or not self.trusted_keys:
            raise ContractError("trusted_keys must be a non-empty mapping")
        for key_id, public_hex in self.trusted_keys.items():
            if not isinstance(key_id, str) or not key_id:
                raise ContractError("trusted key IDs must be non-empty strings")
            if not isinstance(public_hex, str):
                raise ContractError("trusted keys must be hexadecimal strings")
            try:
                public = bytes.fromhex(public_hex)
            except ValueError as exc:
                raise ContractError("trusted keys must be hexadecimal") from exc
            if len(public) != 32 or not signatures.is_valid_public_key(public):
                raise ContractError(
                    "trusted keys must be valid Ed25519 public keys")
        for name in ("required_policy_digest", "required_image_digest"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _DIGEST.fullmatch(value):
                raise ContractError(
                    f"{name} must be a lowercase SHA-256 digest")
        if (not isinstance(self.required_properties, frozenset)
                or not self.required_properties):
            raise ContractError(
                "required_properties must be a non-empty frozenset")
        for prop in self.required_properties:
            if not isinstance(prop, str) or not prop:
                raise ContractError(
                    "required_properties entries must be non-empty strings")
        if not isinstance(self.revoked_keys, frozenset) or not all(
                isinstance(key, str) and key for key in self.revoked_keys):
            raise ContractError(
                "revoked_keys must be a frozenset of non-empty strings")
        if type(self.require_expiry) is not bool:
            raise ContractError("require_expiry must be boolean")
        if self.max_attestation_age_seconds is not None and (
                type(self.max_attestation_age_seconds) is not int
                or not 1 <= self.max_attestation_age_seconds <= 86_400):
            raise ContractError(
                "max_attestation_age_seconds must be null or in [1,86400]")
        object.__setattr__(
            self, "trusted_keys",
            MappingProxyType(dict(self.trusted_keys)))

    @property
    def digest(self) -> str:
        return canonical_digest("isolation_policy", 1, {
            "allowed_backends": sorted(self.allowed_backends),
            "trusted_keys": {
                key_id: self.trusted_keys[key_id]
                for key_id in sorted(self.trusted_keys)},
            "required_policy_digest": self.required_policy_digest,
            "required_image_digest": self.required_image_digest,
            "required_properties": sorted(self.required_properties),
            "revoked_keys": sorted(self.revoked_keys),
            "require_expiry": self.require_expiry,
            "max_attestation_age_seconds": self.max_attestation_age_seconds,
        })


@dataclass(frozen=True)
class IsolationVerification:
    """Typed verdict of one production isolation check (2.2).

    Production classification accepts only this object, never a boolean:
    it names the receipt, policy, backend, worker, signer and the
    properties that were actually verified.
    """

    ok: bool
    reason: str
    receipt_digest: str | None = None
    attestation_digest: str | None = None
    policy_digest: str | None = None
    backend: str | None = None
    worker_identity: str | None = None
    verified_properties: tuple[str, ...] = ()
    signer_key_id: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "receipt_digest": self.receipt_digest,
            "attestation_digest": self.attestation_digest,
            "policy_digest": self.policy_digest,
            "backend": self.backend,
            "worker_identity": self.worker_identity,
            "verified_properties": list(self.verified_properties),
            "signer_key_id": self.signer_key_id,
        }


def issue_attestation_for_receipt(
    receipt,
    seed: bytes,
    key_id: str,
    *,
    backend: str,
    policy_digest: str,
    image_digest: str,
    properties: tuple[str, ...] | list[str],
    issued_at: str | None = None,
    expires_at: str | None = None,
    nonce: str | None = None,
) -> IsolationAttestationV1:
    """Issue an attestation bound to one execution receipt (2.4).

    The isolator reads the receipt the worker actually produced and
    signs only the containment properties that worker enforced. It
    refuses a receipt that self-reports ``isolation:unverified_local``:
    an isolator must never attest containment the worker did not
    provide.
    """
    errors = set(getattr(receipt, "security_errors", ()) or ())
    if "isolation:unverified_local" in errors:
        raise ContractError("cannot_attest_unverified_local_execution")
    if not properties:
        raise ContractError(
            "properties must name the containment the worker enforced")
    for name in ("worker_identity", "command_spec_digest",
                 "before_tree_digest", "digest"):
        value = getattr(receipt, name, None)
        if not isinstance(value, str) or not value:
            raise ContractError(f"receipt is missing {name}")
    return issue_attestation(
        seed, key_id,
        backend=backend,
        worker_identity=receipt.worker_identity,
        policy_digest=policy_digest,
        image_digest=image_digest,
        command_spec_digest=receipt.command_spec_digest,
        workspace_input_digest=receipt.before_tree_digest,
        execution_receipt_digest=receipt.digest,
        properties=properties,
        issued_at=issued_at,
        expires_at=expires_at,
        nonce=nonce,
    )


def verify_production_isolation(
    attestation: IsolationAttestationV1 | Mapping,
    receipt,
    policy: ProductionIsolationPolicy,
    *,
    at_time: str | None = None,
) -> IsolationVerification:
    """Enforce every mandatory isolation property, or fail closed (2.1)."""
    if not isinstance(policy, ProductionIsolationPolicy):
        raise ContractError("policy must be a ProductionIsolationPolicy")
    try:
        att = (attestation if isinstance(attestation, IsolationAttestationV1)
               else IsolationAttestationV1.from_dict(attestation))
    except (ContractError, TypeError, KeyError):
        return IsolationVerification(ok=False, reason="attestation_malformed")
    receipt_digest = getattr(receipt, "digest", None)
    base = {
        "receipt_digest": receipt_digest,
        "attestation_digest": att.digest,
        "policy_digest": att.policy_digest,
        "backend": att.backend,
        "worker_identity": att.worker_identity,
        "signer_key_id": att.signer_key_id,
    }

    def reject(reason: str) -> IsolationVerification:
        return IsolationVerification(ok=False, reason=reason, **base)

    if att.signer_key_id in policy.revoked_keys:
        return reject("signer_revoked")
    public_hex = policy.trusted_keys.get(att.signer_key_id)
    if public_hex is None:
        return reject("untrusted_signer")
    try:
        public = bytes.fromhex(public_hex)
    except ValueError:
        return reject("untrusted_signer")
    if att.backend not in policy.allowed_backends:
        return reject("backend_not_allowed")
    if att.policy_digest != policy.required_policy_digest:
        return reject("policy_mismatch")
    if att.image_digest != policy.required_image_digest:
        return reject("image_mismatch")
    missing = sorted(policy.required_properties - set(att.properties))
    if missing:
        return reject("missing_property:" + missing[0])
    if policy.require_expiry and att.expires_at is None:
        return reject("attestation_has_no_expiry")
    try:
        now = _parse(at_time) if at_time else datetime.now(timezone.utc)
        issued = _parse(att.issued_at)
        expires = _parse(att.expires_at) if att.expires_at is not None else None
    except (ValueError, TypeError):
        return reject("attestation_timestamp_invalid")
    if issued > now:
        return reject("attestation_issued_in_future")
    if expires is not None and now > expires:
        return reject("attestation_expired")
    if policy.max_attestation_age_seconds is not None:
        age = (now - issued).total_seconds()
        if age > policy.max_attestation_age_seconds:
            return reject("attestation_too_old")
    if att.execution_receipt_digest != receipt_digest:
        return reject("receipt_mismatch")
    if att.command_spec_digest != getattr(receipt, "command_spec_digest", None):
        return reject("command_mismatch")
    if att.workspace_input_digest != getattr(receipt, "before_tree_digest", None):
        return reject("workspace_mismatch")
    if att.worker_identity != getattr(receipt, "worker_identity", None):
        return reject("worker_mismatch")
    unsigned = att.to_dict()
    unsigned.pop("signature")
    if not signatures.verify(
            bytes.fromhex(att.signature),
            _SIGNATURE_DOMAIN + canonical_json(unsigned),
            public):
        return reject("signature_invalid")
    return IsolationVerification(
        ok=True, reason="ok",
        verified_properties=tuple(sorted(policy.required_properties)),
        **base)


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
    policy: ProductionIsolationPolicy | None = None,
) -> bool:
    """Fail-closed attestation check; returns False on any violation.

    ``trusted_keys`` maps isolator signer key IDs to public-key hex.
    ``allowed_backends`` is the deployment's executor allowlist — a signed
    attestation for a non-allowlisted backend (including this local
    subprocess) never verifies. ``required_policy_digest`` pins the
    expected sandbox policy when the deployment has one.

    This permissive form exists for development checks. Production
    callers must pass a :class:`ProductionIsolationPolicy`, which
    requires every backend, image, policy, property, freshness and
    binding field instead of treating omitted arguments as "no
    constraint".
    """
    if policy is not None:
        return verify_production_isolation(
            attestation, receipt, policy, at_time=at_time).ok
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
