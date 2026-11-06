"""Authenticated execution identity for repository-aware serving.

The serving gateway must never infer repository identity from task text,
a caller-supplied name, or a tree digest in a prompt. The trusted agent
adapter issues an :class:`ExecutionIdentityV1` binding the requester,
the registry-resolved repository, the exact commit/tree, workspace, task,
family, harness and a session nonce. The gateway verifies that record
against the trusted repository registry and rejects contradictory claims.

A candidate may be authorized for a repository family rather than one
specific commit, but the *current* execution identity still has to be
authenticated. On any failure the gateway returns an abstention with no
actionable candidate instructions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from . import signatures
from .contracts import ContractError, ExecutionIdentityV1, canonical_json

IDENTITY_DOMAIN = b"sis-v3:execution_identity:1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_CLOCK_SKEW_SECONDS = 300
DEFAULT_MAX_IDENTITY_LIFETIME_SECONDS = 3600


class ExecutionIdentityError(RuntimeError):
    """An execution context is missing, forged, stale or contradictory."""

    def __init__(self, reason: str, detail: str = "") -> None:
        self.reason = reason
        super().__init__(f"{reason}: {detail}" if detail else reason)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _instant(value: str) -> datetime:
    raw = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(raw)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def identity_body(identity: ExecutionIdentityV1 | dict) -> bytes:
    body = identity.to_dict() if isinstance(
        identity, ExecutionIdentityV1) else dict(identity)
    body.pop("attestation", None)
    return IDENTITY_DOMAIN + canonical_json(body)


def sign_execution_identity(seed: bytes, **fields) -> ExecutionIdentityV1:
    fields.setdefault("schema_version", 1)
    unsigned = {k: v for k, v in fields.items() if k != "attestation"}
    attestation = signatures.sign(seed, identity_body(unsigned)).hex()
    return ExecutionIdentityV1.from_dict(
        {**unsigned, "attestation": attestation})


def verify_execution_identity(
    identity: ExecutionIdentityV1, public_hex: str
) -> bool:
    try:
        return signatures.verify(
            bytes.fromhex(identity.attestation),
            identity_body(identity), bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class ExecutionIdentityResult:
    ok: bool
    reason: str = "ok"
    detail: str = ""
    identity: ExecutionIdentityV1 | None = None
    repository_identity: object | None = None

    def require_ok(self) -> "ExecutionIdentityResult":
        if not self.ok:
            raise ExecutionIdentityError(self.reason, self.detail)
        return self

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reason": self.reason,
            "detail": self.detail,
            "identity_digest": self.identity.digest
            if self.identity is not None else None,
            "repository_id": self.identity.repository_id
            if self.identity is not None else None,
            "task_id": self.identity.task_id
            if self.identity is not None else None,
        }


class ExecutionIdentityAuthority:
    """Issue and verify harness-signed execution contexts."""

    def __init__(
        self,
        *,
        trusted_harness_keys: dict[str, str],
        repository_registry,
        clock: Callable[[], str] = _utcnow,
        max_identity_lifetime_seconds: int = DEFAULT_MAX_IDENTITY_LIFETIME_SECONDS,
    ) -> None:
        if not trusted_harness_keys:
            raise ExecutionIdentityError("trusted_harness_keys_required")
        for key_id, public_hex in trusted_harness_keys.items():
            if not (isinstance(public_hex, str) and _HEX.fullmatch(public_hex)):
                raise ExecutionIdentityError("harness_public_key_invalid")
        if type(max_identity_lifetime_seconds) is not int or \
                max_identity_lifetime_seconds < 1:
            raise ExecutionIdentityError(
                "max_identity_lifetime_invalid")
        self._keys = dict(trusted_harness_keys)
        self.registry = repository_registry
        self._clock = clock
        self.max_identity_lifetime_seconds = max_identity_lifetime_seconds

    def issue(self, seed: bytes, *, signer_key_id: str, **fields):
        if signer_key_id not in self._keys:
            raise ExecutionIdentityError("signer_key_not_trusted")
        identity = sign_execution_identity(
            seed, signer_key_id=signer_key_id, **fields)
        if not self.verify(identity).ok:
            raise ExecutionIdentityError("issued_identity_did_not_verify")
        return identity

    def verify(
        self,
        identity: ExecutionIdentityV1 | dict | None,
        *,
        used_nonces: set | None = None,
        expected_repository_id: str | None = None,
        expected_tree_digest: str | None = None,
        expected_commit: str | None = None,
        expected_task_id: str | None = None,
        expected_task_family: str | None = None,
        expected_requester: str | None = None,
    ) -> ExecutionIdentityResult:
        if identity is None:
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_missing")
        if not isinstance(identity, ExecutionIdentityV1):
            try:
                identity = ExecutionIdentityV1.from_dict(identity)
            except ContractError as exc:
                return ExecutionIdentityResult(
                    ok=False, reason="execution_identity_malformed",
                    detail=str(exc))
        public_hex = self._keys.get(identity.signer_key_id)
        if public_hex is None or not verify_execution_identity(
                identity, public_hex):
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_signature_invalid",
                identity=identity)
        now = _instant(self._clock())
        try:
            issued = _instant(identity.issued_at)
            expires = _instant(identity.expires_at)
        except (TypeError, ValueError):
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_timestamp_invalid",
                identity=identity)
        if issued > now:
            if (issued - now).total_seconds() > _CLOCK_SKEW_SECONDS:
                return ExecutionIdentityResult(
                    ok=False, reason="execution_identity_issued_in_future",
                    identity=identity)
        if expires <= now:
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_expired",
                identity=identity)
        if expires <= issued:
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_expiry_invalid",
                identity=identity)
        if (expires - issued).total_seconds() > \
                self.max_identity_lifetime_seconds:
            return ExecutionIdentityResult(
                ok=False, reason="execution_identity_lifetime_exceeded",
                detail=f"lifetime exceeds"
                       f" {self.max_identity_lifetime_seconds}s",
                identity=identity)
        if used_nonces is not None:
            if identity.session_nonce in used_nonces:
                return ExecutionIdentityResult(
                    ok=False, reason="execution_identity_replayed",
                    identity=identity)
        repository = self.registry.resolve(identity.repository_id) \
            if self.registry is not None else None
        if repository is None:
            return ExecutionIdentityResult(
                ok=False, reason="repository_identity_unknown",
                identity=identity)
        if identity.repository_tree_digest != repository.base_tree_digest:
            return ExecutionIdentityResult(
                ok=False, reason="repository_tree_mismatch",
                identity=identity, repository_identity=repository)
        if repository.base_commit is not None:
            if identity.repository_commit != repository.base_commit:
                return ExecutionIdentityResult(
                    ok=False, reason="repository_commit_mismatch",
                    identity=identity, repository_identity=repository)
        if identity.task_family != repository.family_id:
            return ExecutionIdentityResult(
                ok=False, reason="repository_family_mismatch",
                identity=identity, repository_identity=repository)
        if expected_repository_id is not None and \
                identity.repository_id != expected_repository_id:
            return ExecutionIdentityResult(
                ok=False, reason="repository_identity_contradiction",
                identity=identity, repository_identity=repository)
        if expected_tree_digest is not None and \
                identity.repository_tree_digest != expected_tree_digest:
            return ExecutionIdentityResult(
                ok=False, reason="repository_tree_contradiction",
                identity=identity, repository_identity=repository)
        if expected_commit is not None and \
                identity.repository_commit != expected_commit:
            return ExecutionIdentityResult(
                ok=False, reason="repository_commit_contradiction",
                identity=identity, repository_identity=repository)
        if expected_task_id is not None and \
                identity.task_id != expected_task_id:
            return ExecutionIdentityResult(
                ok=False, reason="task_identity_contradiction",
                identity=identity, repository_identity=repository)
        if expected_task_family is not None and \
                identity.task_family != expected_task_family:
            return ExecutionIdentityResult(
                ok=False, reason="task_family_contradiction",
                identity=identity, repository_identity=repository)
        if expected_requester is not None and \
                identity.requester_identity != expected_requester:
            return ExecutionIdentityResult(
                ok=False, reason="requester_identity_contradiction",
                identity=identity, repository_identity=repository)
        return ExecutionIdentityResult(
            ok=True, identity=identity, repository_identity=repository)


__all__ = [
    "ExecutionIdentityAuthority",
    "ExecutionIdentityError",
    "ExecutionIdentityResult",
    "IDENTITY_DOMAIN",
    "identity_body",
    "sign_execution_identity",
    "verify_execution_identity",
]
