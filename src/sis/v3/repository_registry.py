"""Trusted repository-identity registry (v3.1-alpha, PR-03).

``RepositoryIdentityV1`` records are issued and signed by the registry
operator's key — custody outside the agent. The registry is the *only*
source of repository identity for scope decisions: request text, role
strings, sidecar flags, and task metadata never confer identity.

- ``register``/``issue`` mint signed identities; duplicate aliases
  (same ``registry_id`` different body, or same ``base_tree_digest`` /
  ``base_commit`` under a different registry id) are rejected — lineage
  must be unambiguous.
- ``resolve(registry_id)`` and ``identity_by_tree(digest)`` answer only
  with signature-verified entries.
- ``load(path)`` reads a JSONL registry file and fails closed on any
  malformed or unsigned entry — a partial or forged registry is never
  silently accepted.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import signatures
from .contracts import (
    ContractError,
    RepositoryIdentityV1,
    canonical_json,
    loads_json,
)

_IDENTITY_DOMAIN = b"sis-v3:repository_identity:1\0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_MAX_LINE = 128 * 1024


class RegistryError(RuntimeError):
    """The trusted repository registry cannot complete an operation."""


def unsigned_identity(
    *,
    registry_id: str,
    family_id: str,
    base_tree_digest: str,
    base_commit: str | None,
    trust_domain_id: str,
    attestation_digest: str,
    signer_key_id: str,
) -> dict:
    return {
        "schema_version": 1,
        "registry_id": registry_id,
        "family_id": family_id,
        "base_tree_digest": base_tree_digest,
        "base_commit": base_commit,
        "trust_domain_id": trust_domain_id,
        "attestation_digest": attestation_digest,
        "signer_key_id": signer_key_id,
        "signature": "",
    }


def sign_identity(seed: bytes, unsigned: dict) -> RepositoryIdentityV1:
    """Sign an unsigned identity body with a registry-custody key."""
    body = _IDENTITY_DOMAIN + canonical_json(
        {k: v for k, v in unsigned.items() if k != "signature"})
    return RepositoryIdentityV1.from_dict({
        **unsigned,
        "signature": signatures.sign(seed, body).hex(),
    })


def verify_identity(identity: RepositoryIdentityV1, public_hex: str) -> bool:
    """Re-verify a signed identity against the registry key."""
    unsigned = {k: v for k, v in identity.to_dict().items() if k != "signature"}
    try:
        body = _IDENTITY_DOMAIN + canonical_json(unsigned)
        return signatures.verify(
            bytes.fromhex(identity.signature), body, bytes.fromhex(public_hex))
    except (ValueError, TypeError):
        return False


class RepositoryRegistry:
    """In-memory verified view over registry-signed repository identities."""

    def __init__(self, *, registry_public_hex: str) -> None:
        if not (isinstance(registry_public_hex, str)
                and re.fullmatch(r"[0-9a-f]{64}", registry_public_hex)):
            raise ContractError("registry public key must be a SHA-256 hex digest")
        self._public = registry_public_hex
        self._by_id: dict[str, RepositoryIdentityV1] = {}
        self._by_tree: dict[str, str] = {}
        self._by_commit: dict[str, str] = {}

    # ---- operator-side issuance (registry custody, never agent paths) ---- #
    def register(self, identity: RepositoryIdentityV1) -> RepositoryIdentityV1:
        """Admit a signed identity; reject unsigned or aliased entries."""
        if not isinstance(identity, RepositoryIdentityV1):
            raise ContractError("identity must be a RepositoryIdentityV1")
        if not verify_identity(identity, self._public):
            raise RegistryError("identity_signature_invalid")
        existing = self._by_id.get(identity.registry_id)
        if existing is not None:
            if existing.digest == identity.digest:
                return existing  # idempotent re-registration
            raise RegistryError("registry_id_alias_conflict")
        tree_owner = self._by_tree.get(identity.base_tree_digest)
        if tree_owner is not None and tree_owner != identity.registry_id:
            raise RegistryError("base_tree_alias_conflict")
        if identity.base_commit is not None:
            owner = self._by_commit.get(identity.base_commit)
            if owner is not None and owner != identity.registry_id:
                raise RegistryError("base_commit_alias_conflict")
        self._by_id[identity.registry_id] = identity
        self._by_tree[identity.base_tree_digest] = identity.registry_id
        if identity.base_commit is not None:
            self._by_commit[identity.base_commit] = identity.registry_id
        return identity

    def issue(self, seed: bytes, **fields) -> RepositoryIdentityV1:
        """Sign and register a new identity (operator path)."""
        return self.register(sign_identity(seed, unsigned_identity(**fields)))

    # ---- resolution (the only identity source for scope decisions) ---- #
    def resolve(self, registry_id: str) -> RepositoryIdentityV1 | None:
        if not isinstance(registry_id, str) or not _IDENTIFIER.fullmatch(registry_id):
            return None
        return self._by_id.get(registry_id)

    def identity_by_tree(self, tree_digest: str) -> RepositoryIdentityV1 | None:
        registry_id = self._by_tree.get(tree_digest)
        return self._by_id.get(registry_id) if registry_id else None

    def identity_by_commit(self, commit: str) -> RepositoryIdentityV1 | None:
        registry_id = self._by_commit.get(commit)
        return self._by_id.get(registry_id) if registry_id else None

    def __len__(self) -> int:
        return len(self._by_id)

    def __contains__(self, registry_id: str) -> bool:
        return registry_id in self._by_id

    def __iter__(self):
        return iter(sorted(self._by_id.values(), key=lambda i: i.registry_id))

    # ---- persistence: signed JSONL registry file ---- #
    @classmethod
    def load(cls, path: str | Path, *, registry_public_hex: str) -> "RepositoryRegistry":
        registry = cls(registry_public_hex=registry_public_hex)
        path = Path(path)
        if not path.exists():
            return registry
        with open(path, "rb") as handle:
            for position, raw in enumerate(handle):
                line = raw.rstrip(b"\n")
                if not line:
                    continue
                if len(line) > _MAX_LINE:
                    raise RegistryError(f"registry line {position} exceeds size bound")
                try:
                    identity = RepositoryIdentityV1.from_dict(loads_json(line))
                except ContractError as exc:
                    raise RegistryError(
                        f"registry line {position} is undecodable") from exc
                registry.register(identity)  # raises on bad signature/alias
        return registry

    def dump(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            for identity in self:
                handle.write(identity.canonical_bytes() + b"\n")
            handle.flush()
