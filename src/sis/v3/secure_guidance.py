"""Production-oriented fail-closed guidance boundary.

The legacy phase-gated gateway moved to ``sis.v3.compat.guidance_gateway``
for fixture compatibility. Production code uses ``StrictGuidanceGateway``
over an ``AuthorityDB`` transactional store: verified promotion decisions
are necessary for any qualified record to exist at all, and
family/cross-repository retrieval requires a signed ``ScopeGrantV1`` that
re-verifies (signature, registry lineage, expiry, distinct transfer
evidence) on every request through ``ScopeGrantAuthority``.
"""
from __future__ import annotations

import os
from pathlib import Path

from .authority import AuthorizedCatalogView, AuthorityError
from .authority_db import AuthorityDB
from .contracts import GuidanceRequestV1, GuidanceV1, canonical_digest
from .guidance import _abstain, sis_recommend
from .promotion import PromotionController
from .catalog import Catalog


class _ScopedCatalog:
    def __init__(self, view: AuthorizedCatalogView, allowed):
        self._view = view
        self._allowed = frozenset(allowed)

    def by_status(self, status):
        return [r for r in self._view.by_status(status) if r.procedure_id in self._allowed]

    def all_latest(self):
        return [r for r in self._view.all_latest() if r.procedure_id in self._allowed]

    def qualified_head_digest(self):
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r.digest for r in self.by_status("qualified")),
        })


class StrictGuidanceGateway:
    """Read-only, decision-backed serving. No direct store write grants authority.

    Repository identity comes only from the trusted ``RepositoryRegistry``
    (or ``ScopeGrantAuthority.registry``): a caller-supplied
    ``repository_id`` that the registry cannot resolve abstains the whole
    request. Repository-local scope is the default and needs no grant —
    the procedure's configured owner must equal the resolved identity.
    Beyond repo-local, a committed ``ScopeGrantV1`` binding the *exact
    serving revision* must pass ``ScopeGrantAuthority.permits``. Missing,
    ambiguous, expired or forged lineage always abstains — it never
    degrades to permissive.
    """

    def __init__(self, store: AuthorityDB, authority: PromotionController,
                 *, catalog: Catalog | None = None,
                 procedure_owners: dict[str, str] | None = None,
                 repository_registry=None,
                 grant_authority=None,
                 revoked_digests: frozenset[str] = frozenset(),
                 kill_switch_path: str | Path | None = None):
        self._view = AuthorizedCatalogView(store, authority)
        self._store = store
        self._catalog = catalog
        self._owners = dict(procedure_owners or {})
        self._grants = grant_authority
        self._registry = repository_registry or getattr(
            grant_authority, "registry", None)
        self._revoked = revoked_digests
        self._kill = Path(kill_switch_path) if kill_switch_path else None

    def recommend(self, request: GuidanceRequestV1 | dict, *, repository_id: str,
                  files_present=(), symbols_extra=(), now=None) -> GuidanceV1:
        if os.environ.get("SIS3_DISABLE") or (self._kill and self._kill.exists()):
            return _abstain("catalog_unavailable", ("SIS guidance disabled by operator.",))
        if not repository_id:
            return _abstain("insufficient_support", ("Trusted repository identity is required.",))
        if self._registry is not None:
            requester = self._registry.resolve(repository_id)
            if requester is None:
                return _abstain("insufficient_support",
                                ("Repository identity is not in the trusted registry.",))
            requester_id = requester.registry_id
        else:
            requester_id = repository_id
        try:
            committed = self._committed_revocations()
            records = self._view.by_status("qualified")
            # Revoked records are denied outright; records citing revoked
            # evidence are denied immediately and suspended via cascade.
            deny = set(self._revoked) | committed["record"]
            for record in records:
                if (set(record.evidence_refs) | set(record.counterexample_refs)) \
                        & committed["receipt"]:
                    deny.add(record.digest)
            allowed = []
            for record in records:
                if record.digest in deny:
                    continue
                # Never infer authorization from untrusted task text.
                owner = self._owners.get(record.procedure_id)
                if owner is not None and owner == requester_id:
                    allowed.append(record.procedure_id)
                elif self._grant_permits(
                        record, owner, requester_id, now=now,
                        revoked=committed["grant"] | committed["receipt"],
                        revoked_signers=committed["signer"]):
                    allowed.append(record.procedure_id)
            scoped = _ScopedCatalog(self._view, allowed)
            return sis_recommend(request, scoped, files_present=files_present,
                                 symbols_extra=symbols_extra, revoked=deny, now=now)
        except (AuthorityError, ValueError, TypeError):
            return _abstain("catalog_unavailable", ("Authoritative qualification evidence could not be verified.",))

    def _committed_revocations(self) -> dict:
        """Committed signed revocations, grouped by kind (PR-04)."""
        out = {"record": set(), "receipt": set(), "grant": set(),
               "signer": set()}
        reader = getattr(self._store, "revocations", None)
        if reader is None:
            return out
        for rev in reader():
            target = (rev.target_digest if rev.target_digest is not None
                      else rev.target_id)
            out.setdefault(rev.kind, set()).add(target)
        return out

    def _grant_permits(self, record, owner, requester_id, now=None,
                       revoked=frozenset(), revoked_signers=frozenset()) -> bool:
        if self._grants is None:
            return False
        reader = getattr(self._store, "scope_grants", None)
        if reader is None:
            return False
        grants = reader(procedure_revision_digest=record.digest)
        return bool(self._grants.permits(
            record,
            owner_identity=owner,
            requester=requester_id,
            grants=grants,
            receipts_for=lambda g: self._store.receipts_for_grant(g.grant_id),
            now=now,
            revoked=revoked,
            revoked_signers=revoked_signers,
        ))
