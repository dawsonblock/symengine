"""Namespace-scoped qualified catalog with revocation cascade (SIS3-150).

Scope is now a *read-only projection* of signed ``ScopeGrantV1`` records
committed to the authority store (v3.1-alpha, PR-03): there is no role-
string write path and no unsigned sidecar. ``repository`` is the implicit
default; ``family`` means a committed grant names a target family;
``cross_repository`` means a committed grant names a distinct target
repository. The label is informational — the serving boundary re-verifies
grant signatures, registry lineage, expiry and transfer evidence on every
request. ``cascade_suspend`` walks evidence_refs: when a piece of evidence
is revoked, every qualified record depending on it is suspended in one
deterministic pass — no stale recommendations survive evidence
invalidation.
"""
from __future__ import annotations

from .contracts import ContractError, canonical_digest
from .procedures import ProcedureStore

SCOPES = frozenset({"repository", "family", "cross_repository"})


class CatalogError(RuntimeError):
    """The catalog cannot complete an operation."""


class Catalog:
    """Read-only scope projection + suspension cascade over the authority store."""

    def __init__(self, store: ProcedureStore) -> None:
        self.store = store

    def scope_of(self, procedure_id: str) -> str:
        """Broadest scope any committed grant confers on the *current* revision.

        ``repository`` is the default when no grant exists. This label is a
        projection only — ``StrictGuidanceGateway`` re-verifies the signed
        grant, registry lineage and evidence before serving anything beyond
        repository-local.
        """
        grants = self._grants_for(procedure_id)
        scope = "repository"
        for grant in grants:
            if grant.target_registry_id is not None:
                return "cross_repository"
            if grant.target_family_id is not None:
                scope = "family"
        return scope

    def _grants_for(self, procedure_id: str):
        reader = getattr(self.store, "scope_grants", None)
        if reader is None:
            return ()
        record = self.store.get(procedure_id)  # raises on unknown id
        return reader(procedure_revision_digest=record.digest)

    def procedures(self, *, status: str | None = None, scope: str | None = None):
        records = self.store.all_latest() if status is None else self.store.by_status(status)
        if scope is None:
            return records
        return [r for r in records if self.scope_of(r.procedure_id) == scope]

    def qualified_head(self, scope: str | None = None) -> str:
        if scope is None:
            return self.store.qualified_head_digest()
        return canonical_digest("qualified_catalog", 1, {
            "head": sorted(r.digest for r in self.procedures(status="qualified", scope=scope)),
            "scope": scope,
        })

    def cascade_suspend(
        self,
        revoked_evidence_digest: str,
        transition_fn,
    ) -> list[str]:
        """Suspend every qualified record citing ``revoked_evidence_digest``.

        ``transition_fn(procedure_id)`` performs one governed suspension and
        returns its decision id; callers wire in the promotion controller so
        every cascade step is itself an authorized signed decision.
        """
        targets = [
            r for r in self.store.by_status("qualified")
            if revoked_evidence_digest in r.evidence_refs
            or revoked_evidence_digest in r.counterexample_refs
        ]
        return [transition_fn(r.procedure_id) for r in sorted(targets, key=lambda r: r.procedure_id)]
