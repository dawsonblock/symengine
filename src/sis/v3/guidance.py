"""Read-only v3 guidance surface (SIS3-010).

Fail-closed by construction: an unverified task intent (no semantic contract)
always abstains, and recommendations require a qualified procedure that
survives every hard gate with evidence references attached. Guidance is
advice — it never mutates catalog, evidence, or agent state.
"""
from .contracts import GuidanceRequestV1, GuidanceV1, canonical_digest
from .procedures import ProcedureStore
from .retrieval import retrieve


_POLICY_DESCRIPTOR = {
    "schema_version": 1,
    "mode": "hard_gated_retrieval",
    "reasons": ["unverified_task_intent", "no_qualified_procedure",
                "precondition_failed", "prior_negative_transfer",
                "insufficient_support", "expired", "revoked"],
}
_POLICY_DIGEST = canonical_digest("guidance_policy", 1, _POLICY_DESCRIPTOR)


def sis_recommend(
    request: GuidanceRequestV1 | dict,
    catalog: ProcedureStore | None = None,
    *,
    files_present=(),
    symbols_extra=(),
    revoked=frozenset(),
    now: str | None = None,
) -> GuidanceV1:
    """Return a strict, bounded recommendation or abstention; never mutates state."""
    if not isinstance(request, GuidanceRequestV1):
        request = GuidanceRequestV1.from_dict(request)
    if request.semantic_contract_digest is None:
        return _abstain(
            "unverified_task_intent",
            (
                "Confirm the requested behavior from task acceptance criteria or an independently reviewed specification.",
                "Reproduce the target failure with task-owned tests before considering any procedure.",
            ),
        )
    if catalog is None or not catalog.by_status("qualified"):
        return _abstain(
            "no_qualified_procedure",
            (
                "No qualified procedure is available for retrieval.",
                "Verify the task outcome independently and retain the evidence for later review.",
            ),
        )

    result = retrieve(
        request, catalog,
        files_present=files_present, symbols_extra=symbols_extra, limit=3,
        revoked=revoked, now=now,
    )
    if not result.candidates:
        dominant = result.rejections[0].reason_code if result.rejections else "insufficient_support"
        return _abstain(
            dominant,
            (
                "No qualified procedure survived the hard applicability gates.",
                "Reproduce the failure and verify any proposed change independently.",
            ),
        )

    top = result.candidates
    return GuidanceV1(
        schema_version=1,
        decision="recommend",
        procedure_ids=tuple(c.record.procedure_id for c in top),
        revision=catalog.qualified_head_digest(),
        matched_preconditions=tuple(
            cond for candidate in top for cond in candidate.matched_preconditions
        )[:32],
        contraindications=tuple(
            cond for candidate in top for cond in candidate.record.contraindications
        )[:32],
        evidence_ids=tuple(
            ref for candidate in top for ref in candidate.record.evidence_refs
        )[:32],
        policy_digest=_POLICY_DIGEST,
        helpful_next_checks=(
            # Serve the winning procedure's steps — they ARE the guidance.
            # Capped at the contract bound; generic checks follow.
            *top[0].record.steps,
            "Confirm each listed precondition holds in the target repository before acting.",
            "Run the procedure's required verification and the project's own tests.",
        )[:32],
        reason_code=None,
        approximate_tokens=min(2_000, 200 + 40 * len(top)),
    )


def _abstain(reason: str, checks: tuple[str, ...]) -> GuidanceV1:
    return GuidanceV1(
        schema_version=1,
        decision="abstain",
        procedure_ids=(),
        revision=None,
        matched_preconditions=(),
        contraindications=(),
        evidence_ids=(),
        policy_digest=_POLICY_DIGEST,
        helpful_next_checks=checks,
        reason_code=reason,
        approximate_tokens=min(2_000, sum(max(1, len(item) // 4) for item in checks)),
    )
