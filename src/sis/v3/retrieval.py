"""Hard-gated, evidence-labeled procedure retrieval (SIS3-009).

Retrieval is two layers. Hard gates first: every ``preconditions`` entry must
hold against the caller-supplied context, and any satisfied contraindication
rejects the procedure outright — a similarity score can never override a
failed gate. Ranking second: surviving qualified procedures are ordered by
matched-gate count and their independently verified outcome distribution.
Procedures carrying ``counterexample_refs`` are eligible only when none of
their contraindications match; their presence is reported to the caller.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .contracts import ContractError, GuidanceRequestV1, ProcedureRecordV1
from .procedures import ProcedureStore


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _expired(record: ProcedureRecordV1, now: datetime) -> bool:
    """Fail closed: malformed or expired timestamps both count as expired."""
    if record.expires_at is None:
        return False
    try:
        return now > _parse_ts(record.expires_at)
    except (ValueError, TypeError):
        return True


@dataclass(frozen=True)
class RetrievalContext:
    """Facts about the requesting task environment, supplied by the caller.

    Everything here is untrusted task data; it gates retrieval but never
    grants authority.
    """

    language: str
    toolchain: str = ""
    dependency_digests: Mapping[str, str] = field(default_factory=dict)
    files_present: frozenset[str] = frozenset()
    symbols_present: frozenset[str] = frozenset()
    failure_signatures: frozenset[str] = frozenset()

    @classmethod
    def from_request(
        cls, request: GuidanceRequestV1, *, files_present=(), symbols_extra=()
    ) -> "RetrievalContext":
        if not isinstance(request, GuidanceRequestV1):
            request = GuidanceRequestV1.from_dict(request)
        return cls(
            language=request.language,
            toolchain=request.toolchain,
            dependency_digests=dict(request.lockfile_digests),
            files_present=frozenset(files_present),
            symbols_present=frozenset(request.present_symbols) | frozenset(symbols_extra),
            failure_signatures=frozenset(request.failure_signatures),
        )


def precondition_holds(condition: Mapping, context: RetrievalContext) -> bool:
    """Evaluate one allowlisted precondition against the context."""
    kind = condition.get("kind")
    if kind == "language_is":
        return context.language.lower() == str(condition.get("value", "")).lower()
    if kind == "toolchain_is":
        return context.toolchain.lower() == str(condition.get("value", "")).lower()
    if kind == "dependency_digest_is":
        return context.dependency_digests.get(condition.get("name", "")) == condition.get("digest")
    if kind == "file_present":
        return condition.get("value") in context.files_present
    if kind == "symbol_present":
        return condition.get("value") in context.symbols_present
    if kind == "failure_signature_is":
        return condition.get("value") in context.failure_signatures
    if kind == "failure_signature_not":
        return condition.get("value") not in context.failure_signatures
    raise ContractError("unknown precondition kind")


def suppression_match(haystack: str, needle: str) -> bool:
    """Boundary-anchored counterexample match.

    Plain substring matching lets a 1-2 character counterexample (or a
    common word inside a longer signature) suppress a candidate on every
    context. Instead we require token boundaries on both ends; needles
    shorter than 3 characters must equal a whole whitespace token.
    """
    needle = needle.strip().lower()
    if not needle:
        return False
    if len(needle) < 3:
        return needle in haystack.split()
    return re.search(
        r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])",
        haystack) is not None


@dataclass(frozen=True)
class Candidate:
    record: ProcedureRecordV1
    matched_preconditions: tuple[Mapping, ...]
    score: int


@dataclass(frozen=True)
class Rejection:
    procedure_id: str
    reason_code: str
    detail: str


@dataclass(frozen=True)
class AblationFlags:
    """Benchmark-only gates removal (SIS3-171); never default-on."""

    skip_preconditions: bool = False
    skip_contraindications: bool = False
    include_unqualified: bool = False


@dataclass(frozen=True)
class RetrievalResult:
    candidates: tuple[Candidate, ...]
    rejections: tuple[Rejection, ...]


def retrieve(
    request: GuidanceRequestV1,
    store: ProcedureStore,
    *,
    files_present=(),
    symbols_extra=(),
    limit: int = 3,
    ablations: AblationFlags = AblationFlags(),
    revoked: frozenset[str] | set[str] = frozenset(),
    now: str | None = None,
) -> RetrievalResult:
    """Apply hard gates then rank surviving qualified procedures.

    ``revoked`` is a policy-managed denylist of procedure record digests —
    it invalidates cached recommendations immediately even while a record's
    stored status remains ``qualified``. ``now`` injects trusted UTC time for
    deterministic testing; expired or malformed ``expires_at`` abstains.
    """
    if type(limit) is not int or not 1 <= limit <= 3:
        raise ContractError("retrieval limit must be in [1,3]")
    if not isinstance(ablations, AblationFlags):
        raise ContractError("ablations must be an AblationFlags value")
    try:
        current = _parse_ts(now) if now else datetime.now(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise ContractError("now must be an ISO-8601 timestamp") from exc
    context = RetrievalContext.from_request(
        request, files_present=files_present, symbols_extra=symbols_extra
    )
    candidates: list[Candidate] = []
    rejections: list[Rejection] = []

    pool = store.by_status("qualified")
    if ablations.include_unqualified:
        pool = list(store.all_latest())
    for record in pool:
        if record.digest in revoked:
            rejections.append(Rejection(
                procedure_id=record.procedure_id,
                reason_code="revoked",
                detail="the record digest is on the revocation list",
            ))
            continue
        if _expired(record, current):
            rejections.append(Rejection(
                procedure_id=record.procedure_id,
                reason_code="expired",
                detail="expires_at has passed or is invalid",
            ))
            continue
        contraindicated = [
            cond for cond in record.contraindications
            if _contradiction_matches(cond, context)
        ]
        if contraindicated and not ablations.skip_contraindications:
            rejections.append(Rejection(
                procedure_id=record.procedure_id,
                reason_code="prior_negative_transfer",
                detail="a contraindication matches the current context",
            ))
            continue
        missing = [
            cond for cond in record.preconditions
            if not precondition_holds(cond, context)
        ]
        if missing and not ablations.skip_preconditions:
            rejections.append(Rejection(
                procedure_id=record.procedure_id,
                reason_code="precondition_failed",
                detail=f"{len(missing)} precondition(s) unmet",
            ))
            continue
        distribution = record.outcome_distribution
        score = (
            len(record.preconditions) * 10
            + distribution.get("successes", 0) * 5
            - distribution.get("failures", 0) * 20
            - distribution.get("regressions", 0) * 30
            - len(record.counterexample_refs) * 15
        )
        candidates.append(Candidate(
            record=record,
            matched_preconditions=tuple(record.preconditions),
            score=score,
        ))

    candidates.sort(key=lambda c: (-c.score, c.record.digest))
    if not candidates and not store.by_status("qualified"):
        rejections.append(Rejection(
            procedure_id="*",
            reason_code="no_qualified_procedure",
            detail="the catalog contains no qualified procedures",
        ))
    elif not candidates:
        rejections.append(Rejection(
            procedure_id="*",
            reason_code="insufficient_support",
            detail="no qualified procedure survived the hard gates",
        ))
    return RetrievalResult(candidates=tuple(candidates[:limit]), rejections=tuple(rejections))


def _contradiction_matches(condition: Mapping, context: RetrievalContext) -> bool:
    """A contraindication fires when its forbidden fact is present."""
    if condition.get("kind") == "failure_signature_not":
        return condition.get("value") in context.failure_signatures
    return precondition_holds(condition, context)
