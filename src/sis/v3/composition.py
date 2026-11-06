"""Guidance composition policy (SIS v3.3, milestone 5).

Multiple qualified artifact types may contribute guidance for one task —
but never as an unrestricted concatenation into a system prompt. This
module is the single choke point that merges candidate content under
explicit rules:

- deterministic precedence by artifact type (most-verified first),
- exact-duplicate step deduplication,
- lexical polarity conflict detection between steps,
- a predeclared conflict policy: ``"precedence"`` (higher-precedence
  artifact wins, the loser is dropped and audited) or ``"abstain"``
  (the whole composition abstains — conflicts are never guessed at),
- a hard instruction budget in approximate tokens.

The output is ordered step *data* plus provenance digests — what the
serving layer delivers through the untrusted context channel. Content
here never alters harness policy, permissions, or authority.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .contracts import CandidateV1, ContractError, ProcedureRecordV1

_PRECEDENCE = {
    "symbolic_procedure": 0,
    "diagnostic_strategy": 1,
    "skill_bundle": 2,
    "skill_instruction": 3,
    "experience_memory": 4,
    "prompt_variant": 5,
}
_PROCEDURE_RANK = 0  # qualified ProcedureRecordV1 == symbolic_procedure

_NEGATORS = re.compile(
    r"\b(never|not|don't|do not|avoid|without|no|must not)\b", re.I)
_AFFIRMERS = re.compile(r"\b(always|must|use|required)\b", re.I)


def _steps_of(item) -> tuple[str, ...]:
    """Extract advisory steps from any supported artifact; data only."""
    if isinstance(item, ProcedureRecordV1):
        return tuple(item.steps)
    if isinstance(item, CandidateV1):
        payload = item.payload
        if item.candidate_type == "experience_memory":
            lesson = payload.get("lesson", "")
            return (lesson,) if isinstance(lesson, str) and lesson else ()
        steps = payload.get("steps", ())
        if isinstance(steps, (list, tuple)):
            return tuple(s for s in steps if isinstance(s, str))
    return ()


def _rank(item) -> int:
    if isinstance(item, ProcedureRecordV1):
        return _PROCEDURE_RANK
    return _PRECEDENCE.get(item.candidate_type, 99)


def _key_terms(step: str) -> frozenset:
    words = re.sub(r"[^a-z0-9 ]", " ", step.lower()).split()
    stop = {"the", "a", "an", "and", "or", "to", "of", "for", "in", "on",
            "is", "be", "with", "that", "this", "it", "as", "by", "at"}
    return frozenset(w for w in words if w not in stop)


def _conflicts(a: str, b: str) -> bool:
    """Polarity heuristic: near-identical key terms, opposite polarity."""
    ka, kb = _key_terms(a), _key_terms(b)
    if not ka or not kb:
        return False
    overlap = len(ka & kb) / max(1, len(ka | kb))
    if overlap < 0.5:
        return False
    neg_a, neg_b = bool(_NEGATORS.search(a)), bool(_NEGATORS.search(b))
    aff_a, aff_b = bool(_AFFIRMERS.search(a)), bool(_AFFIRMERS.search(b))
    return (neg_a and aff_b) or (neg_b and aff_a)


@dataclass(frozen=True)
class ComposedGuidance:
    """The merged advisory payload plus its audit trail.

    ``source_digests`` covers every artifact that contributed a delivered
    step; ``step_sources`` maps each delivered step to its artifact
    digest, so a caller can audit what actually shipped rather than what
    merely composed.
    """

    steps: tuple[str, ...]
    source_digests: tuple[str, ...]
    abstained: bool
    reason: str | None
    resolutions: tuple[str, ...] = field(default_factory=tuple)
    step_sources: tuple[tuple[str, str], ...] = field(default_factory=tuple)


def compose_guidance(
    artifacts,
    *,
    conflict_policy: str = "precedence",
    max_steps: int = 12,
    token_budget: int = 400,
) -> ComposedGuidance:
    """Merge qualified artifacts into one bounded advisory payload.

    ``artifacts`` may mix ``ProcedureRecordV1`` and ``CandidateV1``.
    Output is deterministic: same inputs -> same steps, same audit.
    """
    if conflict_policy not in {"precedence", "abstain"}:
        raise ContractError("conflict_policy must be 'precedence' or 'abstain'")
    if type(token_budget) is not int or token_budget < 1:
        raise ContractError("token_budget must be a positive integer")
    if type(max_steps) is not int or not 1 <= max_steps <= 32:
        raise ContractError("max_steps must be in [1,32]")

    ordered = sorted(
        artifacts, key=lambda item: (_rank(item), item.digest))
    resolutions: list[str] = []
    chosen: list[tuple[str, str, int]] = []  # (step, source_digest, rank)

    for item in ordered:
        for step in _steps_of(item):
            if not isinstance(step, str) or not step.strip():
                continue
            normalized = " ".join(step.split())
            if any(existing[0] == normalized for existing in chosen):
                continue
            conflicted = [c for c in chosen if _conflicts(c[0], normalized)]
            if conflicted:
                if conflict_policy == "abstain":
                    return ComposedGuidance(
                        steps=(), source_digests=(), abstained=True,
                        reason="conflicting_evidence",
                        resolutions=tuple(resolutions))
                # precedence policy: existing higher/equal-precedence
                # steps win; drop the newcomer and record it.
                winner = min(conflicted, key=lambda c: c[2])
                resolutions.append(
                    "conflict:dropped "
                    f"{normalized[:64]!r} in favor of {winner[0][:64]!r}")
                continue
            chosen.append((normalized, item.digest, _rank(item)))

    steps: list[str] = []
    sources: list[str] = []
    step_sources: list[tuple[str, str]] = []
    spent = 0
    for normalized, digest, _rankv in chosen:
        cost = max(1, len(normalized) // 4)
        if len(steps) >= max_steps or spent + cost > token_budget:
            continue
        steps.append(normalized)
        step_sources.append((normalized, digest))
        spent += cost
        if digest not in sources:
            sources.append(digest)
    if not steps:
        return ComposedGuidance(
            steps=(), source_digests=(), abstained=True,
            reason="insufficient_support",
            resolutions=tuple(resolutions))
    return ComposedGuidance(
        steps=tuple(steps), source_digests=tuple(sources),
        abstained=False, reason=None,
        resolutions=tuple(resolutions),
        step_sources=tuple(step_sources))
