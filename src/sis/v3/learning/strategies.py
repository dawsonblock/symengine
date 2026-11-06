"""Deterministic contrastive strategy extraction from *already-verified* episodes.

This is a conservative ReasoningBank-inspired baseline, not a neural extractor:
no free-form generated lesson is trusted, and strategy candidates are never
qualified or sent to the agent without independent promotion.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

from ..contracts import canonical_json


@dataclass(frozen=True)
class EpisodeEvidence:
    episode_id: str
    repository_id: str
    failure_signature: str
    outcome: str  # pass | fail
    receipt_digest: str
    diagnostic_actions: tuple[str, ...]
    verified: bool = False


@dataclass(frozen=True)
class StrategyCandidate:
    candidate_id: str
    failure_signature: str
    diagnostic_steps: tuple[str, ...]
    supporting_receipts: tuple[str, ...]
    negative_receipts: tuple[str, ...]
    repository_count: int
    status: str = "candidate"


def induce_strategies(
    episodes: Sequence[EpisodeEvidence], *, min_successes: int = 2,
    min_distinct_repositories: int = 2,
    receipt_resolver: Callable[[str], Mapping | None] | None = None,
) -> tuple[StrategyCandidate, ...]:
    """Induce recurring *observed actions*, not ungrounded causal assertions.

    Caller must supply receipt-verified evidence. Distinct repository IDs must
    be assigned by a trusted task registry, never guessed from patch digests.
    A lack of contrastive evidence may produce a candidate, but it cannot
    yield qualification. Verifier/provenance custody is deliberately external.

    ``receipt_resolver`` — when given, each episode's ``receipt_digest``
    must resolve to committed evidence (e.g. ``AuthorityDB`` row lookup);
    unresolved digests are rejected. Without it, the caller's ``verified``
    flag is trusted as before — a weaker input contract documented here.
    """
    if min_successes < 1 or min_distinct_repositories < 1:
        raise ValueError("qualification thresholds must be positive")
    groups: dict[str, list[EpisodeEvidence]] = {}
    for episode in episodes:
        if not episode.verified:
            raise ValueError("unverified_episode")
        if receipt_resolver is not None and \
                receipt_resolver(episode.receipt_digest) is None:
            raise ValueError("unresolved_receipt_digest")
        if episode.outcome not in {"pass", "fail"}:
            raise ValueError("invalid_outcome")
        if not episode.repository_id or not episode.receipt_digest or not episode.failure_signature:
            raise ValueError("missing_provenance")
        if len(episode.diagnostic_actions) > 32 or any(len(x) > 256 for x in episode.diagnostic_actions):
            raise ValueError("unbounded_diagnostic_actions")
        groups.setdefault(episode.failure_signature, []).append(episode)

    result: list[StrategyCandidate] = []
    for signature, group in sorted(groups.items()):
        passed = [e for e in group if e.outcome == "pass"]
        repos = {e.repository_id for e in passed}
        if len(passed) < min_successes or len(repos) < min_distinct_repositories:
            continue
        # Only retain diagnostic actions repeated in every successful trace.
        # Never include unrestricted command text in learned guidance.
        shared = set(passed[0].diagnostic_actions)
        for e in passed[1:]:
            shared.intersection_update(e.diagnostic_actions)
        if not shared:
            continue
        # Negative examples are evidence of possible transfer failure, not an
        # automatically derived contraindication or proof of causality.
        good = tuple(sorted({e.receipt_digest for e in passed}))
        bad = tuple(sorted({e.receipt_digest for e in group if e.outcome == "fail"}))
        steps = tuple(sorted(shared))[:16]
        identifier = hashlib.sha256(canonical_json({
            "signature": signature, "steps": steps, "positive": good, "negative": bad,
        })).hexdigest()[:24]
        result.append(StrategyCandidate(
            candidate_id="strategy-" + identifier,
            failure_signature=signature,
            diagnostic_steps=steps,
            supporting_receipts=good,
            negative_receipts=bad,
            repository_count=len(repos),
        ))
    return tuple(result)
