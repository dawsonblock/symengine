"""Bounded, evidence-based EvoSkill-inspired candidate selection.

No LLM-as-judge, no self-reported success, no access to a sealed test set.
Evidence must originate from an independent evaluator and task registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class CandidateTrial:
    candidate_id: str
    repository_id: str
    task_id: str
    baseline_passed: bool
    assisted_passed: bool
    budget_valid: bool
    signed_evidence_digest: str
    evaluator_verified: bool = False


def select_improvement(trials: Sequence[CandidateTrial], *,
                       min_repositories: int = 2, min_net_wins: int = 1,
                       max_candidates: int = 32) -> tuple[str, ...]:
    """Select candidate IDs with genuine paired wins under valid budgets.

    The function cannot validate signatures on its own: its input must be
    produced by the independent evaluator, not an agent-provided verdict.
    """
    if min_repositories < 1 or min_net_wins < 1 or max_candidates < 1:
        raise ValueError("invalid_selection_threshold")
    identifiers = {t.candidate_id for t in trials}
    if len(identifiers) > max_candidates:
        raise ValueError("candidate_search_budget_exceeded")
    seen: set[tuple[str, str, str]] = set()
    grouped: dict[str, list[CandidateTrial]] = {}
    for trial in trials:
        if not trial.evaluator_verified or not trial.signed_evidence_digest:
            raise ValueError("trial_not_independently_verified")
        key = (trial.candidate_id, trial.repository_id, trial.task_id)
        if key in seen:
            raise ValueError("duplicated_trial")
        seen.add(key)
        grouped.setdefault(trial.candidate_id, []).append(trial)
    winners = []
    for candidate, batch in sorted(grouped.items()):
        valid = [t for t in batch if t.budget_valid]
        if len({t.repository_id for t in valid}) < min_repositories:
            continue
        wins = sum(t.assisted_passed and not t.baseline_passed for t in valid)
        losses = sum(t.baseline_passed and not t.assisted_passed for t in valid)
        if wins - losses >= min_net_wins:
            winners.append(candidate)
    return tuple(winners)
