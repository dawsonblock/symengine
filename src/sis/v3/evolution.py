"""Bounded skill evolution (SIS v3.3, milestone 4).

EvoSkill-style failure-driven optimization inside the v3 trust model:

- Mutators produce *data* — ``CandidateV1`` payloads of type
  ``skill_instruction``. Candidate text is never interpolated into
  executable commands; evaluation flows through an injected
  ``EvaluationClient`` against a development task set, and results feed
  a deterministic frontier.
- The optimizer never transitions candidates past PROPOSED itself and
  never touches qualification: ``optimize`` returns a ranked frontier;
  promotion is a separate, operator-gated decision with evaluator
  receipts.
- Budgets are explicit (iterations, evaluations, wall clock, candidate
  count) and enforced inside the loop — an optimizer run cannot grow
  without bound.
- Development data stays development data: the optimizer only sees the
  task set it is given. Final qualification happens on sealed holdouts
  the optimizer cannot name (see ``governed_eval`` partitions).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Protocol, Sequence

from .candidates import content_digest
from .contracts import CandidateV1, ContractError


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# --------------------------------------------------------------------- #
# evaluation interface — injected; the optimizer never grades itself
# --------------------------------------------------------------------- #

@dataclass(frozen=True)
class DevEvalResult:
    """One development-set evaluation of a skill candidate."""

    tasks: int
    solved: int
    regressions: int
    tokens: int
    tool_calls: int
    wall_seconds: int
    receipt_refs: tuple[str, ...] = ()


class EvaluationClient(Protocol):
    """Independent dev-set evaluator; implemented by the caller."""

    def evaluate(self, candidate: CandidateV1, dev_tasks: Sequence) -> DevEvalResult:
        ...


# --------------------------------------------------------------------- #
# mutators — pure payload->payload transforms; no command construction
# --------------------------------------------------------------------- #

Mutator = Callable[[dict], dict | None]


def append_step(step: str) -> Mutator:
    def mutate(payload: dict) -> dict | None:
        steps = list(payload.get("steps", ()))
        if step in steps or len(steps) >= 16:
            return None
        return {**payload, "steps": [*steps, step]}
    return mutate


def specialize_step(index: int, suffix: str) -> Mutator:
    def mutate(payload: dict) -> dict | None:
        steps = list(payload.get("steps", ()))
        if not 0 <= index < len(steps) or steps[index].endswith(suffix):
            return None
        steps[index] = steps[index] + suffix
        return {**payload, "steps": steps}
    return mutate


def drop_step(index: int) -> Mutator:
    def mutate(payload: dict) -> dict | None:
        steps = list(payload.get("steps", ()))
        if not 0 <= index < len(steps) or len(steps) <= 1:
            return None
        del steps[index]
        return {**payload, "steps": steps}
    return mutate


def reorder_step(index: int, offset: int) -> Mutator:
    def mutate(payload: dict) -> dict | None:
        steps = list(payload.get("steps", ()))
        j = index + offset
        if not (0 <= index < len(steps) and 0 <= j < len(steps)):
            return None
        steps[index], steps[j] = steps[j], steps[index]
        return {**payload, "steps": steps}
    return mutate


# --------------------------------------------------------------------- #
# budget + frontier
# --------------------------------------------------------------------- #

@dataclass(frozen=True)
class EvolutionBudget:
    max_iterations: int = 4
    max_evaluations: int = 32
    max_wall_seconds: int = 600
    max_candidates: int = 64
    frontier_size: int = 4

    def __post_init__(self) -> None:
        for name in ("max_iterations", "max_evaluations",
                     "max_wall_seconds", "max_candidates", "frontier_size"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ContractError(f"{name} must be a positive integer")


@dataclass
class FrontierEntry:
    candidate: CandidateV1
    fitness: float
    result: DevEvalResult | None = None


class Frontier:
    """Top-k candidates by deterministic fitness; deduped by content digest."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._entries: list[FrontierEntry] = []
        self._seen: set[str] = set()

    def insert(self, entry: FrontierEntry) -> bool:
        key = entry.candidate.content_digest
        if key in self._seen:
            return False
        self._seen.add(key)
        self._entries.append(entry)
        # Tie-break on the content digest: candidate.digest covers
        # created_at, which would make equal-fitness ordering depend on
        # wall-clock time instead of content.
        self._entries.sort(
            key=lambda e: (-e.fitness, e.candidate.content_digest))
        del self._entries[self._size:]
        return entry in self._entries

    @property
    def entries(self) -> list[FrontierEntry]:
        return list(self._entries)

    def best(self) -> FrontierEntry | None:
        return self._entries[0] if self._entries else None


def fitness(result: DevEvalResult) -> float:
    """Solved rate minus regression penalty minus normalized cost."""
    if result.tasks <= 0:
        return 0.0
    solve_rate = result.solved / result.tasks
    regression_rate = result.regressions / result.tasks
    cost = min(1.0, result.tokens / 100_000)
    return solve_rate - 2.0 * regression_rate - 0.1 * cost


# --------------------------------------------------------------------- #
# optimizer
# --------------------------------------------------------------------- #

class SkillOptimizer:
    """Bounded, failure-driven skill search that can never self-qualify."""

    def __init__(
        self,
        *,
        evaluator: EvaluationClient,
        mutators: Sequence[Mutator],
        budget: EvolutionBudget = EvolutionBudget(),
        generator_identity: str = "sis-v3-skill-optimizer",
        registry_submit: Callable[[CandidateV1], None] | None = None,
    ) -> None:
        self._evaluator = evaluator
        self._mutators = tuple(mutators)
        self._budget = budget
        self._gen = generator_identity
        self._submit = registry_submit
        # Per-child faults observed during the last optimize() call —
        # recorded, never silently swallowed: a failing registry submit
        # or evaluator must not abort the whole search.
        self.failures: list[dict] = []

    def optimize(
        self,
        seeds: Sequence[dict],
        dev_tasks: Sequence,
        *,
        target_task_family: str,
        repository_scope: dict,
        applicability: tuple = ({"kind": "language_is", "value": "python"},),
    ) -> list[FrontierEntry]:
        """Run the bounded search; return the ranked frontier.

        ``seeds`` are skill payloads ({title, steps:[...]}). Every
        generated variant becomes a CandidateV1 and — when
        ``registry_submit`` is bound — is submitted to the registry at
        PROPOSED. Nothing here transitions state beyond intake.
        """
        if not seeds:
            raise ContractError("at least one seed skill is required")
        if not self._mutators:
            raise ContractError("at least one mutator is required")

        frontier = Frontier(self._budget.frontier_size)
        self.failures = []
        start = time.monotonic()
        evaluations = 0
        spawned = 0
        spawned_digests: set[str] = set()
        parents: list[dict] = list(seeds)

        for iteration in range(self._budget.max_iterations):
            if time.monotonic() - start > self._budget.max_wall_seconds:
                break
            next_parents: list[dict] = []
            for parent in parents:
                if spawned >= self._budget.max_candidates:
                    break
                for mut in self._mutators:
                    if spawned >= self._budget.max_candidates:
                        break
                    if evaluations >= self._budget.max_evaluations:
                        break
                    if time.monotonic() - start > self._budget.max_wall_seconds:
                        break
                    try:
                        child_payload = mut(parent)
                    except Exception as exc:
                        self.failures.append({
                            "candidate_id": "<unmutated>",
                            "stage": "mutate",
                            "error": f"{type(exc).__name__}:"
                                     f"{str(exc)[:120]}"})
                        continue
                    if child_payload is None:
                        continue
                    child_digest = content_digest(
                        "skill_instruction", child_payload)
                    if child_digest in spawned_digests:
                        continue
                    spawned_digests.add(child_digest)
                    child = CandidateV1(
                        schema_version=1,
                        candidate_id="skill-" + child_digest[:16],
                        candidate_type="skill_instruction",
                        content_digest=child_digest,
                        parent_candidate_ids=(),
                        source_episode_ids=(),
                        generator_identity=self._gen,
                        target_agent="any",
                        target_task_family=target_task_family,
                        repository_scope=dict(repository_scope),
                        applicability_predicate=tuple(applicability),
                        known_counterexamples=(),
                        payload=dict(child_payload),
                        created_at=_utcnow(),
                    )
                    spawned += 1
                    try:
                        if self._submit is not None:
                            self._submit(child)
                    except Exception as exc:
                        self.failures.append({
                            "candidate_id": child.candidate_id,
                            "stage": "submit",
                            "error": f"{type(exc).__name__}:"
                                     f"{str(exc)[:120]}"})
                        continue
                    try:
                        result = self._evaluator.evaluate(child, dev_tasks)
                    except Exception as exc:
                        self.failures.append({
                            "candidate_id": child.candidate_id,
                            "stage": "evaluate",
                            "error": f"{type(exc).__name__}:"
                                     f"{str(exc)[:120]}"})
                        continue
                    evaluations += 1
                    score = fitness(result)
                    entry = FrontierEntry(
                        candidate=child, fitness=score, result=result)
                    if frontier.insert(entry):
                        next_parents.append(child_payload)
            if not next_parents:
                break
            parents = next_parents
        return frontier.entries
