"""Repository-disjoint paired-study checks (v3.1-alpha, M6).

Enforces the evaluation's core validity conditions before a paired
benchmark report is treated as evidence: evaluation repositories must be
disjoint from the repositories that produced learning evidence, and the
decisive comparison is qualified-guidance (D) vs baseline (A) under the
preregistered budget. Produces a summary; it cannot promote or qualify.
"""
from __future__ import annotations

from typing import Iterable, Mapping, Sequence

from .contracts import ContractError, TaskEnvelopeV1


def assert_repository_disjoint(
    learned_repo_digests: Iterable[str],
    eval_tasks: Sequence[TaskEnvelopeV1],
) -> None:
    """Fail the study if any eval repo supplied learning evidence."""
    learned = set(learned_repo_digests)
    overlap = sorted({t.repo_snapshot_digest for t in eval_tasks}
                     & learned)
    if overlap:
        raise ContractError(
            f"evaluation repositories overlap learning evidence: {overlap}")
    if not eval_tasks:
        raise ContractError("empty evaluation set")


def paired_summary(report: Mapping, *, baseline_arm: str = "A",
                   treatment_arm: str = "D") -> dict:
    """Extract the decisive comparison from a BenchmarkHarness report.

    Returns per-arm solved counts and the paired win/loss table. Raises
    if the report is missing the required arms or was not produced under
    a budget-enforced run.
    """
    rates = report.get("solve_rates") or {}
    paired = report.get("paired") or {}
    key = f"{treatment_arm}_vs_{baseline_arm}"
    for arm in (baseline_arm, treatment_arm):
        if arm not in rates:
            raise ContractError(f"missing arm in report: {arm}")
    if key not in paired:
        raise ContractError(f"missing paired contrast: {key}")
    return {
        "schema_version": 1,
        "tasks": report.get("tasks", 0),
        "budget": report.get("budget", {}),
        "budget_violations": report.get("budget_violations", 0),
        "baseline": {"arm": baseline_arm, **rates[baseline_arm]},
        "treatment": {"arm": treatment_arm, **rates[treatment_arm]},
        "contrast": paired[key],
        "decision_rule": (
            "solved_delta > 0 with mcnemar_exact_p <= 0.05 is the "
            "preregistered efficacy bar; anything else is not evidence "
            "of improvement"),
    }
