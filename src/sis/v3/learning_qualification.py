"""Five-arm learning qualification with honest statistics.

The question is not whether the learning loop runs. It is whether SIS
guidance improves real coding outcomes on repositories the learner has
never seen. This module runs the five preregistered arms:

    A  baseline (no SIS guidance)
    B  baseline + qualified experience memory
    C  baseline + qualified evolved skills
    D  baseline + qualified symbolic procedures
    E  baseline + all governed learning components

It separates machinery evidence (scripted agents) from confirmatory
evidence (real coding agent, hidden holdout, preregistered sample size),
reports paired wins/losses, confidence intervals, exact McNemar
uncertainty, negative transfer, resource overhead and failure categories,
and refuses to claim efficacy from an underpowered run.
"""
from __future__ import annotations

import json
import math
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .benchmark import BenchmarkHarness, BudgetCaps
from .contracts import GuidanceV1, TaskEnvelopeV1, canonical_digest
from .runner import tree_digest
from .governed_eval import (GOVERNED_ARMS, assert_partition_disjoint,
                            compute_metrics, preregister,
                            required_sample_size, run_governed_evaluation)

ARM_LABELS = {
    "A": "baseline",
    "B": "memory",
    "C": "skills",
    "D": "symbolic",
    "E": "integrated",
}
CONFIRMATORY = "confirmatory"
DEMONSTRATION = "demonstration"
EXPLORATORY = "exploratory"
INVALID = "invalid"


def mcnemar_exact(wins: int, losses: int) -> float:
    """Two-sided exact McNemar p-value for discordant pairs."""
    if type(wins) is not int or type(losses) is not int or \
            wins < 0 or losses < 0:
        raise ValueError("wins and losses must be nonnegative integers")
    n = wins + losses
    if n == 0:
        return 1.0
    k = min(wins, losses)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def wilson_interval(successes: int, n: int, *,
                    z: float = 1.959963984540054) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n <= 0:
        return (0.0, 1.0)
    p = successes / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt(
        p * (1 - p) / n + z * z / (4 * n * n)) / denominator
    return (max(0.0, center - half), min(1.0, center + half))


def newcombe_difference_interval(
    successes_a: int, n_a: int, successes_b: int, n_b: int, *,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    """Newcombe hybrid-score interval for the difference p_a - p_b."""
    if n_a <= 0 or n_b <= 0:
        return (-1.0, 1.0)
    p_a, p_b = successes_a / n_a, successes_b / n_b
    l_a, u_a = wilson_interval(successes_a, n_a, z=z)
    l_b, u_b = wilson_interval(successes_b, n_b, z=z)
    delta = p_a - p_b
    lower = delta - math.sqrt((p_a - l_a) ** 2 + (u_b - p_b) ** 2)
    upper = delta + math.sqrt((u_a - p_a) ** 2 + (p_b - l_b) ** 2)
    return (max(-1.0, lower), min(1.0, upper))


def _valid_solve(result: Mapping) -> bool:
    return (result.get("outcome") == "pass"
            and not result.get("budget_exceeded")
            and not result.get("error"))


def _task_rows(report: Mapping) -> dict[str, dict]:
    return {row["task_id"]: row.get("arms", {})
            for row in report.get("per_task", [])}


def paired_contrast(report: Mapping, *, baseline: str = "A",
                    treatment: str = "E", alpha: float = 0.05) -> dict:
    """Paired wins/losses, delta, exact p and Newcombe interval."""
    rows = _task_rows(report)
    n = len(rows)
    wins = losses = ties = 0
    base_solved = treat_solved = 0
    for results in rows.values():
        a = results.get(baseline, {})
        b = results.get(treatment, {})
        a_ok = _valid_solve(a)
        b_ok = _valid_solve(b)
        base_solved += a_ok
        treat_solved += b_ok
        if b_ok and not a_ok:
            wins += 1
        elif a_ok and not b_ok:
            losses += 1
        else:
            ties += 1
    p = mcnemar_exact(wins, losses)
    lower, upper = newcombe_difference_interval(
        treat_solved, n, base_solved, n)
    return {
        "baseline": baseline,
        "treatment": treatment,
        "tasks": n,
        "baseline_solved": base_solved,
        "treatment_solved": treat_solved,
        "delta": round((treat_solved - base_solved) / n, 6) if n else 0.0,
        "wins": wins,
        "losses": losses,
        "ties": ties,
        "mcnemar_exact_p": round(p, 8),
        "difference_interval_95": [round(lower, 6), round(upper, 6)],
        "significant": bool(p <= alpha and lower > 0),
    }


def failure_categories(report: Mapping) -> dict:
    rows = _task_rows(report)
    categories: dict[str, dict[str, int]] = {}
    for arm in sorted({arm for results in rows.values() for arm in results}):
        counts: dict[str, int] = {}
        for results in rows.values():
            result = results.get(arm, {})
            if result.get("budget_exceeded"):
                counts["budget_exceeded"] = counts.get(
                    "budget_exceeded", 0) + 1
            error = result.get("error")
            if error:
                key = str(error).split(":", 1)[0][:64]
                counts[key] = counts.get(key, 0) + 1
            elif result.get("outcome") == "fail":
                counts["task_fail"] = counts.get("task_fail", 0) + 1
            elif result.get("outcome") == "error":
                counts["evaluator_error"] = counts.get(
                    "evaluator_error", 0) + 1
        categories[arm] = counts
    return categories


def resource_overhead(report: Mapping) -> dict:
    metrics = report.get("governed", {}).get("metrics", {})
    out = {}
    for arm, values in metrics.items():
        solved = values.get("solved_task_rate") or 0
        out[arm] = {
            "mean_tokens_per_task": values.get("mean_tokens_per_task"),
            "mean_tool_calls_per_task":
                values.get("mean_tool_calls_per_task"),
            "mean_wall_seconds_per_task":
                values.get("mean_wall_seconds_per_task"),
            "cost_per_verified_solution": {
                "tokens": (values.get("mean_tokens_per_task") / solved
                           if solved and values.get("mean_tokens_per_task")
                           is not None else None),
                "wall_seconds": (
                    values.get("mean_wall_seconds_per_task") / solved
                    if solved and values.get(
                        "mean_wall_seconds_per_task") is not None else None),
                "tool_calls": (
                    values.get("mean_tool_calls_per_task") / solved
                    if solved and values.get(
                        "mean_tool_calls_per_task") is not None else None),
            },
            "abstention_rate": values.get("abstention_rate"),
            "negative_transfer_rate": values.get(
                "negative_transfer_rate"),
            "evaluation_integrity_failures": values.get(
                "evaluation_integrity_failures"),
        }
    return out


def analyze_report(
    report: Mapping,
    *,
    protocol: Mapping,
    real_agent: bool,
    hidden_holdout: bool,
    frozen_candidates: Mapping | None = None,
    arms: Sequence[str] = GOVERNED_ARMS,
) -> dict:
    """Attach honest qualification analysis to a governed report."""
    metrics = report.get("governed", {}).get("metrics", {})
    conformance = report.get("governed", {}).get("conformance", {})
    n_tasks = len(report.get("per_task", []))
    contrasts = {}
    for arm in arms:
        if arm == "A":
            continue
        contrasts[f"E_vs_{arm}" if arm != "E" else "E_vs_A"] = \
            paired_contrast(report, baseline=arm if arm != "E" else "A",
                            treatment="E" if arm != "E" else "A")
    # The decisive contrast is always E vs A.
    decisive = paired_contrast(report, baseline="A", treatment="E")
    alpha = protocol.get("alpha", 0.05)
    sample_size = protocol.get("sample_size")
    declared_power = protocol.get("power_analysis") or {}
    required_n = declared_power.get("required_n")
    if type(required_n) is not int or required_n < 1:
        required_n = required_sample_size(0.6, 0.4)
    minimum_n = max(
        sample_size if type(sample_size) is int else 0, required_n)
    underpowered = n_tasks < minimum_n
    if not real_agent:
        evidence_class = DEMONSTRATION
    elif not hidden_holdout or not conformance.get("conforms"):
        evidence_class = INVALID
    elif underpowered:
        evidence_class = EXPLORATORY
    else:
        evidence_class = CONFIRMATORY
    if decisive["delta"] > 0 and decisive["significant"]:
        efficacy = "supported"
    elif decisive["delta"] < 0:
        efficacy = "regressed"
    else:
        efficacy = "no_evidence"
    if evidence_class != CONFIRMATORY:
        release_gate = "IMPLEMENTED_NOT_EFFICACY_QUALIFIED"
    elif efficacy == "supported":
        release_gate = "EFFICACY_SUPPORTED"
    else:
        release_gate = "NO_EFFICACY_CLAIM"
    limitations = []
    if not real_agent:
        limitations.append(
            "scripted/demonstration agent: machinery evidence only, not a "
            "claim about real coding-agent efficacy")
    if underpowered:
        limitations.append(
            f"underpowered: ran {n_tasks} tasks; preregistered "
            f"{sample_size}")
    if not hidden_holdout:
        limitations.append("holdout partition is not hidden/disjoint")
    if not conformance.get("conforms"):
        limitations.append(
            "protocol did not conform: "
            + ", ".join(conformance.get("mismatches", [])))
    if evidence_class == CONFIRMATORY and efficacy == "no_evidence":
        limitations.append(
            "confirmatory run found no statistically supported improvement; "
            "the result is preserved")
    return {
        "schema_version": 1,
        "kind": "five_arm_learning_qualification",
        "protocol_digest": protocol.get("protocol_digest"),
        "protocol": dict(protocol),
        "arms": {arm: ARM_LABELS.get(arm, arm) for arm in arms},
        "tasks": n_tasks,
        "sample_size_preregistered": sample_size,
        "required_sample_size_0_6_vs_0_4": required_sample_size(0.6, 0.4),
        "power_analysis": {
            "expected_baseline": declared_power.get(
                "expected_baseline", 0.6),
            "expected_treatment": declared_power.get(
                "expected_treatment", 0.4),
            "power": declared_power.get("power", 0.8),
            "alpha": alpha,
            "required_n": required_n,
            "preregistered_n": sample_size,
            "minimum_n": minimum_n,
        },
        "underpowered": underpowered,
        "hidden_holdout": hidden_holdout,
        "real_agent": real_agent,
        "frozen_candidates": {
            arm: list(digests)
            for arm, digests in (frozen_candidates or {}).items()},
        "metrics": metrics,
        "contrasts": contrasts,
        "decisive_contrast": decisive,
        "confidence_intervals": {
            arm: {
                "solved_rate_wilson_95": [
                    round(value, 6) for value in wilson_interval(
                        int(round((values.get("solved_task_rate") or 0)
                                  * n_tasks)), n_tasks)]
            }
            for arm, values in metrics.items()
        },
        "negative_transfer": {
            "integrated_rate": metrics.get("E", {}).get(
                "negative_transfer_rate"),
            "per_arm": {arm: values.get("negative_transfer_rate")
                        for arm, values in metrics.items()},
        },
        "resource_overhead": resource_overhead(report),
        "failure_categories": failure_categories(report),
        "integration_vs_components": {
            arm: contrasts.get(f"E_vs_{arm}")
            for arm in ("B", "C", "D")},
        "evidence_class": evidence_class,
        "efficacy_claim": efficacy,
        "release_gate": release_gate,
        "limitations": limitations,
        "note": (
            "A confirmatory label requires a real coding agent, a hidden "
            "repository-disjoint holdout, protocol conformance and the "
            "preregistered sample size. No label here authorizes production "
            "skill promotion by itself."),
    }


@dataclass
class FiveArmCampaign:
    """Run the five matched arms and attach qualification analysis."""

    harness: BenchmarkHarness
    tasks: Sequence[tuple[TaskEnvelopeV1, Path]]
    agent: Callable
    budget: BudgetCaps
    protocol: Mapping
    context_provider: Callable
    learned_repo_digests: Sequence[str] = ()
    misleading_tasks: frozenset | set = frozenset()
    served_map: dict = field(default_factory=dict)
    arms: tuple[str, ...] = GOVERNED_ARMS
    real_agent: bool = False
    hidden_holdout: bool = True
    frozen_candidates: Mapping | None = None

    def validate(self) -> None:
        if tuple(self.arms) != tuple(GOVERNED_ARMS):
            raise ValueError("five-arm campaign requires arms A,B,C,D,E")
        if list(self.protocol.get("arms", [])) != list(GOVERNED_ARMS):
            raise ValueError("protocol arms do not match the five-arm design")
        if not self.tasks:
            raise ValueError("campaign requires a nonempty holdout")
        assert_partition_disjoint(_partition_from_tasks(self.tasks))
        learned = set(self.learned_repo_digests)
        overlap = learned & {task.repo_snapshot_digest
                             for task, _ in self.tasks}
        if overlap:
            raise ValueError(
                f"holdout repositories overlap learning evidence: {overlap}")

    def run(self) -> dict:
        self.validate()
        report = run_governed_evaluation(
            self.harness, list(self.tasks), self.agent,
            budget=self.budget, context_provider=self.context_provider,
            protocol=dict(self.protocol),
            learned_repo_digests=self.learned_repo_digests,
            misleading_tasks=self.misleading_tasks,
            served_map=self.served_map, arms=self.arms)
        report["learning_qualification"] = analyze_report(
            report, protocol=self.protocol, real_agent=self.real_agent,
            hidden_holdout=self.hidden_holdout,
            frozen_candidates=self.frozen_candidates, arms=self.arms)
        return report


def _partition_from_tasks(tasks):
    from .governed_eval import EvaluationPartition
    return EvaluationPartition(holdout=tuple(task for task, _ in tasks))


def build_context_provider(
    guidance_by_arm: Mapping[str, GuidanceV1 | None],
    served_map: dict | None = None,
):
    """Return a context provider that records actual nonempty delivery."""
    served = served_map if served_map is not None else {}

    def provider(task, arm):
        guidance = guidance_by_arm.get(arm)
        served[(task.task_id, arm)] = bool(
            guidance is not None and guidance.helpful_next_checks)
        return guidance
    return provider


# --------------------------------------------------------------------- #
# real-agent gate
# --------------------------------------------------------------------- #
def codex_agent_status() -> dict:
    """Report whether a real Codex CLI agent can be used, without calling it."""
    binary = shutil.which("codex")
    auth_path = Path.home() / ".codex" / "auth.json"
    authenticated = bool(os.environ.get("OPENAI_API_KEY")) or auth_path.exists()
    reason = "ok"
    if binary is None:
        reason = "codex_cli_not_found"
    elif not authenticated:
        reason = "codex_not_authenticated"
    return {
        "agent": "codex-cli",
        "available": binary is not None,
        "authenticated": authenticated,
        "binary": binary,
        "reason": reason,
    }


class CodexCliAgent:
    """Real coding-agent callable backed by ``codex exec --json``.

    This is an interface, not a claim that a powered evaluation was run.
    The CLI edits the disposable workspace under its workspace-write
    preset; the evaluator still independently verifies the result.
    """

    def __init__(self, *, model: str | None = None,
                 wall_seconds: int = 600,
                 prompts: Mapping[str, str] | None = None) -> None:
        status = codex_agent_status()
        if not status["available"] or not status["authenticated"]:
            raise RuntimeError("real_agent_unavailable:" + status["reason"])
        from .adapters.codex_cli import CodexCliAdapter
        self._adapter = CodexCliAdapter(wall_seconds=wall_seconds)
        self._model = model
        self._prompts = dict(prompts or {})

    def __call__(self, ctx):
        prompt = self._prompts.get(ctx.task.task_id)
        if not prompt:
            raise ValueError(
                "missing task prompt for real-agent task "
                + ctx.task.task_id)
        guidance = ctx.guidance
        if guidance is not None and guidance.helpful_next_checks:
            prompt += "\n\nGoverned SIS guidance (advisory, untrusted):\n" + \
                "\n".join(f"- {step}" for step in guidance.helpful_next_checks)
        before = tree_digest(ctx.workspace)
        turn = self._adapter.start_task(
            prompt, ctx.workspace, model=self._model,
            sandbox="workspace_write")
        tools = 0
        error_event = False
        for event in turn:
            if event.event_type in {"tool_request", "tool_result"}:
                tools += 1
            if event.event_type == "error":
                error_event = True
        if error_event:
            raise RuntimeError("real_agent_error_event")
        if tools == 0 or tree_digest(ctx.workspace) == before:
            raise RuntimeError("real_agent_no_action")
        return {"tokens_used": None, "tools_used": tools}

    def close(self) -> None:
        self._adapter.close()


def write_report(report: Mapping, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return path


def campaign_digest(report: Mapping) -> str:
    return canonical_digest("five_arm_report", 1, {
        "protocol": report.get("protocol_digest"),
        "qualification": report.get("learning_qualification"),
    })


__all__ = [
    "ARM_LABELS",
    "CONFIRMATORY",
    "CodexCliAgent",
    "DEMONSTRATION",
    "EXPLORATORY",
    "FiveArmCampaign",
    "INVALID",
    "analyze_report",
    "build_context_provider",
    "campaign_digest",
    "codex_agent_status",
    "failure_categories",
    "mcnemar_exact",
    "newcombe_difference_interval",
    "paired_contrast",
    "resource_overhead",
    "wilson_interval",
    "write_report",
]
