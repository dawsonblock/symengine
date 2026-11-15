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
import random
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .benchmark import BenchmarkHarness, BudgetCaps
from .contracts import ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest
from .runner import tree_digest
from .governed_eval import (GOVERNED_ARMS, assert_partition_disjoint,
                            protocol_required_sample_size,
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


def newcombe_paired_difference_interval(
    wins: int, losses: int, both: int, neither: int, *,
    z: float = 1.959963984540054,
) -> tuple[float, float]:
    """Newcombe interval for a difference between paired proportions.

    ``wins`` (treatment solved, baseline not) and ``losses`` (baseline
    solved, treatment not) are the discordant pairs; ``both`` and
    ``neither`` are the concordant pairs. The same tasks produce both
    outcomes, so the two solve rates are not independent and
    :func:`newcombe_difference_interval` overstates the variance. This is
    Newcombe's method 10 for paired data: marginal Wilson intervals
    combined with the observed pair correlation ``phi``.
    """
    for name, value in (("wins", wins), ("losses", losses),
                        ("both", both), ("neither", neither)):
        if type(value) is not int or value < 0:
            raise ValueError(f"{name} must be a nonnegative integer")
    n = wins + losses + both + neither
    if n <= 0:
        return (-1.0, 1.0)
    successes_t = both + wins
    successes_b = both + losses
    p_t, p_b = successes_t / n, successes_b / n
    l_t, u_t = wilson_interval(successes_t, n, z=z)
    l_b, u_b = wilson_interval(successes_b, n, z=z)
    delta = p_t - p_b
    phi = 0.0
    product = successes_t * (losses + neither) * successes_b * (wins + neither)
    if product > 0:
        cross = both * neither - wins * losses
        if cross > n / 2:
            cross -= n / 2
        elif cross > 0:
            cross = 0.0
        phi = cross / math.sqrt(product)
    lower = delta - math.sqrt(max(
        0.0, (p_t - l_t) ** 2 - 2 * phi * (p_t - l_t) * (u_b - p_b)
        + (u_b - p_b) ** 2))
    upper = delta + math.sqrt(max(
        0.0, (p_b - l_b) ** 2 - 2 * phi * (p_b - l_b) * (u_t - p_t)
        + (u_t - p_t) ** 2))
    return (max(-1.0, lower), min(1.0, upper))


def _token_total(usage: Mapping) -> int | None:
    """Budget-relevant token total for one usage record.

    ``input_tokens + output_tokens`` is the billed total; summing every
    integer would double-count ``total_tokens`` and the detail counters
    the adapter drops. Fall back to ``total_tokens`` and then to a plain
    sum only when the input/output pair is absent.
    """
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    if (type(input_tokens) is int and input_tokens >= 0
            and type(output_tokens) is int and output_tokens >= 0):
        return input_tokens + output_tokens
    total = usage.get("total_tokens")
    if type(total) is int and total >= 0:
        return total
    counts = [value for value in usage.values()
              if type(value) is int and value >= 0]
    return sum(counts) if counts else None


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
    both_solved = neither_solved = 0
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
            both_solved += a_ok
            neither_solved += not a_ok
    p = mcnemar_exact(wins, losses)
    lower, upper = newcombe_paired_difference_interval(
        wins, losses, both_solved, neither_solved)
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
        "both_solved": both_solved,
        "neither_solved": neither_solved,
        "mcnemar_exact_p": round(p, 8),
        "difference_interval_95": [round(lower, 6), round(upper, 6)],
        "difference_interval_method": "newcombe_paired",
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


def per_repository_metrics(report: Mapping, *,
                           arms: Sequence[str] = GOVERNED_ARMS) -> dict:
    """Solved counts per holdout repository, when task rows name one."""
    repositories: dict[str, dict] = {}
    for row in report.get("per_task", []):
        if not isinstance(row, Mapping):
            continue
        repository_id = row.get("repository_id")
        if not isinstance(repository_id, str) or not repository_id:
            continue
        entry = repositories.setdefault(
            repository_id,
            {"tasks": 0, "solved": {arm: 0 for arm in arms}})
        entry["tasks"] += 1
        results = row.get("arms", {})
        for arm in arms:
            if _valid_solve(results.get(arm, {})):
                entry["solved"][arm] += 1
    return dict(sorted(repositories.items()))


def repository_clustered_delta_interval(
    report: Mapping, *, baseline: str = "A", treatment: str = "E",
    draws: int = 2000, seed: int = 0,
) -> dict | None:
    """Cluster bootstrap over repositories for the pooled solve delta.

    Tasks within one repository are correlated draws, so a task-level
    interval understates uncertainty. This resamples whole repositories
    with replacement and recomputes the pooled ``treatment - baseline``
    solve-rate difference. Returns ``None`` when no task row names a
    repository.
    """
    clusters: dict[str, list[int]] = {}
    for row in report.get("per_task", []):
        if not isinstance(row, Mapping):
            continue
        repository_id = row.get("repository_id")
        if not isinstance(repository_id, str) or not repository_id:
            continue
        results = row.get("arms", {})
        delta = (1 if _valid_solve(results.get(treatment, {})) else 0) - \
                (1 if _valid_solve(results.get(baseline, {})) else 0)
        clusters.setdefault(repository_id, []).append(delta)
    if not clusters:
        return None
    if len(clusters) < 2:
        return {"method": "repository_cluster_bootstrap",
                "repositories": len(clusters), "draws": 0,
                "interval_95": None,
                "reason": "fewer_than_two_repositories"}
    values = [clusters[name] for name in sorted(clusters)]
    rng = random.Random(seed)
    estimates = []
    for _ in range(draws):
        chosen = [values[rng.randrange(len(values))] for _ in values]
        total = sum(len(item) for item in chosen)
        if total:
            estimates.append(
                sum(sum(item) for item in chosen) / total)
    if not estimates:
        return None
    estimates.sort()
    low = estimates[max(0, int(0.025 * (len(estimates) - 1)))]
    high = estimates[min(len(estimates) - 1,
                         int(0.975 * (len(estimates) - 1)))]
    return {"method": "repository_cluster_bootstrap",
            "repositories": len(clusters), "draws": draws,
            "interval_95": [round(low, 6), round(high, 6)]}


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
    provenance: Mapping | None = None,
) -> dict:
    """Attach honest qualification analysis to a governed report.

    ``provenance`` records facts the classifier cannot infer from the
    report: which agent ran, whether the CLI version matched, the custody
    mode, whether guidance came from learned components, and whether the
    manifest was committed before the run. A real-agent run without those
    facts is never confirmatory.
    """
    metrics = report.get("governed", {}).get("metrics", {})
    conformance = report.get("governed", {}).get("conformance", {})
    n_tasks = len(report.get("per_task", []))
    provenance = dict(provenance or {})
    accountings = {
        row.get("budget_accounting")
        for task in report.get("per_task", [])
        for row in task.get("arms", {}).values()}
    if accountings and accountings == {"verified"}:
        token_accounting = "verified"
    elif "partial" in accountings:
        token_accounting = "partial"
    elif accountings == {"reported"}:
        token_accounting = "reported"
    else:
        token_accounting = "unverified"
    provenance["token_accounting"] = token_accounting
    contrasts = {}
    for arm in arms:
        if arm == "A":
            continue
        baseline = "A" if arm == "E" else arm
        contrasts[f"E_vs_{baseline}"] = paired_contrast(
            report, baseline=baseline, treatment="E")
    # The decisive contrast is always E vs A.
    decisive = paired_contrast(report, baseline="A", treatment="E")
    alpha = protocol.get("alpha", 0.05)
    sample_size = protocol.get("sample_size")
    sample_size_valid = type(sample_size) is int and sample_size >= 1
    power_block = protocol.get("power_analysis")
    declared_power = power_block if isinstance(power_block, Mapping) else {}
    # A confirmatory label requires an explicitly powered preregistered
    # plan. ``preregister()`` records power through ``power_analysis``;
    # an explicit ``powered=False``, a non-boolean flag or a diagnostic
    # plan has no floor a reviewer can verify.
    power_flag = protocol.get("powered")
    powered = ((power_flag is True or power_flag is None)
               and protocol.get("analysis_kind") != "diagnostic")
    power_problems: list[str] = []
    required_n: int | None = None
    if powered:
        try:
            required_n = protocol_required_sample_size(protocol)
        except ContractError as exc:
            power_problems.append(str(exc))
    else:
        power_problems.append(
            "protocol is diagnostic or not explicitly powered")
    minimum_n = max(sample_size if sample_size_valid else 0, required_n or 0)
    underpowered = n_tasks < minimum_n
    power_gap = None
    if not powered:
        power_gap = ("protocol is diagnostic/unpowered; a confirmatory "
                     "label requires an explicitly powered preregistered "
                     "plan")
    elif required_n is None:
        power_gap = ("protocol power analysis is missing or inconsistent: "
                     + "; ".join(power_problems))
    elif not sample_size_valid:
        power_gap = "protocol sample_size is not a positive integer"
    provenance_gaps: list[str] = []
    if real_agent:
        if power_gap is not None:
            provenance_gaps.append(power_gap)
        if provenance.get("agent") != "codex-cli":
            provenance_gaps.append(
                "agent provenance is not a real codex-cli run")
        if provenance.get("cli_version_matches") is not True:
            provenance_gaps.append(
                "installed CLI version does not match the manifest")
        if provenance.get("custody") != "split":
            provenance_gaps.append(
                "private acceptance tests ran under shared custody")
        if provenance.get("guidance_source") != "learned":
            provenance_gaps.append(
                "guidance bundles are fixed control prompts, not learned "
                "components")
        if provenance.get("preregistration_anchored") is not True:
            provenance_gaps.append(
                "manifest was not committed before the run")
        if token_accounting != "verified":
            provenance_gaps.append(
                "token and tool usage were not fully metered")
    injected = provenance.get("agent") not in (None, "codex-cli")
    if not real_agent:
        evidence_class = DEMONSTRATION
    elif injected:
        evidence_class = INVALID
    elif not hidden_holdout or not conformance.get("conforms"):
        evidence_class = INVALID
    elif provenance_gaps or underpowered:
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
    if power_gap is not None and not real_agent:
        limitations.append(power_gap)
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
    limitations.extend(provenance_gaps)
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
        "provenance": provenance,
        "confirmatory_eligible": bool(
            real_agent and hidden_holdout and conformance.get("conforms")
            and powered and required_n is not None and sample_size_valid
            and not underpowered and not provenance_gaps),
        "sample_size_preregistered": sample_size,
        "required_sample_size_0_6_vs_0_4": required_sample_size(0.6, 0.4),
        "power_analysis": {
            "powered": powered,
            "expected_baseline": declared_power.get(
                "expected_baseline", 0.6),
            "expected_treatment": declared_power.get(
                "expected_treatment", 0.4),
            "power": declared_power.get("power", 0.8),
            "alpha": alpha,
            "required_n": required_n,
            "required_n_recomputed": required_n,
            "preregistered_n": sample_size,
            "minimum_n": minimum_n,
            "problems": power_problems,
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
        "per_repository": per_repository_metrics(report, arms=arms),
        "repository_clustered_uncertainty":
            repository_clustered_delta_interval(
                report, baseline="A", treatment="E"),
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
    provenance: Mapping | None = None
    arm_order_seed: int | str | None = None
    repository_ids: Mapping[str, str] | None = None

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
            served_map=self.served_map, arms=self.arms,
            arm_order_seed=self.arm_order_seed)
        if self.repository_ids:
            for row in report.get("per_task", []):
                repository_id = self.repository_ids.get(row.get("task_id"))
                if repository_id:
                    row["repository_id"] = repository_id
        report["learning_qualification"] = analyze_report(
            report, protocol=self.protocol, real_agent=self.real_agent,
            hidden_holdout=self.hidden_holdout,
            frozen_candidates=self.frozen_candidates, arms=self.arms,
            provenance=self.provenance)
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
        supervisor = getattr(ctx, "supervisor", None)
        if supervisor is not None:
            supervisor.register_terminator(
                lambda: self._cancel(turn.turn_id))
        tools = 0
        delta_tokens = 0
        terminal_tokens: int | None = None
        error_event = False
        turn_completed = False
        exit_status = None
        timed_out = False
        for event in turn:
            if supervisor is not None and supervisor.aborted:
                raise RuntimeError("real_agent_aborted")
            payload = getattr(event, "payload", None)
            if not isinstance(payload, Mapping):
                continue
            summary = payload.get("summary")
            summary = summary if isinstance(summary, Mapping) else {}
            method = payload.get("sdk_method")
            usage = summary.get("token_usage")
            if not isinstance(usage, Mapping):
                usage = payload.get("token_usage")
            if isinstance(usage, Mapping):
                total = _token_total(usage)
                if total is not None:
                    # ``turn.completed`` reports the cumulative total for
                    # the turn; item-level records are deltas. Taking the
                    # maximum keeps a cumulative record from being added
                    # to itself, and a later terminal total supersedes an
                    # earlier one.
                    if method == "turn.completed":
                        terminal_tokens = max(terminal_tokens or 0, total)
                    else:
                        delta_tokens += total
            if method == "turn.completed":
                turn_completed = True
            elif method == "sis/process_exit":
                exit_status = summary.get("cli_exit_status")
                timed_out = bool(summary.get("timed_out"))
            elif method in {"turn.failed", "turn.cancelled", "error"}:
                error_event = True
            if event.event_type == "error":
                error_event = True
            # Count a completed command/edit once. The start and
            # completion events of one command are not two tool calls.
            if (event.event_type in {"tool_result", "edit"}
                    or (method == "item.completed"
                        and summary.get("item_type")
                        in {"mcp_tool_call", "web_search"})):
                tools += 1
                if ctx.usage_meter is not None:
                    ctx.usage_meter.record_tool_call()
        tokens = max(delta_tokens, terminal_tokens or 0)
        tokens_seen = terminal_tokens is not None or delta_tokens > 0
        if error_event:
            raise RuntimeError("real_agent_error_event")
        if timed_out:
            raise RuntimeError("real_agent_timeout")
        if exit_status is None:
            raise RuntimeError("real_agent_missing_exit_status")
        if exit_status != 0:
            raise RuntimeError(f"real_agent_cli_exit:{exit_status}")
        if not turn_completed:
            raise RuntimeError("real_agent_turn_incomplete")
        if tools == 0 or tree_digest(ctx.workspace) == before:
            raise RuntimeError("real_agent_no_action")
        if tokens_seen and ctx.usage_meter is not None:
            ctx.usage_meter.record_tokens(tokens)
        return {"tokens_used": tokens if tokens_seen else None,
                "tools_used": tools}

    def _cancel(self, turn_id: str) -> None:
        """Terminate the active CLI turn when the harness aborts the arm."""
        try:
            self._adapter.cancel(turn_id)
        except Exception:
            # The turn already exited; nothing left to terminate.
            pass

    def close(self) -> None:
        self._adapter.close()


def write_report(report: Mapping, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return path


def _digest_safe(value):
    """Normalize floats so canonical_digest accepts an analysis report."""
    return json.loads(
        json.dumps(value, sort_keys=True),
        parse_float=lambda item: f"float:{item}")


def campaign_digest(report: Mapping) -> str:
    return canonical_digest("five_arm_report", 1, {
        "protocol": report.get("protocol_digest"),
        "qualification": _digest_safe(report.get("learning_qualification")),
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
    "newcombe_paired_difference_interval",
    "paired_contrast",
    "per_repository_metrics",
    "repository_clustered_delta_interval",
    "resource_overhead",
    "wilson_interval",
    "write_report",
]
