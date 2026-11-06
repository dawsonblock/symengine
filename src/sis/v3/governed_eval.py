"""Independent governed evaluation plane (SIS v3.3, milestone 6).

Five paired arms over the existing hardened ``BenchmarkHarness``:

    A  base agent
    B  base + experience memory
    C  base + evolved skills
    D  base + SIS symbolic procedures
    E  base + full governed integration (all qualified artifacts composed)

Validity conditions enforced structurally:

- Holdout partitions are sealed by construction: the qualification
  holdout and monitoring task sets must not share a repository snapshot
  digest with any induction/development task —
  ``assert_partition_disjoint`` runs before any run. Induction and
  development may overlap (dev data legitimately feeds both), but dev
  evidence is never generalization evidence.
- The protocol is *pre-registered*: metrics, thresholds, sample size,
  and statistical method are frozen into a domain-separated digest
  committed before the holdout run; the report embeds that digest so a
  reviewer can verify the analysis plan preceded the data.
- Evaluator custody is unchanged: outcomes come only from signed
  ``OutcomeReceiptV1``s; this module never touches signing material.
- Labels stay hidden: arms receive only their injected guidance context;
  the task set the optimizer saw (development) cannot appear in the
  holdout partition — enforced, not assumed.

Metrics are reported per arm plus integrity counters; missing usage
stays ``unverified``/``reported`` — nothing is fabricated.
"""
from __future__ import annotations

import json
import math
import statistics
from dataclasses import dataclass
from typing import Mapping, Sequence

from .benchmark import BenchmarkHarness, BudgetCaps
from .contracts import ContractError, TaskEnvelopeV1, canonical_digest
from .evaluation import assert_repository_disjoint

GOVERNED_ARMS = ("A", "B", "C", "D", "E")
PARTITIONS = ("induction", "development", "holdout", "monitoring")


@dataclass(frozen=True)
class EvaluationPartition:
    """Named, disjoint task partitions for the learning lifecycle."""

    induction: tuple[TaskEnvelopeV1, ...] = ()
    development: tuple[TaskEnvelopeV1, ...] = ()
    holdout: tuple[TaskEnvelopeV1, ...] = ()
    monitoring: tuple[TaskEnvelopeV1, ...] = ()

    def by_name(self, name: str) -> tuple[TaskEnvelopeV1, ...]:
        if name not in PARTITIONS:
            raise ContractError(f"unknown partition: {name}")
        return getattr(self, name)


def assert_partition_disjoint(partition: EvaluationPartition) -> None:
    """Hard check: holdout and monitoring stay sealed.

    The qualification holdout (and optional monitoring partition) must
    not share a repository snapshot digest with any task the learner or
    optimizer ever saw — induction or development. Induction and
    development may legitimately overlap: dev tasks both generate
    episodes and drive candidate selection. That reuse is development
    data, never generalization evidence — the holdout is what measures
    generalization, and it must be unseen. A run without a nonempty
    holdout is not a generalization measurement.
    """
    non_holdout = {"induction", "development"}
    seen: dict[str, str] = {}
    for name in PARTITIONS:
        for task in partition.by_name(name):
            other = seen.get(task.repo_snapshot_digest)
            if other is not None and other != name:
                if name in non_holdout and other in non_holdout:
                    continue
                raise ContractError(
                    f"partition overlap: repo digest shared by "
                    f"{other} and {name}")
            seen[task.repo_snapshot_digest] = name
    if not partition.holdout:
        raise ContractError("holdout partition must be nonempty")


def preregister(
    *,
    primary_metric: str,
    method: str,
    alpha: float,
    min_effect: float,
    sample_size: int,
    budget: Mapping[str, int],
    arms: Sequence[str] = GOVERNED_ARMS,
    notes: str = "",
    expected_baseline: float = 0.6,
    expected_treatment: float = 0.4,
    power: float = 0.8,
) -> dict:
    """Freeze the analysis plan; the digest proves it preceded the run."""
    required_n = required_sample_size(
        expected_baseline, expected_treatment, power=power, alpha=alpha)
    doc = {
        "schema_version": 1,
        "primary_metric": primary_metric,
        "method": method,
        "alpha": alpha,
        "min_effect": min_effect,
        "sample_size": sample_size,
        "budget": dict(budget),
        "arms": list(arms),
        "notes": notes,
        "power_analysis": {
            "expected_baseline": expected_baseline,
            "expected_treatment": expected_treatment,
            "power": power,
            "required_n": required_n,
        },
    }
    # canonical_json rejects floats; digest a deterministic normalized copy
    normalized = json.loads(
        json.dumps(doc, sort_keys=True),
        parse_float=lambda v: f"float:{v}")
    doc["protocol_digest"] = canonical_digest(
        "eval_protocol", 1, normalized)
    return doc


def required_sample_size(p1: float = 0.6, p2: float = 0.4, *,
                         power: float = 0.8, alpha: float = 0.05) -> int:
    """Approximate paired-binary sample size (McNemar-normal approx).

    For discordant-pair share q = p1 - p2 > 0 with discordant rate d:
    n ≈ d * ((z_1-α/2 + z_power) / q)². Z-scores are computed exactly for
    the requested alpha/power — no silent lookup substitution.
    """
    if not (0 < p2 < p1 < 1):
        raise ContractError("expected 0 < p2 < p1 < 1")
    if not (0 < alpha < 0.5):
        raise ContractError("alpha must be in (0, 0.5)")
    if not (0 < power < 1):
        raise ContractError("power must be in (0, 1)")
    normal = statistics.NormalDist()
    z_a = normal.inv_cdf(1 - alpha / 2)
    z_p = normal.inv_cdf(power)
    d = p1 * (1 - p2) + p2 * (1 - p1)
    q = p1 - p2
    return max(4, math.ceil(d * ((z_a + z_p) / q) ** 2))


def compute_metrics(report: Mapping, *, served: Mapping | None = None,
                    misleading_tasks: frozenset | set = frozenset()) -> dict:
    """Per-arm efficacy + integrity metrics from a harness report."""
    per_task = {t["task_id"]: t["arms"] for t in report.get("per_task", [])}
    arms = sorted({a for arms_ in per_task.values() for a in arms_})
    served = served or {}
    metrics: dict = {}
    for arm in arms:
        solved = served_n = abstained = served_failed = 0
        neg_served = neg_applied_failed = 0
        tokens: list[int] = []
        tools: list[int] = []
        walls: list[int] = []
        integrity_failures = 0
        for task_id, results in per_task.items():
            r = results.get(arm)
            if r is None:
                continue
            walls.append(int(r.get("wall_seconds") or 0))
            if isinstance(r.get("tokens_used"), int):
                tokens.append(r["tokens_used"])
            if isinstance(r.get("tools_used"), int):
                tools.append(r["tools_used"])
            if r.get("budget_exceeded"):
                integrity_failures += 1
            if r.get("error"):
                integrity_failures += 1
                continue
            was_served = served.get((task_id, arm), False)
            if was_served:
                served_n += 1
            else:
                abstained += 1
            ok = r.get("outcome") == "pass" and not r.get("budget_exceeded")
            solved += ok
            if was_served and not ok:
                served_failed += 1
            if task_id in misleading_tasks and was_served:
                neg_served += 1
                if not ok:
                    neg_applied_failed += 1
        n = len(per_task) or 1
        metrics[arm] = {
            "solved_task_rate": round(solved / n, 6),
            "served": served_n,
            "abstention_rate": round(abstained / n, 6),
            # Failure rate is absolute; verified_regression_rate (below) is
            # relative to the baseline arm and is filled in after the loop.
            "failure_rate": round(
                sum(1 for t in per_task.values()
                    if t.get(arm, {}).get("outcome") == "fail") / n, 6),
            "verified_regression_rate": None,
            "negative_transfer_rate": (
                round(neg_applied_failed / neg_served, 6)
                if neg_served else None),
            "mean_tokens_per_task": (
                round(sum(tokens) / len(tokens), 2) if tokens else None),
            "mean_tool_calls_per_task": (
                round(sum(tools) / len(tools), 2) if tools else None),
            "mean_wall_seconds_per_task": round(sum(walls) / n, 3),
            "mean_cost_per_verified_solve": None,
            "evaluation_integrity_failures": integrity_failures,
        }
    # Paired win/loss rates against the baseline arm, computed with the
    # same valid-solve rule as solved_task_rate (pass, in-budget).
    baseline = "A" if "A" in metrics else None
    baseline_passes = [
        task_id for task_id, results in per_task.items()
        if (results.get(baseline, {}).get("outcome") == "pass"
            and not results.get(baseline, {}).get("budget_exceeded"))
    ] if baseline else []
    for arm in metrics:
        if baseline is None:
            metrics[arm]["paired_win_rate"] = None
            metrics[arm]["paired_loss_rate"] = None
            continue
        wins = losses = 0
        for results in per_task.values():
            a = results.get(baseline, {})
            r = results.get(arm, {})
            a_ok = (a.get("outcome") == "pass"
                    and not a.get("budget_exceeded"))
            r_ok = (r.get("outcome") == "pass"
                    and not r.get("budget_exceeded"))
            wins += r_ok and not a_ok
            losses += a_ok and not r_ok
        metrics[arm]["paired_win_rate"] = round(wins / n, 6)
        metrics[arm]["paired_loss_rate"] = round(losses / n, 6)
        # A regression is a task the baseline verified as solved that this
        # arm no longer solves. An arm that merely fails where the baseline
        # also failed is not a regression; that is captured by failure_rate.
        regressions = sum(
            1 for task_id in baseline_passes
            if not (per_task[task_id].get(arm, {}).get("outcome") == "pass"
                    and not per_task[task_id].get(arm, {}).get("budget_exceeded")))
        metrics[arm]["verified_regression_rate"] = (
            round(regressions / len(baseline_passes), 6)
            if baseline_passes else None)
    return metrics


def run_governed_evaluation(
    harness: BenchmarkHarness,
    tasks,
    agent,
    *,
    budget: BudgetCaps,
    context_provider,
    protocol: dict,
    learned_repo_digests=(),
    misleading_tasks: frozenset | set = frozenset(),
    served_map: dict | None = None,
    arms: tuple[str, ...] = GOVERNED_ARMS,
) -> dict:
    """Run the paired governed evaluation and attach analysis metadata.

    ``context_provider(task, arm) -> guidance|None`` — called for every
    arm; whatever it returns is the only per-arm difference. ``served_map``
    optionally records (task_id, arm) -> bool where guidance was actually
    served (non-abstain) so abstention and negative transfer are measured
    rather than inferred.
    """
    assert_repository_disjoint(
        learned_repo_digests, [t for t, _ in tasks])
    served: dict = served_map if served_map is not None else {}
    report = harness.run(tasks, agent, budget=budget,
                         context_provider=context_provider, arms=arms)
    metrics = compute_metrics(
        report, served=served, misleading_tasks=misleading_tasks)
    report["governed"] = {
        "protocol_digest": protocol.get("protocol_digest"),
        "analysis_mode": "confirmatory",
        "metrics": metrics,
        "arms": list(arms),
        "conformance": _protocol_conformance(
            protocol, report, arms=arms, n_tasks=len(tasks)),
    }
    return report


def run_candidate_probe(
    harness: BenchmarkHarness,
    tasks,
    agent,
    *,
    budget: BudgetCaps,
    context_provider,
    protocol: dict,
    learned_repo_digests=(),
    arm: str = "E",
) -> dict:
    """Run one candidate's sealed-holdout probe under the same gates.

    Qualification evidence must name the candidate it qualifies, so each
    candidate is evaluated alone. The probe is not the confirmatory
    five-arm run, but it still enforces repository disjointness and
    records budget/sample-size conformance against the preregistered
    protocol — the evidence cites that protocol digest, so the run that
    produced it must be checked against the same plan.
    """
    assert_repository_disjoint(
        learned_repo_digests, [t for t, _ in tasks])
    report = harness.run(tasks, agent, budget=budget,
                         context_provider=context_provider, arms=(arm,))
    report["governed"] = {
        "protocol_digest": protocol.get("protocol_digest"),
        "analysis_mode": "candidate_probe",
        "arms": [arm],
        "conformance": _protocol_conformance(
            protocol, report, arms=None, n_tasks=len(tasks)),
    }
    return report


def _protocol_conformance(protocol: Mapping, report: Mapping, *,
                          arms: Sequence[str] | None,
                          n_tasks: int) -> dict:
    """Check the executed run against the preregistered plan.

    The protocol digest proves a plan existed; this block records whether
    *this* run honored it — budget, arm set, and the declared sample
    size. ``conforms=False`` is reported, never hidden: an underpowered
    or off-plan run is still honest evidence. ``arms=None`` skips the arm
    comparison for a single-candidate probe, which is deliberately not
    the preregistered arm set.
    """
    mismatches: list[str] = []
    declared_budget = protocol.get("budget") or {}
    actual_budget = report.get("budget") or {}
    for key, expected in sorted(declared_budget.items()):
        if key not in actual_budget:
            mismatches.append(f"budget.{key}_not_measured")
        elif actual_budget[key] != expected:
            mismatches.append(
                f"budget.{key}:expected={expected} actual={actual_budget[key]}")
    declared_arms = protocol.get("arms")
    if arms is not None and declared_arms is not None and \
            list(declared_arms) != list(arms):
        mismatches.append(
            f"arms:expected={list(declared_arms)} actual={list(arms)}")
    declared_n = protocol.get("sample_size")
    if type(declared_n) is int and n_tasks < declared_n:
        mismatches.append(
            f"sample_size:preregistered={declared_n} ran={n_tasks}"
            " (underpowered)")
    return {"conforms": not mismatches, "mismatches": mismatches}
