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
import random
import statistics
from dataclasses import dataclass
from typing import Mapping, Sequence

from .benchmark import BenchmarkHarness, BudgetCaps
from .contracts import ContractError, TaskEnvelopeV1, canonical_digest
from .evaluation import assert_repository_disjoint

GOVERNED_ARMS = ("A", "B", "C", "D", "E")
PRIMARY_CONTRAST_ARMS = ("A", "E")
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
    expected_baseline: float = 0.4,
    expected_treatment: float = 0.6,
    power: float = 0.8,
    powered: bool = True,
    allow_underpowered: bool = False,
    max_negative_transfer: float | None = None,
) -> dict:
    """Freeze the analysis plan; the digest proves it preceded the run.

    ``expected_baseline`` and ``expected_treatment`` are the expected
    solve rates of the baseline and treatment arms. An efficacy study
    normally expects the treatment to be *higher*; the two-sided power
    calculation is symmetric in the two rates, so a declared regression
    of the same size needs the same number of pairs and is accepted too.
    The recomputation never assumes the treatment is the lower rate.

    The declared effect ``|expected_treatment - expected_baseline|`` may
    not exceed the preregistered ``min_effect``: powering for an effect
    larger than the smallest effect of interest would justify a sample
    too small to detect the effect the study claims to care about. Both
    rates must lie in (0, 1) and ``min_effect`` in (0, 1].

    ``powered=True`` (the default) freezes a powered-experiment plan: the
    declared expectations are recomputed into ``power_analysis.required_n``
    and validators can enforce that the executed run met the floor. A
    powered plan whose declared ``sample_size`` is below that recomputed
    floor is refused at registration — a plan that contradicts its own
    power target is an authoring error, not a finding to discover after
    the run. ``allow_underpowered=True`` is the explicit, digest-visible
    opt-out for a deliberately exploratory run; it records
    ``power_analysis.underpowered_declared`` so the report and any
    downstream certificate carry the shortfall rather than hide it.
    ``powered=False`` registers an explicit *diagnostic* plan — a
    deterministic screen such as a one-task candidate probe — which binds
    the same fields but carries no power claim. A diagnostic protocol
    honestly reports what it is: it can never satisfy production
    qualification because there is no floor for a validator to verify.

    ``max_negative_transfer`` optionally preregisters the largest share of
    paired tasks on which the treatment may lose a baseline solve before
    negative transfer counts as material; when omitted the analysis uses
    its documented default. It is only recorded when supplied, so existing
    protocol digests are unchanged.
    """
    if type(powered) is not bool:
        raise ContractError("powered must be a bool")
    if type(allow_underpowered) is not bool:
        raise ContractError("allow_underpowered must be a bool")
    if not powered and allow_underpowered:
        raise ContractError("allow_underpowered requires a powered plan")
    if type(sample_size) is not int:
        raise ContractError("sample_size must be an int")
    if sample_size < 1:
        raise ContractError("sample_size must be positive")
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
    }
    if max_negative_transfer is not None:
        if type(max_negative_transfer) not in (int, float) or \
                not 0 <= max_negative_transfer < 1:
            raise ContractError("max_negative_transfer must be in [0, 1)")
        doc["max_negative_transfer"] = max_negative_transfer
    if powered:
        _check_declared_effect(min_effect, expected_baseline,
                               expected_treatment)
        required_n = required_sample_size(
            expected_baseline, expected_treatment, power=power, alpha=alpha)
        doc["power_analysis"] = {
            "expected_baseline": expected_baseline,
            "expected_treatment": expected_treatment,
            "power": power,
            "required_n": required_n,
        }
        if sample_size < required_n:
            if not allow_underpowered:
                raise ContractError(
                    f"sample_size={sample_size} is below the recomputed "
                    f"power floor {required_n}; register a diagnostic plan "
                    "or pass allow_underpowered=True deliberately")
            doc["power_analysis"]["underpowered_declared"] = True
    else:
        doc["analysis_kind"] = "diagnostic"
    # canonical_json rejects floats; digest a deterministic normalized copy
    normalized = json.loads(
        json.dumps(doc, sort_keys=True),
        parse_float=lambda v: f"float:{v}")
    doc["protocol_digest"] = canonical_digest(
        "eval_protocol", 1, normalized)
    return doc


_EFFECT_TOLERANCE = 1e-9


def _check_declared_effect(min_effect, expected_baseline,
                           expected_treatment) -> None:
    """Bind the powering effect to the preregistered minimum effect.

    Direction-agnostic: only the size ``|treatment - baseline|`` is
    compared, so a declared regression is treated like an improvement.
    """
    for value in (expected_baseline, expected_treatment):
        if type(value) not in (int, float) or not 0 < value < 1:
            raise ContractError("expected rates must be in (0, 1)")
    if type(min_effect) not in (int, float) or not 0 < min_effect <= 1:
        raise ContractError("min_effect must be in (0, 1]")
    effect = abs(expected_treatment - expected_baseline)
    if effect > min_effect + _EFFECT_TOLERANCE:
        raise ContractError(
            f"declared effect {effect:.6g} exceeds the preregistered "
            f"min_effect {min_effect}; power for the minimum effect of "
            "interest, not a larger one")


def required_sample_size(p1: float = 0.6, p2: float = 0.4, *,
                         power: float = 0.8, alpha: float = 0.05) -> int:
    """Approximate paired-binary sample size (McNemar-normal approx).

    ``p1`` and ``p2`` are the two expected solve rates in either order:
    the alternative is two-sided, so an expected improvement and an
    expected regression of the same size need the same number of pairs.
    Only equality (no effect to detect) and out-of-range rates are
    refused.

    For discordant-pair share q = |p1 - p2| with discordant rate d:
    n ≈ d * ((z_1-α/2 + z_power) / q)². Z-scores are computed exactly for
    the requested alpha/power — no silent lookup substitution.

    Limitations: this is a planning heuristic, not a guaranteed paired
    power computation. The discordant rate
    ``d = p1*(1-p2) + p2*(1-p1)`` treats the two arms' solve outcomes as
    marginally independent; the actual power of a paired McNemar test
    depends on the *joint* discordant split (which tasks each arm wins
    and the other loses), which a two-proportion summary cannot model.
    True paired analyses can require more or fewer discordant pairs
    depending on within-task correlation. The normal approximation is
    also optimistic at small n — the ``max(4, ...)`` floor keeps the
    returned value from becoming absurd, not from being exact.
    """
    for value in (p1, p2):
        # The range check also refuses NaN, infinities and integers too
        # large to convert to a float; do not call math.isfinite() first,
        # which raises OverflowError for such an integer.
        if type(value) not in (int, float) or not 0 < value < 1:
            raise ContractError("expected rates must be in (0, 1)")
    if p1 == p2:
        raise ContractError("expected rates must differ")
    if not (0 < alpha < 0.5):
        raise ContractError("alpha must be in (0, 0.5)")
    if not (0 < power < 1):
        raise ContractError("power must be in (0, 1)")
    normal = statistics.NormalDist()
    z_a = normal.inv_cdf(1 - alpha / 2)
    z_p = normal.inv_cdf(power)
    d = p1 * (1 - p2) + p2 * (1 - p1)
    q = abs(p1 - p2)
    return max(4, math.ceil(d * ((z_a + z_p) / q) ** 2))


def sign_flip_p_value(totals: Sequence[int]) -> float:
    """Exact two-sided sign-flip p-value of per-repository totals.

    The same test as ``learning_qualification.repository_sign_flip_test``:
    under the null every repository total's sign is exchangeable, and the
    p-value is the share of the ``2**R`` sign assignments whose absolute
    sum reaches the observed one. Zero totals do not change it.
    """
    values = [abs(int(total)) for total in totals if total]
    observed = abs(sum(int(total) for total in totals))
    if not values:
        return 1.0
    span = sum(values)
    # Subset-sum counts: choosing the negative set with |sum| j gives the
    # signed sum span - 2j.
    counts = [1] + [0] * span
    for value in values:
        counts = counts[:value] + [
            high + low for high, low in zip(counts[value:], counts)]
    extreme = sum(count for j, count in enumerate(counts)
                  if abs(span - 2 * j) >= observed)
    return extreme / (2 ** len(values))


class _ClusterModel:
    """Latent-threshold model of paired outcomes clustered by repository.

    A task ``t`` of repository ``r`` is solved in arm ``a`` when
    ``z_a + d_ra + sqrt(icc)*u_r + sqrt(1-icc)*(sqrt(k)*v_t + sqrt(1-k)*w_ta)
    > 0`` with standard-normal ``u_r`` (repository difficulty, shared by
    both arms), ``v_t`` (task difficulty, shared by both arms of the task,
    ``k = task_correlation``) and ``w_ta`` (independent noise). The
    treatment arm adds a repository-specific effect ``d_rE = effect_sd *
    h_r`` (``h_r`` standard normal; ``d_rA = 0``). The thresholds ``z_a``
    are scaled so the marginal solve rates are exactly ``baseline_rate``
    and ``treatment_rate``.
    """

    def __init__(self, *, baseline_rate, treatment_rate, icc,
                 task_correlation, effect_sd) -> None:
        normal = statistics.NormalDist()
        self.z_a = normal.inv_cdf(baseline_rate)
        self.z_e = normal.inv_cdf(treatment_rate) * math.sqrt(
            1 + effect_sd * effect_sd)
        self.between = math.sqrt(icc)
        self.within = math.sqrt(1 - icc)
        self.shared = math.sqrt(task_correlation)
        self.own = math.sqrt(1 - task_correlation)
        self.effect_sd = effect_sd

    def repository(self, rng: random.Random, tasks: int) -> list[int]:
        """Per-task paired differences (E minus A) for one repository."""
        difficulty = self.between * rng.gauss(0.0, 1.0)
        effect = self.effect_sd * rng.gauss(0.0, 1.0) if self.effect_sd \
            else 0.0
        deltas = []
        for _ in range(tasks):
            task = self.shared * rng.gauss(0.0, 1.0)
            solved_a = self.z_a + difficulty + self.within * (
                task + self.own * rng.gauss(0.0, 1.0)) > 0
            solved_e = self.z_e + effect + difficulty + self.within * (
                task + self.own * rng.gauss(0.0, 1.0)) > 0
            deltas.append(int(solved_e) - int(solved_a))
        return deltas


def anova_icc(clusters: Sequence[Sequence[float]]) -> float | None:
    """One-way ANOVA intra-cluster correlation (unequal sizes allowed).

    ``(MSB - MSW) / (MSB + (n0 - 1) * MSW)`` with the usual ``n0`` for
    unequal cluster sizes; ``None`` when it is undefined (fewer than two
    clusters, or no within-cluster replication). Clipped below at 0.
    """
    groups = [list(map(float, group)) for group in clusters if group]
    total_n = sum(len(group) for group in groups)
    k = len(groups)
    if k < 2 or total_n <= k:
        return None
    grand = sum(sum(group) for group in groups) / total_n
    ssb = sum(len(g) * (sum(g) / len(g) - grand) ** 2 for g in groups)
    ssw = sum(sum((x - sum(g) / len(g)) ** 2 for x in g) for g in groups)
    msb = ssb / (k - 1)
    msw = ssw / (total_n - k)
    n0 = (total_n - sum(len(g) ** 2 for g in groups) / total_n) / (k - 1)
    denominator = msb + (n0 - 1) * msw
    if denominator <= 0:
        return 0.0
    return max(0.0, (msb - msw) / denominator)


def _simulated_power(repositories: int, *, tasks_per_repository: int,
                     model: _ClusterModel, alpha: float, simulations: int,
                     seed) -> float:
    rng = random.Random(f"{seed}:{repositories}:{tasks_per_repository}")
    supported = 0
    for _ in range(simulations):
        totals = [sum(model.repository(rng, tasks_per_repository))
                  for _ in range(repositories)]
        if sum(totals) > 0 and sign_flip_p_value(totals) <= alpha:
            supported += 1
    return supported / simulations


def _check_power_inputs(repositories, tasks_per_repository, baseline_rate,
                        treatment_rate, icc, task_correlation, effect_sd,
                        alpha, simulations) -> None:
    if type(repositories) is not int or repositories < 1:
        raise ContractError("repositories must be a positive integer")
    if type(tasks_per_repository) is not int or tasks_per_repository < 1:
        raise ContractError("tasks_per_repository must be a positive integer")
    for name, value in (("baseline_rate", baseline_rate),
                        ("treatment_rate", treatment_rate)):
        if type(value) not in (int, float) or not 0 < value < 1:
            raise ContractError(f"{name} must be in (0, 1)")
    if type(icc) not in (int, float) or not 0 <= icc < 1:
        raise ContractError("icc must be in [0, 1)")
    if type(task_correlation) not in (int, float) or \
            not 0 <= task_correlation <= 1:
        raise ContractError("task_correlation must be in [0, 1]")
    if type(effect_sd) not in (int, float) or not 0 <= effect_sd <= 10:
        raise ContractError("effect_sd must be in [0, 10]")
    if type(alpha) not in (int, float) or not 0 < alpha < 0.5:
        raise ContractError("alpha must be in (0, 0.5)")
    if type(simulations) is not int or not 10 <= simulations <= 1_000_000:
        raise ContractError("simulations must be an integer in [10, 1e6]")


def repository_power(repositories: int, *, tasks_per_repository: int,
                     baseline_rate: float, treatment_rate: float,
                     icc: float = 0.0, effect_sd: float = 0.0,
                     task_correlation: float = 0.5, alpha: float = 0.05,
                     simulations: int = 1000, seed: int | str = 0) -> float:
    """Simulated power of the repository-level sign-flip decision.

    Outcomes follow :class:`_ClusterModel`. ``icc`` is the latent
    intra-repository correlation of task difficulty (shared by both arms),
    ``effect_sd`` the between-repository spread of the treatment effect on
    the latent scale (what makes repositories disagree about the effect),
    ``task_correlation`` the share of a task's own difficulty that both
    arms face. A simulated study supports efficacy when its wins-minus-
    losses total is positive and the exact sign-flip p-value over
    repositories is at most ``alpha`` — the decisive test of
    ``analyze_report``. Its cluster-bootstrap interval and the
    negative-transfer gate are not simulated, so this is an upper bound
    on the power of the full gate. Deterministic for a given ``seed``.
    """
    _check_power_inputs(repositories, tasks_per_repository, baseline_rate,
                        treatment_rate, icc, task_correlation, effect_sd,
                        alpha, simulations)
    model = _ClusterModel(baseline_rate=baseline_rate,
                          treatment_rate=treatment_rate, icc=icc,
                          task_correlation=task_correlation,
                          effect_sd=effect_sd)
    return _simulated_power(repositories,
                            tasks_per_repository=tasks_per_repository,
                            model=model, alpha=alpha,
                            simulations=simulations, seed=seed)


def calibrate_effect_sd(difference_icc: float, *, tasks_per_repository: int,
                        baseline_rate: float, treatment_rate: float,
                        icc: float = 0.0, task_correlation: float = 0.5,
                        repositories: int = 2000, seed: int | str = 0
                        ) -> float:
    """The ``effect_sd`` whose simulated difference ICC matches a pilot's.

    A pilot measures the intra-repository correlation of the paired task
    differences (:func:`pilot_planning_inputs`); this inverts the model
    by bisection on a large deterministic simulation. Returns 0 when the
    target is at or below what shared difficulty alone produces.
    """
    if type(difference_icc) not in (int, float) or \
            not 0 <= difference_icc < 1:
        raise ContractError("difference_icc must be in [0, 1)")

    def simulated(effect_sd: float) -> float:
        model = _ClusterModel(baseline_rate=baseline_rate,
                              treatment_rate=treatment_rate, icc=icc,
                              task_correlation=task_correlation,
                              effect_sd=effect_sd)
        rng = random.Random(f"{seed}:calibrate")
        value = anova_icc([model.repository(rng, tasks_per_repository)
                           for _ in range(repositories)])
        return value or 0.0

    low, high = 0.0, 4.0
    if simulated(low) >= difference_icc:
        return 0.0
    if simulated(high) <= difference_icc:
        return high
    for _ in range(20):
        middle = (low + high) / 2
        if simulated(middle) < difference_icc:
            low = middle
        else:
            high = middle
    return round((low + high) / 2, 4)


def pilot_planning_inputs(report: Mapping, *, baseline: str = "A",
                          treatment: str = "E") -> dict:
    """What a pilot run measured that :func:`required_repositories` needs.

    From the task rows of a governed report (``repository_id`` set on
    every row): per-arm valid-solve rates, mean tasks per repository, the
    ANOVA intra-repository correlation of baseline outcomes
    (``outcome_icc``) and of the paired differences
    (``difference_icc``). These are point estimates from a small sample;
    plan with a conservative value, not the estimate alone.
    """
    def solved(row: Mapping) -> int:
        return int(row.get("outcome") == "pass"
                   and not row.get("budget_exceeded")
                   and not row.get("error"))

    outcomes: dict[str, list[int]] = {}
    deltas: dict[str, list[int]] = {}
    base = treat = n = 0
    for row in report.get("per_task", []):
        repository = row.get("repository_id")
        arms = row.get("arms", {})
        if not isinstance(repository, str) or baseline not in arms \
                or treatment not in arms:
            continue
        a, e = solved(arms[baseline]), solved(arms[treatment])
        outcomes.setdefault(repository, []).append(a)
        deltas.setdefault(repository, []).append(e - a)
        base += a
        treat += e
        n += 1
    repositories = len(deltas)
    return {
        "tasks": n,
        "repositories": repositories,
        "tasks_per_repository": round(n / repositories, 3)
        if repositories else None,
        "baseline_rate": round(base / n, 6) if n else None,
        "treatment_rate": round(treat / n, 6) if n else None,
        "outcome_icc": anova_icc(list(outcomes.values())),
        "difference_icc": anova_icc(list(deltas.values())),
    }


def required_repositories(
    *,
    baseline_rate: float,
    treatment_rate: float,
    tasks_per_repository: int,
    icc: float = 0.0,
    effect_sd: float | None = None,
    difference_icc: float | None = None,
    power: float = 0.8,
    alpha: float = 0.05,
    task_correlation: float = 0.5,
    simulations: int = 1000,
    seed: int | str = 0,
    max_repositories: int = 400,
) -> dict:
    """Smallest number of holdout repositories that reaches ``power``.

    Sizes a confirmatory study for the repository-level decision of
    ``analyze_report`` from a pilot's estimates (see
    :func:`pilot_planning_inputs`): per-arm solve rates, tasks per
    repository, the latent difficulty ``icc`` and the between-repository
    spread of the effect — given directly as ``effect_sd`` or as the
    pilot's ``difference_icc`` (then calibrated with
    :func:`calibrate_effect_sd`). :func:`required_sample_size` assumes
    independent tasks; this accounts for repositories being the unit of
    the test. The search doubles until the target is reached and then
    bisects; every candidate size has its own deterministic stream, so
    the result is reproducible for a given ``seed``. ``recommended_*``
    is never below the confirmatory floor
    (``MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES``).
    """
    from .learning_qualification import MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES

    if type(power) not in (int, float) or not 0 < power < 1:
        raise ContractError("power must be in (0, 1)")
    if baseline_rate == treatment_rate:
        raise ContractError("expected rates must differ")
    if type(max_repositories) is not int or max_repositories < 2:
        raise ContractError("max_repositories must be an integer >= 2")
    if effect_sd is not None and difference_icc is not None:
        raise ContractError("give effect_sd or difference_icc, not both")
    _check_power_inputs(2, tasks_per_repository, baseline_rate,
                        treatment_rate, icc, task_correlation,
                        effect_sd or 0.0, alpha, simulations)
    if difference_icc is not None:
        effect_sd = calibrate_effect_sd(
            difference_icc, tasks_per_repository=tasks_per_repository,
            baseline_rate=baseline_rate, treatment_rate=treatment_rate,
            icc=icc, task_correlation=task_correlation, seed=seed)
    effect_sd = effect_sd or 0.0
    model = _ClusterModel(baseline_rate=baseline_rate,
                          treatment_rate=treatment_rate, icc=icc,
                          task_correlation=task_correlation,
                          effect_sd=effect_sd)
    curve: dict[int, float] = {}

    def at(repositories: int) -> float:
        if repositories not in curve:
            curve[repositories] = _simulated_power(
                repositories, tasks_per_repository=tasks_per_repository,
                model=model, alpha=alpha, simulations=simulations, seed=seed)
        return curve[repositories]

    inputs = {"baseline_rate": baseline_rate,
              "treatment_rate": treatment_rate,
              "tasks_per_repository": tasks_per_repository, "icc": icc,
              "effect_sd": effect_sd, "difference_icc": difference_icc,
              "task_correlation": task_correlation, "power": power,
              "alpha": alpha, "simulations": simulations, "seed": seed}
    # A test over R repositories cannot reach p below 2**(1 - R).
    low = max(2, math.ceil(1 - math.log2(alpha)))
    high = low
    while at(high) < power:
        if high >= max_repositories:
            return {"required_repositories": None, "reached": False,
                    "power_at_max": round(at(high), 6),
                    "max_repositories": max_repositories,
                    "curve": {str(k): round(v, 6)
                              for k, v in sorted(curve.items())},
                    **inputs}
        low = high
        high = min(max_repositories, high * 2)
    while high - low > 1:
        middle = (low + high) // 2
        if at(middle) >= power:
            high = middle
        else:
            low = middle
    if at(low) >= power:
        high = low
    recommended = max(high, MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES)
    return {
        "required_repositories": high,
        "reached": True,
        "achieved_power": round(at(high), 6),
        "confirmatory_floor": MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES,
        "recommended_repositories": recommended,
        "recommended_tasks": recommended * tasks_per_repository,
        "independent_task_n": required_sample_size(
            baseline_rate, treatment_rate, power=power, alpha=alpha),
        "curve": {str(k): round(v, 6) for k, v in sorted(curve.items())},
        "decision": "repository_sign_flip_exact",
        "model": "probit latent threshold: repository difficulty, task"
                 " difficulty and repository-specific effect",
        **inputs,
    }


def protocol_required_sample_size(protocol: Mapping) -> int:
    """Recompute the registered power floor; reject absent or inconsistent data.

    Powered protocols must carry a ``power_analysis`` block whose
    ``required_n`` agrees with the value recomputed from the registered
    expectations and ``alpha`` — a caller cannot weaken the floor by
    editing the stored result. Diagnostic protocols
    (``analysis_kind == "diagnostic"``) intentionally have no floor to
    verify, so they are rejected categorically — a forged block mixing
    ``power_analysis`` into a diagnostic document cannot smuggle a floor
    into production qualification.
    """
    if protocol.get("analysis_kind") == "diagnostic":
        raise ContractError("power_analysis_diagnostic")
    analysis = protocol.get("power_analysis")
    if not isinstance(analysis, Mapping):
        raise ContractError("power_analysis_missing")
    try:
        values = [analysis["expected_baseline"], analysis["expected_treatment"],
                  analysis["power"], protocol["alpha"]]
        if any(type(value) not in (int, float) or not math.isfinite(value)
               for value in values):
            raise ContractError("power_analysis_invalid")
        required = required_sample_size(values[0], values[1],
                                        power=values[2], alpha=values[3])
    except (KeyError, TypeError, ValueError, OverflowError) as exc:
        raise ContractError("power_analysis_invalid") from exc
    if type(analysis.get("required_n")) is not int or analysis["required_n"] != required:
        raise ContractError("power_analysis_required_n_mismatch")
    min_effect = protocol.get("min_effect")
    if type(min_effect) not in (int, float) or not 0 < min_effect <= 1:
        raise ContractError("power_analysis_min_effect_invalid")
    try:
        _check_declared_effect(min_effect, values[0], values[1])
    except ContractError as exc:
        raise ContractError(
            "power_analysis_effect_exceeds_min_effect") from exc
    return required


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
    arm_order_seed: int | str | None = None,
    journal=None,
    workers: int = 1,
) -> dict:
    """Run the paired governed evaluation and attach analysis metadata.

    ``context_provider(task, arm) -> guidance|None`` — called for every
    arm; whatever it returns is the only per-arm difference. ``served_map``
    optionally records (task_id, arm) -> bool where guidance was actually
    served (non-abstain) so abstention and negative transfer are measured
    rather than inferred. ``arm_order_seed`` randomizes arm order per task
    and records the executed order. ``journal`` and ``workers`` are passed
    to :meth:`BenchmarkHarness.run` (resume and task parallelism); a
    journal-restored arm's ``served`` flag must already be in
    ``served_map``.
    """
    assert_repository_disjoint(
        learned_repo_digests, [t for t, _ in tasks])
    served: dict = served_map if served_map is not None else {}
    run_kwargs = ({} if arm_order_seed is None
                  else {"arm_order_seed": arm_order_seed})
    if journal is not None:
        run_kwargs["journal"] = journal
    if workers != 1:
        run_kwargs["workers"] = workers
    report = harness.run(tasks, agent, budget=budget,
                         context_provider=context_provider, arms=arms,
                         **run_kwargs)
    metrics = compute_metrics(
        report, served=served, misleading_tasks=misleading_tasks)
    report["governed"] = {
        "protocol_digest": protocol.get("protocol_digest"),
        "analysis_mode": _analysis_mode(protocol),
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


def _analysis_mode(protocol: Mapping) -> str:
    """Label the run by the plan it declares, not by the intended claim."""
    flag = protocol.get("powered")
    if protocol.get("analysis_kind") == "diagnostic" or flag is False:
        return "diagnostic"
    analysis = protocol.get("power_analysis")
    if flag in (True, None) and isinstance(analysis, Mapping):
        return "confirmatory"
    return "exploratory"


def _protocol_conformance(protocol: Mapping, report: Mapping, *,
                          arms: Sequence[str] | None,
                          n_tasks: int) -> dict:
    """Check the executed run against the preregistered plan.

    The protocol digest proves a plan existed; this block records whether
    *this* run honored it — budget, arm set, declared sample size, and,
    for powered protocols, the recomputed power floor. ``conforms=False``
    is reported, never hidden: an underpowered or off-plan run is still
    honest evidence. ``arms=None`` skips the arm comparison for a
    single-candidate probe, which is deliberately not the preregistered
    arm set. Diagnostic protocols (``analysis_kind="diagnostic"``) carry
    no power claim, so only the declared-plan checks apply to them.
    """
    mismatches: list[str] = []
    declared_budget = protocol.get("budget")
    if not isinstance(declared_budget, Mapping):
        declared_budget = {}
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
    if type(declared_n) is not int or declared_n < 1:
        mismatches.append("sample_size_invalid")
    # A diagnostic protocol honestly declares a non-powered plan (a
    # deterministic screen), so there is no floor to check. Powered
    # protocols — and anything not explicitly marked diagnostic — must
    # carry a consistent power_analysis and meet its recomputed floor.
    if protocol.get("analysis_kind") == "diagnostic":
        if "power_analysis" in protocol:
            mismatches.append("power_analysis_diagnostic")
    else:
        try:
            required_n = protocol_required_sample_size(protocol)
        except ContractError as exc:
            mismatches.append(str(exc))
        else:
            if type(declared_n) is int and declared_n < required_n:
                mismatches.append(
                    f"power_analysis:preregistered={declared_n}"
                    f" required={required_n}")
            if n_tasks < required_n:
                mismatches.append(
                    f"power_analysis:required={required_n} ran={n_tasks}"
                    " (underpowered)")
    if type(declared_n) is int and n_tasks < declared_n:
        mismatches.append(
            f"sample_size:preregistered={declared_n} ran={n_tasks}"
            " (underpowered)")
    return {"conforms": not mismatches, "mismatches": mismatches}
