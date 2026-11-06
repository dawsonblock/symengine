"""Four-arm paired benchmark harness (SIS3-012).

Arms: ``A`` baseline agent, ``B`` placebo context, ``C`` raw episode-context
retrieval, ``D`` qualified procedure guidance. For every task, each arm runs
in a fresh disposable workspace with an identical budget envelope
(``BudgetCaps``); the arm callable receives a ``ArmContext`` whose only
difference is the injected context payload. Submissions are scored by the
independent ``OutcomeVerifier`` — the harness never trusts arm-reported
results — and the report counts paired wins/losses/ties, solved rates,
abstentions, and budget violations. Agent callables are injected, so tests
use scripted agents and production runs can plug the Codex adapters without
changing the accounting.
"""
from __future__ import annotations

import json
import math
import secrets
import shutil
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest
from .episode_store import EpisodeStore
from .runner import tree_digest
from .verifier import OutcomeVerifier

ARMS = ("A", "B", "C", "D")
# v3.3 governed evaluation adds a fifth optional arm (full integration).
# It is opt-in via arms= — the four-arm default is unchanged.
ALL_ARMS = ("A", "B", "C", "D", "E")


class BenchmarkError(RuntimeError):
    """The benchmark cannot produce an auditable result."""


@dataclass(frozen=True)
class BudgetCaps:
    wall_seconds: int
    token_budget: int
    tool_budget: int

    def __post_init__(self) -> None:
        for name in ("wall_seconds", "token_budget", "tool_budget"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ContractError(f"{name} must be a positive integer")


@dataclass
class UsageMeter:
    """Harness-issued, agent-independent usage accounting (PR-05).

    The agent callable receives the meter inside ``ArmContext`` and
    records consumption *through the adapter/runtime path it drives* —
    token deltas from SDK event streams, tool invocations via the adapter
    or executor. Counters produced this way are ``verified``: they were
    metered by the runtime path, not self-reported by the agent. An arm
    that returns a bare usage mapping is ``reported``; an arm with no
    usage data at all is ``unverified``.
    """

    tokens: int = 0
    tools: int = 0
    verified: bool = False

    def record_tokens(self, count: int) -> None:
        if type(count) is not int or not 0 <= count <= 2**63 - 1:
            raise ContractError("token count must be a bounded nonnegative int")
        self.tokens += count
        self.verified = True

    def record_tool_call(self, count: int = 1) -> None:
        if type(count) is not int or not 0 < count <= 2**31 - 1:
            raise ContractError("tool count must be a bounded positive int")
        self.tools += count
        self.verified = True


@dataclass(frozen=True)
class ArmContext:
    """The only input that varies between arms of the same task."""

    task: TaskEnvelopeV1
    arm: str
    workspace: Path
    budget: BudgetCaps
    usage_meter: UsageMeter | None = None
    guidance: GuidanceV1 | None = None
    context_digest: str | None = None  # placebo (B) or episode-context (C) digest


@dataclass(frozen=True)
class ArmResult:
    task_id: str
    arm: str
    outcome: str
    receipt_digest: str | None
    submission_digest: str | None
    wall_seconds: int
    budget_exceeded: bool = False
    error: str | None = None
    tokens_used: int | None = None
    tools_used: int | None = None
    budget_accounting: str = "unverified"


@dataclass
class TaskResult:
    task_id: str
    arms: dict[str, ArmResult] = field(default_factory=dict)


AgentFn = Callable[[ArmContext], None]
ContextFn = Callable[[TaskEnvelopeV1, str], GuidanceV1 | None]


class BenchmarkHarness:
    """Runs paired arms and reports independently verified outcomes."""

    def __init__(
        self,
        *,
        verifier: OutcomeVerifier,
        store: EpisodeStore | None = None,
        work_root: str | Path | None = None,
    ) -> None:
        self.verifier = verifier
        self.store = store
        self._own_root = work_root is None
        self.work_root = Path(work_root) if work_root else Path(
            tempfile.mkdtemp(prefix="sis-v3-bench-")
        )
        self.work_root.mkdir(parents=True, exist_ok=True)
        # Identical submissions reuse the issued receipt: the signed outcome
        # binds the tree digest, so re-running the suite would be identical.
        self._receipt_cache: dict[tuple[str, str], tuple[str, str]] = {}

    def run(
        self,
        tasks: list[tuple[TaskEnvelopeV1, Path]],
        agent: AgentFn,
        *,
        budget: BudgetCaps,
        context_provider: ContextFn | None = None,
        arms: tuple[str, ...] = ARMS,
    ) -> dict:
        """Execute every arm per task; return an auditable paired report."""
        unknown = [a for a in arms if a not in ALL_ARMS]
        if unknown:
            raise ContractError(f"unknown arms: {unknown}")
        results: list[TaskResult] = []
        for task, base_dir in tasks:
            task_result = TaskResult(task_id=task.task_id)
            for arm in arms:
                task_result.arms[arm] = self._run_arm(
                    task, Path(base_dir), agent, arm, budget, context_provider
                )
            results.append(task_result)
        return self._report(results, arms, budget)

    def _run_arm(
        self,
        task: TaskEnvelopeV1,
        base_dir: Path,
        agent: AgentFn,
        arm: str,
        budget: BudgetCaps,
        context_provider: ContextFn | None,
    ) -> ArmResult:
        workspace = Path(tempfile.mkdtemp(prefix=f"arm-{arm}-", dir=self.work_root))
        try:
            shutil.copytree(base_dir, workspace, dirs_exist_ok=True)
            guidance = context_provider(task, arm) if context_provider else None
            context_digest = None
            if arm in {"B", "C"}:
                context_digest = canonical_digest("arm_context", 1, {
                    "arm": arm, "task_id": task.task_id,
                    "nonce": secrets.token_hex(8),
                })
            meter = UsageMeter()
            ctx = ArmContext(
                task=task, arm=arm, workspace=workspace,
                budget=budget, usage_meter=meter, guidance=guidance,
                context_digest=context_digest,
            )
            start = time.monotonic()
            error = None
            usage = None
            # Hard wall-clock enforcement (PR-05): the agent runs in a
            # daemon thread and the harness stops waiting at the budget —
            # a runaway arm is flagged and its result recorded, never
            # allowed to stall the suite. Python cannot preempt arbitrary
            # in-process code, so a timed-out callable is abandoned in a
            # daemon thread; subprocess-based agents must use the
            # WorkspaceExecutor, which kills at the same bound.
            box: dict = {}
            def _drive() -> None:
                try:
                    box["usage"] = agent(ctx)
                except Exception as exc:
                    box["error"] = f"{type(exc).__name__}:{str(exc)[:200]}"
            worker = threading.Thread(target=_drive, daemon=True)
            worker.start()
            worker.join(timeout=budget.wall_seconds)
            timed_out = worker.is_alive()
            if timed_out:
                error = "agent_timeout"
                usage = None
            else:
                error = box.get("error")
                usage = box.get("usage")
            elapsed = max(0.0, time.monotonic() - start)
            wall = math.ceil(elapsed)  # integer-only canonical report; no floor bypass
            # Usage precedence (PR-05): metered counters (produced by the
            # runtime path the agent drove) outrank agent-reported usage;
            # missing data stays explicitly unverified.
            tokens = tools = None
            accounting = "unverified"
            if meter.verified:
                tokens, tools = meter.tokens, meter.tools
                accounting = "verified"
            elif isinstance(usage, Mapping):
                tokens, tools = usage.get("tokens_used"), usage.get("tools_used")
                if (tokens is not None and (type(tokens) is not int or tokens < 0)) or \
                   (tools is not None and (type(tools) is not int or tools < 0)):
                    error = "invalid_usage_counters"
                else:
                    accounting = "reported"
            exceeded = (timed_out or elapsed > budget.wall_seconds or
                        (tokens is not None and tokens > budget.token_budget) or
                        (tools is not None and tools > budget.tool_budget))
            submission_digest = tree_digest(workspace)
            if error is not None:
                return ArmResult(task.task_id, arm, "error", None, submission_digest,
                                 wall, exceeded, error, tokens, tools, accounting)
            cache_key = (task.task_id, submission_digest)
            cached = self._receipt_cache.get(cache_key)
            if cached is not None:
                outcome, receipt_digest = cached
            else:
                try:
                    receipt = self.verifier.evaluate(
                        actor_role="evaluator",
                        task=task,
                        submission_dir=workspace,
                        evaluation_nonce=f"bench-{task.task_id}-{arm}-" + secrets.token_hex(6),
                    )
                except Exception as exc:
                    return ArmResult(task.task_id, arm, "error", None, submission_digest,
                                     wall, exceeded, f"evaluation:{str(exc)[:200]}",
                                     tokens, tools, accounting)
                outcome, receipt_digest = receipt.outcome, receipt.digest
                self._receipt_cache[cache_key] = (outcome, receipt_digest)
            return ArmResult(task.task_id, arm, outcome,
                             receipt_digest, submission_digest, wall, exceeded,
                             None, tokens, tools, accounting)
        finally:
            shutil.rmtree(workspace, ignore_errors=True)

    def _report(self, results: list[TaskResult], arms: tuple[str, ...], budget: BudgetCaps) -> dict:
        per_task = []
        for task_result in results:
            entry = {"task_id": task_result.task_id, "arms": {}}
            for arm, res in task_result.arms.items():
                entry["arms"][arm] = {
                    "outcome": res.outcome,
                    "receipt_digest": res.receipt_digest,
                    "wall_seconds": res.wall_seconds,
                    "budget_exceeded": res.budget_exceeded,
                    "tokens_used": res.tokens_used, "tools_used": res.tools_used,
                    "budget_accounting": res.budget_accounting,
                    **({"error": res.error} if res.error else {}),
                }
            per_task.append(entry)

        def valid_solve(r: ArmResult) -> bool:
            return (r.outcome == "pass" and not r.budget_exceeded and r.error is None)
        solved = {arm: sum(1 for t in results if valid_solve(t.arms[arm])) for arm in arms}
        solve_rates = {
            arm: {"solved": solved[arm], "n": len(results),
                  "wilson_ci95": (
                      [f"{x:.10f}" for x in wilson_ci(solved[arm], len(results))]
                      if results else None)}
            for arm in arms
        }
        pairs = {}
        for left, right in (("B", "A"), ("C", "A"), ("D", "A"), ("D", "B"),
                            ("D", "C"), ("E", "A"), ("E", "B"), ("E", "C"),
                            ("E", "D")):
            if left not in arms or right not in arms:
                continue
            wins = losses = ties = 0
            for t in results:
                a, b = valid_solve(t.arms[left]), valid_solve(t.arms[right])
                wins += a and not b
                losses += b and not a
                ties += a == b
            pairs[f"{left}_vs_{right}"] = {
                "wins": wins, "losses": losses, "ties": ties,
                "solved_delta": wins - losses,
                "mcnemar_exact_p": f"{mcnemar_p(wins, losses):.10f}",
            }
        return {
            "schema_version": 1,
            "tasks": len(results),
            "budget": {"wall_seconds": budget.wall_seconds,
                       "token_budget": budget.token_budget,
                       "tool_budget": budget.tool_budget},
            "solved_counts": solved,
            "solve_rates": solve_rates,
            "budget_violations": sum(
                1 for t in results for r in t.arms.values() if r.budget_exceeded
            ),
            "paired": pairs,
            "per_task": per_task,
            "budget_enforcement": "wall clock is hard-enforced: arms run in a watchdog thread abandoned at the limit (agent_timeout); token/tool budgets prefer harness-metered (verified) counters over agent-reported usage; missing usage is UNVERIFIED",
            "harness_digest": None,
        }


def report_digest(report: Mapping) -> str:
    """Content-address a report for anchoring alongside episode evidence."""
    normalized = json.loads(
        json.dumps(report, sort_keys=True), parse_float=lambda v: f"float:{v}")
    return canonical_digest("benchmark_report", 1, normalized)


def wilson_ci(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for a binomial rate (honest even at small n)."""
    if type(k) is not int or type(n) is not int or not (0 <= k <= n) or n == 0:
        raise ContractError("wilson_ci requires integers with 0 <= k <= n, n > 0")
    p = k / n
    denom = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    lo, hi = max(0.0, center - half), min(1.0, center + half)
    if k == 0:
        lo = 0.0
    if k == n:
        hi = 1.0
    return (lo, hi)


def mcnemar_p(b: int, c: int) -> float:
    """Exact two-sided McNemar (binomial sign) p-value on discordant pairs."""
    if type(b) is not int or type(c) is not int or b < 0 or c < 0:
        raise ContractError("mcnemar_p requires nonnegative integer counts")
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # P(X <= k) under Binomial(n, 0.5), doubled and capped at 1.
    cumulative = sum(math.comb(n, i) for i in range(k + 1)) / (2 ** n)
    return min(1.0, 2.0 * cumulative)
