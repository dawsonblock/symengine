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
import os
import random
import secrets
import shutil
import stat
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from .contracts import ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest
from .episode_store import EpisodeStore
from .runner import RunnerError, scan_tree, tree_digest
from .verifier import OutcomeVerifier

ARMS = ("A", "B", "C", "D")
# v3.3 governed evaluation adds a fifth optional arm (full integration).
# It is opt-in via arms= — the four-arm default is unchanged.
ALL_ARMS = ("A", "B", "C", "D", "E")
# How long the harness waits for a cancelled arm to actually stop before
# it declares the workspace unsafe to remove or reuse.
_TERMINATION_GRACE_SECONDS = 10.0


class BenchmarkError(RuntimeError):
    """The benchmark cannot produce an auditable result."""


def _reject_hard_links(root: Path) -> None:
    """Refuse a repository file with a link outside the repository.

    ``scan_tree`` reads bytes, so a hard link to a file outside the
    repository would copy that file's contents into the workspace just
    like an external symlink. A file whose link count exceeds the number
    of paths inside the repository has at least one link outside it;
    internal hard links are allowed. Git checkouts do not contain hard
    links, so this only affects locally supplied repositories.
    """
    counts: dict[tuple[int, int], int] = {}
    entries: list[tuple[Path, os.stat_result]] = []
    for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                continue
            try:
                info = full.stat(follow_symlinks=False)
            except OSError as exc:
                raise BenchmarkError(
                    f"repository_entry_unreadable:{full}") from exc
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_nlink <= 1:
                continue
            key = (info.st_dev, info.st_ino)
            if info.st_ino == 0:
                # Some filesystems do not expose stable inode numbers;
                # without them an external link cannot be distinguished
                # from an internal one, so any shared file is refused.
                relative = full.relative_to(root).as_posix()
                raise BenchmarkError(
                    "repository_contains_hard_links:" + relative)
            counts[key] = counts.get(key, 0) + 1
            entries.append((full, info))
    for full, info in entries:
        key = (info.st_dev, info.st_ino)
        if info.st_nlink > counts.get(key, 0):
            relative = full.relative_to(root).as_posix()
            raise BenchmarkError(
                "repository_contains_hard_links:" + relative)


def stage_repository(base_dir: str | Path, workspace: str | Path) -> str:
    """Copy a repository into a disposable workspace without dereferencing links.

    ``shutil.copytree`` follows symlinks by default, so a link inside a
    public repository can copy an evaluator-readable file from outside it
    into the agent's workspace. This staging path rejects external links
    and hard links before and after the copy, copies links verbatim
    (``symlinks=True``), and re-scans the staged tree so a link swapped
    in during the copy is observed as a link rather than followed. The
    source and staged tree must hash identically; any drift during
    staging aborts the arm. Returns the staged tree digest so the caller
    can bind it to the task envelope.
    """
    source = Path(base_dir)
    target = Path(workspace)
    if source.is_symlink() or not source.is_dir():
        raise BenchmarkError("repository_source_is_not_a_plain_directory")
    _reject_hard_links(source)
    try:
        before = scan_tree(source)
    except (OSError, RunnerError) as exc:
        raise BenchmarkError(f"repository_scan_failed:{exc}") from exc
    if before.external_symlinks:
        raise BenchmarkError(
            "repository_contains_external_symlinks:"
            + ",".join(before.external_symlinks))
    try:
        shutil.copytree(source, target, dirs_exist_ok=True, symlinks=True)
    except (OSError, shutil.Error) as exc:
        raise BenchmarkError(f"repository_staging_failed:{exc}") from exc
    try:
        after = scan_tree(target)
    except (OSError, RunnerError) as exc:
        raise BenchmarkError(f"repository_scan_failed:{exc}") from exc
    if after.external_symlinks:
        raise BenchmarkError(
            "repository_contains_external_symlinks:"
            + ",".join(after.external_symlinks))
    if after.digest != before.digest:
        raise BenchmarkError("repository_changed_during_staging")
    # A hard link swapped in during the copy is copied as an independent
    # file; re-check the source so the secret bytes never reach an agent.
    _reject_hard_links(source)
    return after.digest


class ArmSupervisor:
    """Cancellation channel between the harness and one arm's agent.

    Python cannot preempt an arbitrary in-process callable, so a timeout
    alone cannot terminate the work. An agent that owns a subprocess
    registers a terminator; when the wall budget expires the harness sets
    ``aborted`` and runs every terminator, then waits for the worker to
    exit. A workspace is only removed or reused after that wait succeeds.
    """

    def __init__(self) -> None:
        self._aborted = threading.Event()
        self._terminators: list[Callable[[], object]] = []
        self._lock = threading.Lock()

    @property
    def aborted(self) -> bool:
        return self._aborted.is_set()

    def register_terminator(self, terminator: Callable[[], object]) -> None:
        if not callable(terminator):
            raise ContractError("terminator must be callable")
        with self._lock:
            already_aborted = self._aborted.is_set()
            if not already_aborted:
                self._terminators.append(terminator)
        if already_aborted:
            self._run(terminator)

    def abort(self) -> None:
        with self._lock:
            if self._aborted.is_set():
                return
            self._aborted.set()
            terminators = list(self._terminators)
            self._terminators.clear()
        for terminator in terminators:
            self._run(terminator)

    @staticmethod
    def _run(terminator: Callable[[], object]) -> None:
        try:
            terminator()
        except Exception:
            # A terminator is best-effort cleanup; the harness still waits
            # for the worker and quarantines the workspace if it survives.
            pass


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
    usage data at all is ``unverified``; an arm whose runtime metered
    only one counter is ``partial``.
    """

    tokens: int = 0
    tools: int = 0
    verified: bool = False
    tokens_verified: bool = False
    tools_verified: bool = False

    def record_tokens(self, count: int) -> None:
        if type(count) is not int or not 0 <= count <= 2**63 - 1:
            raise ContractError("token count must be a bounded nonnegative int")
        self.tokens += count
        self.verified = True
        self.tokens_verified = True

    def record_tool_call(self, count: int = 1) -> None:
        if type(count) is not int or not 0 < count <= 2**31 - 1:
            raise ContractError("tool count must be a bounded positive int")
        self.tools += count
        self.verified = True
        self.tools_verified = True


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
    supervisor: ArmSupervisor | None = None


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
    workspace_retained: bool = False


@dataclass
class TaskResult:
    task_id: str
    arms: dict[str, ArmResult] = field(default_factory=dict)
    arm_order: tuple[str, ...] = ()


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
        arm_order_seed: int | str | None = None,
    ) -> dict:
        """Execute every arm per task; return an auditable paired report.

        ``arm_order_seed`` randomizes the arm order per task, as the
        preregistered protocol requires. The order is recorded in the
        report; a fixed order makes a slow or rate-limited remote agent
        confound the arm with run position.
        """
        unknown = [a for a in arms if a not in ALL_ARMS]
        if unknown:
            raise ContractError(f"unknown arms: {unknown}")
        results: list[TaskResult] = []
        for task, base_dir in tasks:
            task_result = TaskResult(task_id=task.task_id)
            order = list(arms)
            if arm_order_seed is not None:
                random.Random(
                    f"{arm_order_seed}:{task.task_id}").shuffle(order)
            task_result.arm_order = tuple(order)
            for arm in order:
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
        retain_workspace = False
        try:
            staged_digest = stage_repository(base_dir, workspace)
            if (task.repo_snapshot_digest
                    and staged_digest != task.repo_snapshot_digest
                    and tree_digest(workspace, version=1)
                    != task.repo_snapshot_digest):
                # The staged tree is the authority; the legacy v1 digest
                # is only consulted so a pre-canonical task envelope can
                # still be replayed.
                raise BenchmarkError("repository_snapshot_mismatch")
            guidance = context_provider(task, arm) if context_provider else None
            context_digest = None
            if arm in {"B", "C"}:
                context_digest = canonical_digest("arm_context", 1, {
                    "arm": arm, "task_id": task.task_id,
                    "nonce": secrets.token_hex(8),
                })
            meter = UsageMeter()
            supervisor = ArmSupervisor()
            ctx = ArmContext(
                task=task, arm=arm, workspace=workspace,
                budget=budget, usage_meter=meter, guidance=guidance,
                context_digest=context_digest, supervisor=supervisor,
            )
            start = time.monotonic()
            error = None
            usage = None
            # Hard wall-clock enforcement (PR-05): the agent runs in a
            # worker thread; at the budget the harness cancels it through
            # the supervisor, then waits for the worker to exit. A
            # subprocess agent registers a terminator that kills its
            # process group. An agent that ignores cancellation leaves
            # its workspace quarantined — never removed or reused.
            box: dict = {}
            def _drive() -> None:
                try:
                    box["usage"] = agent(ctx)
                except BaseException as exc:
                    # A worker that dies with SystemExit/KeyboardInterrupt
                    # must not look like a normally completed arm.
                    box["error"] = f"{type(exc).__name__}:{str(exc)[:200]}"
            worker = threading.Thread(target=_drive, daemon=True)
            worker.start()
            worker.join(timeout=budget.wall_seconds)
            timed_out = worker.is_alive()
            # Record the agent's wall time before cancellation; the
            # termination grace is harness overhead, not agent runtime.
            elapsed = max(0.0, time.monotonic() - start)
            wall = math.ceil(elapsed)  # integer-only canonical report; no floor bypass
            if timed_out:
                supervisor.abort()
                worker.join(timeout=_TERMINATION_GRACE_SECONDS)
                usage = None
                if worker.is_alive():
                    error = "agent_timeout_unterminated"
                    retain_workspace = True
                else:
                    error = "agent_timeout"
            else:
                error = box.get("error")
                usage = box.get("usage")
            # Usage precedence (PR-05): metered counters (produced by the
            # runtime path the agent drove) outrank agent-reported usage;
            # missing data stays explicitly unverified.
            tokens = tools = None
            accounting = "unverified"
            if meter.verified:
                tokens = meter.tokens if meter.tokens_verified else None
                tools = meter.tools if meter.tools_verified else None
                accounting = ("verified" if tokens is not None
                              and tools is not None else "partial")
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
            # A retained workspace may still be written by the runaway
            # worker; hashing it would race the writer and could report a
            # digest for a tree that never existed.
            submission_digest = (None if retain_workspace
                                 else tree_digest(workspace))
            if error is not None:
                return ArmResult(task.task_id, arm, "error", None, submission_digest,
                                 wall, exceeded, error, tokens, tools, accounting,
                                 retain_workspace)
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
                                     tokens, tools, accounting, retain_workspace)
                outcome, receipt_digest = receipt.outcome, receipt.digest
                self._receipt_cache[cache_key] = (outcome, receipt_digest)
            return ArmResult(task.task_id, arm, outcome,
                             receipt_digest, submission_digest, wall, exceeded,
                             None, tokens, tools, accounting, retain_workspace)
        finally:
            if not retain_workspace:
                shutil.rmtree(workspace, ignore_errors=True)

    def _report(self, results: list[TaskResult], arms: tuple[str, ...], budget: BudgetCaps) -> dict:
        per_task = []
        for task_result in results:
            entry = {"task_id": task_result.task_id, "arms": {}}
            if task_result.arm_order:
                entry["arm_order"] = list(task_result.arm_order)
            for arm, res in task_result.arms.items():
                entry["arms"][arm] = {
                    "outcome": res.outcome,
                    "receipt_digest": res.receipt_digest,
                    "wall_seconds": res.wall_seconds,
                    "budget_exceeded": res.budget_exceeded,
                    "tokens_used": res.tokens_used, "tools_used": res.tools_used,
                    "budget_accounting": res.budget_accounting,
                    **({"error": res.error} if res.error else {}),
                    **({"workspace_retained": True}
                       if res.workspace_retained else {}),
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
            "budget_enforcement": "wall clock is hard-enforced: at the limit the harness aborts the arm through its supervisor (subprocess agents kill their process group) and waits for the worker to exit; a worker that survives is reported as agent_timeout_unterminated and its workspace is retained, never reused. Token/tool budgets prefer harness-metered (verified) counters over agent-reported usage; missing usage is UNVERIFIED",
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
