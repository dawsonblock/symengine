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
from .runner import (RunnerError, external_symlinks,
                     repository_execution_digest, scan_tree, tree_digest,
                     verify_repository_digest)
from .verifier import OutcomeVerifier

ARMS = ("A", "B", "C", "D")
# v3.3 governed evaluation adds a fifth optional arm (full integration).
# It is opt-in via arms= — the four-arm default is unchanged.
ALL_ARMS = ("A", "B", "C", "D", "E")
# How long the harness waits for a cancelled arm to actually stop before
# it declares the workspace unsafe to remove or reuse.
_TERMINATION_GRACE_SECONDS = 10.0
# VCS metadata is not repository content: the v3 identity excludes it,
# and a local Git clone legitimately hard-links its object database to
# the source. The staging guard must not treat those links as external
# content links.
_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})


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
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames
                       if name not in _VCS_DIRECTORIES]
        for name in filenames:
            if name in _VCS_DIRECTORIES:
                continue
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


def _reject_symlinks(root: Path) -> None:
    """Refuse every symlink, internal ones included.

    Every executor's ``prepare`` rejects a tree containing any symlink,
    so a repository staged with an internal link could never be
    evaluated: the arm would end in an evaluator error after the agent
    already ran. Refusing at staging keeps one coherent rule (no links
    anywhere in an evaluated tree) and reports it before any work starts.
    """
    links: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            if full.is_symlink():
                links.append(full.relative_to(root).as_posix())
    if links:
        raise BenchmarkError(
            "repository_contains_symlinks:" + ",".join(sorted(links)[:20]))


def stage_repository(base_dir: str | Path, workspace: str | Path, *,
                     expected_execution: str | None = None) -> str:
    """Copy a repository into a disposable workspace without dereferencing links.

    ``shutil.copytree`` follows symlinks by default, so a link inside a
    public repository can copy an evaluator-readable file from outside it
    into the agent's workspace. This staging path rejects external links
    and hard links before and after the copy, copies links verbatim
    (``symlinks=True``), and re-scans the staged tree so a link swapped
    in during the copy is observed as a link rather than followed. The
    source and staged tree must hash identically; any drift during
    staging aborts the arm. Internal links are refused too, with
    ``repository_contains_symlinks``: no executor will evaluate a tree
    that contains a link. When ``expected_execution`` is supplied, the
    staged tree's execution fingerprint (permission bits, entry types
    and symlink targets) must also match it, so a mode change after
    manifest validation cannot reach the agent. Returns the staged tree
    digest so the caller can bind it to the task envelope.
    """
    source = Path(base_dir)
    target = Path(workspace)
    if source.is_symlink() or not source.is_dir():
        raise BenchmarkError("repository_source_is_not_a_plain_directory")
    _reject_hard_links(source)
    try:
        before = scan_tree(source, version=3)
        before_execution = repository_execution_digest(source)
    except (OSError, RunnerError) as exc:
        raise BenchmarkError(f"repository_scan_failed:{exc}") from exc
    if before.external_symlinks:
        raise BenchmarkError(
            "repository_contains_external_symlinks:"
            + ",".join(before.external_symlinks))
    external = external_symlinks(source)
    if external:
        raise BenchmarkError(
            "repository_contains_external_symlinks:" + ",".join(external))
    _reject_symlinks(source)
    try:
        shutil.copytree(source, target, dirs_exist_ok=True, symlinks=True)
    except (OSError, shutil.Error) as exc:
        raise BenchmarkError(f"repository_staging_failed:{exc}") from exc
    try:
        after = scan_tree(target, version=3)
        after_execution = repository_execution_digest(target)
    except (OSError, RunnerError) as exc:
        raise BenchmarkError(f"repository_scan_failed:{exc}") from exc
    if after.external_symlinks:
        raise BenchmarkError(
            "repository_contains_external_symlinks:"
            + ",".join(after.external_symlinks))
    external = external_symlinks(target)
    if external:
        raise BenchmarkError(
            "repository_contains_external_symlinks:" + ",".join(external))
    _reject_symlinks(target)
    if after.digest != before.digest:
        raise BenchmarkError("repository_changed_during_staging")
    if after_execution != before_execution:
        raise BenchmarkError("repository_execution_changed_during_staging")
    if (expected_execution is not None
            and after_execution != expected_execution):
        raise BenchmarkError("repository_execution_mismatch")
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
    #: Metered counters that are reported but never budgeted, such as
    #: cache-read tokens or a provider-reported cost in micro-USD.
    detail: dict = field(default_factory=dict)

    def record_detail(self, name: str, count: int) -> None:
        if not (isinstance(name, str) and 0 < len(name) <= 64
                and name.replace("_", "").isalnum()):
            raise ContractError("usage detail name must be a short identifier")
        if type(count) is not int or not 0 <= count <= 2**63 - 1:
            raise ContractError("usage detail must be a bounded nonnegative int")
        self.detail[name] = count

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
    usage_detail: Mapping | None = None


def arm_result_row(res: ArmResult, *, journal: bool = False) -> dict:
    """The report row for one arm (``journal=True`` adds resume fields)."""
    row = {
        "outcome": res.outcome,
        "receipt_digest": res.receipt_digest,
        "wall_seconds": res.wall_seconds,
        "budget_exceeded": res.budget_exceeded,
        "tokens_used": res.tokens_used, "tools_used": res.tools_used,
        "budget_accounting": res.budget_accounting,
        **({"error": res.error} if res.error else {}),
        **({"workspace_retained": True} if res.workspace_retained else {}),
        **({"usage_detail": dict(res.usage_detail)}
           if res.usage_detail else {}),
    }
    if journal:
        row["submission_digest"] = res.submission_digest
    return row


_OUTCOMES = frozenset({"pass", "fail", "error"})
_ACCOUNTINGS = frozenset({"verified", "partial", "reported", "unverified"})


def arm_result_from_row(task_id: str, arm: str, row: Mapping) -> ArmResult:
    """Rebuild a journaled arm result, refusing a malformed row."""
    def optional_int(name):
        value = row.get(name)
        if value is not None and (type(value) is not int or value < 0):
            raise BenchmarkError(f"journal_row_invalid:{name}")
        return value

    def optional_digest(name):
        value = row.get(name)
        if value is not None and not (
                isinstance(value, str) and len(value) == 64
                and all(ch in "0123456789abcdef" for ch in value)):
            raise BenchmarkError(f"journal_row_invalid:{name}")
        return value

    outcome = row.get("outcome")
    if outcome not in _OUTCOMES:
        raise BenchmarkError("journal_row_invalid:outcome")
    accounting = row.get("budget_accounting")
    if accounting not in _ACCOUNTINGS:
        raise BenchmarkError("journal_row_invalid:budget_accounting")
    wall = row.get("wall_seconds")
    if type(wall) is not int or wall < 0:
        raise BenchmarkError("journal_row_invalid:wall_seconds")
    if type(row.get("budget_exceeded")) is not bool:
        raise BenchmarkError("journal_row_invalid:budget_exceeded")
    error = row.get("error")
    if error is not None and not isinstance(error, str):
        raise BenchmarkError("journal_row_invalid:error")
    receipt = optional_digest("receipt_digest")
    if outcome in ("pass", "fail") and receipt is None:
        raise BenchmarkError("journal_row_invalid:receipt_digest")
    detail = row.get("usage_detail")
    if detail is not None and not (
            isinstance(detail, Mapping) and all(
                isinstance(k, str) and type(v) is int and v >= 0
                for k, v in detail.items())):
        raise BenchmarkError("journal_row_invalid:usage_detail")
    if row.get("workspace_retained"):
        # A quarantined workspace may still be written by a runaway
        # worker; its arm is re-run rather than trusted after a restart.
        raise BenchmarkError("journal_row_invalid:workspace_retained")
    return ArmResult(
        task_id, arm, outcome, receipt, optional_digest("submission_digest"),
        wall, row["budget_exceeded"], error, optional_int("tokens_used"),
        optional_int("tools_used"), accounting, False,
        dict(detail) if detail else None)


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
        expected_execution: Mapping[str, str] | None = None,
    ) -> None:
        self.verifier = verifier
        self.store = store
        self._own_root = work_root is None
        self.work_root = Path(work_root) if work_root else Path(
            tempfile.mkdtemp(prefix="sis-v3-bench-")
        )
        self.work_root.mkdir(parents=True, exist_ok=True)
        # Optional per-repository execution fingerprints, keyed by the
        # resolved source path. A staged tree that does not match its
        # fingerprint is refused before any arm runs.
        self.expected_execution = {
            str(Path(path).resolve()): digest
            for path, digest in (expected_execution or {}).items()}
        # Identical submissions reuse the issued receipt: the signed outcome
        # binds the tree digest, so re-running the suite would be identical.
        self._receipt_cache: dict[tuple[str, str], tuple[str, str]] = {}
        # Evaluations are serialized even when tasks run in parallel: the
        # verifier's journal and nonce set are single-writer state.
        self._evaluation_lock = threading.Lock()

    def run(
        self,
        tasks: list[tuple[TaskEnvelopeV1, Path]],
        agent: AgentFn,
        *,
        budget: BudgetCaps,
        context_provider: ContextFn | None = None,
        arms: tuple[str, ...] = ARMS,
        arm_order_seed: int | str | None = None,
        journal=None,
        workers: int = 1,
        submission_observer: Callable | None = None,
    ) -> dict:
        """Execute every arm per task; return an auditable paired report.

        ``arm_order_seed`` randomizes the arm order per task, as the
        preregistered protocol requires. The order is recorded in the
        report; a fixed order makes a slow or rate-limited remote agent
        confound the arm with run position.

        ``journal`` (see :class:`sis.v3.study_runtime.RunJournal`) makes
        the run resumable: every finished ``(task, arm)`` row is recorded
        through ``journal.record`` as soon as it exists, and a row that
        ``journal.completed`` returns is reused instead of re-run. The
        caller is responsible for proving that journaled receipts belong
        to this verifier.

        ``workers`` runs that many tasks concurrently. Each task still runs
        its arms one after another in its seeded order; guidance is
        resolved up front in serial order and evaluations are serialized,
        so the report is identical to a one-worker run apart from wall
        times and receipt nonces.

        ``submission_observer(task, arm, workspace, result, usage)`` is
        called after an arm is scored and before its workspace is removed
        (for example to capture a verified source change).
        """
        unknown = [a for a in arms if a not in ALL_ARMS]
        if unknown:
            raise ContractError(f"unknown arms: {unknown}")
        if type(workers) is not int or not 1 <= workers <= 256:
            raise ContractError("workers must be an integer in [1, 256]")
        plans: list[tuple[TaskEnvelopeV1, Path, tuple[str, ...]]] = []
        for task, base_dir in tasks:
            order = list(arms)
            if arm_order_seed is not None:
                random.Random(
                    f"{arm_order_seed}:{task.task_id}").shuffle(order)
            plans.append((task, Path(base_dir), tuple(order)))
        restored: dict[tuple[str, str], ArmResult] = {}
        if journal is not None:
            for task, _, order in plans:
                for arm in order:
                    row = journal.completed(task.task_id, arm)
                    if row is None:
                        continue
                    result = arm_result_from_row(task.task_id, arm, row)
                    restored[(task.task_id, arm)] = result
                    if (result.receipt_digest is not None
                            and result.submission_digest is not None):
                        self._receipt_cache[
                            (task.task_id, result.submission_digest)] = (
                                result.outcome, result.receipt_digest)
        provider = context_provider
        if workers > 1 and context_provider is not None:
            # Guidance is resolved on the calling thread, in exactly the
            # order a serial run would ask for it, so the serving
            # decisions (and anything the provider records) are identical
            # to a one-worker run and the provider need not be
            # thread-safe.
            prefetched: dict[tuple[str, str], GuidanceV1 | None] = {}
            for task, _, order in plans:
                for arm in order:
                    if (task.task_id, arm) not in restored:
                        prefetched[(task.task_id, arm)] = context_provider(
                            task, arm)

            def provider(task, arm):
                return prefetched[(task.task_id, arm)]
        stop = threading.Event()

        def run_task(task, base_dir, order) -> TaskResult:
            task_result = TaskResult(task_id=task.task_id,
                                     arm_order=tuple(order))
            for arm in order:
                result = restored.get((task.task_id, arm))
                if result is None:
                    if stop.is_set():
                        raise BenchmarkError("run_stopped")
                    result = self._run_arm(
                        task, base_dir, agent, arm, budget, provider,
                        submission_observer=submission_observer)
                    if journal is not None:
                        journal.record(task.task_id, arm,
                                       arm_result_row(result, journal=True))
                task_result.arms[arm] = result
            return task_result

        results: list[TaskResult] = []
        if workers == 1:
            for task, base_dir, order in plans:
                results.append(run_task(task, base_dir, order))
            return self._report(results, arms, budget)
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers,
                                thread_name_prefix="sis-bench") as pool:
            futures = [pool.submit(run_task, task, base_dir, order)
                       for task, base_dir, order in plans]
            try:
                # Task order, not completion order: the report is the same
                # as a serial run's.
                for future in futures:
                    results.append(future.result())
            except BaseException:
                stop.set()
                for future in futures:
                    future.cancel()
                raise
        return self._report(results, arms, budget)

    def _run_arm(
        self,
        task: TaskEnvelopeV1,
        base_dir: Path,
        agent: AgentFn,
        arm: str,
        budget: BudgetCaps,
        context_provider: ContextFn | None,
        *,
        submission_observer: Callable | None = None,
    ) -> ArmResult:
        workspace = Path(tempfile.mkdtemp(prefix=f"arm-{arm}-", dir=self.work_root))
        retain_workspace = False
        try:
            staged_digest = stage_repository(
                base_dir, workspace,
                expected_execution=self.expected_execution.get(
                    str(base_dir.resolve())))
            if task.repo_snapshot_digest and staged_digest != task.repo_snapshot_digest:
                try:
                    verify_repository_digest(
                        workspace, task.repo_snapshot_digest,
                        canonical=staged_digest)
                except RunnerError as exc:
                    # The staged tree is the authority; a full-tree v2 or
                    # legacy v1 record is accepted only if it matches.
                    raise BenchmarkError(
                        "repository_snapshot_mismatch") from exc
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
            detail = dict(sorted(meter.detail.items())) or None
            if error is not None:
                return ArmResult(task.task_id, arm, "error", None, submission_digest,
                                 wall, exceeded, error, tokens, tools, accounting,
                                 retain_workspace, detail)
            cache_key = (task.task_id, submission_digest)
            with self._evaluation_lock:
                cached = self._receipt_cache.get(cache_key)
                if cached is None and submission_digest is not None:
                    # A resumed run: this exact tree may have been graded
                    # before the interruption without reaching the journal.
                    lookup = getattr(self.verifier, "prior_receipt", None)
                    prior = lookup(task.evaluator_task_ref or task.task_id,
                                   submission_digest) \
                        if callable(lookup) else None
                    if prior is not None:
                        cached = (prior.outcome, prior.digest)
                        self._receipt_cache[cache_key] = cached
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
                                         tokens, tools, accounting, retain_workspace,
                                         detail)
                    outcome, receipt_digest = receipt.outcome, receipt.digest
                    self._receipt_cache[cache_key] = (outcome, receipt_digest)
            result = ArmResult(task.task_id, arm, outcome,
                               receipt_digest, submission_digest, wall, exceeded,
                               None, tokens, tools, accounting, retain_workspace,
                               detail)
            if submission_observer is not None:
                submission_observer(task, arm, workspace, result, usage)
            return result
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
                entry["arms"][arm] = arm_result_row(res)
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
