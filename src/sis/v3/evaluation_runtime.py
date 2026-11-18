"""Pinned evaluator runtime, bootstrap checks and outcome taxonomy.

Revision 4's scripted holdouts failed because the evaluator's default
512 MiB address-space limit was too small for pytest and installed plugin
imports. The failure was then easy to misread as an agent task failure.
This module separates:

- evaluator bootstrap (interpreter + pytest import/version);
- agent/task execution;
- candidate code execution inside the disposable workspace;
- evidence verification (outside the executor).

Infrastructure failures have their own outcome classes and never count
as a task pass or as proof that a candidate is ineffective.
"""
from __future__ import annotations

import importlib.metadata
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .contracts import canonical_digest
from .isolation import (
    IsolationVerification,
    ProductionIsolationPolicy,
    verify_production_isolation,
)
from .runner import CommandSpec, ResourceLimits, WorkspaceExecutor

TASK_PASS = "TASK_PASS"
TASK_FAIL = "TASK_FAIL"
EVALUATOR_BOOTSTRAP_ERROR = "EVALUATOR_BOOTSTRAP_ERROR"
RESOURCE_LIMIT = "RESOURCE_LIMIT"
TIMEOUT = "TIMEOUT"
SANDBOX_FAILURE = "SANDBOX_FAILURE"
EVIDENCE_FAILURE = "EVIDENCE_FAILURE"
INFRASTRUCTURE_ERROR = "INFRASTRUCTURE_ERROR"

OUTCOME_CLASSES = (
    TASK_PASS, TASK_FAIL, EVALUATOR_BOOTSTRAP_ERROR, RESOURCE_LIMIT,
    TIMEOUT, SANDBOX_FAILURE, EVIDENCE_FAILURE, INFRASTRUCTURE_ERROR,
)
TASK_OUTCOMES = frozenset({TASK_PASS, TASK_FAIL})

GIB = 1 << 30


class RuntimePinError(RuntimeError):
    """The evaluator runtime does not match the pinned profile."""


@dataclass(frozen=True)
class EvaluationRuntimeProfile:
    """Pinned runtime and resource envelope for one evaluator.

    ``bootstrap_memory_bytes`` covers interpreter/pytest initialization;
    ``task_memory_bytes`` covers the actual acceptance run. Both are
    measured envelopes, not guesses: the bootstrap limit must be large
    enough to import pytest and its required plugins without treating a
    bootstrap failure as a task failure.
    """

    profile_version: str = "sis-evaluator-runtime/1"
    python_version: str = f"{sys.version_info.major}.{sys.version_info.minor}"
    pytest_version: str = "8.4.2"
    bootstrap_memory_bytes: int = 2 * GIB
    task_memory_bytes: int = 2 * GIB
    cpu_seconds: int = 60
    wall_seconds: int = 120
    process_count: int | None = 64
    # Bootstrap may fork for plugin discovery; RLIMIT_NPROC counts every
    # process of the real UID on macOS, so the bootstrap probe leaves it
    # untouched while the task envelope keeps the configured bound.
    bootstrap_process_count: int | None = None
    disk_bytes: int = 64 * 1024 * 1024
    output_bytes: int = 1024 * 1024
    disabled_plugins: tuple[str, ...] = (
        "cacheprovider", "randomly", "xdist", "cov",
    )
    enabled_plugins: tuple[str, ...] = ()
    environment_extra: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for name, maximum in (
            ("bootstrap_memory_bytes", 1 << 40),
            ("task_memory_bytes", 1 << 40),
            ("cpu_seconds", 86_400),
            ("wall_seconds", 86_400),
            ("disk_bytes", 1 << 40),
            ("output_bytes", 1 << 30),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise RuntimePinError(f"{name}_outside_bound")
        for name in ("process_count", "bootstrap_process_count"):
            value = getattr(self, name)
            if value is not None and (
                    type(value) is not int
                    or not 1 <= value <= 65_535):
                raise RuntimePinError(f"{name}_outside_bound")

    @property
    def bootstrap_limits(self) -> ResourceLimits:
        return ResourceLimits(
            cpu_seconds=self.cpu_seconds,
            wall_seconds=self.wall_seconds,
            memory_bytes=self.bootstrap_memory_bytes,
            output_bytes=self.output_bytes,
            disk_bytes=self.disk_bytes,
            process_count=self.bootstrap_process_count)

    @property
    def task_limits(self) -> ResourceLimits:
        return ResourceLimits(
            cpu_seconds=self.cpu_seconds,
            wall_seconds=self.wall_seconds,
            memory_bytes=self.task_memory_bytes,
            output_bytes=self.output_bytes,
            disk_bytes=self.disk_bytes,
            process_count=self.process_count)

    def environment(self) -> dict[str, str]:
        """Evaluator-owned environment: no user site, no plugin autoload."""
        env = {
            "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": "0",
            "TZ": "UTC",
        }
        env.update(dict(self.environment_extra))
        return env

    def pytest_argv(self, argv: tuple[str, ...] | list[str]) -> tuple[str, ...]:
        """Add explicit plugin policy to an evaluator-owned pytest argv."""
        values = list(argv)
        if len(values) >= 3 and values[1] == "-m" and values[2] == "pytest":
            insert_at = 3
        else:
            insert_at = 1
        extra: list[str] = []
        for plugin in self.disabled_plugins:
            flag = ("-p", f"no:{plugin}")
            if flag[0] not in values or flag[1] not in values:
                extra.extend(flag)
        for plugin in self.enabled_plugins:
            if plugin not in values:
                extra.extend(("-p", plugin))
        if extra:
            values[insert_at:insert_at] = extra
        return tuple(values)

    def assert_pinned(self) -> dict:
        """Check the evaluator process against the pinned profile."""
        actual = importlib.metadata.version("pytest")
        if actual != self.pytest_version:
            raise RuntimePinError(
                f"pytest_version_mismatch:expected={self.pytest_version}"
                f" actual={actual}")
        if not sys.version.startswith(self.python_version):
            raise RuntimePinError(
                f"python_version_mismatch:expected={self.python_version}"
                f" actual={sys.version.split()[0]}")
        return self.as_dict()

    def as_dict(self) -> dict:
        return {
            "profile_version": self.profile_version,
            "python_version": self.python_version,
            "pytest_version": self.pytest_version,
            "bootstrap_memory_bytes": self.bootstrap_memory_bytes,
            "task_memory_bytes": self.task_memory_bytes,
            "cpu_seconds": self.cpu_seconds,
            "wall_seconds": self.wall_seconds,
            "process_count": self.process_count,
            "bootstrap_process_count": self.bootstrap_process_count,
            "disk_bytes": self.disk_bytes,
            "output_bytes": self.output_bytes,
            "disabled_plugins": list(self.disabled_plugins),
            "enabled_plugins": list(self.enabled_plugins),
        }

    @property
    def digest(self) -> str:
        return canonical_digest("evaluator_runtime", 1, self.as_dict())


@dataclass(frozen=True)
class BootstrapResult:
    ok: bool
    reason: str
    detail: str = ""
    import_receipt_digest: str | None = None
    pytest_receipt_digest: str | None = None
    pytest_version: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok, "reason": self.reason, "detail": self.detail,
            "import_receipt_digest": self.import_receipt_digest,
            "pytest_receipt_digest": self.pytest_receipt_digest,
            "pytest_version": self.pytest_version,
        }


def bootstrap_check(
    executor: WorkspaceExecutor,
    profile: EvaluationRuntimeProfile,
    *,
    root: str | Path | None = None,
) -> BootstrapResult:
    """Verify interpreter + pytest initialization before any task run."""
    workspace = None
    try:
        with tempfile.TemporaryDirectory(
                dir=str(root) if root is not None else None,
                prefix="sis-bootstrap-") as temp:
            workspace = executor.prepare(temp, label="bootstrap")
            import_receipt = executor.run(workspace, CommandSpec(
                argv=(sys.executable, "-c",
                      "import pytest; print(pytest.__version__)"),
                env=profile.environment(),
                limits=profile.bootstrap_limits))
            if import_receipt.timeout or import_receipt.exit_status != 0:
                return BootstrapResult(
                    ok=False, reason="pytest_import_failed",
                    detail=_receipt_detail(executor, import_receipt),
                    import_receipt_digest=import_receipt.digest)
            stdout, _ = executor.output(import_receipt.execution_id)
            version = stdout.decode("utf-8", "replace").strip().splitlines()
            actual = version[-1].strip() if version else ""
            if actual != profile.pytest_version:
                return BootstrapResult(
                    ok=False, reason="pytest_version_mismatch",
                    detail=f"expected={profile.pytest_version}"
                           f" actual={actual}",
                    import_receipt_digest=import_receipt.digest)
            pytest_receipt = executor.run(workspace, CommandSpec(
                argv=profile.pytest_argv(
                    (sys.executable, "-m", "pytest", "--version")),
                env=profile.environment(),
                limits=profile.bootstrap_limits))
            if pytest_receipt.timeout or pytest_receipt.exit_status != 0:
                return BootstrapResult(
                    ok=False, reason="pytest_bootstrap_failed",
                    detail=_receipt_detail(executor, pytest_receipt),
                    import_receipt_digest=import_receipt.digest,
                    pytest_receipt_digest=pytest_receipt.digest)
            return BootstrapResult(
                ok=True, reason="ok", pytest_version=actual,
                import_receipt_digest=import_receipt.digest,
                pytest_receipt_digest=pytest_receipt.digest)
    except Exception as exc:  # noqa: BLE001 - classified, not hidden
        return BootstrapResult(
            ok=False, reason="bootstrap_infrastructure_error",
            detail=f"{type(exc).__name__}: {exc}")
    finally:
        if workspace is not None:
            try:
                executor.destroy(workspace)
            except Exception:
                pass


def _receipt_detail(executor, receipt) -> str:
    try:
        stdout, stderr = executor.output(receipt.execution_id)
    except Exception:
        return "output_unavailable"
    tail = (stderr or stdout).decode("utf-8", "replace")[-400:]
    return tail.strip()


REPORT_NONCE_ENV = "SIS_PYTEST_REPORT_NONCE"
_REPORT_PREFIX = b"SIS_PYTEST_REPORT:"
#: Exit status the trusted bootstrap uses when the test runner is missing.
RUNNER_UNAVAILABLE_EXIT = 70


@dataclass(frozen=True)
class PytestReportCheck:
    """Whether a run carried positive evidence of a complete pytest pass.

    Produced by :func:`check_pytest_report` from the report the
    evaluator bootstrap writes after pytest's session finished. ``ok``
    is the only field classification reads; ``reason`` explains a
    rejection.
    """

    ok: bool
    reason: str
    counts: tuple[tuple[str, int], ...] = ()


def check_pytest_report(
    stdout: bytes, nonce: str, *,
    expected_files: tuple[str, ...] = (),
) -> PytestReportCheck:
    """Require a finished, all-passing pytest session report.

    The report must appear exactly once with the run's nonce, describe a
    finished session with exit status 0, at least one collected and
    passed test, no failures, errors or collection errors, and a result
    for every collected test. Every name in ``expected_files`` (the
    evaluator-private test files named on the command line) must have
    contributed at least one collected test, and no collected test may
    come from outside the private directory.

    Shared custody runs the submission in the same process as pytest, so
    code that discovers the nonce can still forge this report. It stops
    an exit-status-only pass (``os._exit(0)``) but is not a boundary;
    only split custody is qualification-grade.
    """
    if not isinstance(nonce, str) or not nonce:
        return PytestReportCheck(False, "report_nonce_missing")
    marker = _REPORT_PREFIX + nonce.encode("ascii") + b":"
    lines = [line for line in (stdout or b"").splitlines()
             if line.startswith(marker)]
    if not lines:
        return PytestReportCheck(False, "report_missing")
    if len(lines) != 1:
        return PytestReportCheck(False, "report_duplicated")
    try:
        import json
        payload = json.loads(lines[0][len(marker):].decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return PytestReportCheck(False, "report_malformed")
    if not isinstance(payload, dict):
        return PytestReportCheck(False, "report_malformed")
    names = ("collected", "passed", "failed", "errors", "skipped",
             "xfailed", "xpassed", "collection_errors")
    counts = {}
    for name in names:
        value = payload.get(name)
        if type(value) is not int or value < 0:
            return PytestReportCheck(False, "report_malformed")
        counts[name] = value
    summary = tuple(sorted(counts.items()))
    files = payload.get("files")
    if not isinstance(files, dict) or not all(
            isinstance(key, str) and type(value) is int
            for key, value in files.items()):
        return PytestReportCheck(False, "report_malformed", summary)
    if payload.get("finished") is not True:
        return PytestReportCheck(False, "session_not_finished", summary)
    if payload.get("exitstatus") != 0 or payload.get("returned") != 0:
        return PytestReportCheck(False, "session_not_successful", summary)
    if counts["collected"] < 1 or counts["passed"] < 1:
        return PytestReportCheck(False, "no_passing_tests", summary)
    if counts["failed"] or counts["errors"] or counts["collection_errors"]:
        return PytestReportCheck(False, "failures_reported", summary)
    resulted = (counts["passed"] + counts["skipped"] + counts["xfailed"]
                + counts["xpassed"])
    if resulted != counts["collected"]:
        return PytestReportCheck(False, "tests_without_result", summary)
    if expected_files:
        if files.get("<outside>", 0):
            return PytestReportCheck(False, "unexpected_tests", summary)
        for name in expected_files:
            if files.get(name, 0) < 1:
                return PytestReportCheck(
                    False, "expected_tests_not_collected", summary)
    return PytestReportCheck(True, "ok", summary)


def classify_execution(
    receipt,
    *,
    bootstrap_ok: bool = True,
    stderr_tail: str = "",
    require_verified_isolation: bool = False,
    production: bool = False,
    infrastructure_error: str | None = None,
    report: PytestReportCheck | None = None,
) -> str:
    """Map receipt facts to one outcome class; never grants production authority.

    ``production=True`` is retained only to fail closed. A caller cannot
    obtain a production pass from a receipt, a self-reported marker, or a
    typed verification object. The evaluator-owned route is
    :func:`classify_production_execution`, which verifies a signed
    attestation against the exact execution receipt and policy first.

    Only trusted signals decide the class: the caller's own flags, the
    executor's receipt markers and timeout, the exit status, and — when
    supplied — the result ``report``. ``stderr_tail`` is accepted for
    compatibility and ignored: it is submission-controlled text, so
    matching it (``MemoryError``, ``Killed``, a runner-unavailable line)
    would let a failing submission turn its verdict into an error. When
    ``report`` is given, a pass also requires ``report.ok``; an exit
    status of 0 without it is a task failure.
    """
    del stderr_tail  # submission-controlled; never a classification input
    if infrastructure_error:
        return INFRASTRUCTURE_ERROR
    if not bootstrap_ok:
        return EVALUATOR_BOOTSTRAP_ERROR
    errors = set(getattr(receipt, "security_errors", ()) or ())
    if ("evaluation:process_split" in errors
            and getattr(receipt, "exit_status", None)
            == RUNNER_UNAVAILABLE_EXIT):
        # Under split custody the acceptance process never runs submitted
        # code, so its bootstrap's runner-unavailable status is trusted.
        return EVALUATOR_BOOTSTRAP_ERROR
    if production:
        # No public production authority: the real route is
        # classify_production_execution with a signed attestation.
        return SANDBOX_FAILURE
    if require_verified_isolation and "isolation:unverified_local" in errors:
        return SANDBOX_FAILURE
    if getattr(receipt, "timeout", False):
        return TIMEOUT
    if any(error.startswith("fs:external_symlink") for error in errors):
        return SANDBOX_FAILURE
    if any(error.startswith("sandbox:") for error in errors):
        return SANDBOX_FAILURE
    if any(error.startswith(("fs:", "output:", "rlimit:"))
           for error in errors):
        return RESOURCE_LIMIT
    if getattr(receipt, "exit_status", None) == 0 and (
            report is None or report.ok):
        return TASK_PASS
    return TASK_FAIL


@dataclass(frozen=True)
class ProductionClassification:
    """Evaluator-owned production verdict with the verified isolation report."""

    outcome_class: str
    verification: IsolationVerification


def classify_production_execution(
    receipt,
    attestation,
    policy: ProductionIsolationPolicy,
    *,
    bootstrap_ok: bool = True,
    stderr_tail: str = "",
    at_time: str | None = None,
    infrastructure_error: str | None = None,
    report: PytestReportCheck | None = None,
) -> ProductionClassification:
    """Verify signed isolation evidence, then classify the execution.

    This is the only route that can return TASK_PASS under production
    conditions. It requires the actual ``IsolationAttestationV1`` and a
    :class:`ProductionIsolationPolicy`; a preconstructed positive
    ``IsolationVerification`` is not an attestation and fails schema
    parsing. A local ``isolation:unverified_local`` receipt is a sandbox
    failure even when the attestation verifies.
    """
    verification = verify_production_isolation(
        attestation, receipt, policy, at_time=at_time)
    if not verification.ok:
        return ProductionClassification(SANDBOX_FAILURE, verification)
    errors = set(getattr(receipt, "security_errors", ()) or ())
    if "isolation:unverified_local" in errors:
        return ProductionClassification(SANDBOX_FAILURE, verification)
    outcome = classify_execution(
        receipt, bootstrap_ok=bootstrap_ok, stderr_tail=stderr_tail,
        infrastructure_error=infrastructure_error, report=report)
    return ProductionClassification(outcome, verification)


def receipt_outcome_class(receipt, **kwargs) -> str:
    return classify_execution(receipt, **kwargs)


__all__ = [
    "BootstrapResult",
    "EVALUATOR_BOOTSTRAP_ERROR",
    "EVIDENCE_FAILURE",
    "EvaluationRuntimeProfile",
    "GIB",
    "ProductionClassification",
    "INFRASTRUCTURE_ERROR",
    "OUTCOME_CLASSES",
    "PytestReportCheck",
    "REPORT_NONCE_ENV",
    "RESOURCE_LIMIT",
    "RuntimePinError",
    "SANDBOX_FAILURE",
    "TASK_FAIL",
    "TASK_OUTCOMES",
    "TASK_PASS",
    "TIMEOUT",
    "bootstrap_check",
    "check_pytest_report",
    "classify_execution",
    "classify_production_execution",
    "receipt_outcome_class",
]
