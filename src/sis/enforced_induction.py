"""Process-isolated induction with an OS-enforced memory ceiling.

``SearchBudget.max_memory_bytes`` is a soft, in-process ``tracemalloc``
budget. A search that owns its interpreter can stop, reset or replace the
tracer, and no in-process measurement can prove a hard cap. This module
runs the search in a separate Python process whose address space is
limited with ``RLIMIT_AS`` before the interpreter starts, and returns the
search result only alongside a receipt describing the limit the child
actually observed.

Two levels stay separate:

- the in-process budget remains diagnostic and explicitly soft;
- ``run_induction_enforced`` reports a hard-budget claim only when its
  receipt validates (the child observed the exact requested soft and hard
  limits) and the child was not killed by the cap.

The receipt is local evidence, not an independent attestation. The parent
applies the limit and the child reports it back; a principal that
controls both can forge the pair. Production execution still requires a
separately qualified worker (cgroup/microVM) and an externally signed
isolation attestation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .errors import InvalidInput
from .induction import SearchBudget, induce
from .validation import canonical, digest

try:
    import resource
except ImportError:  # pragma: no cover - non-POSIX platforms
    resource = None

_MODE = "posix_rlimit_as"
_MIN_LIMIT = 1 << 20
_MAX_LIMIT = 1 << 40
_MEMORY_SIGNALS = frozenset(
    value for value in (
        getattr(signal, "SIGKILL", None),
        getattr(signal, "SIGSEGV", None),
        getattr(signal, "SIGABRT", None),
        getattr(signal, "SIGBUS", None),
    ) if value is not None
)


class EnforcementUnavailable(RuntimeError):
    """The platform cannot apply an OS-level memory limit."""


@dataclass(frozen=True)
class MemoryEnforcementReceipt:
    """What the parent and child observed about one enforced run.

    ``valid`` is derived, never caller-asserted: it requires the child to
    have observed exactly the requested soft and hard ``RLIMIT_AS``
    values. A completed result without a valid receipt is not evidence
    that a hard memory bound held.

    ``platform`` and ``python`` describe the host that built the receipt,
    not the child interpreter: they are the parent's values, which differ
    when ``python_executable`` names another interpreter.
    """

    schema_version: int
    mode: str
    requested_limit_bytes: int
    observed_soft_limit_bytes: int | None
    observed_hard_limit_bytes: int | None
    child_pid: int | None
    child_exit_status: int
    child_signal: int | None
    completed: bool
    timed_out: bool
    memory_limit_hit: bool
    stdout_digest: str
    stderr_digest: str
    result_digest: str | None
    platform: str
    python: str

    @property
    def valid(self) -> bool:
        return (
            self.mode == _MODE
            and type(self.observed_soft_limit_bytes) is int
            and type(self.observed_hard_limit_bytes) is int
            and self.observed_soft_limit_bytes == self.requested_limit_bytes
            and self.observed_hard_limit_bytes == self.requested_limit_bytes
        )

    @property
    def body(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "requested_limit_bytes": self.requested_limit_bytes,
            "observed_soft_limit_bytes": self.observed_soft_limit_bytes,
            "observed_hard_limit_bytes": self.observed_hard_limit_bytes,
            "child_pid": self.child_pid,
            "child_exit_status": self.child_exit_status,
            "child_signal": self.child_signal,
            "completed": self.completed,
            "timed_out": self.timed_out,
            "memory_limit_hit": self.memory_limit_hit,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "result_digest": self.result_digest,
            "platform": self.platform,
            "python": self.python,
        }

    @property
    def receipt_digest(self) -> str:
        return digest(self.body)

    def to_dict(self) -> dict:
        return {**self.body, "valid": self.valid,
                "receipt_digest": self.receipt_digest}

    @classmethod
    def from_child_report(
        cls,
        report,
        *,
        requested_limit_bytes: int,
        child_pid: int | None,
        child_exit_status: int,
        child_signal: int | None,
        stdout: bytes,
        stderr: bytes,
        platform_name: str,
        python_version: str,
        timed_out: bool = False,
    ) -> "MemoryEnforcementReceipt":
        """Build a receipt from a child envelope, without trusting it."""
        enforcement = (report.get("enforcement")
                       if isinstance(report, Mapping) else None)
        if not isinstance(enforcement, Mapping):
            enforcement = {}
        soft = enforcement.get("observed_soft_limit_bytes")
        hard = enforcement.get("observed_hard_limit_bytes")
        mode = enforcement.get("mode")
        result = report.get("result") if isinstance(report, Mapping) else None
        error = report.get("error") if isinstance(report, Mapping) else None
        memory_limit_hit = (
            not timed_out
            and (error == "MemoryError"
                 or (result is None and child_signal in _MEMORY_SIGNALS)))
        completed = (isinstance(result, dict)
                     and child_exit_status == 0
                     and child_signal is None
                     and not timed_out)
        return cls(
            schema_version=1,
            mode=mode if isinstance(mode, str) else "",
            requested_limit_bytes=requested_limit_bytes,
            observed_soft_limit_bytes=soft if type(soft) is int else None,
            observed_hard_limit_bytes=hard if type(hard) is int else None,
            child_pid=child_pid,
            child_exit_status=child_exit_status,
            child_signal=child_signal,
            completed=completed,
            timed_out=timed_out,
            memory_limit_hit=memory_limit_hit,
            stdout_digest=hashlib.sha256(stdout).hexdigest(),
            stderr_digest=hashlib.sha256(stderr).hexdigest(),
            result_digest=(digest(result) if result is not None else None),
            platform=platform_name,
            python=python_version,
        )


@dataclass(frozen=True)
class EnforcedInduction:
    """An enforced run: a result plus the receipt that qualifies it."""

    result: dict | None
    receipt: MemoryEnforcementReceipt

    @property
    def hard_memory_verified(self) -> bool:
        """Whether a hard memory bound held for a completed search."""
        return (self.result is not None
                and self.receipt.valid
                and self.receipt.completed
                and not self.receipt.timed_out
                and not self.receipt.memory_limit_hit)


def run_induction_enforced(
    train,
    validation=None,
    *,
    dev=None,
    holdout=None,
    budget: SearchBudget | None = None,
    memory_limit_bytes: int,
    timeout_seconds: float = 120.0,
    namespace: str = "default",
    proposals=None,
    use_z3: bool = False,
    max_refinement_rounds: int = 2,
    python_executable: str | None = None,
    env: Mapping[str, str] | None = None,
) -> EnforcedInduction:
    """Run ``induce`` in a child process capped by ``RLIMIT_AS``.

    ``memory_limit_bytes`` is the total address-space ceiling for the
    child, not the incremental soft budget. It must leave room for the
    interpreter and the search; a value that is too small fails the child
    and produces an invalid or memory-hit receipt, never a success.
    """
    if (type(memory_limit_bytes) is not int
            or not _MIN_LIMIT <= memory_limit_bytes <= _MAX_LIMIT):
        raise InvalidInput(
            f"memory_limit_bytes must be an integer in "
            f"[{_MIN_LIMIT},{_MAX_LIMIT}]")
    if (type(timeout_seconds) not in (int, float)
            or isinstance(timeout_seconds, bool)
            or not 0 < timeout_seconds <= 3600):
        raise InvalidInput("timeout_seconds must be in (0, 3600]")
    if resource is None or not hasattr(resource, "RLIMIT_AS"):
        raise EnforcementUnavailable("posix_rlimit_as_unavailable")

    induce_kwargs = {
        "validation": validation,
        "dev": dev,
        "holdout": holdout,
        "budget": budget.as_dict() if budget is not None else None,
        "namespace": namespace,
        "proposals": proposals,
        "use_z3": use_z3,
        "max_refinement_rounds": max_refinement_rounds,
    }
    payload = {
        "schema_version": 1,
        "memory_limit_bytes": memory_limit_bytes,
        "train": train,
        "induce": induce_kwargs,
    }
    try:
        payload_text = canonical(payload)
    except (TypeError, ValueError) as exc:
        raise InvalidInput("induction payload is not JSON serializable") from exc

    python_executable = python_executable or sys.executable
    with tempfile.TemporaryDirectory(prefix="sis-enforced-") as temp:
        root = Path(temp)
        payload_path = root / "payload.json"
        output_path = root / "result.json"
        payload_path.write_text(payload_text, encoding="utf-8")
        argv = [
            python_executable, "-m", "sis.enforced_induction",
            "--payload", str(payload_path),
            "--output", str(output_path),
        ]
        child_env = dict(os.environ)
        if env is not None:
            child_env.update({str(key): str(value)
                              for key, value in env.items()})

        def apply_limit() -> None:
            resource.setrlimit(
                resource.RLIMIT_AS,
                (memory_limit_bytes, memory_limit_bytes))

        try:
            proc = subprocess.Popen(
                argv,
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
                preexec_fn=apply_limit,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise EnforcementUnavailable(
                "memory_limit_not_applied") from exc

        timed_out = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            stdout, stderr = proc.communicate()

        child_signal = -proc.returncode if proc.returncode is not None \
            and proc.returncode < 0 else None
        report = None
        if not timed_out and output_path.is_file():
            try:
                report = json.loads(output_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                report = None
        receipt = MemoryEnforcementReceipt.from_child_report(
            report,
            requested_limit_bytes=memory_limit_bytes,
            child_pid=proc.pid,
            child_exit_status=proc.returncode if proc.returncode is not None
            else -1,
            child_signal=child_signal,
            stdout=stdout or b"",
            stderr=stderr or b"",
            platform_name=platform.platform(),
            python_version=platform.python_version(),
            timed_out=timed_out,
        )
        result = report.get("result") if isinstance(report, Mapping) else None
        return EnforcedInduction(
            result=result if isinstance(result, dict) else None,
            receipt=receipt)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:  # pragma: no cover - this module requires POSIX rlimits
            proc.kill()
    except (OSError, ProcessLookupError):
        try:
            proc.kill()
        except OSError:
            pass


def _child_main(argv=None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--payload", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    payload = json.loads(Path(args.payload).read_text(encoding="utf-8"))
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    envelope = {
        "enforcement": {
            "mode": _MODE,
            "observed_soft_limit_bytes": soft,
            "observed_hard_limit_bytes": hard,
        },
    }
    code = 0
    try:
        kwargs = dict(payload.get("induce") or {})
        budget_dict = kwargs.pop("budget", None)
        budget = SearchBudget(**budget_dict) if budget_dict else None
        envelope["result"] = induce(payload["train"], budget=budget, **kwargs)
    except MemoryError:
        envelope["error"] = "MemoryError"
        code = 3
    except BaseException as exc:  # report the failure, never fake a result
        envelope["error"] = type(exc).__name__
        envelope["detail"] = str(exc)[:2000]
        code = 1
    Path(args.output).write_text(canonical(envelope), encoding="utf-8")
    return code


if __name__ == "__main__":  # pragma: no cover - child entry point
    raise SystemExit(_child_main())
