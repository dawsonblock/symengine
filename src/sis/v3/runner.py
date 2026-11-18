"""Disposable workspace execution boundary for SIS v3 (SIS3-003).

A ``WorkspaceExecutor`` prepares a disposable copy of an immutable base tree,
runs a bounded non-shell command inside it, and reports a deterministic
:class:`ExecutionReceiptV1`. ``LocalSubprocessExecutor`` is the development
backend: a child process group with POSIX resource limits, a scrubbed
environment, capped output capture, and a wall-clock kill switch. On macOS it
can additionally wrap commands in ``sandbox-exec`` (seatbelt) to deny network
access and confine file writes to the workspace.

This backend is NOT a validated OS security boundary. Kernel exploits, host
credential access without seatbelt, and side channels remain possible. Receipts
always carry the ``isolation:unverified_local`` marker plus factual capability
markers so downstream evidence handling cannot mistake them for sandboxed
execution. Production deployments require a real OS-isolated implementation
(Linux rootless worker, microVM, or equivalent) behind the same interface.
"""
from __future__ import annotations

import hashlib
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol, runtime_checkable

from .contracts import ContractError, ExecutionReceiptV1, canonical_digest
from .split_harness import (
    MARKER_SEATBELT,
    MARKER_SPLIT,
    SPLIT_BOOTSTRAP_NAME,
    SPLIT_BOOTSTRAP_SOURCE,
    SPLIT_INI_NAME,
    SPLIT_INI_SOURCE,
    is_python_command,
    split_bootstrap_argv,
    split_failure_marker,
    split_pytest_argv,
    worker_argv,
)
from .workspace_guard import ManagedWorkspaceRegistry, protected_overlap

try:
    import resource
except ImportError:  # pragma: no cover - non-POSIX platforms
    resource = None

MAX_ARGV_ITEMS = 32
MAX_ARG_CHARS = 1_024
MAX_ENV_ITEMS = 32
MAX_ENV_CHARS = 4_096
MAX_STDIN_BYTES = 1 << 20
MAX_WORKSPACE_FILES = 200_000
MAX_PRIVATE_FILES = 64
MAX_PRIVATE_FILE_BYTES = 1 << 20
MAX_PRIVATE_TOTAL_BYTES = 8 << 20
_READ_CHUNK = 65_536

_ARG_TEXT = re.compile(r"^[^\x00]{1,1024}$", re.DOTALL)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_CWD = re.compile(r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{0,512}$")
_PRIVATE_NAME = re.compile(r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")

_LIMIT_LAUNCHER = r'''
import os
import resource
import signal
import sys

# Evaluator-owned launcher. It runs with ``python -I`` from a neutral
# working directory, so nothing in the graded workspace is importable here,
# and it fails closed: a limit it cannot apply stops the run before the
# command starts instead of being skipped.
args = sys.argv[1:]
status_fd = None
cwd = None
cgroup = None
supervise = False
triples = []
while args and args[0] != "--":
    option = args.pop(0)
    if option == "--status-fd":
        status_fd = int(args.pop(0))
    elif option == "--cwd":
        cwd = args.pop(0)
    elif option == "--cgroup":
        cgroup = args.pop(0)
    elif option == "--supervise":
        supervise = True
    else:
        triples.append((option, int(args.pop(0)), int(args.pop(0))))
if not args or args[0] != "--" or len(args) < 2:
    raise SystemExit(64)
command = args[1:]


def report(text):
    global status_fd
    if status_fd is None:
        return
    try:
        os.write(status_fd, text.encode("ascii", "replace")[:512])
        os.close(status_fd)
    except OSError:
        pass
    status_fd = None


def refuse(reason):
    report("F" + reason)
    sys.stderr.write("sis_launcher_refused: " + reason + "\n")
    sys.stderr.flush()
    os._exit(71)


if cgroup is not None:
    # Join the cgroup before anything is forked, so every descendant of
    # the command is created inside it.
    try:
        with open(cgroup, "w") as handle:
            handle.write(str(os.getpid()))
    except OSError as exc:
        refuse("cgroup_join_failed:%s" % (exc.errno,))
for name, soft, hard in triples:
    limit = getattr(resource, name, None)
    if limit is None:
        refuse("rlimit_unavailable:" + name)
    try:
        resource.setrlimit(limit, (soft, hard))
    except (OSError, ValueError) as exc:
        refuse("rlimit_failed:" + name)
if cwd is not None:
    try:
        os.chdir(cwd)
    except OSError:
        refuse("chdir_failed")


def children():
    found = []
    me = str(os.getpid())
    try:
        names = os.listdir("/proc")
    except OSError:
        return found
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open("/proc/" + name + "/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        fields = data[data.rfind(b")") + 2:].split()
        if len(fields) > 1 and fields[1].decode() == me:
            found.append(int(name))
    return found


def reap_all():
    # Orphaned descendants, including ones that left the process group
    # with setsid(), are reparented to this subreaper. Kill and reap until
    # none remain (bounded, so a pathological tree cannot hold the run).
    import time
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        for pid in children():
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            pid, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        except OSError:
            return
        if pid == 0:
            time.sleep(0.005)


if supervise and sys.platform.startswith("linux"):
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    PR_SET_CHILD_SUBREAPER = 36
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        supervise = False
if supervise and sys.platform.startswith("linux"):
    report("LS")
    child = os.fork()
    if child == 0:
        try:
            for number in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
                signal.signal(number, signal.SIG_DFL)
            os.execvpe(command[0], command, os.environ)
        except BaseException:
            pass
        os._exit(127)

    def stop(_number, _frame):
        try:
            os.kill(child, signal.SIGKILL)
        except OSError:
            pass

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    while True:
        try:
            _pid, status = os.waitpid(child, 0)
            break
        except ChildProcessError:
            status = 127 << 8
            break
    reap_all()
    if os.WIFSIGNALED(status):
        # Die by the same signal, so the runner sees the command's own
        # termination (SIGXCPU/SIGKILL at the CPU limit, for example).
        number = os.WTERMSIG(status)
        try:
            signal.signal(number, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
        try:
            os.kill(os.getpid(), number)
        except OSError:
            pass
        os._exit(128 + number)
    os._exit(os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1)
report("L")
os.execvpe(command[0], command, os.environ)
'''

_BOOTSTRAP_NAME = "_sis_bootstrap.py"
# Staged read-only next to the private material and run as the Python entry
# point. It imports the test runner before the graded workspace becomes
# importable, so a submission can neither shadow ``pytest`` nor supply a
# ``sitecustomize`` that runs at interpreter startup.
_BOOTSTRAP_SOURCE = '''"""SIS evaluator bootstrap (evaluator-owned, read-only).

The graded workspace becomes importable only after the interpreter has
started and the test runner has been imported. A submission therefore
cannot supply ``sitecustomize`` or shadow ``pytest`` before the
acceptance command runs.
"""
import importlib
import os
import runpy
import sys
import warnings

warnings.filterwarnings(
    "ignore", message=r".*found in sys\\.modules.*", category=RuntimeWarning)

workspace = sys.argv[1]
target = sys.argv[2:]
if not target:
    raise SystemExit(64)
# A per-run nonce for the result report. It is removed from the
# environment before any submitted code can be imported.
REPORT_NONCE = os.environ.pop("SIS_PYTEST_REPORT_NONCE", "")
HERE = os.path.dirname(os.path.abspath(__file__))


def run_pytest_with_report(args):
    """Run pytest in-process and emit positive evidence of the result.

    An exit status alone is not evidence: submitted code shares this
    process and can call ``os._exit(0)``. The report is written only
    after pytest finished its session, so an early exit leaves no report
    and the verifier fails the run.
    """
    import json
    import pytest

    counts = {"collected": 0, "passed": 0, "failed": 0, "errors": 0,
              "skipped": 0, "xfailed": 0, "xpassed": 0,
              "collection_errors": 0}
    files = {}
    state = {"finished": False, "exitstatus": None}

    class SisReport:
        def pytest_collectreport(self, report):
            if report.failed:
                counts["collection_errors"] += 1

        def pytest_collection_finish(self, session):
            counts["collected"] = len(session.items)
            for item in session.items:
                path = os.path.abspath(str(getattr(item, "path", "")))
                if path.startswith(HERE + os.sep):
                    key = os.path.relpath(path, HERE).replace(os.sep, "/")
                else:
                    key = "<outside>"
                files[key] = files.get(key, 0) + 1

        def pytest_runtest_logreport(self, report):
            if report.when == "call":
                if hasattr(report, "wasxfail"):
                    counts["xpassed" if report.passed else "xfailed"] += 1
                elif report.passed:
                    counts["passed"] += 1
                elif report.failed:
                    counts["failed"] += 1
                elif report.skipped:
                    counts["skipped"] += 1
            elif report.failed:
                counts["errors"] += 1
            elif report.when == "setup" and report.skipped:
                counts["xfailed" if hasattr(report, "wasxfail")
                       else "skipped"] += 1

        def pytest_sessionfinish(self, session, exitstatus):
            state["finished"] = True
            state["exitstatus"] = int(exitstatus)

    code = int(pytest.main(list(args), plugins=[SisReport()]))
    payload = dict(counts, files=files, finished=state["finished"],
                   exitstatus=state["exitstatus"], returned=code)
    line = ("\\nSIS_PYTEST_REPORT:" + REPORT_NONCE + ":"
            + json.dumps(payload, sort_keys=True) + "\\n")
    try:
        os.write(1, line.encode("utf-8"))
    except OSError:
        pass
    raise SystemExit(code)


def block_missing_runner():
    """Refuse a workspace pytest module when the trusted runner is absent."""
    class BlockPytest:
        def find_spec(self, name, path=None, target=None):
            if (name == "pytest" or name.startswith("pytest.")
                    or name == "_pytest" or name.startswith("_pytest.")):
                raise ModuleNotFoundError(
                    "evaluation_runner_unavailable: pytest")
            return None
    sys.meta_path.insert(0, BlockPytest())


def preload_pytest():
    try:
        importlib.import_module("pytest")
    except ImportError:
        block_missing_runner()


if target[0] == "-m":
    if len(target) < 2:
        raise SystemExit(64)
    module = target[1]
    # A -m runner must resolve from the trusted environment, before the
    # graded workspace is importable. A missing runner is an evaluator
    # bootstrap failure, never a submission-controlled module.
    try:
        importlib.import_module(module)
    except ImportError:
        sys.stderr.write("evaluation_runner_unavailable: " + module + "\\n")
        raise SystemExit(70)
    sys.path.insert(0, workspace)
    sys.argv = [module, *target[2:]]
    if module == "pytest" and REPORT_NONCE:
        run_pytest_with_report(target[2:])
    runpy.run_module(module, run_name="__main__", alter_sys=True)
elif target[0] == "-c":
    if len(target) < 2:
        raise SystemExit(64)
    preload_pytest()
    sys.path.insert(0, workspace)
    sys.argv = ["-c", *target[2:]]
    exec(compile(target[1], "<string>", "exec"), {"__name__": "__main__"})
else:
    preload_pytest()
    sys.path.insert(0, workspace)
    sys.argv = target
    runpy.run_path(target[0], run_name="__main__")
'''


def limit_triples(
    limits: ResourceLimits, security_errors: list[str], *,
    extra: tuple[tuple[str, int, int], ...] = (),
    cpu_grace_seconds: int = 0,
) -> list[tuple[str, int, int]]:
    """Resolve ``(RLIMIT_NAME, soft, hard)`` triples for the launcher.

    A requested value above the evaluator's own hard limit cannot be set
    by an unprivileged launcher; it is clamped to that hard limit (a
    stricter bound) and recorded, instead of failing every run.
    """
    if resource is None:
        return []
    wanted: list[tuple[str, int, int]] = [
        ("RLIMIT_CPU", limits.cpu_seconds,
         limits.cpu_seconds + cpu_grace_seconds)]
    if hasattr(resource, "RLIMIT_AS"):
        wanted.append(("RLIMIT_AS", limits.memory_bytes, limits.memory_bytes))
    if hasattr(resource, "RLIMIT_FSIZE"):
        # RLIMIT_FSIZE bounds each file, not the workspace total; the
        # total is audited after the run (``fs:disk_budget_exceeded``).
        wanted.append(("RLIMIT_FSIZE", limits.disk_bytes, limits.disk_bytes))
    if limits.process_count is not None:
        if hasattr(resource, "RLIMIT_NPROC"):
            wanted.append(("RLIMIT_NPROC", limits.process_count,
                           limits.process_count))
        else:
            security_errors.append("rlimit:nproc_unavailable")
    wanted.extend(extra)
    resolved: list[tuple[str, int, int]] = []
    for name, soft, hard in wanted:
        try:
            _current_soft, current_hard = resource.getrlimit(
                getattr(resource, name))
        except (AttributeError, OSError, ValueError):
            current_hard = resource.RLIM_INFINITY
        if current_hard != resource.RLIM_INFINITY and hard > current_hard:
            hard = current_hard
            soft = min(soft, hard)
            security_errors.append(f"rlimits:clamped:{name}")
        resolved.append((name, soft, hard))
    return resolved


def limit_launcher_argv(
    argv, triples, *, cwd: str | Path | None = None,
    status_fd: int | None = None, cgroup_procs: str | Path | None = None,
    supervise: bool = False,
) -> list[str]:
    """Argv that applies ``triples`` (and optionally joins a cgroup) then execs.

    The launcher is evaluator code run as ``python -I``: neither the
    current directory nor ``PYTHON*`` variables reach its ``sys.path``.
    Start it from a neutral directory and pass the workspace as ``cwd``;
    it changes directory only after every limit is applied. With
    ``cgroup_procs`` it writes its own pid to that ``cgroup.procs`` file
    first, so nothing it starts is ever outside the cgroup. With
    ``supervise`` (Linux) it stays as a child subreaper that kills and
    reaps every descendant when the command exits or on SIGTERM.
    """
    launcher = [sys.executable, "-I", "-c", _LIMIT_LAUNCHER]
    if cwd is not None:
        launcher += ["--cwd", str(cwd)]
    if status_fd is not None:
        launcher += ["--status-fd", str(status_fd)]
    if cgroup_procs is not None:
        launcher += ["--cgroup", str(cgroup_procs)]
    if supervise:
        launcher.append("--supervise")
    for name, soft, hard in triples:
        launcher += [name, str(int(soft)), str(int(hard))]
    launcher.append("--")
    return [*launcher, *argv]


def read_launcher_status(fd: int) -> str:
    """Read what the limit launcher reported, without blocking."""
    try:
        os.set_blocking(fd, False)
        data = os.read(fd, 1024)
    except (BlockingIOError, OSError):
        data = b""
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return data.decode("ascii", "replace")


def launcher_markers(status: str) -> list[str]:
    """Receipt markers for the launcher status: only what was applied.

    ``L`` means every limit was set before exec; ``LS`` additionally
    means the launcher supervised the command as a child subreaper. Any
    other status (a refusal, or nothing because the launcher never ran)
    is a sandbox failure, never a silent ``rlimits:launcher`` claim.
    """
    if status == "LS":
        return ["rlimits:launcher", "process:subreaper"]
    if status == "L":
        return ["rlimits:launcher"]
    reason = status[1:] if status.startswith("F") else "no_status"
    return ["sandbox:rlimits_not_applied:" + (reason or "unknown")]


#: Receipt marker for evaluator-private material run in the submission's
#: own process (shared custody). Such a verdict is development evidence,
#: never qualification-grade: submitted code shares the test runner's
#: process and principal and can forge whatever that process reports.
MARKER_SHARED_CUSTODY = "custody:shared_unqualified"


class RunnerError(RuntimeError):
    """A workspace or command specification cannot be executed."""


@dataclass(frozen=True)
class ResourceLimits:
    """Bounded resource envelope for one command run.

    ``process_count`` maps to POSIX ``RLIMIT_NPROC``, which on some kernels
    counts the real UID's existing processes rather than only descendants; a
    low value can therefore prevent a command from forking at all. Set ``None``
    to leave the limit untouched.

    ``disk_bytes`` is enforced live only per file (``RLIMIT_FSIZE``) by the
    local and bubblewrap backends; the workspace total is checked after
    the run and reported as ``fs:disk_budget_exceeded``. Only the Docker
    backend bounds the total during the run (a sized tmpfs).
    """

    cpu_seconds: int = 30
    wall_seconds: int = 60
    # 2 GiB: pytest plus installed plugins exceed the old 512 MiB
    # address-space limit during interpreter/bootstrap initialization.
    # That failure is an evaluator bootstrap error, never a task failure.
    memory_bytes: int = 2 * 1024 * 1024 * 1024
    output_bytes: int = 1_048_576
    disk_bytes: int = 67_108_864
    process_count: int | None = 64

    def __post_init__(self) -> None:
        for name, maximum in (
            ("cpu_seconds", 86_400),
            ("wall_seconds", 86_400),
            ("memory_bytes", 1 << 40),
            ("output_bytes", 1 << 30),
            ("disk_bytes", 1 << 40),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ContractError(f"{name} must be an integer in [1,{maximum}]")
        if self.process_count is not None and (
            type(self.process_count) is not int or not 1 <= self.process_count <= 65_535
        ):
            raise ContractError("process_count must be an integer in [1,65535] or None")


@dataclass(frozen=True)
class CommandSpec:
    """A single non-shell command with explicit environment and limits."""

    argv: tuple[str, ...]
    env: Mapping[str, str] = field(default_factory=dict)
    cwd: str = "."
    stdin: bytes = b""
    limits: ResourceLimits = field(default_factory=ResourceLimits)

    def __post_init__(self) -> None:
        argv = tuple(self.argv)
        object.__setattr__(self, "argv", argv)
        if not argv or len(argv) > MAX_ARGV_ITEMS:
            raise ContractError(f"argv must contain 1-{MAX_ARGV_ITEMS} entries")
        if any(not isinstance(arg, str) or not _ARG_TEXT.fullmatch(arg) for arg in argv):
            raise ContractError("argv entries must be bounded text without NUL")
        if ".." in _path_parts(argv[0]):
            raise ContractError("argv[0] must not traverse directories")
        env = dict(self.env)
        object.__setattr__(self, "env", env)
        if len(env) > MAX_ENV_ITEMS:
            raise ContractError(f"env must contain at most {MAX_ENV_ITEMS} entries")
        for key, value in env.items():
            if not isinstance(key, str) or not _ENV_NAME.fullmatch(key):
                raise ContractError("env keys must be portable variable names")
            if not isinstance(value, str) or len(value) > MAX_ENV_CHARS or "\x00" in value:
                raise ContractError("env values must be bounded text without NUL")
        if not isinstance(self.cwd, str) or not _SAFE_CWD.fullmatch(self.cwd) or "\\" in self.cwd:
            raise ContractError("cwd must be a normalized relative path inside the workspace")
        if self.cwd != "." and any(part in {"", ".", ".."} for part in self.cwd.split("/")):
            raise ContractError("cwd must be a normalized relative path inside the workspace")
        if not isinstance(self.stdin, bytes) or len(self.stdin) > MAX_STDIN_BYTES:
            raise ContractError(f"stdin must be at most {MAX_STDIN_BYTES} bytes")
        if not isinstance(self.limits, ResourceLimits):
            raise ContractError("limits must be a ResourceLimits instance")


def _path_parts(text: str) -> tuple[str, ...]:
    return tuple(part for part in text.split("/") if part)


def command_spec_digest(spec: CommandSpec) -> str:
    """Domain-separated digest binding the exact command, env, and limits."""
    limits = spec.limits
    return canonical_digest("command_spec", 1, {
        "argv": list(spec.argv),
        "env": dict(sorted(spec.env.items())),
        "cwd": spec.cwd,
        "stdin_digest": hashlib.sha256(spec.stdin).hexdigest(),
        "limits": {
            "cpu_seconds": limits.cpu_seconds,
            "wall_seconds": limits.wall_seconds,
            "memory_bytes": limits.memory_bytes,
            "output_bytes": limits.output_bytes,
            "disk_bytes": limits.disk_bytes,
            "process_count": limits.process_count if limits.process_count is not None else -1,
        },
    })


def normalize_private_files(
    files: Mapping[str, bytes] | None,
) -> dict[str, bytes]:
    """Validate evaluator-private material before it is staged anywhere."""
    if not files:
        return {}
    if len(files) > MAX_PRIVATE_FILES:
        raise ContractError("private material exceeds the file-count bound")
    normalized: dict[str, bytes] = {}
    total = 0
    for name, data in files.items():
        if (not isinstance(name, str) or not _PRIVATE_NAME.fullmatch(name)
                or any(part in {"", ".", ".."} for part in name.split("/"))):
            raise ContractError(
                "private material names must be normalized relative paths")
        if not isinstance(data, bytes) or len(data) > MAX_PRIVATE_FILE_BYTES:
            raise ContractError("private material must be bounded bytes")
        total += len(data)
        normalized[name] = data
    if total > MAX_PRIVATE_TOTAL_BYTES:
        raise ContractError("private material exceeds the byte bound")
    return normalized


def stage_private_material(
    root: str | Path, files: Mapping[str, bytes] | None, *,
    bootstrap: bool = False,
    private_mode: bool = False,
    split_bootstrap: bool = False,
) -> Path:
    """Write private material into a fresh directory outside any workspace.

    The directory is a sibling of the backend's managed workspaces, never a
    descendant of one, so submitted code cannot reach the material through
    its own workspace tree, the tree digest, or the copy-out archive. When
    ``bootstrap`` is set, the trusted runner bootstrap is staged beside it.

    ``private_mode`` stages owner-only modes for the split harness: the
    directory is 0700 and every file 0400. A worker running as another UID
    then cannot read the material, and the runner keeps access as owner.
    ``split_bootstrap`` stages the proxy bootstrap instead of the plain one.
    """
    material = normalize_private_files(files)
    if bootstrap and _BOOTSTRAP_NAME in material:
        raise ContractError(f"{_BOOTSTRAP_NAME} is reserved for evaluator staging")
    if split_bootstrap and SPLIT_BOOTSTRAP_NAME in material:
        raise ContractError(
            f"{SPLIT_BOOTSTRAP_NAME} is reserved for evaluator staging")
    directory = Path(tempfile.mkdtemp(dir=Path(root), prefix=".private-"))
    try:
        # A Docker bind mount preserves host ownership, and the container
        # user may be a different numeric UID than the host owner. The
        # material must therefore be traversable/readable by that UID; the
        # executor root itself is expected to be private.
        os.chmod(directory, 0o700 if private_mode else 0o755)
        file_mode = 0o400 if private_mode else 0o444
        for name, data in sorted(material.items()):
            target = directory / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            os.chmod(target, file_mode)
        if bootstrap:
            target = directory / _BOOTSTRAP_NAME
            target.write_bytes(_BOOTSTRAP_SOURCE.encode("utf-8"))
            os.chmod(target, file_mode)
        if split_bootstrap:
            target = directory / SPLIT_BOOTSTRAP_NAME
            target.write_bytes(SPLIT_BOOTSTRAP_SOURCE.encode("utf-8"))
            os.chmod(target, file_mode)
            # Evaluator-owned pytest configuration: split custody pins
            # rootdir and conftest discovery here, never in the workspace.
            target = directory / SPLIT_INI_NAME
            target.write_bytes(SPLIT_INI_SOURCE)
            os.chmod(target, file_mode)
    except BaseException:
        shutil.rmtree(directory, ignore_errors=True)
        raise
    return directory


def private_command_spec(
    spec: CommandSpec, *,
    names: Mapping[str, bytes] | set[str] | tuple[str, ...],
    prefix: str,
    workspace: str,
    bootstrap: bool = True,
) -> CommandSpec:
    """Point registered private-file arguments at the staged directory.

    Only exact argument matches (optionally ``./``-prefixed) are rewritten;
    every other argument, the cwd, stdin and the limits stay unchanged. A
    Python invocation is routed through the staged bootstrap, which imports
    the test runner and only then adds ``workspace`` to ``sys.path``. The
    workspace is never placed on ``PYTHONPATH``: a submission must not be
    importable — and must not be able to supply ``sitecustomize`` — before
    the acceptance command starts.
    """
    known = set(names)
    if not known:
        return spec

    def rewrite(arg: str) -> str:
        candidate = arg[2:] if arg.startswith("./") else arg
        head, separator, tail = candidate.partition("::")
        if head in known:
            return prefix.rstrip("/") + "/" + head + separator + tail
        return arg

    argv = tuple(rewrite(arg) for arg in spec.argv)
    if bootstrap and is_python_command(argv):
        argv = (
            argv[0],
            prefix.rstrip("/") + "/" + _BOOTSTRAP_NAME,
            workspace,
            *argv[1:],
        )
    return CommandSpec(
        argv=argv, env=dict(spec.env), cwd=spec.cwd,
        stdin=spec.stdin, limits=spec.limits)


def private_material_modified(
    directory: str | Path, files: Mapping[str, bytes] | None,
) -> bool:
    """True when a staged private file no longer matches its registered bytes."""
    material = normalize_private_files(files)
    root = Path(directory)
    for name, data in material.items():
        try:
            if (root / name).read_bytes() != data:
                return True
        except OSError:
            return True
    bootstrap = root / _BOOTSTRAP_NAME
    if bootstrap.exists():
        try:
            if bootstrap.read_bytes() != _BOOTSTRAP_SOURCE.encode("utf-8"):
                return True
        except OSError:
            return True
    split_bootstrap = root / SPLIT_BOOTSTRAP_NAME
    if split_bootstrap.exists():
        try:
            if split_bootstrap.read_bytes() != SPLIT_BOOTSTRAP_SOURCE.encode(
                    "utf-8"):
                return True
        except OSError:
            return True
    split_ini = root / SPLIT_INI_NAME
    if split_ini.exists():
        try:
            if split_ini.read_bytes() != SPLIT_INI_SOURCE:
                return True
        except OSError:
            return True
    return False


def mark_private_material_modified(
    receipt: ExecutionReceiptV1,
) -> ExecutionReceiptV1:
    """Append the tamper marker; classification maps ``sandbox:`` to failure."""
    return replace(
        receipt,
        security_errors=receipt.security_errors
        + ("sandbox:private_material_modified",),
    )


TREE_DIGEST_VERSIONS = (1, 2, 3)
# New records always carry the canonical version. Version 1 is legacy:
# it is retained only to re-verify digests recorded before the canonical
# format existed. Version 3 is the repository-content format: it hashes
# the working tree and excludes VCS metadata, so two clones of one
# revision share an identity. Version 2 remains the full-tree format
# used for workspace execution receipts and disk accounting.
CANONICAL_TREE_DIGEST_VERSION = 2
REPOSITORY_DIGEST_VERSION = 3
REPOSITORY_EXECUTION_DIGEST_VERSION = 1
_TREE_DIGEST_DOMAINS = {
    1: b"sis-v3:tree:1\0",
    2: b"sis-v3:tree:2\0",
    3: b"sis-v3:repository:1\0",
}
_REPOSITORY_EXECUTION_DOMAIN = b"sis-v3:repository_execution:1\0"
_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class TreeScan:
    digest: str
    file_count: int
    total_bytes: int
    external_symlinks: tuple[str, ...]
    version: int = CANONICAL_TREE_DIGEST_VERSION


def _check_tree_digest_version(version: int) -> None:
    if type(version) is not int or version not in _TREE_DIGEST_DOMAINS:
        raise RunnerError(f"unsupported_tree_digest_version:{version!r}")


def _external_symlink(root: Path, full: Path) -> bool:
    try:
        resolved = full.resolve(strict=True)
    except OSError:
        return True
    return not resolved.is_relative_to(root.resolve())


def external_symlinks(root: Path) -> tuple[str, ...]:
    """List symlinks anywhere under ``root`` that resolve outside it.

    Unlike the repository-content scan, this walker includes VCS
    metadata. Staging must reject an external link even when it lives
    under ``.git``, because the link is copied into the workspace.
    """
    root = Path(root)
    external: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            full = Path(dirpath) / name
            if full.is_symlink() and _external_symlink(root, full):
                external.append(full.relative_to(root).as_posix())
    return tuple(sorted(external))


def _scan_tree_legacy(root: Path) -> TreeScan:
    """Reproduce the pre-canonical digest byte for byte.

    This traversal hashes entries in ``os.walk`` order, which depends on
    the filesystem. It exists only to re-verify historical records; it
    must never mint a digest for a new record.
    """
    root = Path(root)
    hasher = hashlib.sha256(_TREE_DIGEST_DOMAINS[1])
    file_count = 0
    total_bytes = 0
    external: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        for name in dirnames:
            full = Path(dirpath) / name
            if full.is_symlink():
                filenames.append(name)
            else:
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            full = Path(dirpath) / name
            relative = full.relative_to(root).as_posix()
            if full.is_symlink():
                target = os.readlink(full)
                hasher.update(b"L" + relative.encode("utf-8") + b"\0" + target.encode("utf-8") + b"\0")
                if _external_symlink(root, full):
                    external.append(relative)
                continue
            if not full.is_file():
                continue
            file_count += 1
            if file_count > MAX_WORKSPACE_FILES:
                raise RunnerError("workspace exceeds the file-count bound")
            digest = hashlib.sha256()
            size = 0
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
                    digest.update(chunk)
                    size += len(chunk)
            total_bytes += size
            hasher.update(
                b"F" + relative.encode("utf-8") + b"\0" + digest.hexdigest().encode("ascii")
                + b"\0" + str(size).encode("ascii") + b"\0"
            )
    return TreeScan(hasher.hexdigest(), file_count, total_bytes,
                    tuple(sorted(external)), 1)


def _scan_tree_canonical(
    root: Path, *,
    exclude: frozenset[str] = frozenset(),
    domain: bytes = _TREE_DIGEST_DOMAINS[2],
    version: int = 2,
) -> TreeScan:
    """Canonical v2 tree fingerprint: traversal order is part of the format.

    Directory names and entry names are sorted by their encoded bytes at
    every level, so the digest depends only on the tree's contents, never
    on the order the filesystem returns directory entries. Names are
    encoded with ``os.fsencode`` so a name that is not valid UTF-8
    round-trips instead of raising. A directory's entries are hashed
    before its children are visited; within a directory, regular files
    and symlinks are interleaved in name order. Empty directories,
    special files, and file permissions are not part of the fingerprint —
    this is a content identity, not a filesystem metadata identity.

    ``exclude`` removes matching names at every level; the repository
    format uses it to drop VCS metadata so clones share an identity.
    """
    root = Path(root)
    hasher = hashlib.sha256(domain)
    file_count = 0
    total_bytes = 0
    external: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        kept = []
        linked_dirs = []
        for name in dirnames:
            if name in exclude:
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                linked_dirs.append(name)
            else:
                kept.append(name)
        dirnames[:] = sorted(kept, key=os.fsencode)
        for name in sorted(filenames + linked_dirs, key=os.fsencode):
            if name in exclude:
                continue
            full = Path(dirpath) / name
            relative = full.relative_to(root).as_posix()
            path_bytes = os.fsencode(relative)
            if full.is_symlink():
                target = os.readlink(full)
                hasher.update(b"L" + path_bytes + b"\0" + os.fsencode(target) + b"\0")
                if _external_symlink(root, full):
                    external.append(relative)
                continue
            if not full.is_file():
                continue
            file_count += 1
            if file_count > MAX_WORKSPACE_FILES:
                raise RunnerError("workspace exceeds the file-count bound")
            digest = hashlib.sha256()
            size = 0
            with open(full, "rb") as handle:
                for chunk in iter(lambda: handle.read(_READ_CHUNK), b""):
                    digest.update(chunk)
                    size += len(chunk)
            total_bytes += size
            hasher.update(
                b"F" + path_bytes + b"\0" + digest.hexdigest().encode("ascii")
                + b"\0" + str(size).encode("ascii") + b"\0"
            )
    return TreeScan(hasher.hexdigest(), file_count, total_bytes,
                    tuple(sorted(external)), version)


def _scan_tree_repository(root: Path) -> TreeScan:
    return _scan_tree_canonical(
        Path(root), exclude=_VCS_DIRECTORIES,
        domain=_TREE_DIGEST_DOMAINS[REPOSITORY_DIGEST_VERSION],
        version=REPOSITORY_DIGEST_VERSION)


def _execution_mode(info: os.stat_result) -> bytes:
    return f"{stat.S_IMODE(info.st_mode):04o}".encode("ascii")


def repository_execution_digest(root: Path) -> str:
    """Fingerprint the metadata that decides how a repository executes.

    The repository-content digest binds bytes and symlink targets but
    deliberately ignores permissions. Two checkouts can share that
    identity and still execute differently: a script that is executable
    in one and not the other, a directory that cannot be traversed, or a
    setuid binary. This separate fingerprint hashes each entry's type,
    permission bits (including setuid, setgid and sticky), and, for a
    symlink, its target. It uses the same canonical ordering and VCS
    exclusion as the content digest, so it is stable across filesystem
    iteration order. It is an addition, not a replacement: the content
    digest stays clone-shareable.

    Ownership and hard-link identity are not included: a Git checkout
    does not preserve them, and the staged workspace is owned by the
    runner.
    """
    root = Path(root)
    try:
        root_info = root.stat()
    except OSError as exc:
        raise RunnerError(
            f"repository_entry_unreadable:{root}") from exc
    hasher = hashlib.sha256(_REPOSITORY_EXECUTION_DOMAIN)
    hasher.update(b"R\0" + _execution_mode(root_info) + b"\0")

    def unreadable(error: OSError) -> None:
        raise RunnerError(
            f"repository_entry_unreadable:{error.filename}") from error

    file_count = 0
    for dirpath, dirnames, filenames in os.walk(
            root, followlinks=False, onerror=unreadable):
        kept: list[str] = []
        linked: list[str] = []
        for name in dirnames:
            if name in _VCS_DIRECTORIES:
                continue
            full = Path(dirpath) / name
            if full.is_symlink():
                linked.append(name)
            else:
                kept.append(name)
        dirnames[:] = sorted(kept, key=os.fsencode)
        entries = sorted(kept + linked + filenames, key=os.fsencode)
        for name in entries:
            if name in _VCS_DIRECTORIES:
                continue
            full = Path(dirpath) / name
            relative = full.relative_to(root).as_posix()
            path_bytes = os.fsencode(relative)
            try:
                info = full.stat(follow_symlinks=False)
            except OSError as exc:
                raise RunnerError(
                    f"repository_entry_unreadable:{relative}") from exc
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(full)
                hasher.update(
                    b"L" + path_bytes + b"\0" + os.fsencode(target) + b"\0")
                continue
            mode = _execution_mode(info)
            if stat.S_ISDIR(info.st_mode):
                hasher.update(b"D" + path_bytes + b"\0" + mode + b"\0")
                continue
            if not stat.S_ISREG(info.st_mode):
                hasher.update(b"O" + path_bytes + b"\0" + mode + b"\0")
                continue
            file_count += 1
            if file_count > MAX_WORKSPACE_FILES:
                raise RunnerError("workspace exceeds the file-count bound")
            hasher.update(
                b"F" + path_bytes + b"\0" + mode + b"\0"
                + str(info.st_size).encode("ascii") + b"\0")
    return hasher.hexdigest()


def scan_tree(root: Path, *, version: int = CANONICAL_TREE_DIGEST_VERSION) -> TreeScan:
    """Digest every file byte and symlink target under ``root``.

    ``version=2`` (default) is the canonical full-tree format used for
    workspace execution receipts and disk accounting. ``version=3`` is
    the repository-content format: it excludes VCS metadata, so two
    clones of one revision share an identity. ``version=1`` reproduces
    the legacy traversal-order-dependent digest and is supported only to
    re-verify records created before the canonical format existed.
    """
    _check_tree_digest_version(version)
    if version == 1:
        return _scan_tree_legacy(Path(root))
    if version == REPOSITORY_DIGEST_VERSION:
        return _scan_tree_repository(Path(root))
    return _scan_tree_canonical(Path(root))


def tree_digest(root: Path, *, version: int = CANONICAL_TREE_DIGEST_VERSION) -> str:
    return scan_tree(root, version=version).digest


def verify_tree_digest(
    root: Path,
    expected: str,
    *,
    canonical: str | None = None,
    allow_legacy: bool = True,
) -> int:
    """Match a recorded tree digest and return the version that matched.

    The canonical v2 digest is checked first. With ``allow_legacy`` the
    legacy v1 digest is also recomputed, so evidence recorded before the
    canonical format remains verifiable. A caller that must not accept
    legacy evidence passes ``allow_legacy=False``. ``canonical`` must be
    the v2 digest of ``root``; a caller that already computed it avoids a
    second scan.
    """
    if not isinstance(expected, str) or not _HEX_256.fullmatch(expected):
        raise RunnerError("tree_digest_malformed")
    if canonical is None:
        canonical = tree_digest(root)
    if canonical == expected:
        return CANONICAL_TREE_DIGEST_VERSION
    if allow_legacy:
        try:
            legacy = tree_digest(root, version=1)
        except UnicodeEncodeError:
            # A legacy scan cannot encode this tree's names, so no legacy
            # record can name it.
            legacy = None
        if legacy == expected:
            return 1
    raise RunnerError("tree_digest_mismatch")


def verify_repository_digest(
    root: Path,
    expected: str,
    *,
    canonical: str | None = None,
    allow_full_tree: bool = True,
    allow_legacy: bool = True,
) -> str:
    """Match a recorded repository digest and report the format that matched.

    The repository-content v3 digest (working tree, no VCS metadata) is
    checked first. ``allow_full_tree`` accepts a v2 full-tree digest so
    records minted before the repository format remain replayable;
    ``allow_legacy`` accepts the order-dependent v1 digest. Returns
    ``"repository"``, ``"tree:2"`` or ``"tree:1"``. ``canonical`` must be
    the v3 digest of ``root`` when supplied.
    """
    if not isinstance(expected, str) or not _HEX_256.fullmatch(expected):
        raise RunnerError("tree_digest_malformed")
    if canonical is None:
        canonical = tree_digest(root, version=REPOSITORY_DIGEST_VERSION)
    if canonical == expected:
        return "repository"
    if allow_full_tree and tree_digest(root) == expected:
        return "tree:2"
    if allow_legacy:
        try:
            legacy = tree_digest(root, version=1)
        except UnicodeEncodeError:
            legacy = None
        if legacy == expected:
            return "tree:1"
    raise RunnerError("tree_digest_mismatch")


@dataclass(frozen=True)
class Workspace:
    """A handle to a disposable workspace.

    ``path`` is informational. Backends resolve execution and deletion
    through their private registry and reject a handle whose path does
    not match the registered canonical path, so a caller cannot redirect
    a mount, an execution, or a delete by supplying its own path.
    """

    workspace_id: str
    path: Path
    before_tree_digest: str
    executor_identity: str


@runtime_checkable
class WorkspaceExecutor(Protocol):
    """Lifecycle for an isolated disposable task workspace."""

    supports_private_material: bool
    supports_split_custody: bool

    def prepare(self, base_dir: str | Path, *, label: str = "task") -> Workspace: ...

    def run(
        self, workspace: Workspace, spec: CommandSpec, *,
        private_files: Mapping[str, bytes] | None = None,
        split_custody: bool = False,
    ) -> ExecutionReceiptV1: ...

    def destroy(self, workspace: Workspace) -> None: ...

    def terminate_all(self) -> None: ...


def _minimal_env(workspace: Path) -> dict[str, str]:
    tool_paths = [os.defpath, str(Path(sys.executable).resolve().parent)]
    scratch = workspace / ".scratch"
    scratch.mkdir(exist_ok=True)
    env = {
        "PATH": os.pathsep.join(tool_paths),
        "HOME": str(workspace),
        "TMPDIR": str(scratch),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    if sys.platform == "win32":  # pragma: no cover - Windows fallback
        for name in ("SYSTEMROOT", "WINDIR", "COMSPEC"):
            if os.environ.get(name):
                env[name] = os.environ[name]
    return env


def _seatbelt_binary() -> str | None:
    if sys.platform != "darwin":
        return None
    binary = shutil.which("sandbox-exec")
    return binary


def _sensitive_paths() -> list[Path]:
    """Host credential stores that must never be visible to a child."""
    home = Path.home()
    candidates = [
        home / ".ssh", home / ".aws", home / ".gnupg", home / ".config",
        home / ".docker", home / ".kube", home / ".netrc",
        home / "Library" / "Keychains", Path("/etc/ssh"),
        Path("/private/etc/ssh"),
    ]
    return [path.resolve() for path in candidates if path.exists()]


def _seatbelt_profile(
    workspace: Path,
    scratch: Path,
    protected_paths: tuple[Path, ...] = (),
) -> str | None:
    """Deny-by-default profile: workspace writes, no network, protected reads.

    macOS Python startup and site-package discovery touch many system and
    home paths (including editable-install finders), so reads are broad.
    Signing keys, the authority database, checkpoint credentials, sealed
    evaluation datasets and host credential stores are explicitly denied
    after the read allow, which Seatbelt evaluates as a veto. Production
    deployments should still use a dedicated rootless worker/microVM with
    a minimal runtime image; this local backend is defense-in-depth, not a
    validated security boundary.

    Returns None when a path cannot be safely embedded in the profile
    language; the caller then runs without seatbelt and flags the receipt.
    """
    allowed_write = {workspace.resolve(), scratch.resolve()}
    denied_read = {
        *(path.resolve() for path in protected_paths),
        *_sensitive_paths(),
    }
    rendered = [str(p) for p in [*allowed_write, *denied_read]]
    if any('"' in path or "\\" in path or "\n" in path for path in rendered):
        return None
    if any(path == workspace.resolve() or
           workspace.resolve().is_relative_to(path) for path in denied_read):
        return None
    write_literals = "\n".join(
        f'(subpath "{path}")' for path in sorted(allowed_write, key=str))
    deny_literals = "\n".join(
        f'(subpath "{path}")' for path in sorted(denied_read, key=str))
    return (
        "(version 1)(deny default)"
        "(allow process*)(allow mach-lookup)(allow sysctl-read)"
        "(allow ipc-posix-shm)"
        "(allow file-read*)"
        f"(allow file-write* {write_literals} (literal \"/dev/null\"))"
        + (f"(deny file-read* {deny_literals})" if deny_literals else "")
        + "(deny network*)"
    )


class LocalSubprocessExecutor:
    """Development executor: bounded subprocess in a copied workspace.

    Isolation facts are reported per receipt; never treat this backend as a
    sandbox for hostile code without an OS-validated replacement.
    """

    supports_private_material = True

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        worker_identity: str = "local-subprocess-v1",
        use_seatbelt: bool | None = None,
        protected_paths=(),
        production: bool = False,
        verified_isolation: bool = False,
    ) -> None:
        if verified_isolation:
            # This backend is an ordinary local subprocess: it can never
            # be a validated containment boundary, so it must never mint
            # an ``isolation:verified`` claim on its own receipts.
            # Production qualification requires an IsolationAttestationV1
            # from a separately trusted isolator.
            raise ContractError(
                "verified_isolation_unavailable_for_local_backend")
        self.root = Path(os.path.abspath(
            root if root is not None
            else tempfile.mkdtemp(prefix="sis-v3-exec-")))
        self.root.mkdir(parents=True, exist_ok=True)
        self._registry = ManagedWorkspaceRegistry(
            self.root, executor_identity=worker_identity, error=RunnerError)
        self.worker_identity = worker_identity
        self._production = bool(production)
        self._seatbelt = None if use_seatbelt is False else _seatbelt_binary()
        self._protected: set[Path] = set()
        self._live: dict[str, subprocess.Popen] = {}
        self._live_ws: dict[str, str] = {}
        self._outputs: dict[str, tuple[bytes, bytes]] = {}
        self._lock = threading.Lock()
        for path in protected_paths:
            self.protect(path)

    def protect(self, path: str | Path) -> None:
        """Deny the child read access to a key/authority/dataset path."""
        resolved = Path(path).resolve()
        root = self.root.resolve()
        if resolved.is_relative_to(root) or root.is_relative_to(resolved):
            raise RunnerError(
                "protected path must not overlap the executor root")
        with self._lock:
            self._protected.add(resolved)

    @property
    def protected_paths(self) -> tuple[Path, ...]:
        with self._lock:
            return tuple(sorted(self._protected, key=str))

    @property
    def production(self) -> bool:
        return self._production

    @property
    def supports_split_custody(self) -> bool:
        """Split custody needs a kernel-enforced read denial for the worker."""
        return bool(self._seatbelt)

    @property
    def network_isolation(self) -> str:
        return "seatbelt_denied" if self._seatbelt else "not_enforced"

    def prepare(self, base_dir: str | Path, *, label: str = "task") -> Workspace:
        base = Path(base_dir)
        if not base.is_dir():
            raise RunnerError("base_dir must be an existing directory")
        if base.resolve().is_relative_to(self.root.resolve()):
            raise RunnerError("base_dir must not live inside the executor root")
        if protected_overlap(base, self.protected_paths) is not None:
            raise RunnerError("base_dir_overlaps_protected_material")
        self._reject_symlinks(base)
        workspace_id, path = self._registry.allocate()
        try:
            shutil.copytree(base, path, symlinks=False)
            scan = scan_tree(path)
            record = self._registry.register(
                workspace_id, path, before_tree_digest=scan.digest)
        except BaseException:
            shutil.rmtree(path, ignore_errors=True)
            raise
        return Workspace(
            record.workspace_id, record.path, record.before_tree_digest,
            record.executor_identity)

    def run(
        self, workspace: Workspace, spec: CommandSpec, *,
        private_files: Mapping[str, bytes] | None = None,
        split_custody: bool = False,
    ) -> ExecutionReceiptV1:
        if not isinstance(spec, CommandSpec):
            raise ContractError("spec must be a CommandSpec")
        if self._production:
            # Hostile-code execution stays disabled in production until
            # an OS-enforced containment has been independently
            # validated. This backend is explicitly not that — no flag or
            # attestation can qualify it.
            raise RunnerError("local_backend_not_production_qualified")
        if split_custody and not private_files:
            raise ContractError("split custody requires private material")
        if split_custody and not self._seatbelt:
            # Without a kernel read denial the worker could read the
            # private directory, so the split would be a rename, not a
            # boundary.
            raise RunnerError("split_custody_unavailable")
        with self._registry.execution(
                workspace.workspace_id, workspace.path,
                executor_identity=workspace.executor_identity) as record:
            material = None
            parent_sock = child_sock = None
            worker = None
            worker_id = None
            try:
                if split_custody:
                    material = stage_private_material(
                        self.root, private_files, private_mode=True,
                        split_bootstrap=True)
                    parent_sock, child_sock = socket.socketpair()
                    worker, worker_markers = self._start_split_worker(
                        record, child_sock, material, spec)
                    # The worker executes submitted code, so it belongs to
                    # the same kill switch as the acceptance process: a
                    # shutdown or a workspace destruction must reach it.
                    worker_id = "split-" + secrets.token_hex(8)
                    with self._lock:
                        self._live[worker_id] = worker
                        self._live_ws[worker_id] = record.workspace_id
                    child_sock.close()
                    child_sock = None
                    base = private_command_spec(
                        spec, names=private_files, prefix=str(material),
                        workspace=str(record.path), bootstrap=False)
                    base = replace(base, argv=split_pytest_argv(
                        base.argv, private_dir=str(material)))
                    spec = replace(base, argv=split_bootstrap_argv(
                        base.argv,
                        bootstrap_path=str(material / SPLIT_BOOTSTRAP_NAME),
                        transport=("--fd", str(parent_sock.fileno())),
                        workspace=str(record.path)))
                    receipt = self._run_workspace(
                        record, spec, private=True,
                        pass_fds=(parent_sock.fileno(),),
                        extra_markers=(MARKER_SPLIT, MARKER_SEATBELT,
                                       *worker_markers))
                    # A harness failure is not a verdict about the
                    # submission; the bootstrap reports it by exit status.
                    marker = split_failure_marker(receipt.exit_status)
                    if marker is not None:
                        receipt = replace(
                            receipt,
                            security_errors=receipt.security_errors + (marker,))
                else:
                    if private_files:
                        material = stage_private_material(
                            self.root, private_files, bootstrap=True)
                        spec = private_command_spec(
                            spec, names=private_files, prefix=str(material),
                            workspace=str(record.path))
                    receipt = self._run_workspace(
                        record, spec, private=material is not None,
                        extra_markers=(
                            (MARKER_SHARED_CUSTODY,) if material is not None
                            else ()))
                if material is not None and private_material_modified(
                        material, private_files):
                    # The local backend runs the submission as the same OS
                    # principal, so mode bits are not a tamper boundary.
                    receipt = mark_private_material_modified(receipt)
                return receipt
            finally:
                if worker is not None:
                    if worker_id is not None:
                        with self._lock:
                            self._live.pop(worker_id, None)
                            self._live_ws.pop(worker_id, None)
                    self._kill_group(worker)
                    try:
                        worker.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        worker.kill()
                        worker.wait(timeout=10)
                for sock in (parent_sock, child_sock):
                    if sock is not None:
                        try:
                            sock.close()
                        except OSError:
                            pass
                if material is not None:
                    shutil.rmtree(material, ignore_errors=True)

    def _start_split_worker(
        self, record, child_sock: socket.socket, material: Path,
        spec: CommandSpec,
    ) -> tuple[subprocess.Popen, list[str]]:
        """Start the restricted worker under a read denial for ``material``.

        The worker imports submitted code, so its seatbelt profile denies
        ``file-read*`` on the private directory while still allowing the
        workspace and scratch tree. It is a separate process but the same
        UID; the kernel denial, not the UID, is the boundary.
        """
        scratch = record.path / ".scratch"
        scratch.mkdir(exist_ok=True)
        profile = _seatbelt_profile(
            record.path, scratch, (*self.protected_paths, material))
        if profile is None:
            raise RunnerError("split_custody_unavailable")
        argv = [
            self._resolve_executable(sys.executable),
            *worker_argv(("--fd", str(child_sock.fileno())), str(record.path)),
        ]
        argv = [self._seatbelt, "-p", profile, *argv]
        env = _minimal_env(record.path)
        env.update(spec.env)
        markers: list[str] = []
        # The launcher starts from a neutral directory and enters the
        # workspace only after the limits are set.
        argv = self._limit_argv(argv, spec.limits, markers, cwd=record.path)
        try:
            proc = subprocess.Popen(
                argv,
                cwd=os.path.abspath(os.sep),
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=(os.name == "posix"),
                pass_fds=(child_sock.fileno(),),
            )
        except OSError as exc:
            raise RunnerError(
                f"split_custody_worker_start_failed:{exc}") from exc
        proc._sis_supervised = resource is not None
        return proc, markers

    def _run_workspace(
        self, record, spec: CommandSpec, *, private: bool = False,
        pass_fds: tuple[int, ...] = (),
        extra_markers: tuple[str, ...] = (),
    ) -> ExecutionReceiptV1:
        before = scan_tree(record.path)
        if before.external_symlinks:
            raise RunnerError("workspace contains external symlinks")
        workdir = (record.path / spec.cwd).resolve()
        if not workdir.is_dir() or not workdir.is_relative_to(record.path.resolve()):
            raise RunnerError("command cwd escapes or is absent from the workspace")

        security_errors: list[str] = ["isolation:unverified_local"]
        if private:
            security_errors.append("evaluation:private_material_separated")
        security_errors.extend(extra_markers)
        security_errors.append(
            "network:seatbelt_denied" if self._seatbelt
            else "network:not_enforced")
        limits = spec.limits
        argv = list(spec.argv)
        argv[0] = self._resolve_executable(argv[0])
        if self._seatbelt:
            scratch = record.path / ".scratch"
            scratch.mkdir(exist_ok=True)
            profile = _seatbelt_profile(
                record.path, scratch, self.protected_paths)
            if profile is not None:
                argv = [self._seatbelt, "-p", profile, *argv]
                security_errors.append("isolation:seatbelt")
            else:
                security_errors = [
                    error for error in security_errors
                    if error != "network:seatbelt_denied"]
                security_errors.append("network:not_enforced")
                security_errors.append("seatbelt:profile_unembeddable_path")

        status_read = status_write = None
        if resource is not None:
            status_read, status_write = os.pipe()
        argv = self._limit_argv(
            argv, limits, security_errors, cwd=workdir,
            status_fd=status_write)
        env = _minimal_env(record.path)
        env.update(spec.env)

        execution_id = "exec-" + secrets.token_hex(8)
        stdout_chunks = bytearray()
        stderr_chunks = bytearray()
        truncated = {"stdout": False, "stderr": False}
        start = time.monotonic()
        usage_before = (
            resource.getrusage(resource.RUSAGE_CHILDREN) if resource is not None else None
        )
        try:
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            # A neutral cwd: the launcher must not start inside the
            # untrusted workspace (see ``_limit_argv``).
            proc = subprocess.Popen(
                argv,
                cwd=(os.path.abspath(os.sep) if status_write is not None
                     else str(workdir)),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
                pass_fds=(*pass_fds,
                          *(() if status_write is None else (status_write,))),
            )
        except BaseException:
            if status_read is not None:
                os.close(status_read)
            raise
        finally:
            if status_write is not None:
                try:
                    os.close(status_write)
                except OSError:
                    pass
        proc._sis_supervised = status_write is not None
        with self._lock:
            self._live[execution_id] = proc
            self._live_ws[execution_id] = record.workspace_id
        if self._registry.is_closing(record.workspace_id):
            # Destruction began between the pre-launch check and the
            # registration above; never leave a process running against
            # a workspace that is about to be removed.
            self._kill_group(proc)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
            with self._lock:
                self._live.pop(execution_id, None)
                self._live_ws.pop(execution_id, None)
            for pipe in (proc.stdout, proc.stderr, proc.stdin):
                try:
                    if pipe is not None and not pipe.closed:
                        pipe.close()
                except OSError:
                    pass
            if status_read is not None:
                read_launcher_status(status_read)
            raise RunnerError("workspace_is_closing")

        stop = threading.Event()

        def pump(pipe, sink: bytearray, name: str) -> None:
            try:
                if os.name == "posix":
                    import select
                    fd = pipe.fileno()
                    while not stop.is_set():
                        ready, _, _ = select.select([fd], [], [], 0.1)
                        if not ready:
                            continue
                        chunk = os.read(fd, _READ_CHUNK)
                        if not chunk:
                            return
                        if len(sink) + len(chunk) > limits.output_bytes:
                            sink.extend(chunk[
                                : max(0, limits.output_bytes - len(sink))])
                            truncated[name] = True
                            self._kill_group(proc)
                            return
                        sink.extend(chunk)
                    return
                while not stop.is_set():
                    chunk = pipe.read(_READ_CHUNK)
                    if not chunk:
                        return
                    if len(sink) + len(chunk) > limits.output_bytes:
                        sink.extend(chunk[
                            : max(0, limits.output_bytes - len(sink))])
                        truncated[name] = True
                        self._kill_group(proc)
                        return
                    sink.extend(chunk)
            except (OSError, ValueError):
                return

        def feed() -> None:
            try:
                if spec.stdin:
                    for offset in range(0, len(spec.stdin), _READ_CHUNK):
                        if stop.is_set():
                            break
                        proc.stdin.write(
                            spec.stdin[offset:offset + _READ_CHUNK])
                        proc.stdin.flush()
                proc.stdin.close()
            except (OSError, ValueError):
                pass

        stdout_thread = threading.Thread(
            target=pump, args=(proc.stdout, stdout_chunks, "stdout"),
            daemon=True)
        stderr_thread = threading.Thread(
            target=pump, args=(proc.stderr, stderr_chunks, "stderr"),
            daemon=True)
        feed_thread = threading.Thread(target=feed, daemon=True)
        threads = [stdout_thread, stderr_thread, feed_thread]
        pumps = [(stdout_thread, proc.stdout), (stderr_thread, proc.stderr)]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            proc.wait(timeout=limits.wall_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill_group(proc)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        # Nothing the command started may outlive the run: the launcher
        # reaps descendants as a child subreaper where the platform allows
        # it, and the process group is killed even after a normal exit, so
        # a background child cannot keep running after the receipt.
        self._kill_group(proc)
        if status_read is not None:
            security_errors.extend(
                launcher_markers(read_launcher_status(status_read)))
            # RLIMIT_FSIZE bounds each file; the workspace total is only
            # audited after the run (``fs:disk_budget_exceeded``).
            security_errors.append("disk:per_file_limit_post_run_audit")
        # The parent's monotonic deadline is authoritative even when the
        # child exits on its own just after the limit. Without this check a
        # search that overruns the cooperative deadline by a few
        # milliseconds could still produce a passing receipt.
        process_wall = time.monotonic() - start
        if process_wall > limits.wall_seconds:
            timed_out = True
        capture_incomplete = False

        def close_pipe(pipe) -> None:
            try:
                if pipe is not None and not pipe.closed:
                    pipe.close()
            except OSError:
                pass

        try:
            if timed_out:
                # A killed group may leave a grandchild holding a pipe.
                # Signal the pumps to stop instead of closing a pipe from
                # this thread while a reader is blocked on it.
                stop.set()
                for thread in threads:
                    thread.join(timeout=0.5)
                    capture_incomplete = (
                        capture_incomplete or thread.is_alive())
            else:
                for thread in threads:
                    thread.join(timeout=10)
                    if thread.is_alive():
                        stop.set()
                        thread.join(timeout=0.5)
                        capture_incomplete = (
                            capture_incomplete or thread.is_alive())
            for thread, pipe in pumps:
                if not thread.is_alive():
                    close_pipe(pipe)
            if not feed_thread.is_alive():
                close_pipe(proc.stdin)
        finally:
            with self._lock:
                self._live.pop(execution_id, None)
                self._live_ws.pop(execution_id, None)
        if capture_incomplete:
            security_errors.append("output:capture_incomplete")

        after = scan_tree(record.path)
        if truncated["stdout"]:
            security_errors.append("output:stdout_truncated")
        if truncated["stderr"]:
            security_errors.append("output:stderr_truncated")
        if timed_out:
            security_errors.append("process:wall_clock_killed")
        if after.external_symlinks:
            security_errors.append("fs:external_symlink")
        if after.total_bytes > limits.disk_bytes:
            security_errors.append("fs:disk_budget_exceeded")

        usage: dict[str, int] = {
            "wall_seconds": max(0, int(round(process_wall))),
            "output_bytes": len(stdout_chunks) + len(stderr_chunks),
            "disk_bytes": after.total_bytes,
        }
        if usage_before is not None:
            usage_after = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu = (usage_after.ru_utime - usage_before.ru_utime) + (
                usage_after.ru_stime - usage_before.ru_stime
            )
            usage["cpu_seconds"] = max(0, int(round(cpu)))
            # ru_maxrss is the cumulative child high-water mark, not a delta.
            peak = max(0, int(usage_after.ru_maxrss))
            usage["memory_bytes"] = peak if sys.platform == "darwin" else peak * 1024
        cpu_killed = (
            not timed_out
            and proc.returncode is not None and proc.returncode < 0
            and usage.get("cpu_seconds", 0) >= limits.cpu_seconds)
        if (proc.returncode is not None and proc.returncode < 0
                and -proc.returncode == getattr(signal, "SIGXCPU", None)):
            security_errors.append("rlimit:cpu_exceeded")
        elif cpu_killed or usage.get("cpu_seconds", 0) > limits.cpu_seconds:
            # Linux sends SIGKILL at the hard RLIMIT_CPU limit when the
            # process ignores SIGXCPU. A kill at the CPU ceiling is a
            # resource limit, never a task failure.
            security_errors.append("rlimit:cpu_exceeded")

        with self._lock:
            self._outputs[execution_id] = (bytes(stdout_chunks), bytes(stderr_chunks))

        return ExecutionReceiptV1(
            schema_version=1,
            execution_id=execution_id,
            worker_identity=self.worker_identity,
            environment_digest=self._environment_digest(),
            before_tree_digest=before.digest,
            after_tree_digest=after.digest,
            command_spec_digest=command_spec_digest(spec),
            exit_status=proc.returncode if proc.returncode is not None else -1,
            stdout_digest=hashlib.sha256(bytes(stdout_chunks)).hexdigest() if stdout_chunks else None,
            stderr_digest=hashlib.sha256(bytes(stderr_chunks)).hexdigest() if stderr_chunks else None,
            resource_usage=usage,
            timeout=timed_out,
            security_errors=tuple(security_errors),
        )

    def output(self, execution_id: str) -> tuple[bytes, bytes]:
        """Return the bounded captured output retained for one execution."""
        with self._lock:
            if execution_id not in self._outputs:
                raise RunnerError("unknown execution_id")
            return self._outputs[execution_id]

    def destroy(self, workspace: Workspace) -> None:
        if not self._registry.destroy(
                workspace.workspace_id, workspace.path,
                executor_identity=workspace.executor_identity,
                terminate=self._terminate_workspace):
            raise RunnerError("workspace_remove_failed")

    def _terminate_workspace(self, workspace_id: str) -> None:
        with self._lock:
            targets = [
                proc for exec_id, proc in self._live.items()
                if self._live_ws.get(exec_id) == workspace_id
            ]
        for proc in targets:
            if proc.poll() is None:
                self._kill_group(proc)
        for proc in targets:
            if proc.poll() is None:
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass

    def terminate_all(self) -> None:
        with self._lock:
            procs = list(self._live.values())
            self._live.clear()
            self._live_ws.clear()
        for proc in procs:
            if proc.poll() is None:
                self._kill_group(proc)

    def _resolve_executable(self, name: str) -> str:
        if os.path.isabs(name):
            if not Path(name).exists():
                raise RunnerError("absolute argv[0] does not exist")
            return name
        found = shutil.which(name, path=os.pathsep.join([os.defpath, str(Path(sys.executable).resolve().parent)]))
        if found is None:
            raise RunnerError("argv[0] is not resolvable on the executor tool path")
        return found

    def _environment_digest(self) -> str:
        return canonical_digest("execution_environment", 1, {
            "implementation": "local-subprocess",
            "worker_identity": self.worker_identity,
            "platform": sys.platform,
            "python": platform.python_version(),
            "posix_rlimits": resource is not None,
            "seatbelt": bool(self._seatbelt),
            "protected_paths": len(self.protected_paths),
        })

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        """Stop a launched command and everything it started.

        A supervised launcher is asked first (SIGTERM to the launcher
        only): it kills the command and reaps every reparented
        descendant, including ones that left the group with ``setsid``.
        The process group is then killed by its id, which equals the
        leader's pid because every launch uses ``start_new_session``; this
        still reaches group members after the leader has been reaped.
        """
        if os.name != "posix":  # pragma: no cover - Windows fallback
            try:
                proc.kill()
            except OSError:
                pass
            return
        if getattr(proc, "_sis_supervised", False) and proc.poll() is None:
            try:
                os.kill(proc.pid, signal.SIGTERM)
                proc.wait(timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            if proc.poll() is None:
                try:
                    proc.kill()
                except OSError:
                    pass

    def _limit_argv(self, argv: list[str], limits: ResourceLimits,
                    security_errors: list[str], *, cwd: Path,
                    status_fd: int | None = None) -> list[str]:
        """Wrap ``argv`` in the evaluator-owned limit launcher.

        The launcher runs as ``python -I`` from a neutral working
        directory and only changes into ``cwd`` after the limits are set,
        so a workspace module (``resource.py``, ``signal.py``) can never be
        imported before the limits apply or outside the seatbelt wrapper.
        It fails closed: a limit it cannot set stops the run, and the
        status it writes to ``status_fd`` lets the receipt record what was
        actually applied (see :func:`launcher_markers`).
        """
        if resource is None:
            security_errors.append("rlimits:unavailable_platform")
            return argv
        return limit_launcher_argv(
            argv, limit_triples(limits, security_errors), cwd=cwd,
            status_fd=status_fd, supervise=True)

    @staticmethod
    def _reject_symlinks(base: Path) -> None:
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for name in list(dirnames) + filenames:
                if (Path(dirpath) / name).is_symlink():
                    raise RunnerError("base tree must not contain symlinks")
