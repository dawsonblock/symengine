"""Linux rootless containment worker scaffold (SIS v3.3.4, Phase 2.4).

This is a containment *backend* for the production isolation boundary,
not a qualified deployment by itself. It runs on Linux only, inside a
bubblewrap user namespace with no network, a private PID namespace, a
read-only system tree, and exactly one writable workspace bind. The
parent applies address-space, CPU, file-size, descriptor and process
limits, enforces a wall-clock deadline, and kills the whole process
group on timeout.

The worker never holds evaluator signing keys, never mounts the
evaluator registry, and only sees the workspace the evaluator prepared.
It emits a factual ``ExecutionReceiptV1``; containment is attested
separately by an isolator that signs the properties this backend
actually enforced. No receipt can qualify itself.

Run ``tools/linux_worker_probe.py`` on the target Linux host to test the
platform's namespaces, network denial, filesystem confinement, fork and
memory limits, wall-clock kill, and process-group termination. That
probe is the evidence for choosing a backend; this module is the
mechanism.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import resource
except ImportError:  # Windows: the backend is unavailable, not import-broken
    resource = None

from .contracts import ContractError, ExecutionReceiptV1, canonical_digest
from .runner import (
    CommandSpec,
    ResourceLimits,
    RunnerError,
    Workspace,
    command_spec_digest,
    scan_tree,
)

_DEFAULT_SYSTEM_BINDS = (
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc",
)
_DEFAULT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/workspace",
    "TMPDIR": "/tmp",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TZ": "UTC",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
    "PYTHONHASHSEED": "0",
}


class WorkerBackendUnavailable(RuntimeError):
    """The platform cannot provide this containment backend."""


@dataclass(frozen=True)
class LinuxWorkerConfig:
    """Containment facts the isolator will attest.

    ``share_network`` is an explicit opt-in and must never be used for
    hostile code. ``system_binds`` should be minimized for the image the
    worker actually runs; the defaults are a usable scaffold, not a
    hardened image definition.
    """

    worker_identity: str = "linux-rootless-bwrap"
    bwrap: str = "bwrap"
    system_binds: tuple[str, ...] = _DEFAULT_SYSTEM_BINDS
    environment: tuple[tuple[str, str], ...] = ()
    share_network: bool = False
    use_pid_namespace: bool = True
    die_with_parent: bool = True
    max_output_bytes: int = 1 << 20

    def __post_init__(self) -> None:
        if (not isinstance(self.worker_identity, str)
                or not self.worker_identity
                or len(self.worker_identity) > 128):
            raise ContractError("worker_identity must be 1-128 characters")
        if not isinstance(self.bwrap, str) or not self.bwrap:
            raise ContractError("bwrap must be a nonempty path or name")
        if not isinstance(self.system_binds, tuple) or not all(
                isinstance(path, str) and path.startswith("/")
                for path in self.system_binds):
            raise ContractError("system_binds must be absolute paths")
        if not isinstance(self.environment, tuple) or not all(
                isinstance(item, tuple) and len(item) == 2
                and isinstance(item[0], str) and isinstance(item[1], str)
                for item in self.environment):
            raise ContractError("environment must be (name, value) pairs")
        for flag in ("share_network", "use_pid_namespace", "die_with_parent"):
            if type(getattr(self, flag)) is not bool:
                raise ContractError(f"{flag} must be boolean")
        if (type(self.max_output_bytes) is not int
                or not 1 <= self.max_output_bytes <= (1 << 30)):
            raise ContractError("max_output_bytes must be in [1,1 GiB]")

    @property
    def digest(self) -> str:
        return canonical_digest("linux_worker_config", 1, {
            "worker_identity": self.worker_identity,
            "system_binds": sorted(self.system_binds),
            "environment": sorted(self.environment),
            "share_network": self.share_network,
            "use_pid_namespace": self.use_pid_namespace,
            "die_with_parent": self.die_with_parent,
        })


def build_bwrap_argv(config: LinuxWorkerConfig, workspace_path: Path,
                     spec: CommandSpec) -> list[str]:
    """Build the exact bubblewrap invocation; no shell, no host env."""
    if not isinstance(config, LinuxWorkerConfig):
        raise ContractError("config must be a LinuxWorkerConfig")
    if not isinstance(spec, CommandSpec):
        raise ContractError("spec must be a CommandSpec")
    argv = [config.bwrap]
    if config.die_with_parent:
        argv.append("--die-with-parent")
    argv.append("--new-session")
    # --unshare-all covers user, PID, network, IPC, UTS and cgroup.
    argv.append("--unshare-all")
    if config.share_network:
        argv.append("--share-net")
    for path in config.system_binds:
        source = Path(path)
        if source.exists():
            argv += ["--ro-bind", str(source.resolve()), path]
    argv += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    argv += ["--bind", str(Path(workspace_path).resolve()), "/workspace"]
    argv += ["--chdir", "/workspace"]
    argv.append("--clearenv")
    environment = dict(_DEFAULT_ENV)
    environment.update(dict(config.environment))
    environment.update(dict(spec.env))
    for name, value in sorted(environment.items()):
        argv += ["--setenv", name, value]
    argv.append("--")
    argv.extend(spec.argv)
    return argv


def _apply_limits(limits: ResourceLimits):
    """preexec hook: bound the child before exec (same model as runner)."""
    if resource is None:
        raise WorkerBackendUnavailable("resource_limits_unavailable")

    def apply() -> None:
        resource.setrlimit(
            resource.RLIMIT_AS, (limits.memory_bytes, limits.memory_bytes))
        resource.setrlimit(
            resource.RLIMIT_CPU, (limits.cpu_seconds, limits.cpu_seconds + 1))
        resource.setrlimit(
            resource.RLIMIT_FSIZE, (limits.disk_bytes, limits.disk_bytes))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if limits.process_count is not None:
            resource.setrlimit(
                resource.RLIMIT_NPROC,
                (limits.process_count, limits.process_count))
    return apply


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _read_capped(path: Path, limit: int) -> tuple[bytes, bool]:
    with open(path, "rb") as handle:
        data = handle.read(limit + 1)
    return data[:limit], len(data) > limit


class LinuxRootlessWorker:
    """Bubblewrap-based rootless worker; Linux only, fails closed elsewhere."""

    def __init__(self, root: str | Path, *,
                 config: LinuxWorkerConfig | None = None) -> None:
        if not sys.platform.startswith("linux"):
            raise WorkerBackendUnavailable("linux_required")
        self.config = config or LinuxWorkerConfig()
        self._bwrap = shutil.which(self.config.bwrap)
        if self._bwrap is None:
            raise WorkerBackendUnavailable("bwrap_required")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "workspaces").mkdir(exist_ok=True)
        self._workspaces: dict[str, Workspace] = {}
        self._live: dict[str, subprocess.Popen] = {}
        self._outputs: dict[str, tuple[bytes, bytes]] = {}
        self._lock = threading.Lock()

    @property
    def worker_identity(self) -> str:
        return self.config.worker_identity

    def prepare(self, base_dir: str | Path, *, label: str = "task") -> Workspace:
        base = Path(base_dir)
        if not base.is_dir():
            raise RunnerError("base_dir must be an existing directory")
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            for name in list(dirnames) + filenames:
                if (Path(dirpath) / name).is_symlink():
                    raise RunnerError("base tree must not contain symlinks")
        workspace_id = "ws-" + secrets.token_hex(8)
        path = self.root / "workspaces" / workspace_id
        shutil.copytree(base, path, symlinks=False)
        scan = scan_tree(path)
        workspace = Workspace(
            workspace_id, path, scan.digest, self.worker_identity)
        with self._lock:
            self._workspaces[workspace_id] = workspace
        return workspace

    def run(self, workspace: Workspace, spec: CommandSpec) -> ExecutionReceiptV1:
        if not isinstance(spec, CommandSpec):
            raise ContractError("spec must be a CommandSpec")
        before = scan_tree(workspace.path)
        if before.external_symlinks:
            raise RunnerError("workspace contains external symlinks")
        execution_id = "exec-" + secrets.token_hex(8)
        argv = build_bwrap_argv(self.config, workspace.path, spec)
        security_errors = ["backend:linux-rootless-bwrap"]
        if self.config.share_network:
            security_errors.append("net:shared_by_configuration")
        else:
            security_errors.append("net:denied")
        if self.config.use_pid_namespace:
            security_errors.append("proc:namespaced")
        security_errors.append("fs:workspace_confined")

        with tempfile.TemporaryDirectory(
                dir=self.root, prefix=".worker-") as temp:
            stdout_path = Path(temp) / "stdout"
            stderr_path = Path(temp) / "stderr"
            started = time.monotonic()
            timed_out = False
            exit_status = -1
            with open(stdout_path, "wb") as out, open(stderr_path, "wb") as err:
                try:
                    process = subprocess.Popen(
                        argv,
                        stdin=subprocess.PIPE,
                        stdout=out,
                        stderr=err,
                        start_new_session=True,
                        preexec_fn=_apply_limits(spec.limits),
                        env={},
                    )
                except OSError as exc:
                    raise RunnerError("worker_launch_failed") from exc
                with self._lock:
                    self._live[execution_id] = process
                try:
                    process.communicate(
                        input=spec.stdin, timeout=spec.limits.wall_seconds)
                    exit_status = process.returncode
                except subprocess.TimeoutExpired:
                    timed_out = True
                    security_errors.append("process:wall_clock_killed")
                    _kill_group(process)
                    process.wait()
                finally:
                    _kill_group(process)
                    with self._lock:
                        self._live.pop(execution_id, None)
            elapsed = time.monotonic() - started
            output_cap = min(
                self.config.max_output_bytes, spec.limits.output_bytes)
            stdout, stdout_cut = _read_capped(stdout_path, output_cap)
            stderr, stderr_cut = _read_capped(stderr_path, output_cap)
            if stdout_cut:
                security_errors.append("output:stdout_truncated")
            if stderr_cut:
                security_errors.append("output:stderr_truncated")

        after = scan_tree(workspace.path)
        if after.external_symlinks:
            security_errors.append("fs:external_symlink")
        if after.total_bytes > spec.limits.disk_bytes:
            security_errors.append("fs:disk_budget_exceeded")
        if timed_out:
            exit_status = -1

        with self._lock:
            self._outputs[execution_id] = (stdout, stderr)
        return ExecutionReceiptV1(
            schema_version=1,
            execution_id=execution_id,
            worker_identity=self.worker_identity,
            environment_digest=self.config.digest,
            before_tree_digest=before.digest,
            after_tree_digest=after.digest,
            command_spec_digest=command_spec_digest(spec),
            exit_status=exit_status,
            stdout_digest=hashlib.sha256(stdout).hexdigest(),
            stderr_digest=hashlib.sha256(stderr).hexdigest(),
            resource_usage={"wall_seconds": int(elapsed)},
            timeout=timed_out,
            security_errors=tuple(security_errors),
        )

    def output(self, execution_id: str) -> tuple[bytes, bytes]:
        with self._lock:
            return self._outputs.get(execution_id, (b"", b""))

    def destroy(self, workspace: Workspace) -> None:
        shutil.rmtree(workspace.path, ignore_errors=True)
        with self._lock:
            self._workspaces.pop(workspace.workspace_id, None)

    def terminate_all(self) -> None:
        with self._lock:
            live = list(self._live.values())
        for process in live:
            _kill_group(process)


__all__ = [
    "LinuxRootlessWorker",
    "LinuxWorkerConfig",
    "WorkerBackendUnavailable",
    "build_bwrap_argv",
]
