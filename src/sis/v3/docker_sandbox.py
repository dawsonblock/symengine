"""Docker-backed workspace executor for untrusted evaluation code.

The evaluator runs submitted code and private acceptance tests inside a
container with no network, a read-only root filesystem, a
quota-limited tmpfs workspace, a tmpfs ``/tmp``, a non-root user, all
capabilities dropped, ``no-new-privileges``, and explicit memory, pid,
CPU-time, disk and wall-clock bounds.

The workspace is copied into the container's tmpfs before the command
runs and copied back afterwards, so ``disk_bytes`` is enforced by the
filesystem during execution rather than audited after it. The copy-out
archive is filtered: absolute paths, ``..`` escapes, device nodes and
links that leave the workspace are rejected.

This backend reports factual container controls on every receipt. It is
not a signed isolation attestation: production qualification still
requires an ``IsolationAttestationV1`` from a separately trusted
isolator. A receipt carrying ``isolation:docker_sandbox`` is a claim about
how the command was launched, not a proof that the kernel enforced it.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from pathlib import Path

from .contracts import ContractError, ExecutionReceiptV1, canonical_digest
from .runner import (CommandSpec, ResourceLimits, RunnerError, Workspace,
                     command_spec_digest, scan_tree)
from .workspace_guard import ManagedWorkspaceRegistry, protected_overlap

_IMAGE_DIGEST = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_USER = re.compile(r"^([0-9]{1,10})(?::([0-9]{1,10}))?$")
_READ_CHUNK = 65_536
_COPY_OUT_SECONDS = 300.0


def _error_tail(handle, limit: int = 4_096) -> str:
    """Return a bounded diagnostic tail from a drained stderr file."""
    try:
        handle.seek(0)
        return handle.read(limit).decode("utf-8", "replace").strip()[:200]
    except (OSError, ValueError):
        return ""


def _default_user() -> str:
    """A non-root container identity, even when the host runs as root."""
    if os.name == "posix":
        uid, gid = os.getuid(), os.getgid()
        if uid != 0 and gid != 0:
            return f"{uid}:{gid}"
    return "65534:65534"


def _parse_user(value: str) -> tuple[int, int]:
    """Return ``(uid, gid)`` and refuse any root container identity."""
    match = _USER.fullmatch(value or "")
    if match is None:
        raise ContractError("container user must be numeric uid[:gid]")
    uid = int(match.group(1))
    gid = int(match.group(2)) if match.group(2) is not None else uid
    if uid == 0 or gid == 0:
        raise ContractError("container user must not be root")
    return uid, gid


def _reject_symlinks(root: Path) -> None:
    for path in root.rglob("*"):
        if path.is_symlink():
            raise RunnerError("workspace symlinks are not allowed")


class DockerSandboxExecutor:
    """Run evaluator commands in a bounded Docker container."""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        image: str,
        worker_identity: str = "docker-sandbox-v1",
        docker_binary: str = "docker",
        production: bool = False,
        require_image_digest: bool = True,
        memory_bytes: int = 2 * 1024 * 1024 * 1024,
        pids_limit: int = 128,
        cpus: float = 1.0,
        output_bytes: int = 1_048_576,
        tmpfs_bytes: int = 64 * 1024 * 1024,
        nofile_limit: int = 1024,
        user: str | None = None,
        image_id: str | None = None,
    ) -> None:
        if not isinstance(image, str) or not image:
            raise ContractError("image must be a non-empty string")
        if require_image_digest or production:
            if not _IMAGE_DIGEST.fullmatch(image):
                raise ContractError(
                    "image must be digest-pinned (name@sha256:...) for "
                    "production or when require_image_digest is set")
        for name, value, maximum in (
            ("memory_bytes", memory_bytes, 1 << 40),
            ("pids_limit", pids_limit, 65_535),
            ("output_bytes", output_bytes, 1 << 30),
            ("tmpfs_bytes", tmpfs_bytes, 1 << 30),
            ("nofile_limit", nofile_limit, 1 << 20),
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ContractError(f"{name} must be an integer in [1,{maximum}]")
        if not isinstance(cpus, (int, float)) or not 0 < float(cpus) <= 64:
            raise ContractError("cpus must be in (0,64]")
        self._user = user or _default_user()
        self._uid, self._gid = _parse_user(self._user)
        self.root = Path(os.path.abspath(
            root if root is not None
            else tempfile.mkdtemp(prefix="sis-v3-docker-")))
        self.root.mkdir(parents=True, exist_ok=True)
        self._registry = ManagedWorkspaceRegistry(
            self.root, executor_identity=worker_identity, error=RunnerError)
        self._image = image
        self._image_id = image_id
        self.worker_identity = worker_identity
        self._docker = docker_binary
        self._production = bool(production)
        self._memory = memory_bytes
        self._pids = pids_limit
        self._cpus = float(cpus)
        self._output_bytes = output_bytes
        self._tmpfs = tmpfs_bytes
        self._nofile = nofile_limit
        self._live: dict[str, str] = {}
        self._live_ws: dict[str, str] = {}
        self._outputs: dict[str, tuple[bytes, bytes]] = {}
        self._protected: set[Path] = set()
        self._lock = threading.Lock()
        self._server_version = self._require_docker()

    # ---- lifecycle ------------------------------------------------------ #
    def protect(self, path: str | Path) -> None:
        """Record a host path that must never be mounted into a container."""
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
    def network_isolation(self) -> str:
        return "docker_none"

    @property
    def server_version(self) -> str:
        return self._server_version

    def prepare(self, base_dir: str | Path, *, label: str = "task") -> Workspace:
        base = Path(base_dir)
        if not base.is_dir():
            raise RunnerError("base_dir must be an existing directory")
        if base.resolve().is_relative_to(self.root.resolve()):
            raise RunnerError("base_dir must not live inside the executor root")
        if protected_overlap(base, self.protected_paths) is not None:
            raise RunnerError("base_dir_overlaps_protected_material")
        _reject_symlinks(base)
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

    def run(self, workspace: Workspace, spec: CommandSpec) -> ExecutionReceiptV1:
        if not isinstance(spec, CommandSpec):
            raise ContractError("spec must be a CommandSpec")
        with self._registry.execution(
                workspace.workspace_id, workspace.path,
                executor_identity=workspace.executor_identity) as record:
            return self._run_workspace(record, spec)

    def _run_workspace(
        self, record, spec: CommandSpec,
    ) -> ExecutionReceiptV1:
        before = scan_tree(record.path)
        if before.external_symlinks:
            raise RunnerError("workspace contains external symlinks")
        if not (record.path / spec.cwd).is_dir():
            raise RunnerError("command cwd escapes or is absent from the workspace")
        argv = self._container_argv(spec)
        execution_id = "exec-" + secrets.token_hex(8)
        container = "sis-exec-" + secrets.token_hex(8)
        limits = spec.limits
        memory = min(self._memory, limits.memory_bytes)
        pids = (self._pids if limits.process_count is None
                else min(self._pids, limits.process_count))
        output_cap = min(self._output_bytes, limits.output_bytes)
        disk = limits.disk_bytes
        workdir = ("/workspace" if spec.cwd == "."
                   else "/workspace/" + spec.cwd)

        security_errors = [
            "isolation:docker_sandbox",
            "docker:network_none",
            "docker:read_only_root",
            "docker:cap_drop_all",
            "docker:no_new_privileges",
            "docker:tmpfs_workspace",
            f"docker:user:{self._user}",
            f"docker:memory_bytes:{memory}",
            f"docker:pids_limit:{pids}",
            f"docker:disk_bytes:{disk}",
            f"docker:ulimit_cpu:{limits.cpu_seconds}",
            f"docker:ulimit_nofile:{self._nofile}",
            f"docker:output_bytes:{output_cap}",
        ]
        if not _IMAGE_DIGEST.fullmatch(self._image):
            security_errors.append("docker:image_tag_only")

        stdout_chunks = bytearray()
        stderr_chunks = bytearray()
        truncated = {"stdout": False, "stderr": False}
        captured = {"total": 0}
        capture_lock = threading.Lock()
        start = time.monotonic()
        timed_out = False
        exit_status = -1
        try:
            self._start_container(
                container, record, spec, limits, memory, pids, disk)
            with self._lock:
                self._live[execution_id] = container
                self._live_ws[execution_id] = record.workspace_id
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            self._copy_in(container)
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            proc = self._exec_command(container, argv, spec, workdir)

            def pump(pipe, sink: bytearray, name: str) -> None:
                try:
                    while True:
                        chunk = pipe.read(_READ_CHUNK)
                        if not chunk:
                            return
                        with capture_lock:
                            remaining = output_cap - captured["total"]
                            if remaining <= 0:
                                truncated[name] = True
                                over = True
                            else:
                                take = chunk[:remaining]
                                sink.extend(take)
                                captured["total"] += len(take)
                                over = len(take) < len(chunk)
                                if over:
                                    truncated[name] = True
                        if over:
                            self._kill(container)
                            pipe.read()  # drain so the client cannot linger
                            return
                except (OSError, ValueError):
                    return

            def feed() -> None:
                try:
                    if spec.stdin:
                        proc.stdin.write(spec.stdin)
                    proc.stdin.close()
                except (OSError, ValueError):
                    pass

            threads = [
                threading.Thread(target=pump, args=(proc.stdout, stdout_chunks, "stdout"),
                                 daemon=True),
                threading.Thread(target=pump, args=(proc.stderr, stderr_chunks, "stderr"),
                                 daemon=True),
                threading.Thread(target=feed, daemon=True),
            ]
            for thread in threads:
                thread.start()
            try:
                proc.wait(timeout=limits.wall_seconds)
                exit_status = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(container)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                for thread in threads:
                    thread.join(timeout=10)
                for pipe in (proc.stdout, proc.stderr, proc.stdin):
                    try:
                        if pipe is not None and not pipe.closed:
                            pipe.close()
                    except OSError:
                        pass
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            if timed_out or truncated["stdout"] or truncated["stderr"]:
                # Stopping the container destroys its tmpfs. There is no
                # workspace state left to collect, and the receipt must
                # say so rather than report the pre-run tree as final.
                security_errors.append("fs:workspace_state_unavailable")
            else:
                try:
                    self._copy_out(container, record)
                except RunnerError:
                    if exit_status == 0:
                        raise
                    # A resource-exhausted command may leave no cgroup
                    # slot for the copy-out process. The run is still
                    # classifiable as a resource limit, never a pass.
                    security_errors.append("fs:workspace_state_unavailable")
        finally:
            with self._lock:
                self._live.pop(execution_id, None)
                self._live_ws.pop(execution_id, None)
            self._remove_container(container)
        wall = time.monotonic() - start

        after = scan_tree(record.path)
        if truncated["stdout"]:
            security_errors.append("output:stdout_truncated")
        if truncated["stderr"]:
            security_errors.append("output:stderr_truncated")
        if timed_out:
            security_errors.append("process:wall_clock_killed")
        if after.external_symlinks:
            security_errors.append("fs:external_symlink")
        if after.total_bytes > disk:
            security_errors.append("fs:disk_budget_exceeded")

        with self._lock:
            self._outputs[execution_id] = (bytes(stdout_chunks), bytes(stderr_chunks))
        return ExecutionReceiptV1(
            schema_version=1,
            execution_id=execution_id,
            worker_identity=self.worker_identity,
            environment_digest=canonical_digest("docker_environment", 2, {
                "image": self._image,
                "image_id": self.image_id(),
                "user": self._user,
                "network": "none",
                "read_only_root": True,
                "cap_drop": "ALL",
                "no_new_privileges": True,
                "workspace_fs": "tmpfs",
                "memory_bytes": memory,
                "pids_limit": pids,
                "disk_bytes": disk,
                "cpu_seconds": limits.cpu_seconds,
                "output_bytes": output_cap,
                "nofile_limit": self._nofile,
                "cpus": f"{self._cpus:g}",
            }),
            before_tree_digest=before.digest,
            after_tree_digest=after.digest,
            command_spec_digest=command_spec_digest(spec),
            exit_status=exit_status if exit_status is not None else -1,
            stdout_digest=(hashlib.sha256(bytes(stdout_chunks)).hexdigest()
                           if stdout_chunks else None),
            stderr_digest=(hashlib.sha256(bytes(stderr_chunks)).hexdigest()
                           if stderr_chunks else None),
            resource_usage={
                "wall_seconds": max(0, int(round(wall))),
                "output_bytes": len(stdout_chunks) + len(stderr_chunks),
                "disk_bytes": after.total_bytes,
            },
            timeout=timed_out,
            security_errors=tuple(security_errors),
        )

    def output(self, execution_id: str) -> tuple[bytes, bytes]:
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
            containers = [
                name for exec_id, name in self._live.items()
                if self._live_ws.get(exec_id) == workspace_id
            ]
        for container in containers:
            self._kill(container)

    def terminate_all(self) -> None:
        with self._lock:
            containers = list(self._live.values())
            self._live.clear()
            self._live_ws.clear()
        for container in containers:
            self._kill(container)

    # ---- container lifecycle -------------------------------------------- #
    def _start_container(
        self, container: str, record, spec: CommandSpec,
        limits: ResourceLimits, memory: int, pids: int, disk: int,
    ) -> None:
        command = [
            self._docker, "run", "-d", "--name", container,
            "--network", "none",
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={self._tmpfs}",
            "--tmpfs",
            (f"/workspace:rw,nosuid,nodev,size={disk},"
             f"uid={self._uid},gid={self._gid},mode=0770"),
            "--user", self._user,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", str(memory),
            "--memory-swap", str(memory),
            "--pids-limit", str(pids),
            "--cpus", str(self._cpus),
            # RLIMIT_CPU is inherited by the exec'd command, so CPU time
            # is a kernel-enforced budget, not only a scheduling share.
            "--ulimit", f"cpu={limits.cpu_seconds}",
            "--ulimit", f"nofile={self._nofile}:{self._nofile}",
            "--ipc", "none",
            "--mount",
            f"type=bind,source={record.real_path},target=/submission,readonly",
            "--workdir", "/workspace",
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
        ]
        for key, value in spec.env.items():
            command.extend(("-e", f"{key}={value}"))
        command.extend((
            "--entrypoint", "python3", self._image,
            "-c", "import time; time.sleep(86400)",
        ))
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(f"docker_start_failed:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError(
                "docker_start_failed:"
                + (result.stderr or result.stdout).strip()[:200])

    def _copy_in(self, container: str) -> None:
        """Populate the quota-limited workspace from the read-only bind."""
        try:
            result = subprocess.run(
                [self._docker, "exec", "--user", self._user, container,
                 "sh", "-c", "cp -R /submission/. /workspace/"],
                capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(f"workspace_copy_in_failed:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError(
                "workspace_copy_in_failed:"
                + (result.stderr or result.stdout).strip()[:200])

    def _exec_command(
        self, container: str, argv: list[str], spec: CommandSpec,
        workdir: str,
    ) -> subprocess.Popen:
        command = [
            self._docker, "exec", "-i",
            "--user", self._user,
            "--workdir", workdir,
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
        ]
        for key, value in spec.env.items():
            command.extend(("-e", f"{key}={value}"))
        command.append(container)
        command.extend(argv)
        try:
            return subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            raise RunnerError(f"docker_unavailable:{exc}") from exc

    def _copy_out(self, container: str, record) -> None:
        """Copy the tmpfs workspace back through a filtered tar stream."""
        if not self._container_running(container):
            # A stopped container has already lost its tmpfs; restarting
            # would copy an empty tree over the real workspace.
            raise RunnerError(
                "workspace_copy_out_failed:container_stopped")
        staging = Path(tempfile.mkdtemp(dir=self.root, prefix=".staging-"))
        # stderr goes to a file, never a pipe. A tar that reports one
        # error per unreadable entry writes far more than one pipe
        # buffer, and a pipe the parent is not draining blocks the child
        # before it finishes writing the archive.
        errors = tempfile.TemporaryFile()
        watchdog = None
        try:
            try:
                proc = subprocess.Popen(
                    [self._docker, "exec", "--user", self._user, container,
                     "tar", "-C", "/workspace", "-cf", "-", "."],
                    stdout=subprocess.PIPE,
                    stderr=errors,
                    start_new_session=(os.name == "posix"),
                )
            except OSError as exc:
                raise RunnerError(
                    f"workspace_copy_out_failed:{exc}") from exc
            watchdog = threading.Timer(_COPY_OUT_SECONDS, proc.kill)
            watchdog.daemon = True
            watchdog.start()
            try:
                with tarfile.open(fileobj=proc.stdout, mode="r|") as archive:
                    try:
                        archive.extractall(path=staging, filter="data")
                    except TypeError as exc:
                        raise RunnerError(
                            "workspace_copy_out_failed:"
                            "safe_extraction_unavailable") from exc
            except (tarfile.TarError, OSError) as exc:
                proc.kill()
                raise RunnerError(
                    f"workspace_copy_out_failed:{type(exc).__name__}") from exc
            finally:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
                try:
                    returncode = proc.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    returncode = -1
            if returncode != 0:
                raise RunnerError(
                    "workspace_copy_out_failed:" + _error_tail(errors))
            shutil.rmtree(record.path, ignore_errors=True)
            try:
                os.rename(staging, record.path)
            except OSError as exc:
                raise RunnerError(
                    f"workspace_copy_out_failed:{exc}") from exc
            staging = None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            errors.close()
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)

    def _container_running(self, container: str) -> bool:
        try:
            result = subprocess.run(
                [self._docker, "inspect", "--format",
                 "{{.State.Running}}", container],
                capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0 and result.stdout.strip() == "true"

    def _remove_container(self, container: str) -> None:
        try:
            subprocess.run([self._docker, "rm", "-f", container],
                           capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            pass

    # ---- image and probe ------------------------------------------------ #
    def image_id(self) -> str:
        if self._image_id:
            return self._image_id
        result = subprocess.run(
            [self._docker, "image", "inspect", "--format", "{{.Id}}", self._image],
            capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            raise RunnerError("docker_image_inspect_failed:" +
                              result.stderr.strip()[:200])
        self._image_id = result.stdout.strip().removeprefix("sha256:")
        return self._image_id

    def probe(self) -> dict:
        """Run factual containment checks and return their observations."""
        temp = Path(tempfile.mkdtemp(prefix="sis-docker-probe-"))
        checks: list[dict] = []
        try:
            (temp / "seed.txt").write_text("seed")

            def check(name, argv, *, expect_success, limits=None):
                workspace = self.prepare(temp, label=name)
                try:
                    spec = CommandSpec(
                        argv=tuple(argv), limits=limits or ResourceLimits())
                    receipt = self.run(workspace, spec)
                    stdout, stderr = self.output(receipt.execution_id)
                finally:
                    self.destroy(workspace)
                observed = receipt.exit_status == 0
                checks.append({
                    "name": name,
                    "expected": "success" if expect_success else "failure",
                    "exit_status": receipt.exit_status,
                    "ok": observed == expect_success,
                    "stdout": stdout.decode("utf-8", "replace")[:200],
                    "stderr": stderr.decode("utf-8", "replace")[:200],
                })

            check("network_denied", (
                "python3", "-c",
                "import socket; socket.create_connection(('1.1.1.1', 53), 2)"),
                expect_success=False)
            check("root_write_denied", (
                "python3", "-c", "open('/probe-escape', 'w')"),
                expect_success=False)
            check("workspace_write_allowed", (
                "python3", "-c",
                "open('/workspace/probe.txt', 'w').write('ok')"),
                expect_success=True)
            check("non_root_user", (
                "python3", "-c",
                "import os,sys; sys.exit(0 if os.getuid() != 0 else 1)"),
                expect_success=True)
            small = ResourceLimits(
                memory_bytes=128 * 1024 * 1024,
                wall_seconds=30, output_bytes=65_536,
                disk_bytes=16 * 1024 * 1024, process_count=32)
            check("memory_limit_enforced", (
                "python3", "-c", "bytearray(512 * 1024 * 1024)"),
                expect_success=False, limits=small)
            pids = ResourceLimits(
                memory_bytes=256 * 1024 * 1024,
                wall_seconds=30, output_bytes=65_536,
                disk_bytes=16 * 1024 * 1024, process_count=16)
            check("pids_limit_enforced", (
                "python3", "-c",
                "import subprocess; [subprocess.Popen("
                "['python3', '-c', 'pass']) for _ in range(64)]"),
                expect_success=False, limits=pids)
            disk = ResourceLimits(
                memory_bytes=256 * 1024 * 1024,
                wall_seconds=30, output_bytes=65_536,
                disk_bytes=8 * 1024 * 1024, process_count=32)
            check("disk_limit_enforced", (
                "python3", "-c",
                "open('/workspace/big.bin', 'wb').write("
                "b'x' * (32 * 1024 * 1024))"),
                expect_success=False, limits=disk)
            cpu = ResourceLimits(
                cpu_seconds=1, memory_bytes=256 * 1024 * 1024,
                wall_seconds=30, output_bytes=65_536,
                disk_bytes=8 * 1024 * 1024, process_count=32)
            check("cpu_time_enforced", (
                "python3", "-c", "while True: pass"),
                expect_success=False, limits=cpu)

            workspace = self.prepare(temp, label="output_limit")
            try:
                receipt = self.run(workspace, CommandSpec(
                    argv=("python3", "-c",
                          "import sys; "
                          "sys.stdout.write('o' * 200000); "
                          "sys.stderr.write('e' * 200000)"),
                    limits=ResourceLimits(
                        memory_bytes=256 * 1024 * 1024,
                        wall_seconds=30, output_bytes=65_536,
                        disk_bytes=16 * 1024 * 1024, process_count=32)))
                stdout, stderr = self.output(receipt.execution_id)
            finally:
                self.destroy(workspace)
            retained = len(stdout) + len(stderr)
            checks.append({
                "name": "output_limit_enforced",
                "expected": "<=65536",
                "retained_bytes": retained,
                "ok": retained <= 65_536,
            })
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        return {
            "ok": all(item["ok"] for item in checks),
            "image": self._image,
            "image_id": self.image_id(),
            "docker_server_version": self._server_version,
            "worker_identity": self.worker_identity,
            "checks": checks,
        }

    # ---- internals ------------------------------------------------------ #
    def _require_docker(self) -> str:
        try:
            result = subprocess.run(
                [self._docker, "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(f"docker_unavailable:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError("docker_unavailable:" +
                              (result.stderr or result.stdout).strip()[:200])
        return result.stdout.strip()

    def _container_argv(self, spec: CommandSpec) -> list[str]:
        argv = list(spec.argv)
        if argv and self._is_host_interpreter(argv[0]):
            argv[0] = "python3"
        return argv

    @staticmethod
    def _is_host_interpreter(value: str) -> bool:
        if value == sys.executable:
            return True
        name = Path(value).name
        return bool(re.fullmatch(r"python(\d+(\.\d+)?)?", name)) and (
            value.startswith("/") or os.sep not in value)

    def _kill(self, container: str) -> None:
        try:
            subprocess.run([self._docker, "kill", container],
                           capture_output=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired):
            pass
