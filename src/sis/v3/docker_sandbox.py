"""Docker-backed workspace executor for untrusted evaluation code.

The evaluator runs submitted code and private acceptance tests inside a
container with no network, a read-only root filesystem, a writable
workspace bind mount, a tmpfs ``/tmp``, a non-root user, all capabilities
dropped, ``no-new-privileges``, and explicit memory, pid and CPU bounds.

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
import tempfile
import threading
import time
from pathlib import Path

from .contracts import ContractError, ExecutionReceiptV1, canonical_digest
from .runner import (CommandSpec, ResourceLimits, RunnerError, Workspace,
                     command_spec_digest, scan_tree)

_IMAGE_DIGEST = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_READ_CHUNK = 65_536


def _host_user() -> str:
    if os.name == "posix":
        return f"{os.getuid()}:{os.getgid()}"
    return "65534:65534"


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
        ):
            if type(value) is not int or not 1 <= value <= maximum:
                raise ContractError(f"{name} must be an integer in [1,{maximum}]")
        if not isinstance(cpus, (int, float)) or not 0 < float(cpus) <= 64:
            raise ContractError("cpus must be in (0,64]")
        self.root = (Path(root) if root is not None
                     else Path(tempfile.mkdtemp(prefix="sis-v3-docker-")))
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "workspaces").mkdir(exist_ok=True)
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
        self._user = user or _host_user()
        self._workspaces: dict[str, Workspace] = {}
        self._live: dict[str, str] = {}
        self._outputs: dict[str, tuple[bytes, bytes]] = {}
        self._protected: set[Path] = set()
        self._lock = threading.Lock()
        self._server_version = self._require_docker()

    # ---- lifecycle ------------------------------------------------------ #
    def protect(self, path: str | Path) -> None:
        """Record a host path that must never be mounted into a container."""
        resolved = Path(path).resolve()
        if resolved.is_relative_to(self.root.resolve()):
            raise RunnerError("protected path must not live inside the executor root")
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
        workspace_id = "ws-" + secrets.token_hex(8)
        path = self.root / "workspaces" / workspace_id
        _reject_symlinks(base)
        shutil.copytree(base, path, symlinks=False)
        scan = scan_tree(path)
        workspace = Workspace(workspace_id, path, scan.digest, self.worker_identity)
        with self._lock:
            self._workspaces[workspace_id] = workspace
        return workspace

    def run(self, workspace: Workspace, spec: CommandSpec) -> ExecutionReceiptV1:
        if not isinstance(spec, CommandSpec):
            raise ContractError("spec must be a CommandSpec")
        if workspace.workspace_id not in self._workspaces:
            raise RunnerError("unknown workspace")
        argv = self._container_argv(spec)
        execution_id = "exec-" + secrets.token_hex(8)
        container = "sis-exec-" + secrets.token_hex(8)
        limits = spec.limits
        memory = min(self._memory, limits.memory_bytes)
        pids = limits.process_count or self._pids
        workdir = "/workspace"
        cwd = (spec.cwd or ".").strip("./")
        if cwd:
            workdir = "/workspace/" + cwd
        command = [
            self._docker, "run", "--rm", "--name", container,
            "--network", "none",
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={self._tmpfs}",
            "--user", self._user,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--memory", str(memory),
            "--memory-swap", str(memory),
            "--pids-limit", str(pids),
            "--cpus", str(self._cpus),
            "--ipc", "none",
            "--mount",
            f"type=bind,source={workspace.path.resolve()},target=/workspace",
            "--workdir", workdir,
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
        ]
        for key, value in spec.env.items():
            command.extend(("-e", f"{key}={value}"))
        command.extend((self._image, *argv))

        security_errors = [
            "isolation:docker_sandbox",
            "docker:network_none",
            "docker:read_only_root",
            "docker:cap_drop_all",
            "docker:no_new_privileges",
            f"docker:user:{self._user}",
            f"docker:memory_bytes:{memory}",
            f"docker:pids_limit:{pids}",
        ]
        if not _IMAGE_DIGEST.fullmatch(self._image):
            security_errors.append("docker:image_tag_only")

        stdout_chunks = bytearray()
        stderr_chunks = bytearray()
        truncated = {"stdout": False, "stderr": False}
        start = time.monotonic()
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            raise RunnerError(f"docker_unavailable:{exc}") from exc
        with self._lock:
            self._live[execution_id] = container

        def pump(pipe, sink: bytearray, name: str) -> None:
            try:
                while True:
                    chunk = pipe.read(_READ_CHUNK)
                    if not chunk:
                        return
                    if len(sink) + len(chunk) > self._output_bytes:
                        sink.extend(chunk[: max(0, self._output_bytes - len(sink))])
                        truncated[name] = True
                        self._kill(container)
                        pipe.read()
                        return
                    sink.extend(chunk)
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
        timed_out = False
        try:
            proc.wait(timeout=limits.wall_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(container)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)
        finally:
            for thread in threads:
                thread.join(timeout=10)
            for pipe in (proc.stdout, proc.stderr, proc.stdin):
                try:
                    if pipe is not None and not pipe.closed:
                        pipe.close()
                except OSError:
                    pass
            with self._lock:
                self._live.pop(execution_id, None)
        wall = time.monotonic() - start

        after = scan_tree(workspace.path)
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

        with self._lock:
            self._outputs[execution_id] = (bytes(stdout_chunks), bytes(stderr_chunks))
        return ExecutionReceiptV1(
            schema_version=1,
            execution_id=execution_id,
            worker_identity=self.worker_identity,
            environment_digest=canonical_digest("docker_environment", 1, {
                "image": self._image,
                "image_id": self.image_id(),
                "user": self._user,
                "network": "none",
                "read_only_root": True,
                "cap_drop": "ALL",
                "no_new_privileges": True,
                "memory_bytes": memory,
                "pids_limit": pids,
                "cpus": f"{self._cpus:g}",
            }),
            before_tree_digest=workspace.before_tree_digest,
            after_tree_digest=after.digest,
            command_spec_digest=command_spec_digest(spec),
            exit_status=proc.returncode if proc.returncode is not None else -1,
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
        with self._lock:
            self._workspaces.pop(workspace.workspace_id, None)
        shutil.rmtree(workspace.path, ignore_errors=True)

    def terminate_all(self) -> None:
        with self._lock:
            containers = list(self._live.values())
            self._live.clear()
        for container in containers:
            self._kill(container)

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
        workspace = None
        try:
            (temp / "seed.txt").write_text("seed")
            workspace = self.prepare(temp, label="probe")

            def check(name, argv, *, expect_success, limits=None):
                spec = CommandSpec(
                    argv=tuple(argv), limits=limits or ResourceLimits())
                receipt = self.run(workspace, spec)
                stdout, stderr = self.output(receipt.execution_id)
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
        finally:
            if workspace is not None:
                self.destroy(workspace)
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
