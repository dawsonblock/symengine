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

The security-relevant ``docker run`` flags and the sandbox policy whose
digest an isolator signs are produced by one method
(:meth:`DockerSandboxExecutor.launch_flags`): the policy holds the flag
template with placeholders for the per-run values, the launch substitutes
them, and :func:`render_launch_flags` performs the same substitution so a
test can check that the signed policy is exactly what ``docker run``
received.

A production executor runs under gVisor (``runtime="runsc"``) with an
allowlist seccomp profile (``docker/sandbox/seccomp.json``).
"""
from __future__ import annotations

import hashlib
import io
import json
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
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path, PurePosixPath

from .contracts import ContractError, ExecutionReceiptV1, canonical_digest
from .isolation import ProductionIsolationPolicy
from .runner import (MARKER_SHARED_CUSTODY, MAX_WORKSPACE_FILES,
                     CommandSpec, ResourceLimits,
                     RunnerError, Workspace, command_spec_digest,
                     mark_private_material_modified, private_command_spec,
                     private_material_modified, scan_tree,
                     stage_private_material)
from .split_harness import (MARKER_SEPARATE_UID, MARKER_SPLIT,
                            SPLIT_BOOTSTRAP_NAME, SPLIT_SOCKET_NAME,
                            WORKER_SOURCE, split_bootstrap_argv,
                            split_failure_marker, split_pytest_argv)
from .workspace_guard import ManagedWorkspaceRegistry, protected_overlap

#: Label on every sandbox container, so leaked ones can be listed and
#: removed: ``docker rm -f $(docker ps -aq --filter label=sis.v3.sandbox)``.
CONTAINER_LABEL = "sis.v3.sandbox"
_IMAGE_DIGEST = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*(?::[A-Za-z0-9._-]+)?@sha256:[0-9a-f]{64}$")
_USER = re.compile(r"^([0-9]{1,10})(?::([0-9]{1,10}))?$")
_READ_CHUNK = 65_536
_COPY_OUT_SECONDS = 300.0
_COPY_OUT_MAX_MEMBERS = MAX_WORKSPACE_FILES * 2
_COPY_OUT_STREAM_FLOOR = 1 << 20
#: Container runtimes the executor may request. ``None`` keeps the
#: daemon default (normally runc); production requires gVisor.
RUNTIMES = (None, "runc", "runsc")
PRODUCTION_RUNTIME = "runsc"
#: Memory the container cgroup gets on top of the workload limit under
#: gVisor. The sentry and its memory-backed /workspace and /tmp count
#: against the container limit, so a 128 MiB workload limit left no room
#: to copy the workspace in. The workload limit itself is unchanged and is
#: what receipts report; the allowance is part of the signed policy.
RUNSC_MEMORY_OVERHEAD_BYTES = 256 * 1024 * 1024
#: Host pids the container cgroup gets on top of the workload limit under
#: gVisor: the sentry and gofer threads live in that cgroup, so a 16-pid
#: workload limit used as the container limit left runsc unable to start.
#: The workload limit is enforced inside the sandbox with RLIMIT_NPROC
#: (``--ulimit nproc``), which gVisor accounts per sandbox.
RUNSC_PIDS_OVERHEAD = 256
BACKEND = "docker_sandbox"
POLICY_SCHEMA_VERSION = 2
#: Containment properties a production attestation for this backend must
#: carry. The release gate and ``tools/qualify_docker_isolation.py`` use
#: this set; ``kernel:gvisor`` and ``syscalls:seccomp_allowlist`` are only
#: claimable for a receipt that ran under runsc with the allowlist profile.
PRODUCTION_PROPERTIES = (
    "net:denied",
    "fs:root_read_only",
    "fs:workspace_confined",
    "user:non_root",
    "caps:dropped",
    "proc:no_new_privileges",
    "limits:memory",
    "limits:pids",
    "limits:disk",
    "limits:cpu_time",
    "output:capped",
    "kernel:gvisor",
    "syscalls:seccomp_allowlist",
)
#: gVisor's sentry reports this fixed kernel build string in
#: ``/proc/version``; a container on the host kernel reports the host's.
GVISOR_KERNEL_SIGNATURE = "#1 SMP Sun Jan 10 15:06:54 PST 2016"
#: Placeholders for the per-run values in the policy's flag template.
LAUNCH_PLACEHOLDERS = {
    "memory_bytes": "{memory_bytes}",
    "pids_limit": "{pids_limit}",
    "workload_pids_limit": "{workload_pids_limit}",
    "disk_bytes": "{disk_bytes}",
    "cpu_seconds": "{cpu_seconds}",
    "uid": "{uid}",
    "gid": "{gid}",
    "workspace_mode": "{workspace_mode}",
    "seccomp_profile": "{seccomp_profile}",
}
_WORKSPACE_MODES = ("0770", "0777")
_DENY_BY_DEFAULT = ("SCMP_ACT_ERRNO", "SCMP_ACT_KILL", "SCMP_ACT_KILL_PROCESS",
                    "SCMP_ACT_KILL_THREAD", "SCMP_ACT_TRAP")
_BUDGET_MARKERS = {
    "disk_budget_exceeded": "fs:disk_budget_exceeded",
    "archive_budget_exceeded": "fs:disk_budget_exceeded",
    "file_count_exceeded": "fs:file_count_exceeded",
    "sparse_member_rejected": "fs:sparse_member_rejected",
}


class CopyOutBudgetError(RunnerError):
    """The copy-out archive exceeded the workspace's declared budget."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"workspace_copy_out_failed:{reason}")
        self.reason = reason


class _BudgetedReader:
    """Read the tar stream but refuse to exceed a hard byte budget.

    ``tarfile`` reads ahead in fixed-size buffers, so the budget carries a
    floor that covers one buffer plus tar record padding; the authoritative
    limit on extracted bytes is enforced per member by ``_extract_bounded``.
    """

    def __init__(self, stream, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.read_bytes = 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._stream.read(size)
        self.read_bytes += len(chunk)
        if self.read_bytes > self._limit:
            raise CopyOutBudgetError("archive_budget_exceeded")
        return chunk


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


def load_seccomp_profile(path: str | Path) -> bytes:
    """Read an allowlist seccomp profile and refuse a denylist."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ContractError(f"seccomp_profile_unreadable:{exc}") from exc
    try:
        document = json.loads(raw)
    except ValueError as exc:
        raise ContractError("seccomp_profile_not_json") from exc
    if not isinstance(document, dict):
        raise ContractError("seccomp_profile_not_an_object")
    # An allowlist denies by default. A profile whose default action
    # allows every unlisted syscall is a denylist and is refused.
    if document.get("defaultAction") not in _DENY_BY_DEFAULT:
        raise ContractError("seccomp_profile_must_deny_by_default")
    if not isinstance(document.get("syscalls"), list) or not document["syscalls"]:
        raise ContractError("seccomp_profile_has_no_syscall_rules")
    return raw


def render_launch_flags(policy: Mapping, values: Mapping[str, object]) -> list[str]:
    """Substitute one run's ``values`` into a policy's flag template.

    The result is the exact security-relevant argv a launch under
    ``policy`` passes to ``docker run``. Every placeholder the template
    uses must be supplied; an unknown value name is refused.
    """
    unknown = set(values) - set(LAUNCH_PLACEHOLDERS)
    if unknown:
        raise ContractError(f"unknown_launch_values:{sorted(unknown)}")
    rendered = []
    for token in policy["launch_flags"]:
        for key, value in values.items():
            token = token.replace(LAUNCH_PLACEHOLDERS[key], str(value))
        if any(marker in token for marker in LAUNCH_PLACEHOLDERS.values()):
            raise ContractError(f"unrendered_launch_placeholder:{token}")
        rendered.append(token)
    return rendered


def policy_document_digest(policy: Mapping) -> str:
    """The ``policy_digest`` an isolator signs for a launch policy."""
    return canonical_digest(
        "docker_sandbox_policy", POLICY_SCHEMA_VERSION, dict(policy))


def production_isolation_policy(
    *, trusted_keys: Mapping[str, str], image_digest: str,
    policy_digest: str, revoked_keys: frozenset[str] = frozenset(),
    max_attestation_age_seconds: int | None = 3600,
) -> ProductionIsolationPolicy:
    """The production isolation contract for the Docker + gVisor backend.

    It allows only this backend and requires every property in
    :data:`PRODUCTION_PROPERTIES`, including ``kernel:gvisor``.
    """
    return ProductionIsolationPolicy(
        allowed_backends=frozenset({BACKEND}),
        trusted_keys=dict(trusted_keys),
        required_policy_digest=policy_digest,
        required_image_digest=image_digest,
        required_properties=frozenset(PRODUCTION_PROPERTIES),
        revoked_keys=revoked_keys,
        max_attestation_age_seconds=max_attestation_age_seconds,
    )


class DockerSandboxExecutor:
    """Run evaluator commands in a bounded Docker container."""

    supports_private_material = True

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
        split_user: str | None = None,
        image_id: str | None = None,
        runtime: str | None = None,
        seccomp_profile: str | Path | None = None,
    ) -> None:
        if not isinstance(image, str) or not image:
            raise ContractError("image must be a non-empty string")
        if runtime not in RUNTIMES:
            raise ContractError("runtime must be None, 'runc' or 'runsc'")
        if production and runtime != PRODUCTION_RUNTIME:
            # The production boundary is gVisor's user-space kernel, not
            # the host kernel that runc exposes to the container.
            raise ContractError("production_requires_gvisor_runtime")
        if production and seccomp_profile is None:
            raise ContractError("production_requires_seccomp_profile")
        seccomp_raw = (load_seccomp_profile(seccomp_profile)
                       if seccomp_profile is not None else None)
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
        # One spelling everywhere: ``--user 1000`` would leave Docker to
        # pick the group (root's, for an unknown uid), while the
        # workspace tmpfs is owned by the parsed gid.
        self._user = f"{self._uid}:{self._gid}"
        self._split_user = None
        if split_user is not None:
            split_uid, split_gid = _parse_user(split_user)
            if split_uid == self._uid:
                raise ContractError(
                    "split_user must differ from the evaluator user")
            self._split_user = f"{split_uid}:{split_gid}"
        self.root = Path(os.path.abspath(
            root if root is not None
            else tempfile.mkdtemp(prefix="sis-v3-docker-")))
        self.root.mkdir(parents=True, exist_ok=True)
        self._runtime = runtime
        self._seccomp_sha256: str | None = None
        self._seccomp_path: Path | None = None
        if seccomp_raw is not None:
            self._seccomp_sha256 = hashlib.sha256(seccomp_raw).hexdigest()
            self._seccomp_path = self._install_seccomp_profile(seccomp_raw)
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
    def supports_split_custody(self) -> bool:
        """Split custody needs a second, non-root container identity."""
        return self._split_user is not None

    @property
    def split_user(self) -> str | None:
        """The configured second container identity, if any."""
        return self._split_user

    @property
    def network_isolation(self) -> str:
        return "docker_none"

    @property
    def server_version(self) -> str:
        return self._server_version

    @property
    def runtime(self) -> str | None:
        return self._runtime

    @property
    def seccomp_profile_sha256(self) -> str | None:
        return self._seccomp_sha256

    def _install_seccomp_profile(self, raw: bytes) -> Path:
        """Keep an executor-owned, read-only copy of the profile.

        The Docker CLI reads the profile file on every launch; launching
        from a private copy means the bytes named by the policy digest
        cannot be swapped underneath the executor.
        """
        private = self.root / ".seccomp"
        private.mkdir(mode=0o700, exist_ok=True)
        target = private / f"profile-{self._seccomp_sha256}.json"
        if target.is_file() and target.read_bytes() == raw:
            return target
        temp = private / (".tmp-" + secrets.token_hex(4))
        temp.write_bytes(raw)
        os.chmod(temp, 0o400)
        os.replace(temp, target)
        return target

    # ---- launch policy -------------------------------------------------- #
    def launch_flags(
        self, *, memory_bytes, pids_limit, disk_bytes, cpu_seconds,
        uid, gid, workspace_mode, seccomp_profile, workload_pids_limit,
    ) -> list[str]:
        """The security-relevant ``docker run`` flags, in launch order.

        This is the single source of both the real launch argv (called
        with the run's values by ``_start_container``) and the signed
        policy (called with :data:`LAUNCH_PLACEHOLDERS` by
        :meth:`launch_policy`), so the two cannot drift.
        """
        flags: list[str] = []
        if self._runtime is not None:
            flags += ["--runtime", self._runtime]
        flags += [
            "--network", "none",
            "--read-only",
            "--tmpfs", f"/tmp:rw,noexec,nosuid,size={self._tmpfs}",
            "--tmpfs",
            (f"/workspace:rw,nosuid,nodev,size={disk_bytes},"
             f"uid={uid},gid={gid},mode={workspace_mode}"),
            "--user", f"{uid}:{gid}",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
        ]
        if self._seccomp_path is not None:
            flags += ["--security-opt", f"seccomp={seccomp_profile}"]
        flags += [
            "--memory", str(memory_bytes),
            "--memory-swap", str(memory_bytes),
            "--pids-limit", str(pids_limit),
            "--cpus", str(self._cpus),
            # RLIMIT_CPU is inherited by the exec'd command, so CPU time
            # is a kernel-enforced budget, not only a scheduling share.
            "--ulimit", f"cpu={cpu_seconds}",
            "--ulimit", f"nofile={self._nofile}:{self._nofile}",
            "--ipc", "none",
        ]
        if self._runtime == PRODUCTION_RUNTIME:
            # Inside gVisor RLIMIT_NPROC is counted per sandbox, so it bounds
            # the workload; under runc it would count the host UID instead.
            flags += ["--ulimit",
                      f"nproc={workload_pids_limit}:{workload_pids_limit}"]
        return flags

    def launch_policy(self) -> dict:
        """The sandbox policy document whose digest an isolator signs.

        It holds the flag template (per-run values as placeholders), the
        ceilings those values never exceed, the runtime, and the seccomp
        profile by content digest. Host-specific values (paths, numeric
        principals) are placeholders, so one image and executor
        configuration has one policy digest on every host.
        """
        image_digest = (self._image.rsplit("@sha256:", 1)[1]
                        if _IMAGE_DIGEST.fullmatch(self._image) else None)
        return {
            "backend": BACKEND,
            "image_digest": image_digest,
            "runtime": self._runtime or "default",
            "seccomp_profile_sha256": self._seccomp_sha256,
            "launch_flags": self.launch_flags(**LAUNCH_PLACEHOLDERS),
            "ceilings": {
                "memory_bytes": self._memory,
                "pids_limit": self._pids,
                "output_bytes": self._output_bytes,
                "tmpfs_bytes": self._tmpfs,
                "runtime_memory_overhead_bytes":
                    self._runtime_memory_overhead(),
                "runtime_pids_overhead": self._runtime_pids_overhead(),
                "nofile_limit": self._nofile,
                "cpus": f"{self._cpus:g}",
            },
            "principals": "non_root",
            "workspace_modes": list(_WORKSPACE_MODES),
            "split_principal": self._split_user is not None,
        }

    def policy_digest(self) -> str:
        """Digest of :meth:`launch_policy`: the value ``policy_digest`` pins."""
        return policy_document_digest(self.launch_policy())

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

    def run(
        self, workspace: Workspace, spec: CommandSpec, *,
        private_files: Mapping[str, bytes] | None = None,
        split_custody: bool = False,
    ) -> ExecutionReceiptV1:
        if not isinstance(spec, CommandSpec):
            raise ContractError("spec must be a CommandSpec")
        if split_custody and not private_files:
            raise ContractError("split custody requires private material")
        if split_custody and not self.supports_split_custody:
            raise RunnerError("split_custody_unavailable")
        with self._registry.execution(
                workspace.workspace_id, workspace.path,
                executor_identity=workspace.executor_identity) as record:
            material = None
            try:
                if split_custody:
                    # Private material is copied into the container's
                    # tmpfs as the evaluator UID instead of being mounted:
                    # a host bind mount would carry host ownership, which
                    # need not match the container's evaluator UID.
                    material = stage_private_material(
                        self.root, private_files, private_mode=True,
                        split_bootstrap=True)
                    base = private_command_spec(
                        spec, names=private_files, prefix=self._split_dir,
                        workspace="/workspace", bootstrap=False)
                    base = replace(base, argv=split_pytest_argv(
                        base.argv, private_dir=self._split_dir))
                    spec = replace(base, argv=split_bootstrap_argv(
                        base.argv,
                        bootstrap_path=(
                            self._split_dir + "/" + SPLIT_BOOTSTRAP_NAME),
                        transport=("--socket", self._split_socket),
                        workspace="/workspace"))
                    receipt = self._run_workspace(
                        record, spec, split_material=material)
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
                            spec, names=private_files, prefix="/private",
                            workspace="/workspace")
                    receipt = self._run_workspace(
                        record, spec, private_host=material)
                    if material is not None:
                        receipt = replace(
                            receipt, security_errors=receipt.security_errors
                            + (MARKER_SHARED_CUSTODY,))
                    if material is not None and private_material_modified(
                            material, private_files):
                        # The mounted directory is the copy the run could
                        # reach, so re-read it here. Split custody installs
                        # a container copy instead and verifies that one.
                        receipt = mark_private_material_modified(receipt)
                return receipt
            finally:
                if material is not None:
                    shutil.rmtree(material, ignore_errors=True)

    @property
    def _split_socket(self) -> str:
        return "/tmp/" + SPLIT_SOCKET_NAME

    @property
    def _split_dir(self) -> str:
        # The container root is read-only, so the private directory lives
        # on the tmpfs. It is created by the evaluator UID with mode 0700.
        return "/tmp/sis-private"

    def _run_workspace(
        self, record, spec: CommandSpec, *, private_host: Path | None = None,
        split_material: Path | None = None,
    ) -> ExecutionReceiptV1:
        split = split_material is not None
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
            f"docker:runtime:{self._runtime or 'default'}",
        ]
        if self._runtime_memory_overhead():
            security_errors.append("docker:runtime_memory_overhead:"
                           f"{self._runtime_memory_overhead()}")
        if self._runtime_pids_overhead():
            security_errors.append("docker:runtime_pids_overhead:"
                                   f"{self._runtime_pids_overhead()}")
        if self._seccomp_sha256 is not None:
            security_errors.append(
                f"docker:seccomp_profile:{self._seccomp_sha256}")
        security_errors.append(f"docker:policy:{self.policy_digest()}")
        if not _IMAGE_DIGEST.fullmatch(self._image):
            security_errors.append("docker:image_tag_only")
        if private_host is not None or split:
            security_errors.append("evaluation:private_material_separated")
        if split:
            security_errors.append(MARKER_SPLIT)
            security_errors.append(MARKER_SEPARATE_UID)
            security_errors.append(f"docker:split_user:{self._split_user}")

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
                container, record, spec, limits, memory, pids, disk,
                private_host, split=split)
            with self._lock:
                self._live[execution_id] = container
                self._live_ws[execution_id] = record.workspace_id
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            self._copy_in(container, record)
            if self._registry.is_closing(record.workspace_id):
                raise RunnerError("workspace_is_closing")
            if split:
                self._install_split_material(container, split_material)
                self._start_split_worker(container)
                self._await_split_socket(container)
                if self._registry.is_closing(record.workspace_id):
                    raise RunnerError("workspace_is_closing")
            proc = self._exec_command(container, argv, spec, workdir)

            stop = threading.Event()
            over = False

            def consume(pipe, sink: bytearray, name: str) -> bool:
                chunk = (os.read(pipe.fileno(), _READ_CHUNK)
                         if os.name == "posix" else pipe.read(_READ_CHUNK))
                if not chunk:
                    return False
                nonlocal over
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
                return True

            def discard(pipe) -> None:
                # After the cap the container is killed, but the docker
                # client can still hold buffered output. Keep draining (and
                # dropping) it: a pipe nobody reads blocks the client, which
                # then never exits and the run is reported as a wall-clock
                # timeout instead of an output cap.
                while not stop.is_set():
                    if os.name == "posix":
                        import select
                        ready, _, _ = select.select(
                            [pipe.fileno()], [], [], 0.1)
                        if not ready:
                            continue
                        chunk = os.read(pipe.fileno(), _READ_CHUNK)
                    else:
                        chunk = pipe.read(_READ_CHUNK)
                    if not chunk:
                        return

            def pump(pipe, sink: bytearray, name: str) -> None:
                try:
                    if os.name == "posix":
                        import select
                        fd = pipe.fileno()
                        while not stop.is_set():
                            ready, _, _ = select.select([fd], [], [], 0.1)
                            if not ready:
                                continue
                            if not consume(pipe, sink, name):
                                return
                            if over:
                                self._kill(container)
                                discard(pipe)
                                return
                        return
                    while not stop.is_set():
                        if not consume(pipe, sink, name):
                            return
                        if over:
                            self._kill(container)
                            discard(pipe)
                            return
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
            pumps = [
                (stdout_thread, proc.stdout),
                (stderr_thread, proc.stderr),
            ]
            for thread in threads:
                thread.start()
            try:
                proc.wait(timeout=limits.wall_seconds)
                exit_status = proc.returncode
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill(container)
                stop.set()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            finally:
                if timed_out:
                    stop.set()
                for thread in threads:
                    thread.join(timeout=0.5 if timed_out else 10)
                    if thread.is_alive():
                        stop.set()
                        thread.join(timeout=0.5)
                for thread, pipe in pumps:
                    if not thread.is_alive():
                        try:
                            if pipe is not None and not pipe.closed:
                                pipe.close()
                        except OSError:
                            pass
                if not feed_thread.is_alive():
                    try:
                        if proc.stdin is not None and not proc.stdin.closed:
                            proc.stdin.close()
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
                # Background processes the command left behind could keep
                # writing while the workspace is archived; stop them first.
                self._stop_background(container, split=split)
                try:
                    # Files created by the submission are owned by the
                    # worker UID in split mode; collect them as that UID.
                    self._copy_out(
                        container, record, disk,
                        user=self._split_user if split else self._user)
                except CopyOutBudgetError as exc:
                    # The archive exceeded a budget the run declared. The
                    # prepared workspace is preserved, but its post-run state
                    # was never collected: the receipt must say both.
                    security_errors.append(_BUDGET_MARKERS.get(
                        exc.reason, "fs:disk_budget_exceeded"))
                    security_errors.append("fs:workspace_state_unavailable")
                    security_errors.append(
                        f"fs:copy_out_rejected:{exc.reason}")
                except RunnerError:
                    if exit_status == 0:
                        raise
                    # A resource-exhausted command may leave no cgroup
                    # slot for the copy-out process. The run is still
                    # classifiable as a resource limit, never a pass.
                    security_errors.append("fs:workspace_state_unavailable")
                if split and self._split_material_modified(
                        container, split_material):
                    # The container copy, not the host staging directory,
                    # is what the worker could reach.
                    security_errors.append(
                        "sandbox:private_material_modified")
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
            environment_digest=canonical_digest("docker_environment", 3, {
                "image": self._image,
                "policy_digest": self.policy_digest(),
                "runtime": self._runtime or "default",
                "seccomp_profile_sha256": self._seccomp_sha256,
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
        private_host: Path | None = None, *, split: bool = False,
    ) -> None:
        # The workspace is not bind-mounted: ``_copy_in`` streams it from
        # the registry path into the tmpfs, so no host path of the
        # submission appears in the container and its host ownership and
        # modes never decide whether the container user can read it.
        command = [
            # --rm and the label: a container leaked by a crashed
            # evaluator stops being kept once it stops, and a running one
            # can be found with ``docker ps --filter label=...``.
            self._docker, "run", "-d", "--rm", "--name", container,
            "--label", f"{CONTAINER_LABEL}={self.worker_identity}",
            *self.launch_flags(**self._launch_values(
                memory=memory, pids=pids, disk=disk,
                cpu_seconds=limits.cpu_seconds, split=split)),
            "--workdir", "/workspace",
            "-e", "HOME=/tmp",
            "-e", "TMPDIR=/tmp",
        ]
        if private_host is not None:
            # Evaluator-private acceptance material is mounted outside the
            # submission workspace and is never part of the copy-out tree.
            # Docker's --mount grammar has no escaping for commas, so a path
            # that cannot be represented fails closed instead of being
            # mounted somewhere unintended.
            source = str(Path(private_host).resolve())
            if "," in source:
                raise RunnerError("private_material_path_unrepresentable")
            command.extend((
                "--mount",
                f"type=bind,source={source},target=/private,readonly",
            ))
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

    def _runtime_pids_overhead(self) -> int:
        """Container pids added to the workload limit for the runtime."""
        return RUNSC_PIDS_OVERHEAD if self._runtime == PRODUCTION_RUNTIME else 0

    def _runtime_memory_overhead(self) -> int:
        """Container memory added to the workload limit for the runtime."""
        return (RUNSC_MEMORY_OVERHEAD_BYTES
                if self._runtime == PRODUCTION_RUNTIME else 0)

    def _launch_values(
        self, *, memory: int, pids: int, disk: int, cpu_seconds: int,
        split: bool,
    ) -> dict:
        """The per-run values substituted into the launch template."""
        # Split custody runs the worker as a second UID, which must be
        # able to read the copied-in workspace; the evaluator UID keeps
        # write access. Only the two run principals can reach this tmpfs.
        return {
            "memory_bytes": memory + self._runtime_memory_overhead(),
            "pids_limit": pids + self._runtime_pids_overhead(),
            "workload_pids_limit": pids,
            "disk_bytes": disk,
            "cpu_seconds": cpu_seconds,
            "uid": self._uid,
            "gid": self._gid,
            "workspace_mode": _WORKSPACE_MODES[1 if split else 0],
            "seccomp_profile": (str(self._seccomp_path)
                                if self._seccomp_path is not None else None),
        }

    def _copy_in(self, container: str, record) -> None:
        """Populate the quota-limited workspace from the registry path.

        The host process archives the prepared workspace and the container
        user extracts it into ``/workspace``. A read-only bind of the host
        tree would carry host ownership: on a root host the prepared tree
        is root-owned (mode 0700 at its top when the source was a
        ``mkdtemp``), and the unprivileged container user could not read
        it. Streaming needs no change of host ownership or modes, so no
        other host principal gains access to the workspace.

        Only the children of the workspace are archived, never its root
        entry: extracting a root entry would apply the host directory's
        mode to the tmpfs, and the split worker UID must keep reading it.
        The archive is spooled under the executor root, which is private.
        """
        source = Path(record.real_path)

        def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
            # Ownership is the container user's; tar ignores host names.
            info.uid, info.gid = self._uid, self._gid
            info.uname = info.gname = ""
            return info

        with tempfile.TemporaryFile(dir=self.root) as spool:
            try:
                with tarfile.open(fileobj=spool, mode="w") as archive:
                    for child in sorted(source.iterdir()):
                        archive.add(child, arcname=child.name,
                                    filter=normalize)
            except (OSError, tarfile.TarError) as exc:
                raise RunnerError(
                    f"workspace_copy_in_failed:{type(exc).__name__}") from exc
            spool.seek(0)
            try:
                result = subprocess.run(
                    [self._docker, "exec", "-i", "--user", self._user,
                     container, "tar", "-x", "-C", "/workspace", "-f", "-"],
                    stdin=spool, capture_output=True, timeout=120)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RunnerError(f"workspace_copy_in_failed:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError(
                "workspace_copy_in_failed:"
                + (result.stderr or result.stdout).decode(
                    "utf-8", "replace").strip()[:200])

    def _install_split_material(
        self, container: str, material: Path,
    ) -> None:
        """Copy private material into the container as the evaluator UID.

        The directory is created by the evaluator UID with mode 0700, so
        the worker UID cannot traverse or read it. Files are read-only.
        """
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode="w") as archive:
            for path in sorted(material.rglob("*")):
                archive.add(path, arcname=str(path.relative_to(material)))
        try:
            result = subprocess.run(
                [self._docker, "exec", "-i", "--user", self._user, container,
                 "sh", "-c",
                 f"rm -rf {self._split_dir} && mkdir -p {self._split_dir} && "
                 f"tar -x -C {self._split_dir} && "
                 f"chmod 700 {self._split_dir}"],
                input=payload.getvalue(), capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(
                f"split_custody_install_failed:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError(
                "split_custody_install_failed:"
                + (result.stderr or result.stdout).decode(
                    "utf-8", "replace").strip()[:200])

    def _split_material_modified(
        self, container: str, material: Path,
    ) -> bool:
        """Compare the container's private copy to the staged material.

        Split custody installs a copy into the container tmpfs, so the host
        staging directory is not the copy the worker could reach. Any read
        failure counts as modified: the receipt must never claim a tree it
        did not verify.
        """
        expected = {}
        for path in material.rglob("*"):
            if path.is_file():
                expected[path.relative_to(material).as_posix()] = (
                    path.read_bytes())
        try:
            result = subprocess.run(
                [self._docker, "exec", "--user", self._user, container,
                 "tar", "-C", self._split_dir, "-cf", "-", "."],
                capture_output=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            return True
        if result.returncode != 0:
            return True
        observed = {}
        try:
            with tarfile.open(fileobj=io.BytesIO(result.stdout)) as archive:
                for member in archive.getmembers():
                    if not member.isfile():
                        continue
                    name = member.name
                    while name.startswith("./"):
                        name = name[2:]
                    handle = archive.extractfile(member)
                    if handle is None:
                        return True
                    observed[name] = handle.read()
        except (tarfile.TarError, OSError, ValueError):
            return True
        return observed != expected

    def _start_split_worker(self, container: str) -> None:
        """Start the restricted worker as the second container UID."""
        try:
            result = subprocess.run(
                [self._docker, "exec", "-d", "--user", self._split_user,
                 "--workdir", "/workspace",
                 "-e", "HOME=/tmp", "-e", "TMPDIR=/tmp",
                 container, "python3", "-I", "-c", WORKER_SOURCE,
                 "--socket", self._split_socket, "/workspace"],
                capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError(
                f"split_custody_worker_start_failed:{exc}") from exc
        if result.returncode != 0:
            raise RunnerError(
                "split_custody_worker_start_failed:"
                + (result.stderr or result.stdout).strip()[:200])

    def _await_split_socket(self, container: str, seconds: float = 30.0) -> None:
        """Wait until the worker is listening, or fail closed."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                result = subprocess.run(
                    [self._docker, "exec", "--user", self._user, container,
                     "test", "-S", self._split_socket],
                    capture_output=True, timeout=15)
            except (OSError, subprocess.TimeoutExpired):
                result = None
            if result is not None and result.returncode == 0:
                return
            time.sleep(0.1)
        raise RunnerError("split_custody_unavailable")

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

    def _copy_out(
        self, container: str, record, disk_bytes: int,
        user: str | None = None,
    ) -> None:
        """Copy the tmpfs workspace back through a filtered tar stream.

        The declared disk budget and file-count bound are enforced while the
        archive is read, not audited after the host has already written it.
        The prepared workspace is replaced only after a complete, in-budget
        extraction succeeded; a failed swap restores it.
        """
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
        retired: Path | None = None
        try:
            try:
                proc = subprocess.Popen(
                    [self._docker, "exec", "--user", user or self._user,
                     container, "tar", "-C", "/workspace", "-cf", "-", "."],
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
            # tarfile reads ahead in fixed-size buffers; the stream budget
            # carries a floor for that read-ahead. Extracted bytes are
            # bounded exactly, per member, below.
            stream_limit = max(
                disk_bytes * 2 + _COPY_OUT_STREAM_FLOOR,
                _COPY_OUT_STREAM_FLOOR)
            try:
                self._extract_bounded(
                    _BudgetedReader(proc.stdout, stream_limit),
                    staging, disk_bytes)
            except (tarfile.TarError, OSError) as exc:
                proc.kill()
                raise RunnerError(
                    f"workspace_copy_out_failed:{type(exc).__name__}") from exc
            except BaseException:
                proc.kill()
                raise
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
            retired = record.path.with_name(
                record.path.name + ".retired-" + secrets.token_hex(4))
            try:
                os.rename(record.path, retired)
            except OSError as exc:
                raise RunnerError(
                    f"workspace_copy_out_failed:{exc}") from exc
            try:
                os.rename(staging, record.path)
            except OSError as exc:
                try:
                    os.rename(retired, record.path)
                except OSError as restore_exc:
                    raise RunnerError(
                        "workspace_copy_out_failed:"
                        f"workspace_restore_failed:{restore_exc}") from exc
                retired = None
                raise RunnerError(
                    f"workspace_copy_out_failed:{exc}") from exc
            staging = None
            shutil.rmtree(retired, ignore_errors=True)
            retired = None
        finally:
            if watchdog is not None:
                watchdog.cancel()
            errors.close()
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            if retired is not None and not record.path.exists():
                # Restoration failed earlier: the retired directory holds
                # the only copy of the prepared workspace. Try once more.
                try:
                    os.rename(retired, record.path)
                except OSError:
                    pass

    @staticmethod
    def _safe_member(member) -> bool:
        """Normalize and validate one archive member.

        Python 3.12's ``filter="data"`` provides these checks, but the
        package supports 3.10 and 3.11. Validate the same properties
        explicitly before every extraction so the fallback path is not
        weaker than the modern one. Returns False for the archive's
        leading ``.`` directory entry, which needs no extraction.
        """
        name = member.name
        if not isinstance(name, str) or not name:
            raise RunnerError(
                "workspace_copy_out_failed:unsafe_member_path")
        while name.startswith("./"):
            name = name[2:]
        if name in ("", "."):
            if member.isdir():
                return False
            raise RunnerError(
                "workspace_copy_out_failed:unsafe_member_path")
        if (PurePosixPath(name).is_absolute()
                or "\\" in name
                or any(part in ("", ".", "..")
                       for part in name.split("/"))):
            raise RunnerError(
                "workspace_copy_out_failed:unsafe_member_path")
        if (member.issym() or member.islnk() or member.ischr()
                or member.isblk() or member.isfifo()
                or not (member.isreg() or member.isdir())):
            raise RunnerError(
                "workspace_copy_out_failed:unsupported_member_type")
        member.name = name
        member.mode = 0o755 if member.isdir() else 0o644
        member.uid = member.gid = 0
        member.uname = member.gname = ""
        return True

    @staticmethod
    def _extract_bounded(reader, staging: Path, disk_bytes: int) -> None:
        """Extract one filtered archive under an exact byte/member budget."""
        extracted = 0
        members = 0
        files = 0
        with tarfile.open(fileobj=reader, mode="r|") as archive:
            for member in archive:
                members += 1
                if members > _COPY_OUT_MAX_MEMBERS:
                    raise CopyOutBudgetError("file_count_exceeded")
                if not member.isdir():
                    files += 1
                    if files > MAX_WORKSPACE_FILES:
                        raise CopyOutBudgetError("file_count_exceeded")
                if getattr(member, "sparse", None) is not None:
                    # A sparse header can declare small archived data while
                    # extraction writes a much larger logical file.
                    raise CopyOutBudgetError("sparse_member_rejected")
                if member.isreg() and (
                        member.size < 0
                        or extracted + member.size > disk_bytes):
                    raise CopyOutBudgetError("disk_budget_exceeded")
                if not DockerSandboxExecutor._safe_member(member):
                    continue
                try:
                    archive.extract(member, path=staging, filter="data")
                except TypeError:
                    # Python 3.10/3.11 predate extraction filters; the
                    # explicit member validation above is the boundary.
                    archive.extract(member, path=staging)
                if member.isreg():
                    extracted += member.size

    def _stop_background(self, container: str, *, split: bool) -> None:
        """SIGKILL every run-principal process except the container's PID 1.

        ``kill -9 -1`` signals every process the caller may signal except
        PID 1 (the idle keeper) and itself. It runs as each run principal,
        so it can only reach processes the submission could have started.
        Best effort: a failure leaves the copy-out to its own checks.
        """
        users = [self._user]
        if split and self._split_user:
            users.append(self._split_user)
        for user in users:
            try:
                subprocess.run(
                    [self._docker, "exec", "--user", user, container,
                     "sh", "-c", "kill -9 -1 2>/dev/null; exit 0"],
                    capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass

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
            check("docker_socket_absent", (
                "python3", "-c",
                "import os,sys; "
                "sys.exit(0 if not os.path.exists('/var/run/docker.sock') else 1)"),
                expect_success=True)
            check("no_new_privileges", (
                "python3", "-c",
                "import sys; "
                "status = dict(line.split(':', 1) for line in "
                "open('/proc/self/status') if ':' in line); "
                "sys.exit(0 if status.get('NoNewPrivs', '').strip() == '1' else 1)"),
                expect_success=True)
            check("capabilities_dropped", (
                "python3", "-c",
                "import sys; "
                "status = dict(line.split(':', 1) for line in "
                "open('/proc/self/status') if ':' in line); "
                "sys.exit(0 if int(status.get('CapEff', '0').strip() or '0', 16) == 0 else 1)"),
                expect_success=True)
            check("setuid_denied", (
                "python3", "-c", "import os; os.setuid(0)"),
                expect_success=False)
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
            if self._runtime == PRODUCTION_RUNTIME:
                # gVisor's sentry answers /proc/version itself with a fixed
                # build string; under runc the host kernel's appears.
                check("kernel_gvisor", (
                    "python3", "-c",
                    "import sys; "
                    f"sys.exit(0 if {GVISOR_KERNEL_SIGNATURE!r} in "
                    "open('/proc/version').read() else 1)"),
                    expect_success=True)
            if self._seccomp_path is not None:
                # Seccomp mode 2 is a filter; the allowlist profile denies
                # unshare(2) even before the missing capability does.
                check("seccomp_filter_active", (
                    "python3", "-c",
                    "import sys; "
                    "status = dict(line.split(':', 1) for line in "
                    "open('/proc/self/status') if ':' in line); "
                    "sys.exit(0 if status.get('Seccomp', '').strip() == '2' else 1)"),
                    expect_success=True)

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
            if self.split_user is not None:
                # The second principal is only real if it can execute a
                # command and the run records both split markers.
                workspace = self.prepare(temp, label="split_identity")
                try:
                    receipt = self.run(
                        workspace,
                        CommandSpec(
                            argv=("python3", "-c", "print('split-ok')"),
                            limits=ResourceLimits(
                                memory_bytes=256 * 1024 * 1024,
                                wall_seconds=30, output_bytes=65_536,
                                disk_bytes=16 * 1024 * 1024,
                                process_count=32)),
                        private_files={"acceptance.py": b"# probe\n"},
                        split_custody=True)
                    stdout, stderr = self.output(receipt.execution_id)
                finally:
                    self.destroy(workspace)
                markers = receipt.security_errors or ()
                checks.append({
                    "name": "split_identity_exec",
                    "expected": "success",
                    "exit_status": receipt.exit_status,
                    "ok": (receipt.exit_status == 0
                           and MARKER_SPLIT in markers
                           and MARKER_SEPARATE_UID in markers),
                    "stdout": stdout.decode("utf-8", "replace")[:200],
                    "stderr": stderr.decode("utf-8", "replace")[:200],
                })
        finally:
            shutil.rmtree(temp, ignore_errors=True)
        return {
            "ok": all(item["ok"] for item in checks),
            "image": self._image,
            "image_id": self.image_id(),
            "docker_server_version": self._server_version,
            "worker_identity": self.worker_identity,
            "runtime": self._runtime or "default",
            "seccomp_profile_sha256": self._seccomp_sha256,
            "policy_digest": self.policy_digest(),
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
