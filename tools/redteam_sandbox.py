#!/usr/bin/env python3
"""Run hostile payloads through the Docker sandbox and check each outcome.

Every payload has one expected outcome. A payload that probes a boundary
reports its own verdict by exit status (0: the attempt failed, 3: it
succeeded); resource payloads are expected to be stopped by a limit; the
copy-out payloads plant links that the filtered copy-out must reject. The
report is JSON and the exit status is non-zero when any observed outcome
differs from the expected one, so CI fails on a containment regression.

Outcomes:

``contained``          the command exited 0: the hostile attempt failed
``escaped``            the command exited 3, or a link reached the host tree
``limited``            the command was stopped (non-zero exit) by a limit
``timeout``            the wall clock killed the run
``output_capped``      the combined output cap truncated the run
``copy_out_rejected``  the copy-out refused the planted links
``staged_accepted``    planted links were copied back without rejection
``harness_error``      the executor failed for an unrelated reason

The default is the production configuration (gVisor + allowlist seccomp).
This is engineering evidence about the launch configuration, not a proof
against a kernel or gVisor vulnerability.

Usage:
    PYTHONPATH=src python3 tools/redteam_sandbox.py \\
      --image sis-evaluator:3.3.9@sha256:<64 hex> \\
      --output evidence/sandbox/redteam_report.json
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import tempfile
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sis.v3.runner import CommandSpec, ResourceLimits, RunnerError

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECCOMP = ROOT / "docker" / "sandbox" / "seccomp.json"
CANARY_ENV = "SIS_REDTEAM_HOST_CANARY"
SCRIPT = "redteam_payload.py"
ARGV = ("python3", SCRIPT)
ESCAPED_EXIT = 3
STAGED_EXIT = 4
OUTCOMES = ("contained", "escaped", "limited", "timeout", "output_capped",
            "copy_out_rejected", "staged_accepted", "harness_error")

_PRELUDE = '''\
import os, sys
def contained():
    sys.exit(0)
def escaped(why):
    print("ESCAPED:", why)
    sys.exit(3)
'''


def _limits(**overrides) -> ResourceLimits:
    values = {"cpu_seconds": 10, "wall_seconds": 30,
              "memory_bytes": 256 * 1024 * 1024, "output_bytes": 65_536,
              "disk_bytes": 8 * 1024 * 1024, "process_count": 32}
    values.update(overrides)
    return ResourceLimits(**values)


@dataclass(frozen=True)
class Payload:
    name: str
    category: str
    expected: str
    code: str
    limits: ResourceLimits = field(default_factory=_limits)
    description: str = ""

    def script(self, canary: str) -> str:
        """The payload source, staged into the workspace as ``SCRIPT``."""
        body = textwrap.dedent(self.code).replace("{CANARY}", canary)
        return f"# redteam:{self.name}\n" + _PRELUDE + body


PAYLOADS: tuple[Payload, ...] = (
    Payload("fork_bomb", "resources", "limited", '''
        import time
        while True:
            if os.fork() == 0:
                os.close(1)
                os.close(2)
                time.sleep(30)
                os._exit(0)
        ''', description="fork until the pids limit refuses (EAGAIN)"),
    Payload("memory_bomb", "resources", "limited", '''
        blocks = []
        while True:
            blocks.append(bytearray(32 * 1024 * 1024))
        ''', description="allocate until MemoryError or the OOM killer"),
    Payload("disk_fill", "resources", "limited", '''
        with open("/workspace/fill.bin", "wb") as handle:
            while True:
                handle.write(b"x" * (1024 * 1024))
                handle.flush()
        ''', description="fill the quota-limited workspace tmpfs"),
    Payload("huge_output", "resources", "output_capped", '''
        chunk = "x" * 65536
        for _ in range(512):
            sys.stdout.write(chunk)
        sys.stdout.flush()
        ''', description="write 32 MiB to stdout"),
    Payload("sleep_forever", "resources", "timeout", '''
        import time
        time.sleep(10 ** 6)
        ''', limits=_limits(wall_seconds=5),
        description="never exit; the wall clock must stop it"),
    Payload("egress_tcp", "network", "contained", '''
        import socket
        for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
            try:
                socket.create_connection((host, port), 3).close()
            except OSError:
                continue
            escaped(f"tcp {host}:{port}")
        contained()
        ''', description="open TCP connections to public addresses"),
    Payload("egress_udp", "network", "contained", '''
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.sendto(b"x", ("1.1.1.1", 53))
        except OSError:
            contained()
        escaped("udp datagram accepted for a public address")
        ''', description="send a UDP datagram to a public resolver"),
    Payload("egress_dns", "network", "contained", '''
        import socket
        try:
            socket.getaddrinfo("example.com", 443)
        except OSError:
            contained()
        escaped("DNS resolution succeeded")
        ''', description="resolve a public name"),
    Payload("docker_socket", "host_control", "contained", '''
        import socket
        for path in ("/var/run/docker.sock", "/run/docker.sock",
                     "/run/containerd/containerd.sock",
                     "/var/run/containerd/containerd.sock"):
            if os.path.exists(path):
                escaped(f"runtime socket visible: {path}")
        contained()
        ''', description="look for Docker or containerd control sockets"),
    Payload("setuid", "privilege", "contained", '''
        import stat
        for change in (lambda: os.setuid(0), lambda: os.setgid(0),
                       lambda: os.setgroups([0])):
            try:
                change()
            except OSError:
                continue
            escaped("identity change to root succeeded")
        status = dict(line.split(":", 1) for line in
                      open("/proc/self/status") if ":" in line)
        no_new_privs = status.get("NoNewPrivs", "").strip() == "1"
        for directory in ("/bin", "/sbin", "/usr/bin", "/usr/sbin"):
            try:
                names = os.listdir(directory)
            except OSError:
                continue
            for name in names:
                try:
                    mode = os.stat(os.path.join(directory, name)).st_mode
                except OSError:
                    continue
                if mode & stat.S_ISUID and not no_new_privs:
                    escaped(f"setuid binary usable: {directory}/{name}")
        contained()
        ''', description="become root directly or through setuid binaries"),
    Payload("ptrace", "privilege", "contained", '''
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        libc.ptrace.restype = ctypes.c_long
        libc.ptrace.argtypes = (ctypes.c_long, ctypes.c_int,
                                ctypes.c_void_p, ctypes.c_void_p)
        PTRACE_ATTACH, PTRACE_DETACH = 16, 17
        if libc.ptrace(PTRACE_ATTACH, 1, None, None) == 0:
            libc.ptrace(PTRACE_DETACH, 1, None, None)
            escaped("ptrace attach to pid 1 succeeded")
        contained()
        ''', description="attach to the container's init process"),
    Payload("mount_unshare", "privilege", "contained", '''
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        CLONE_NEWUSER, CLONE_NEWNS = 0x10000000, 0x00020000
        if libc.unshare(CLONE_NEWUSER) == 0:
            escaped("unshare(CLONE_NEWUSER) succeeded")
        if libc.unshare(CLONE_NEWNS) == 0:
            escaped("unshare(CLONE_NEWNS) succeeded")
        if libc.mount(b"none", b"/tmp", b"tmpfs", 0, None) == 0:
            escaped("mount succeeded")
        contained()
        ''', description="create namespaces or mount a filesystem"),
    Payload("kill_outside", "host_control", "contained", '''
        import signal
        me = os.getuid()
        for entry in os.listdir("/proc"):
            if not entry.isdigit():
                continue
            try:
                status = open(f"/proc/{entry}/status").read()
            except OSError:
                continue
            uids = [line.split()[1] for line in status.splitlines()
                    if line.startswith("Uid:")]
            if not uids or int(uids[0]) == me:
                continue
            if int(uids[0]) == 0:
                escaped(f"a root process is visible: pid {entry}")
            try:
                os.kill(int(entry), 0)
            except OSError:
                continue
            escaped(f"can signal a foreign process: pid {entry}")
        contained()
        ''', description="see or signal processes outside the sandbox"),
    Payload("symlink_copy_out", "copy_out", "copy_out_rejected", '''
        os.symlink("/etc/passwd", "/workspace/escape")
        os.symlink("../../../../", "/workspace/up")
        sys.exit(4)
        ''', description="plant symlinks that leave the workspace"),
    Payload("hardlink_copy_out", "copy_out", "copy_out_rejected", '''
        try:
            os.link("/etc/passwd", "/workspace/passwd")
        except OSError:
            pass
        with open("/workspace/a", "w") as handle:
            handle.write("x")
        os.link("/workspace/a", "/workspace/b")
        sys.exit(4)
        ''', description="plant hard links for the copy-out archive"),
    Payload("proc_sys_writes", "kernel_interfaces", "contained", '''
        for path in ("/proc/sys/kernel/hostname", "/proc/sysrq-trigger",
                     "/proc/sys/vm/drop_caches",
                     "/sys/kernel/uevent_helper",
                     "/sys/fs/cgroup/cgroup.procs",
                     "/proc/sys/kernel/core_pattern"):
            try:
                with open(path, "w") as handle:
                    handle.write("1")
            except OSError:
                continue
            escaped(f"wrote {path}")
        contained()
        ''', description="write kernel tunables through /proc and /sys"),
    Payload("host_credentials", "secrets", "contained", '''
        import re
        canary = "{CANARY}"
        for key, value in os.environ.items():
            if canary in value or key == "SIS_REDTEAM_HOST_CANARY":
                escaped(f"host environment leaked: {key}")
            if re.search(r"TOKEN|SECRET|PASSWORD|AWS_|GITHUB_|SIS_", key):
                escaped(f"credential-like variable present: {key}")
        for entry in os.listdir("/proc"):
            try:
                data = open(f"/proc/{entry}/environ", "rb").read()
            except OSError:
                continue
            if canary.encode() in data:
                escaped(f"canary in /proc/{entry}/environ")
        for path in ("/etc/shadow", "/root/.ssh/id_rsa",
                     "/root/.ssh/id_ed25519", "/root/.docker/config.json",
                     "/var/run/secrets/kubernetes.io/serviceaccount/token",
                     "/run/secrets"):
            try:
                if os.path.isdir(path):
                    if os.listdir(path):
                        escaped(f"secret directory readable: {path}")
                    continue
                open(path, "rb").read(1)
            except OSError:
                continue
            escaped(f"credential readable: {path}")
        contained()
        ''', description="read host environment and credential files"),
    Payload("post_attack_health", "health", "contained", '''
        print("ok")
        contained()
        ''', description="the sandbox still runs ordinary code afterwards"),
)


def classify(*, exit_status: int | None, timeout: bool,
             markers: tuple[str, ...] | list[str], error: str | None,
             host_symlinks: bool = False) -> str:
    """Map one run's observable facts to an outcome label."""
    if host_symlinks:
        return "escaped"
    if error is not None:
        if error.startswith("workspace_copy_out_failed"):
            return "copy_out_rejected"
        return "harness_error"
    markers = tuple(markers)
    if timeout:
        return "timeout"
    if any(marker.startswith("output:") for marker in markers):
        return "output_capped"
    if exit_status == ESCAPED_EXIT:
        return "escaped"
    if exit_status == STAGED_EXIT:
        return ("copy_out_rejected"
                if "fs:workspace_state_unavailable" in markers
                else "staged_accepted")
    if exit_status == 0:
        return "contained"
    return "limited"


def _has_symlinks(path: Path) -> bool:
    if not path.exists():
        return False
    return any(item.is_symlink() for item in path.rglob("*"))


def run_payload(executor, payload: Payload, *, base: Path,
                canary: str) -> dict:
    """Stage one payload as a workspace script and run it once."""
    base = base / payload.name
    base.mkdir()
    (base / "seed.txt").write_text("redteam")
    (base / SCRIPT).write_text(payload.script(canary))
    workspace = executor.prepare(base, label=payload.name)
    receipt = None
    error = None
    stdout = stderr = b""
    host_symlinks = False
    try:
        try:
            receipt = executor.run(workspace, CommandSpec(
                argv=ARGV, limits=payload.limits))
            stdout, stderr = executor.output(receipt.execution_id)
        except RunnerError as exc:
            error = str(exc)
        host_symlinks = _has_symlinks(Path(workspace.path))
    finally:
        executor.destroy(workspace)
    markers = tuple(receipt.security_errors) if receipt is not None else ()
    observed = classify(
        exit_status=receipt.exit_status if receipt is not None else None,
        timeout=bool(receipt.timeout) if receipt is not None else False,
        markers=markers, error=error, host_symlinks=host_symlinks)
    return {
        "name": payload.name,
        "category": payload.category,
        "description": payload.description,
        "expected": payload.expected,
        "observed": observed,
        "ok": observed == payload.expected,
        "exit_status": receipt.exit_status if receipt is not None else None,
        "timeout": bool(receipt.timeout) if receipt is not None else False,
        "markers": [m for m in markers
                    if not m.startswith(("docker:", "isolation:"))],
        "error": error,
        "stdout": stdout.decode("utf-8", "replace")[:300],
        "stderr": stderr.decode("utf-8", "replace")[-300:],
    }


def run_suite(executor, payloads=PAYLOADS) -> dict:
    """Run every payload; the host canary is set for the suite's duration."""
    canary = "canary-" + secrets.token_hex(12)
    previous = os.environ.get(CANARY_ENV)
    os.environ[CANARY_ENV] = canary
    temp = Path(tempfile.mkdtemp(prefix="sis-redteam-"))
    try:
        results = [run_payload(executor, payload, base=temp, canary=canary)
                   for payload in payloads]
    finally:
        shutil.rmtree(temp, ignore_errors=True)
        if previous is None:
            os.environ.pop(CANARY_ENV, None)
        else:
            os.environ[CANARY_ENV] = previous
    unexpected = [item["name"] for item in results if not item["ok"]]
    report = {
        "schema_version": 1,
        "kind": "docker_sandbox_redteam",
        "ok": not unexpected,
        "unexpected": unexpected,
        "payloads": len(results),
        "results": results,
    }
    for name in ("worker_identity", "runtime", "seccomp_profile_sha256"):
        report[name] = getattr(executor, name, None)
    for name in ("policy_digest", "image_id"):
        method = getattr(executor, name, None)
        try:
            report[name] = method() if callable(method) else None
        except RunnerError:
            report[name] = None
    report["docker_server_version"] = getattr(
        executor, "server_version", None)
    return report


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def build_executor(args, root: Path):
    from sis.v3.docker_sandbox import PRODUCTION_RUNTIME, DockerSandboxExecutor
    production = args.runtime == PRODUCTION_RUNTIME
    return DockerSandboxExecutor(
        root, image=args.image, production=production,
        runtime=args.runtime, seccomp_profile=args.seccomp_profile)


def main(argv=None, *, executor_factory=build_executor) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", required=True,
                        help="digest-pinned evaluator image")
    parser.add_argument("--output", type=Path,
                        default=Path("evidence/sandbox/redteam_report.json"))
    parser.add_argument("--runtime", choices=("runsc", "runc"),
                        default="runsc",
                        help="container runtime (production: runsc)")
    parser.add_argument("--seccomp-profile", type=Path,
                        default=DEFAULT_SECCOMP)
    parser.add_argument("--only", action="append", default=None,
                        help="run only the named payload (repeatable)")
    args = parser.parse_args(argv)
    payloads = PAYLOADS
    if args.only:
        names = {payload.name for payload in PAYLOADS}
        unknown = sorted(set(args.only) - names)
        if unknown:
            parser.error(f"unknown payloads: {', '.join(unknown)}")
        payloads = tuple(p for p in PAYLOADS if p.name in args.only)

    with tempfile.TemporaryDirectory(prefix="sis-redteam-root-") as root:
        executor = executor_factory(args, Path(root))
        try:
            report = run_suite(executor, payloads)
        finally:
            executor.terminate_all()
    document = {
        "generated_at": _utcnow(),
        "image": args.image,
        "note": ("Hostile-payload containment evidence for one launch "
                 "configuration. It is not a signed attestation and does "
                 "not prove the absence of kernel or gVisor defects."),
        **report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ok": document["ok"],
                      "payloads": document["payloads"],
                      "unexpected": document["unexpected"]}, indent=2))
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
