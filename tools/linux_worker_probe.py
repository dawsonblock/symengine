"""Probe a Linux host for the rootless worker's containment properties (2.4).

This tool is the evidence for choosing a worker backend. It runs on the
target Linux host, inside the same bubblewrap configuration the worker
uses, and reports whether each required property actually held:

- the sandbox can execute the interpreter;
- network connections are denied;
- writes and reads outside the workspace are denied;
- fork and memory limits fire;
- the wall clock kills the whole process group, including a child that
  tries to outlive its parent;
- the environment is scrubbed.

Exit codes: 0 all probes passed, 1 a probe failed, 2 the platform or
bubblewrap is unavailable. It never claims production qualification on
its own; a passing probe is platform evidence for the isolator.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

from sis.v3.linux_worker import (
    LinuxRootlessWorker,
    LinuxWorkerConfig,
    WorkerBackendUnavailable,
)
from sis.v3.runner import CommandSpec, ResourceLimits


def _limits(**overrides) -> ResourceLimits:
    fields = dict(
        cpu_seconds=5, wall_seconds=5, memory_bytes=256 << 20,
        output_bytes=1 << 20, disk_bytes=8 << 20, process_count=16)
    fields.update(overrides)
    return ResourceLimits(**fields)


def _run(worker, workspace, code, *, limits, extra_env=None):
    spec = CommandSpec(
        argv=(sys.executable, "-c", code),
        limits=limits,
        env=dict(extra_env or {}))
    receipt = worker.run(workspace, spec)
    stdout, stderr = worker.output(receipt.execution_id)
    return {
        "exit_status": receipt.exit_status,
        "timeout": receipt.timeout,
        "errors": list(receipt.security_errors),
        "stdout": stdout.decode("utf-8", "replace")[:600],
        "stderr": stderr.decode("utf-8", "replace")[:600],
    }


def _workspace(worker, base):
    return worker.prepare(base)


def _probe(worker, base, name, code, *, limits, predicate,
           extra_env=None, settle=0.0):
    try:
        workspace = _workspace(worker, base)
    except WorkerBackendUnavailable as exc:
        return {"ok": False, "reason": str(exc)}
    try:
        result = _run(worker, workspace, code, limits=limits,
                      extra_env=extra_env)
        if settle:
            time.sleep(settle)
        result["ok"] = bool(predicate(result, workspace))
        return result
    except WorkerBackendUnavailable as exc:
        return {"ok": False, "reason": str(exc)}
    finally:
        worker.destroy(workspace)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None,
                        help="write the full report here")
    parser.add_argument("--workspace", type=Path, default=None,
                        help="host directory for probe workspaces")
    args = parser.parse_args(argv)

    report = {
        "kind": "linux_worker_probe",
        "platform": sys.platform,
        "probes": {},
        "ok": False,
    }
    if not sys.platform.startswith("linux"):
        report["reason"] = "linux_required"
        _emit(report, args.json)
        return 2

    root = args.workspace or Path(
        tempfile.mkdtemp(prefix="sis-worker-probe-"))
    try:
        worker = LinuxRootlessWorker(root, config=LinuxWorkerConfig())
    except WorkerBackendUnavailable as exc:
        report["reason"] = str(exc)
        _emit(report, args.json)
        return 2
    report["worker_identity"] = worker.worker_identity
    report["bwrap"] = worker.config.bwrap

    base = root / "base"
    base.mkdir(parents=True, exist_ok=True)
    (base / "README.txt").write_text("probe\n", encoding="utf-8")
    host_secret = root / "host-secret.txt"
    host_secret.write_text("outside\n", encoding="utf-8")

    probes = report["probes"]
    probes["execute"] = _probe(
        worker, base, "execute", "print('alive')",
        limits=_limits(),
        predicate=lambda r, w: r["exit_status"] == 0 and "alive" in r["stdout"])

    probes["network_denied"] = _probe(
        worker, base, "network_denied",
        "import socket\n"
        "s = socket.socket(); s.settimeout(2)\n"
        "try:\n"
        "    s.connect(('1.1.1.1', 80)); print('CONNECTED')\n"
        "except OSError as exc:\n"
        "    print('DENIED', type(exc).__name__); raise SystemExit(1)\n",
        limits=_limits(),
        predicate=lambda r, w: "CONNECTED" not in r["stdout"])

    probes["write_outside_denied"] = _probe(
        worker, base, "write_outside_denied",
        "open('/etc/sis-probe-escape', 'w').write('x')\n",
        limits=_limits(),
        predicate=lambda r, w: r["exit_status"] != 0)

    probes["read_outside_denied"] = _probe(
        worker, base, "read_outside_denied",
        f"print(open({str(host_secret)!r}).read())\n",
        limits=_limits(),
        predicate=lambda r, w: r["exit_status"] != 0)

    probes["fork_bounded"] = _probe(
        worker, base, "fork_bounded",
        "import os\n"
        "for _ in range(100):\n"
        "    os.fork()\n",
        limits=_limits(process_count=8),
        predicate=lambda r, w: r["exit_status"] != 0)

    probes["memory_bounded"] = _probe(
        worker, base, "memory_bounded",
        "b = bytearray(4 * 1024 ** 3)\n",
        limits=_limits(memory_bytes=256 << 20),
        predicate=lambda r, w: r["exit_status"] != 0)

    probes["cgroup_pids"] = _probe(
        worker, base, "cgroup_pids",
        "import os\n"
        "for _ in range(100):\n"
        "    os.fork()\n",
        limits=_limits(process_count=8, wall_seconds=5),
        predicate=lambda r, w: (
            r["exit_status"] != 0
            and "cgroup:v2" in r["errors"]
            and not r["timeout"]))

    probes["cgroup_memory"] = _probe(
        worker, base, "cgroup_memory",
        "b = bytearray(4 * 1024 ** 3)\n",
        limits=_limits(memory_bytes=256 << 20, wall_seconds=5),
        predicate=lambda r, w: (
            r["exit_status"] != 0 and "cgroup:v2" in r["errors"]))

    probes["seccomp_mode"] = _probe(
        worker, base, "seccomp_mode",
        "for line in open('/proc/self/status'):\n"
        "    if line.startswith('Seccomp:'):\n"
        "        print(line.strip())\n",
        limits=_limits(),
        predicate=lambda r, w: any(
            f"seccomp:{mode}" in r["errors"]
            for mode in ("disabled", "strict", "filter")))

    probes["wall_clock_killed"] = _probe(
        worker, base, "wall_clock_killed",
        "import time\ntime.sleep(30)\n",
        limits=_limits(wall_seconds=1),
        predicate=lambda r, w: (
            r["timeout"] and "process:wall_clock_killed" in r["errors"]))

    probes["process_group_killed"] = _probe(
        worker, base, "process_group_killed",
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c',\n"
        "    \"import time; time.sleep(2); open('survived.txt','w').write('x')\"])\n"
        "time.sleep(30)\n",
        limits=_limits(wall_seconds=1),
        predicate=lambda r, w: (
            r["timeout"] and not (w.path / "survived.txt").exists()),
        settle=3.0)

    probes["environment_scrubbed"] = _probe(
        worker, base, "environment_scrubbed",
        "import os, json\n"
        "print(json.dumps(dict(os.environ)))\n",
        limits=_limits(),
        predicate=lambda r, w: (
            r["exit_status"] == 0
            and "SIS_" not in r["stdout"]
            and "EVALUATOR" not in r["stdout"].upper()
            and "/workspace" in r["stdout"]))

    probes["workspace_writable"] = _probe(
        worker, base, "workspace_writable",
        "open('written.txt', 'w').write('ok')\n",
        limits=_limits(),
        predicate=lambda r, w: (
            r["exit_status"] == 0 and (w.path / "written.txt").exists()))

    report["ok"] = all(item["ok"] for item in probes.values())
    _emit(report, args.json)
    return 0 if report["ok"] else 1


def _emit(report: dict, path: Path | None) -> None:
    text = json.dumps(report, indent=2, sort_keys=True)
    if path is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    print(text)


if __name__ == "__main__":
    raise SystemExit(main())
