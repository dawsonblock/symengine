"""Linux worker launch: no preexec_fn, cgroup joined before exec, PID option."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import linux_worker
from sis.v3.linux_worker import (
    LinuxRootlessWorker,
    LinuxWorkerConfig,
    build_bwrap_argv,
)
from sis.v3.runner import CommandSpec, ResourceLimits

PY = sys.executable

# Stands in for bubblewrap: drop every option and exec the inner command.
_FAKE_BWRAP = f"""#!{PY} -I
import os, sys
args = sys.argv[1:]
command = args[args.index("--") + 1:]
os.execvp(command[0], command)
"""


class _FakeCgroup:
    """A cgroup whose ``cgroup.procs`` is a plain file we can inspect."""

    instances: list["_FakeCgroup"] = []
    root: Path

    def __init__(self, _root):
        self.path = _FakeCgroup.root / f"leaf{len(_FakeCgroup.instances)}"
        _FakeCgroup.instances.append(self)
        self.killed = False

    def create(self, **_kwargs):
        self.path.mkdir()
        (self.path / "cgroup.procs").write_text("")
        return self

    def attach(self, pid):  # pragma: no cover - must not be used
        raise AssertionError("attach after Popen is the race being fixed")

    def kill(self):
        self.killed = True

    def remove(self):
        pass


class BwrapArgvTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.spec = CommandSpec(argv=(PY, "-c", "print(1)"))

    def test_pid_namespace_opt_out_is_honoured(self):
        default = build_bwrap_argv(
            LinuxWorkerConfig(apply_seccomp=False), self.workspace, self.spec)
        self.assertIn("--unshare-all", default)
        opted_out = build_bwrap_argv(
            LinuxWorkerConfig(apply_seccomp=False, use_pid_namespace=False),
            self.workspace, self.spec)
        self.assertNotIn("--unshare-all", opted_out)
        self.assertNotIn("--unshare-pid", opted_out)
        for flag in ("--unshare-user-try", "--unshare-ipc", "--unshare-uts",
                     "--unshare-cgroup-try", "--unshare-net"):
            self.assertIn(flag, opted_out)
        shared = build_bwrap_argv(
            LinuxWorkerConfig(apply_seccomp=False, use_pid_namespace=False,
                              share_network=True),
            self.workspace, self.spec)
        self.assertNotIn("--unshare-net", shared)

    def test_seccomp_wrapper_runs_isolated(self):
        argv = build_bwrap_argv(
            LinuxWorkerConfig(), self.workspace, self.spec,
            seccomp_dir=self.workspace)
        inner = argv[argv.index("--") + 1:]
        self.assertEqual(inner[:3], [PY, "-I", "/opt/sis-seccomp/seccomp_exec.py"])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux worker")
class WorkerLaunchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / "fake-bwrap"
        self.fake.write_text(_FAKE_BWRAP)
        self.fake.chmod(0o755)
        base = self.root / "base"
        base.mkdir()
        self.base = base
        _FakeCgroup.instances = []
        _FakeCgroup.root = self.root / "cgroups"
        _FakeCgroup.root.mkdir()

    def worker(self, **config) -> LinuxRootlessWorker:
        config.setdefault("apply_seccomp", False)
        config.setdefault("require_cgroups", False)
        return LinuxRootlessWorker(
            self.root / "exec",
            config=LinuxWorkerConfig(bwrap=str(self.fake), **config))

    def test_limits_without_preexec_fn(self):
        worker = self.worker()
        workspace = worker.prepare(self.base)
        self.addCleanup(worker.destroy, workspace)
        with mock.patch.object(subprocess, "Popen",
                               wraps=subprocess.Popen) as popen:
            receipt = worker.run(workspace, CommandSpec(
                argv=(PY, "-I", "-c",
                      "import resource; print(resource.getrlimit("
                      "resource.RLIMIT_NOFILE)[0], resource.getrlimit("
                      "resource.RLIMIT_FSIZE)[0])"),
                limits=ResourceLimits(disk_bytes=4242, process_count=None)))
        self.assertIsNone(popen.call_args.kwargs.get("preexec_fn"))
        self.assertEqual(popen.call_args.kwargs["cwd"], os.path.abspath(os.sep))
        stdout, stderr = worker.output(receipt.execution_id)
        self.assertEqual(receipt.exit_status, 0, stderr)
        self.assertEqual(stdout.decode().split(), ["256", "4242"])
        self.assertIn("rlimits:launcher", receipt.security_errors)
        self.assertIn("disk:per_file_limit_post_run_audit",
                      receipt.security_errors)

    def test_cgroup_is_joined_before_bwrap_starts(self):
        with mock.patch.object(linux_worker, "CgroupV2Controller", _FakeCgroup):
            worker = self.worker(require_cgroups=True)
            workspace = worker.prepare(self.base)
            self.addCleanup(worker.destroy, workspace)
            receipt = worker.run(workspace, CommandSpec(
                argv=(PY, "-I", "-c", "import os; print(os.getpid())"),
                limits=ResourceLimits(process_count=None)))
        stdout, stderr = worker.output(receipt.execution_id)
        self.assertEqual(receipt.exit_status, 0, stderr)
        procs = _FakeCgroup.instances[0].path / "cgroup.procs"
        # The launcher wrote its own pid, then exec'd into (fake) bwrap,
        # which exec'd the command: one pid, inside the cgroup from start.
        self.assertEqual(procs.read_text().strip(), stdout.decode().strip())
        self.assertIn("cgroup:v2", receipt.security_errors)

    def test_cgroup_join_failure_fails_closed(self):
        class Unjoinable(_FakeCgroup):
            def create(self, **_kwargs):
                self.path.mkdir()  # no cgroup.procs inside a missing dir
                self.path = self.path / "missing"
                return self

        marker = self.root / "RAN"
        with mock.patch.object(linux_worker, "CgroupV2Controller", Unjoinable):
            worker = self.worker(require_cgroups=True)
            workspace = worker.prepare(self.base)
            self.addCleanup(worker.destroy, workspace)
            with self.assertRaisesRegex(
                    linux_worker.WorkerBackendUnavailable,
                    "cgroup_attach_failed"):
                worker.run(workspace, CommandSpec(
                    argv=(PY, "-c", f"open({str(marker)!r}, 'w')")))
        self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
