"""Local runner launcher, limits and process-lifetime regressions."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import runner as runner_module
from sis.v3.evaluation_runtime import SANDBOX_FAILURE, TASK_PASS, classify_execution
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    ResourceLimits,
    launcher_markers,
    limit_launcher_argv,
    read_launcher_status,
)

PY = sys.executable
POSIX = os.name == "posix"
_LINUX = sys.platform.startswith("linux")


def _LIFETIME_LIMITS(wall_seconds: int) -> ResourceLimits:
    # Lifetime tests exercise reaping, not RLIMIT_NPROC. The default
    # process_count counts every process the user owns, so on a host where
    # the user already runs more (macOS CI) the submission could not fork.
    return ResourceLimits(wall_seconds=wall_seconds, process_count=None)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/stat", "rb") as handle:
            state = handle.read().rsplit(b")", 1)[1].split()[0]
        return state != b"Z"
    except OSError:
        return True


@unittest.skipUnless(POSIX, "POSIX launcher")
class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        self.marker = self.root / "SHADOW_RAN"
        # Modules the launcher may import. A workspace copy must never run
        # in the launcher, which executes before limits and outside any
        # sandbox wrapper.
        for name in ("resource", "ctypes", "signal", "time", "encodings"):
            (self.base / f"{name}.py").write_text(
                f"open({str(self.marker)!r}, 'a').write({name!r})\n")
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, self.workspace)

    def test_launcher_never_imports_from_the_workspace(self):
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=("true",),
            env={"PYTHONPATH": str(self.workspace.path),
                 "PYTHONSTARTUP": str(self.workspace.path / "resource.py")}))
        self.assertEqual(receipt.exit_status, 0,
                         self.executor.output(receipt.execution_id))
        self.assertFalse(self.marker.exists())
        self.assertIn("rlimits:launcher", receipt.security_errors)

    def test_launcher_uses_isolated_mode_and_a_neutral_cwd(self):
        argv = limit_launcher_argv(["true"], [], cwd="/somewhere")
        self.assertEqual(argv[:3], [sys.executable, "-I", "-c"])
        with mock.patch.object(subprocess, "Popen",
                               wraps=subprocess.Popen) as popen:
            self.executor.run(self.workspace, CommandSpec(argv=("true",)))
        self.assertEqual(popen.call_args.kwargs["cwd"],
                         os.path.abspath(os.sep))
        self.assertIn("-I", popen.call_args.args[0][:2])

    def test_command_still_runs_in_its_workspace_cwd(self):
        (self.base / "sub").mkdir()
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        receipt = self.executor.run(workspace, CommandSpec(
            argv=(PY, "-I", "-c", "import os; print(os.getcwd())"),
            cwd="sub"))
        stdout, _ = self.executor.output(receipt.execution_id)
        self.assertEqual(Path(stdout.decode().strip()).resolve(),
                         (workspace.path / "sub").resolve())

    def test_limits_are_applied(self):
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-I", "-c",
                  "import resource; print(resource.getrlimit("
                  "resource.RLIMIT_FSIZE)[0])"),
            limits=ResourceLimits(disk_bytes=12345, process_count=None)))
        stdout, _ = self.executor.output(receipt.execution_id)
        self.assertEqual(stdout.decode().strip(), "12345")

    def test_an_unsettable_limit_fails_closed_and_is_recorded(self):
        def bad(limits, errors, **_kwargs):
            return [("RLIMIT_CPU", 10, 5)]  # soft > hard: EINVAL
        with mock.patch.object(runner_module, "limit_triples", bad):
            receipt = self.executor.run(self.workspace, CommandSpec(
                argv=(PY, "-I", "-c",
                      f"open({str(self.root / 'RAN')!r}, 'w')")))
        self.assertFalse((self.root / "RAN").exists())
        self.assertNotIn("rlimits:launcher", receipt.security_errors)
        self.assertTrue(any(
            error.startswith("sandbox:rlimits_not_applied:rlimit_failed")
            for error in receipt.security_errors), receipt.security_errors)
        self.assertEqual(classify_execution(receipt), SANDBOX_FAILURE)

    def test_launcher_status_markers(self):
        self.assertEqual(launcher_markers("L"), ["rlimits:launcher"])
        self.assertEqual(launcher_markers("LS"),
                         ["rlimits:launcher", "process:subreaper"])
        self.assertEqual(launcher_markers(""),
                         ["sandbox:rlimits_not_applied:no_status"])
        read_end, write_end = os.pipe()
        proc = subprocess.Popen(
            limit_launcher_argv(["true"], [("RLIMIT_NOPE", 1, 1)],
                                status_fd=write_end),
            pass_fds=(write_end,), stderr=subprocess.DEVNULL)
        os.close(write_end)
        self.assertEqual(proc.wait(timeout=30), 71)
        self.assertEqual(read_launcher_status(read_end),
                         "Frlimit_unavailable:RLIMIT_NOPE")

    def test_cgroup_procs_is_joined_before_exec(self):
        procs = self.root / "cgroup.procs"
        procs.write_text("")
        completed = subprocess.run(
            limit_launcher_argv(
                [PY, "-I", "-c", "import os; print(os.getpid())"], [],
                cgroup_procs=procs),
            capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(procs.read_text().strip(), completed.stdout.strip())

    def test_an_unjoinable_cgroup_refuses_to_run(self):
        completed = subprocess.run(
            limit_launcher_argv(
                [PY, "-c", f"open({str(self.root / 'RAN')!r}, 'w')"], [],
                cgroup_procs=self.root / "missing" / "cgroup.procs"),
            capture_output=True, text=True, timeout=30)
        self.assertEqual(completed.returncode, 71)
        self.assertFalse((self.root / "RAN").exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "subreaper is Linux")
class DarwinMemoryLimitTests(unittest.TestCase):
    """macOS refuses RLIMIT_AS below the interpreter's address space."""

    def test_darwin_omits_rlimit_as_and_records_it(self):
        errors: list[str] = []
        with mock.patch.object(runner_module.sys, "platform", "darwin"):
            triples = runner_module.limit_triples(
                ResourceLimits(process_count=None), errors)
        self.assertNotIn("RLIMIT_AS", [name for name, _s, _h in triples])
        self.assertIn("memory:not_enforced", errors)

    def test_darwin_marker_does_not_change_the_verdict(self):
        receipt = mock.Mock(security_errors=("memory:not_enforced",),
                            exit_status=0, timeout=False)
        self.assertEqual(classify_execution(receipt, bootstrap_ok=True),
                         TASK_PASS)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux bounds AS")
    def test_linux_still_bounds_memory(self):
        errors: list[str] = []
        triples = runner_module.limit_triples(
            ResourceLimits(process_count=None), errors)
        self.assertIn("RLIMIT_AS", [name for name, _s, _h in triples])
        self.assertNotIn("memory:not_enforced", errors)


class ProcessLifetimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        base = self.root / "base"
        base.mkdir()
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(base)
        self.addCleanup(self.executor.destroy, self.workspace)
        self.pidfile = self.root / "child.pid"

    def _pid(self) -> int:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                text = self.pidfile.read_text().strip()
            except OSError:
                text = ""
            if text:
                return int(text)
            time.sleep(0.05)
        self.fail("child never wrote its pid")

    def _assert_dead(self, pid: int) -> None:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and _alive(pid):
            time.sleep(0.05)
        if _alive(pid):
            os.kill(pid, signal.SIGKILL)
            self.fail(f"process {pid} outlived the run")

    def test_background_child_does_not_outlive_a_normal_exit(self):
        code = (
            "import subprocess, sys\n"
            "p = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)'], stdout=subprocess.DEVNULL, "
            "stderr=subprocess.DEVNULL)\n"
            f"open({str(self.pidfile)!r}, 'w').write(str(p.pid))\n")
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-c", code), limits=_LIFETIME_LIMITS(20)))
        self.assertFalse(receipt.timeout)
        self._assert_dead(self._pid())

    @unittest.skipUnless(_LINUX, "subreaper reaping is Linux-only")
    def test_setsid_child_does_not_outlive_a_normal_exit(self):
        code = (
            "import os, sys, time\n"
            "if os.fork() == 0:\n"
            "    os.setsid()\n"
            "    os.closerange(0, 3)\n"
            f"    open({str(self.pidfile)!r}, 'w').write(str(os.getpid()))\n"
            "    time.sleep(60)\n"
            "    os._exit(0)\n"
            "time.sleep(0.5)\n")
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-c", code), limits=_LIFETIME_LIMITS(20)))
        self.assertFalse(receipt.timeout)
        self.assertIn("process:subreaper", receipt.security_errors)
        self._assert_dead(self._pid())

    @unittest.skipUnless(_LINUX, "subreaper reaping is Linux-only")
    def test_setsid_child_does_not_outlive_a_timeout(self):
        code = (
            "import os, time\n"
            "if os.fork() == 0:\n"
            "    os.setsid()\n"
            f"    open({str(self.pidfile)!r}, 'w').write(str(os.getpid()))\n"
            "    time.sleep(60)\n"
            "    os._exit(0)\n"
            "time.sleep(60)\n")
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-c", code), limits=_LIFETIME_LIMITS(2)))
        self.assertTrue(receipt.timeout)
        self._assert_dead(self._pid())

    def test_exit_status_and_signals_pass_through_the_supervisor(self):
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-c", "raise SystemExit(7)")))
        self.assertEqual(receipt.exit_status, 7)
        receipt = self.executor.run(self.workspace, CommandSpec(
            argv=(PY, "-c", "import os, signal; "
                  "os.kill(os.getpid(), signal.SIGTERM)")))
        self.assertEqual(receipt.exit_status, -signal.SIGTERM)


if __name__ == "__main__":
    unittest.main()
