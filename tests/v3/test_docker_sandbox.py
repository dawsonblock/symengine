"""Docker sandbox executor: fail-closed construction and resource limits.

The integration tests require a working Docker daemon and the evaluator
image. They are skipped otherwise, so the unit-level fail-closed checks
still run in environments without Docker.
"""
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.runner import CommandSpec, ResourceLimits

IMAGE = "sis-evaluator:3.3.8"


def _docker_ready(image=IMAGE):
    if shutil.which("docker") is None:
        return False
    try:
        subprocess.run(["docker", "info"], check=True, capture_output=True,
                       timeout=30)
        subprocess.run(["docker", "image", "inspect", image], check=True,
                       capture_output=True, timeout=30)
        # A reachable daemon that cannot create a container (read-only
        # metadata store, exhausted VM disk, paused engine) is not a
        # usable integration environment; the class must skip, not fail.
        probe = subprocess.run(
            ["docker", "run", "--rm", "--network", "none",
             "--entrypoint", "python3", image, "-c", "pass"],
            capture_output=True, timeout=120)
        return probe.returncode == 0
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


class ConstructionTests(unittest.TestCase):
    def test_tagged_image_rejected_when_digest_required(self):
        with self.assertRaises(ContractError):
            DockerSandboxExecutor(image="sis-evaluator:3.3.8")

    def test_tagged_image_rejected_in_production(self):
        with self.assertRaises(ContractError):
            DockerSandboxExecutor(image="sis-evaluator:3.3.8",
                                  production=True)

    def test_empty_image_rejected(self):
        with self.assertRaises(ContractError):
            DockerSandboxExecutor(image="", require_image_digest=False)

    def test_root_user_is_rejected(self):
        for user in ("0", "0:0", "0:1000", "1000:0", "root", "root:root"):
            with self.subTest(user=user):
                with self.assertRaises(ContractError):
                    DockerSandboxExecutor(
                        image="sis-evaluator:3.3.8",
                        require_image_digest=False, user=user)

    def test_non_numeric_user_is_rejected(self):
        with self.assertRaises(ContractError):
            DockerSandboxExecutor(
                image="sis-evaluator:3.3.8",
                require_image_digest=False, user="nobody")

    def test_nofile_limit_is_bounded(self):
        for value in (0, -1, 1 << 21, "1024"):
            with self.subTest(value=value):
                with self.assertRaises(ContractError):
                    DockerSandboxExecutor(
                        image="sis-evaluator:3.3.8",
                        require_image_digest=False, nofile_limit=value)

    def test_host_interpreter_translation(self):
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter(
            sys.executable))
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter("python3"))
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter(
            "/usr/local/bin/python3.12"))
        self.assertFalse(DockerSandboxExecutor._is_host_interpreter("pytest"))
        self.assertFalse(DockerSandboxExecutor._is_host_interpreter(
            "scripts/run.py"))


def limits(**overrides):
    values = {"cpu_seconds": 20, "wall_seconds": 30, "memory_bytes": 512 << 20,
              "output_bytes": 1 << 20, "disk_bytes": 16 << 20,
              "process_count": 32}
    values.update(overrides)
    return ResourceLimits(**values)


@unittest.skipUnless(
    _docker_ready(), f"Docker daemon or image {IMAGE} unavailable")
class ContainerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.base = root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n")
        self.executor = self.make_executor()

    def make_executor(self, **kwargs):
        options = {
            "image": IMAGE,
            "require_image_digest": False,
            "root": tempfile.mkdtemp(dir=self.temp.name, prefix="exec-"),
        }
        options.update(kwargs)
        executor = DockerSandboxExecutor(**options)
        self.addCleanup(executor.terminate_all)
        return executor

    def run_argv(self, argv, *, executor=None, run_limits=None):
        executor = executor or self.executor
        workspace = executor.prepare(self.base, label="test")
        self.addCleanup(executor.destroy, workspace)
        receipt = executor.run(
            workspace, CommandSpec(argv=tuple(argv),
                                   limits=run_limits or limits()))
        return receipt, executor.output(receipt.execution_id), workspace

    def test_container_runs_and_reports_controls(self):
        receipt, (stdout, _), _ = self.run_argv(
            ("python3", "-c", "print('ok')"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(stdout.decode().strip(), "ok")
        self.assertIn("isolation:docker_sandbox", receipt.security_errors)
        self.assertIn("docker:network_none", receipt.security_errors)
        self.assertIn("docker:read_only_root", receipt.security_errors)
        self.assertIn("docker:cap_drop_all", receipt.security_errors)
        self.assertIn("docker:no_new_privileges", receipt.security_errors)
        self.assertIn("docker:tmpfs_workspace", receipt.security_errors)
        self.assertIn("docker:ulimit_cpu:20", receipt.security_errors)
        self.assertFalse(receipt.timeout)

    def test_network_is_denied(self):
        receipt, _, _ = self.run_argv(
            ("python3", "-c",
             "import socket; socket.create_connection(('1.1.1.1', 53), 2)"))
        self.assertNotEqual(receipt.exit_status, 0)

    def test_root_write_is_denied(self):
        receipt, _, _ = self.run_argv(
            ("python3", "-c", "open('/probe-escape', 'w')"))
        self.assertNotEqual(receipt.exit_status, 0)

    def test_workspace_write_is_allowed_and_copied_back(self):
        receipt, _, workspace = self.run_argv(
            ("python3", "-c",
             "open('/workspace/probe.txt', 'w').write('ok')"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertTrue((workspace.path / "probe.txt").is_file())
        self.assertEqual(
            (workspace.path / "probe.txt").read_text(), "ok")

    def test_wall_clock_kills_the_container(self):
        receipt, _, _ = self.run_argv(
            ("python3", "-c", "import time; time.sleep(30)"),
            run_limits=limits(wall_seconds=2))
        self.assertTrue(receipt.timeout)
        self.assertIn("process:wall_clock_killed", receipt.security_errors)
        self.assertIn("fs:workspace_state_unavailable",
                      receipt.security_errors)

    def test_cpu_time_budget_is_kernel_enforced(self):
        receipt, _, _ = self.run_argv(
            ("python3", "-c", "while True: pass"),
            run_limits=limits(cpu_seconds=1, wall_seconds=30))
        self.assertFalse(receipt.timeout)
        self.assertNotEqual(receipt.exit_status, 0)
        self.assertIn("docker:ulimit_cpu:1", receipt.security_errors)

    def test_pids_limit_uses_the_executor_cap(self):
        executor = self.make_executor(pids_limit=16)
        receipt, _, _ = self.run_argv(
            ("python3", "-c",
             "import subprocess\n"
             "procs = []\n"
             "for _ in range(64):\n"
             "    procs.append(subprocess.Popen("
             "['python3', '-c', 'pass']))\n"
             "print(len(procs))\n"),
            executor=executor,
            run_limits=limits(process_count=700))
        self.assertNotEqual(receipt.exit_status, 0)
        self.assertIn("docker:pids_limit:16", receipt.security_errors)

    def test_descriptor_budget_allows_a_normal_test_suite(self):
        receipt, (stdout, _), _ = self.run_argv(
            ("python3", "-c",
             "handles = [open('/tmp/f-%d' % i, 'w') for i in range(300)]\n"
             "print(len(handles))\n"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(stdout.strip(), b"300")
        self.assertIn("docker:ulimit_nofile:1024", receipt.security_errors)

    def test_output_limit_is_combined_across_streams(self):
        receipt, (stdout, stderr), _ = self.run_argv(
            ("python3", "-c",
             "import sys\n"
             "sys.stdout.write('o' * 200000)\n"
             "sys.stderr.write('e' * 200000)\n"),
            run_limits=limits(output_bytes=65_536))
        self.assertLessEqual(len(stdout) + len(stderr), 65_536)
        self.assertTrue(
            {"output:stdout_truncated", "output:stderr_truncated"}
            & set(receipt.security_errors))

    def test_output_limit_of_one_byte_is_never_exceeded(self):
        receipt, (stdout, stderr), _ = self.run_argv(
            ("python3", "-c", "print('hello')"),
            run_limits=limits(output_bytes=1))
        self.assertLessEqual(len(stdout) + len(stderr), 1)
        self.assertIn("output:stdout_truncated", receipt.security_errors)

    def test_memory_limit_terminates_execution(self):
        receipt, _, _ = self.run_argv(
            ("python3", "-c", "bytearray(512 * 1024 * 1024)"),
            run_limits=limits(memory_bytes=128 << 20))
        self.assertNotEqual(receipt.exit_status, 0)

    def test_disk_quota_blocks_writes_during_execution(self):
        receipt, _, workspace = self.run_argv(
            ("python3", "-c",
             "open('/workspace/big.bin', 'wb').write("
             "b'x' * (32 * 1024 * 1024))"),
            run_limits=limits(disk_bytes=8 << 20))
        self.assertNotEqual(receipt.exit_status, 0)
        written = workspace.path / "big.bin"
        if written.exists():
            self.assertLessEqual(written.stat().st_size, 8 << 20)

    def test_dot_directory_cwd_is_preserved(self):
        (self.base / ".config").mkdir()
        (self.base / ".config" / "check.py").write_text("print('cwd-ok')\n")
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        receipt = self.executor.run(workspace, CommandSpec(
            argv=("python3", "check.py"), cwd=".config", limits=limits()))
        stdout, _ = self.executor.output(receipt.execution_id)
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(stdout.strip(), b"cwd-ok")

    def test_pytest_acceptance_run_works_in_the_sandbox(self):
        (self.base / "test_ok.py").write_text(
            "def test_ok():\n    assert True\n")
        receipt, (stdout, _), _ = self.run_argv(
            ("python3", "-m", "pytest", "-q", "test_ok.py"),
            run_limits=limits(cpu_seconds=30, wall_seconds=60))
        self.assertEqual(receipt.exit_status, 0)
        self.assertIn(b"1 passed", stdout)

    def test_probe_reports_every_check(self):
        report = self.executor.probe()
        self.assertTrue(report["ok"], report)
        names = {check["name"] for check in report["checks"]}
        self.assertEqual(names, {
            "network_denied", "root_write_denied",
            "workspace_write_allowed", "non_root_user",
            "docker_socket_absent", "no_new_privileges",
            "capabilities_dropped", "setuid_denied",
            "memory_limit_enforced", "pids_limit_enforced",
            "disk_limit_enforced", "cpu_time_enforced",
            "output_limit_enforced"})
