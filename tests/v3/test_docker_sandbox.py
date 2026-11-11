"""Docker sandbox executor: fail-closed construction and containment probes.

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
        return True
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

    def test_host_interpreter_translation(self):
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter(
            sys.executable))
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter("python3"))
        self.assertTrue(DockerSandboxExecutor._is_host_interpreter(
            "/usr/local/bin/python3.12"))
        self.assertFalse(DockerSandboxExecutor._is_host_interpreter("pytest"))
        self.assertFalse(DockerSandboxExecutor._is_host_interpreter(
            "scripts/run.py"))


@unittest.skipUnless(_docker_ready(), f"Docker image {IMAGE} unavailable")
class ContainerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.base = root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n")
        self.executor = DockerSandboxExecutor(
            root / "exec", image=IMAGE, require_image_digest=False)
        self.workspace = self.executor.prepare(self.base, label="test")
        self.addCleanup(self.executor.destroy, self.workspace)

    def run_argv(self, argv, limits=None):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=tuple(argv), limits=limits or ResourceLimits()))
        return receipt, self.executor.output(receipt.execution_id)

    def test_container_runs_and_reports_controls(self):
        receipt, (stdout, _) = self.run_argv(
            ("python3", "-c", "print('ok')"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(stdout.decode().strip(), "ok")
        self.assertIn("isolation:docker_sandbox", receipt.security_errors)
        self.assertIn("docker:network_none", receipt.security_errors)
        self.assertIn("docker:read_only_root", receipt.security_errors)
        self.assertIn("docker:cap_drop_all", receipt.security_errors)
        self.assertIn("docker:no_new_privileges", receipt.security_errors)
        self.assertFalse(receipt.timeout)

    def test_network_is_denied(self):
        receipt, _ = self.run_argv(
            ("python3", "-c",
             "import socket; socket.create_connection(('1.1.1.1', 53), 2)"))
        self.assertNotEqual(receipt.exit_status, 0)

    def test_root_write_is_denied(self):
        receipt, _ = self.run_argv(
            ("python3", "-c", "open('/probe-escape', 'w')"))
        self.assertNotEqual(receipt.exit_status, 0)

    def test_workspace_write_is_allowed(self):
        receipt, _ = self.run_argv(
            ("python3", "-c",
             "open('/workspace/probe.txt', 'w').write('ok')"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertTrue((self.workspace.path / "probe.txt").is_file())

    def test_wall_clock_kills_the_container(self):
        receipt, _ = self.run_argv(
            ("python3", "-c", "import time; time.sleep(30)"),
            limits=ResourceLimits(wall_seconds=2, memory_bytes=256 << 20,
                                  output_bytes=65_536,
                                  disk_bytes=16 << 20, process_count=32))
        self.assertTrue(receipt.timeout)
        self.assertIn("process:wall_clock_killed", receipt.security_errors)

    def test_probe_reports_every_check(self):
        report = self.executor.probe()
        self.assertTrue(report["ok"], report)
        names = {check["name"] for check in report["checks"]}
        self.assertEqual(names, {
            "network_denied", "root_write_denied",
            "workspace_write_allowed", "non_root_user",
            "memory_limit_enforced", "pids_limit_enforced"})
