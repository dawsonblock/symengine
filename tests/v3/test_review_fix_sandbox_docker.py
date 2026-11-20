"""Docker container argv: cleanable containers and representable mounts.

These tests mock the Docker CLI; the integration suite needs a daemon.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sis.v3 import docker_sandbox
from sis.v3.docker_sandbox import CONTAINER_LABEL, DockerSandboxExecutor
from sis.v3.runner import CommandSpec, ResourceLimits


class DockerArgvTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               return_value="test"):
            self.executor = DockerSandboxExecutor(
                self.root / "exec", image="sis-evaluator:test",
                require_image_digest=False, user="1000:1000",
                split_user="1001:1001")
        self.calls: list[list[str]] = []

    def fake_run(self, command, **_kwargs):
        self.calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, "", "")

    def start(self, real_path: Path):
        record = SimpleNamespace(real_path=real_path)
        limits = ResourceLimits(process_count=None)
        with mock.patch.object(docker_sandbox.subprocess, "run",
                               self.fake_run):
            self.executor._start_container(
                "sis-exec-test", record, CommandSpec(argv=("true",)),
                limits, 1 << 30, 64, 1 << 20)
        return self.calls[-1]

    def test_containers_are_removed_on_stop_and_labelled(self):
        command = self.start(self.root)
        self.assertIn("--rm", command)
        label = command[command.index("--label") + 1]
        self.assertEqual(label, f"{CONTAINER_LABEL}={self.executor.worker_identity}")

    def test_the_workspace_host_path_is_never_mounted(self):
        # The workspace is streamed in by _copy_in, so a host path that
        # the --mount grammar could not represent never reaches the argv.
        path = self.root / "a,target=/etc"
        command = self.start(path)
        self.assertNotIn(str(path), " ".join(command))
        self.assertFalse(any("/submission" in part for part in command))

    def test_background_processes_are_stopped_as_each_principal(self):
        with mock.patch.object(docker_sandbox.subprocess, "run",
                               self.fake_run):
            self.executor._stop_background("sis-exec-test", split=True)
        users = [call[call.index("--user") + 1] for call in self.calls]
        self.assertEqual(users, ["1000:1000", "1001:1001"])
        for call in self.calls:
            self.assertEqual(call[-3:], ["sh", "-c",
                                         "kill -9 -1 2>/dev/null; exit 0"])


if __name__ == "__main__":
    unittest.main()
