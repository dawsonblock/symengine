"""SIS v3.3.4 Linux rootless worker scaffold tests (Phase 2.4).

The containment itself can only be validated on Linux; these tests cover
the platform-independent contract here (argv confinement, config
validation, fail-closed behavior) and the host probe's refusal to run
off-Linux. Run ``tools/linux_worker_probe.py`` on the target host for
the actual namespace/limit evidence.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError
from sis.v3.linux_worker import (
    LinuxRootlessWorker,
    LinuxWorkerConfig,
    WorkerBackendUnavailable,
    build_bwrap_argv,
)
from sis.v3.runner import CommandSpec


class WorkerConfigTests(unittest.TestCase):
    def test_each_field_is_validated(self):
        for kwargs in (
                {"worker_identity": ""},
                {"worker_identity": "x" * 129},
                {"bwrap": ""},
                {"system_binds": ("relative",)},
                {"environment": (("A",),)},
                {"share_network": "yes"},
                {"max_output_bytes": 0},
        ):
            with self.subTest(**{k: str(v)[:20] for k, v in kwargs.items()}):
                with self.assertRaises(ContractError):
                    LinuxWorkerConfig(**kwargs)

    def test_digest_binds_network_policy(self):
        closed = LinuxWorkerConfig()
        shared = LinuxWorkerConfig(share_network=True)
        self.assertNotEqual(closed.digest, shared.digest)


class BwrapArgvTests(unittest.TestCase):
    def setUp(self):
        self.workspace = Path(tempfile.gettempdir()) / "sis-ws"
        self.spec = CommandSpec(
            argv=(sys.executable, "-c", "print(1)"),
            env={"SIS_EXTRA": "1"})

    def test_default_argv_is_confined(self):
        argv = build_bwrap_argv(
            LinuxWorkerConfig(), self.workspace, self.spec)
        self.assertIn("--unshare-all", argv)
        self.assertNotIn("--share-net", argv)
        self.assertIn("--die-with-parent", argv)
        self.assertIn("--new-session", argv)
        self.assertIn("--clearenv", argv)
        bind_at = argv.index("--bind")
        self.assertEqual(argv[bind_at + 1], str(self.workspace.resolve()))
        self.assertEqual(argv[bind_at + 2], "/workspace")
        self.assertIn("--chdir", argv)
        self.assertNotIn("--cap-add", argv)
        self.assertNotIn("--privileged", argv)
        self.assertEqual(argv[argv.index("--") + 1:], list(self.spec.argv))

    def test_network_share_is_explicit(self):
        argv = build_bwrap_argv(
            LinuxWorkerConfig(share_network=True), self.workspace, self.spec)
        self.assertIn("--share-net", argv)

    def test_environment_is_cleared_then_set(self):
        argv = build_bwrap_argv(
            LinuxWorkerConfig(environment=(("WORKER_ONLY", "1"),)),
            self.workspace, self.spec)
        env = {}
        for index, item in enumerate(argv):
            if item == "--setenv":
                env[argv[index + 1]] = argv[index + 2]
        self.assertEqual(env["HOME"], "/workspace")
        self.assertEqual(env["TMPDIR"], "/tmp")
        self.assertEqual(env["SIS_EXTRA"], "1")
        self.assertEqual(env["WORKER_ONLY"], "1")
        self.assertEqual(env["PATH"], "/usr/local/bin:/usr/bin:/bin")

    def test_system_binds_are_read_only(self):
        argv = build_bwrap_argv(
            LinuxWorkerConfig(system_binds=("/usr",)), self.workspace,
            self.spec)
        index = argv.index("--ro-bind")
        self.assertEqual(argv[index + 2], "/usr")


class FailClosedTests(unittest.TestCase):
    def test_non_linux_worker_fails_closed(self):
        if sys.platform.startswith("linux"):
            self.skipTest("Linux host: backend availability is probed")
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                    WorkerBackendUnavailable, "linux_required"):
                LinuxRootlessWorker(tmp)

    def test_probe_refuses_non_linux(self):
        if sys.platform.startswith("linux"):
            self.skipTest("Linux host: run tools/linux_worker_probe.py")
        from tools.linux_worker_probe import main
        with tempfile.TemporaryDirectory() as tmp:
            report_path = Path(tmp) / "probe.json"
            self.assertEqual(main(["--json", str(report_path)]), 2)
            import json
            report = json.loads(report_path.read_text())
            self.assertFalse(report["ok"])
            self.assertEqual(report["reason"], "linux_required")

    def test_worker_has_no_evaluator_key_access(self):
        import sis.v3.linux_worker as module
        source = Path(module.__file__).read_text(encoding="utf-8")
        for forbidden in (
                "EvaluatorKeyStore", "keystore", "ed25519.seed",
                "registry_dir", "OutcomeVerifier"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
