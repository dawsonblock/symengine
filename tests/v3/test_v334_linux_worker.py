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

from sis.v3.cgroups import CgroupUnavailable, CgroupV2Controller
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
                {"require_cgroups": "yes"},
                {"require_seccomp": 1},
                {"bind_etc_files": "no"},
                {"apply_seccomp": "yes"},
                {"cgroup_root": "relative"},
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
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(tempfile.gettempdir()) / "sis-ws"
        self.seccomp_dir = Path(self.temp.name) / "seccomp"
        self.seccomp_dir.mkdir()
        self.spec = CommandSpec(
            argv=(sys.executable, "-c", "print(1)"),
            env={"SIS_EXTRA": "1"})

    def _argv(self, config):
        return build_bwrap_argv(
            config, self.workspace, self.spec,
            seccomp_dir=self.seccomp_dir)

    def test_default_argv_is_confined(self):
        argv = self._argv(LinuxWorkerConfig())
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
        self.assertEqual(
            argv[-len(self.spec.argv):], list(self.spec.argv))

    def test_etc_is_hardened_to_individual_files(self):
        argv = self._argv(LinuxWorkerConfig())
        self.assertIn("--tmpfs", argv)
        self.assertEqual(argv[argv.index("--tmpfs") + 1], "/etc")
        self.assertIn("--remount-ro", argv)
        self.assertEqual(argv[argv.index("--remount-ro") + 1], "/etc")
        binds = [
            (argv[i + 1], argv[i + 2])
            for i, item in enumerate(argv) if item == "--ro-bind"
        ]
        self.assertNotIn("/etc", [destination for _source, destination in binds])
        for _source, destination in binds:
            if destination.startswith("/etc/"):
                self.assertIn(destination, {
                    "/etc/ld.so.cache", "/etc/localtime", "/etc/passwd",
                    "/etc/group", "/etc/nsswitch.conf"})

    def test_etc_can_be_disabled(self):
        argv = self._argv(LinuxWorkerConfig(bind_etc_files=False))
        tmpfs_targets = [
            argv[i + 1] for i, item in enumerate(argv) if item == "--tmpfs"]
        self.assertNotIn("/etc", tmpfs_targets)
        self.assertNotIn("--remount-ro", argv)

    def test_seccomp_wrapper_is_bound_and_invoked(self):
        argv = self._argv(LinuxWorkerConfig())
        pairs = [
            (argv[i + 1], argv[i + 2])
            for i, item in enumerate(argv) if item == "--ro-bind"
        ]
        self.assertIn(
            (str(self.seccomp_dir.resolve()), "/opt/sis-seccomp"), pairs)
        inner = argv[argv.index("--") + 1:]
        self.assertEqual(inner[0], sys.executable)
        self.assertEqual(inner[1], "/opt/sis-seccomp/seccomp_exec.py")
        self.assertEqual(inner[2], "--")
        self.assertEqual(inner[3:], list(self.spec.argv))

    def test_seccomp_can_be_disabled(self):
        argv = self._argv(LinuxWorkerConfig(apply_seccomp=False))
        self.assertNotIn("/opt/sis-seccomp", argv)
        self.assertEqual(argv[argv.index("--") + 1:], list(self.spec.argv))

    def test_private_material_is_bound_outside_the_workspace(self):
        private = Path(self.temp.name) / "private"
        private.mkdir()
        argv = build_bwrap_argv(
            LinuxWorkerConfig(), self.workspace, self.spec,
            seccomp_dir=self.seccomp_dir, private_dir=private)
        pairs = [
            (argv[i + 1], argv[i + 2])
            for i, item in enumerate(argv) if item == "--ro-bind"
        ]
        self.assertIn((str(private.resolve()), "/private"), pairs)

    def test_network_share_is_explicit(self):
        argv = self._argv(LinuxWorkerConfig(share_network=True))
        self.assertIn("--share-net", argv)

    def test_environment_is_cleared_then_set(self):
        argv = self._argv(LinuxWorkerConfig(environment=(("WORKER_ONLY", "1"),)))
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
        argv = self._argv(LinuxWorkerConfig(system_binds=("/usr",)))
        index = argv.index("--ro-bind")
        self.assertEqual(argv[index + 2], "/usr")


class SeccompFilterTests(unittest.TestCase):
    def test_filter_has_arch_check_and_denials(self):
        from sis.v3.seccomp_exec import (
            AUDIT_ARCH_AARCH64,
            AUDIT_ARCH_X86_64,
            SECCOMP_RET_ALLOW,
            SECCOMP_RET_ERRNO,
            SECCOMP_RET_KILL_PROCESS,
            build_filter,
        )
        for arch, audit in (
                ("x86_64", AUDIT_ARCH_X86_64),
                ("aarch64", AUDIT_ARCH_AARCH64)):
            filters = build_filter(arch)
            self.assertGreater(len(filters), 10)
            self.assertEqual(filters[1].k, audit)
            self.assertEqual(filters[-3].k, SECCOMP_RET_ALLOW)
            self.assertEqual(filters[-2].k, SECCOMP_RET_KILL_PROCESS)
            self.assertEqual(filters[-1].k, SECCOMP_RET_ERRNO | 1)

    def test_unsupported_arch_rejected(self):
        from sis.v3.seccomp_exec import SeccompUnavailable, detect_arch
        with self.assertRaises(SeccompUnavailable):
            detect_arch("riscv64")

    def test_apply_fails_closed_off_linux(self):
        if sys.platform.startswith("linux"):
            self.skipTest("Linux: the probe applies the real filter")
        from sis.v3.seccomp_exec import SeccompUnavailable, apply_filter
        with self.assertRaises(SeccompUnavailable):
            apply_filter()


class CgroupControllerTests(unittest.TestCase):
    """cgroup v2 leaf behavior; real enforcement is probed on Linux."""

    def test_requires_cgroup_v2(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(
                    CgroupUnavailable, "cgroup_v2_required"):
                CgroupV2Controller(tmp)

    def test_existing_leaf_name_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cgroup.controllers").write_text("pids memory\n")
            (root / "cgroup.subtree_control").write_text("+pids +memory\n")
            (root / "sis-test").mkdir()
            controller = CgroupV2Controller(root, name="sis-test")
            with self.assertRaisesRegex(
                    CgroupUnavailable, "cgroup_name_conflict"):
                controller.create()

    def test_missing_controller_reports_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cgroup.controllers").write_text("pids memory\n")
            (root / "cgroup.subtree_control").write_text("")
            controller = CgroupV2Controller(root, name="sis-test")
            with self.assertRaisesRegex(
                    CgroupUnavailable, "cgroup_controller_unavailable"):
                controller.create(pids_max=8)
            self.assertFalse(controller.path.exists())

    def test_attach_rejects_invalid_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "cgroup.controllers").write_text("pids\n")
            (root / "cgroup.subtree_control").write_text("+pids\n")
            controller = CgroupV2Controller(root, name="sis-test")
            controller.path.mkdir()
            controller._created = True
            with self.assertRaises(ValueError):
                controller.attach(0)
            controller.remove()

    def test_real_leaf_if_host_provides_one(self):
        if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            self.skipTest("cgroup v2 not present on this host")
        try:
            controller = CgroupV2Controller()
            controller.create(pids_max=8, memory_max=1 << 28)
        except CgroupUnavailable as exc:
            self.skipTest(f"cgroup leaf unavailable: {exc}")
        try:
            self.assertEqual(
                (controller.path / "pids.max").read_text().strip(), "8")
            self.assertEqual(
                (controller.path / "memory.max").read_text().strip(),
                str(1 << 28))
        finally:
            controller.remove()


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
