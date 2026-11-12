"""Workspace ownership invariant across every executor backend (v3.3.8).

A ``Workspace`` handle is a capability. These tests forge handles with a
valid ID but a substituted path, replay a workspace against a different
executor, redirect the managed directory through a symlink, and race
destruction against a live execution. Every case must be rejected before
a mount, an execution, or a delete touches the substituted path.
"""
from __future__ import annotations

import io
import os
import shlex
import shutil
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.contracts import ContractError
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.linux_worker import LinuxRootlessWorker, LinuxWorkerConfig
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    ResourceLimits,
    RunnerError,
    Workspace,
)
from sis.v3.workspace_guard import (
    ManagedWorkspaceRegistry,
    WorkspaceOwnershipError,
    protected_overlap,
)

PY = sys.executable
POSIX = os.name == "posix"


def fast_limits(**overrides):
    values = {"cpu_seconds": 20, "wall_seconds": 15, "memory_bytes": 1 << 30,
              "output_bytes": 1 << 20, "disk_bytes": 16 << 20,
              "process_count": 64}
    values.update(overrides)
    return ResourceLimits(**values)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n", encoding="utf-8")
        self.outside = self.root / "outside"
        self.outside.mkdir()
        self.sentinel = self.outside / "keep.txt"
        self.sentinel.write_text("do not delete\n", encoding="utf-8")

    def forged(self, workspace, path):
        return Workspace(
            workspace_id=workspace.workspace_id,
            path=path,
            before_tree_digest=workspace.before_tree_digest,
            executor_identity=workspace.executor_identity,
        )


class RegistryContractTests(Fixture):
    def registry(self, name="exec"):
        return ManagedWorkspaceRegistry(
            self.root / name, executor_identity="worker-A")

    def test_allocate_register_and_resolve_round_trip(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.mkdir()
        record = registry.register(
            workspace_id, path, before_tree_digest="d" * 64)
        self.assertEqual(record.path, path)
        resolved = registry.resolve(
            workspace_id, path, executor_identity="worker-A")
        self.assertEqual(resolved, record)

    def test_register_rejects_path_outside_workspace_root(self):
        registry = self.registry()
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "outside_workspace_root"):
            registry.register(
                "ws-" + "0" * 16, self.outside, before_tree_digest="d")

    def test_register_rejects_symlinked_workspace_directory(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.symlink_to(self.outside)
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "not_a_managed_directory"):
            registry.register(workspace_id, path, before_tree_digest="d")

    def test_resolve_rejects_unknown_id_and_substituted_path(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.mkdir()
        registry.register(workspace_id, path, before_tree_digest="d")
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "not_registered"):
            registry.resolve(
                "ws-" + "1" * 16, path, executor_identity="worker-A")
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "path_substituted"):
            registry.resolve(
                workspace_id, self.outside, executor_identity="worker-A")

    def test_resolve_rejects_other_executor_identity(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.mkdir()
        registry.register(workspace_id, path, before_tree_digest="d")
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "identity_mismatch"):
            registry.resolve(
                workspace_id, path, executor_identity="worker-B")

    def test_remove_is_idempotent_and_stays_inside_the_root(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.mkdir()
        (path / "file.txt").write_text("x")
        record = registry.register(
            workspace_id, path, before_tree_digest="d")
        self.assertTrue(registry.remove(record))
        self.assertTrue(registry.remove(record))
        self.assertFalse(path.exists())
        self.assertTrue(self.sentinel.exists())

    def test_destroy_of_unknown_id_never_touches_a_path(self):
        registry = self.registry()
        record = registry.begin_destroy(
            "ws-" + "2" * 16, self.outside, executor_identity="worker-A")
        self.assertIsNone(record)
        self.assertTrue(self.sentinel.exists())

    def test_symlink_swap_is_rejected_before_deletion(self):
        registry = self.registry()
        workspace_id, path = registry.allocate()
        path.mkdir()
        registry.register(workspace_id, path, before_tree_digest="d")
        shutil.rmtree(path)
        path.symlink_to(self.outside)
        with self.assertRaisesRegex(
                WorkspaceOwnershipError, "symlink_escape"):
            registry.begin_destroy(
                workspace_id, path, executor_identity="worker-A")
        self.assertTrue(self.sentinel.exists())


class LocalOwnershipTests(Fixture):
    def setUp(self):
        super().setUp()
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(self.base)
        self.spec = CommandSpec(
            argv=(PY, "-c", "print('ok')"), limits=fast_limits())

    def test_valid_workspace_runs_and_uses_registry_digest(self):
        receipt = self.executor.run(self.workspace, self.spec)
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(
            receipt.before_tree_digest, self.workspace.before_tree_digest)

    def test_receipt_digest_comes_from_the_registry_not_the_handle(self):
        forged = Workspace(
            self.workspace.workspace_id, self.workspace.path,
            "f" * 64, self.workspace.executor_identity)
        receipt = self.executor.run(forged, self.spec)
        self.assertEqual(
            receipt.before_tree_digest, self.workspace.before_tree_digest)

    def test_symlink_alias_of_the_workspace_is_rejected(self):
        if not POSIX:
            self.skipTest("symlink fixture requires POSIX")
        alias = self.root / "alias"
        alias.symlink_to(self.workspace.path)
        forged = self.forged(self.workspace, alias)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.executor.run(forged, self.spec)
        self.assertTrue(self.workspace.path.exists())

    def test_forged_path_is_rejected_for_run_and_destroy(self):
        forged = self.forged(self.workspace, self.outside)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.executor.run(forged, self.spec)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.executor.destroy(forged)
        self.assertTrue(self.sentinel.exists())
        self.assertTrue(self.workspace.path.exists())

    def test_unknown_workspace_id_is_rejected(self):
        unknown = Workspace(
            "ws-" + "3" * 16, self.outside,
            self.workspace.before_tree_digest,
            self.workspace.executor_identity)
        with self.assertRaisesRegex(RunnerError, "not_registered"):
            self.executor.run(unknown, self.spec)
        self.executor.destroy(unknown)
        self.assertTrue(self.sentinel.exists())

    def test_workspace_from_another_executor_is_rejected(self):
        other = LocalSubprocessExecutor(
            self.root / "exec-other", use_seatbelt=False)
        with self.assertRaisesRegex(RunnerError, "not_registered"):
            other.run(self.workspace, self.spec)
        other.destroy(self.workspace)
        self.assertTrue(self.workspace.path.exists())

    def test_mismatched_executor_identity_is_rejected(self):
        forged = Workspace(
            self.workspace.workspace_id, self.workspace.path,
            self.workspace.before_tree_digest, "worker-B")
        with self.assertRaisesRegex(RunnerError, "identity_mismatch"):
            self.executor.run(forged, self.spec)
        with self.assertRaisesRegex(RunnerError, "identity_mismatch"):
            self.executor.destroy(forged)
        self.assertTrue(self.workspace.path.exists())

    def test_symlink_redirected_workspace_is_rejected(self):
        shutil.rmtree(self.workspace.path)
        self.workspace.path.symlink_to(self.outside)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.executor.run(self.workspace, self.spec)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.executor.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())

    def test_deleted_workspace_is_rejected_before_execution(self):
        shutil.rmtree(self.workspace.path)
        with self.assertRaisesRegex(RunnerError, "path_missing"):
            self.executor.run(self.workspace, self.spec)

    def test_constructor_protected_paths_cannot_overlap_the_root(self):
        with self.assertRaisesRegex(RunnerError, "must not overlap"):
            LocalSubprocessExecutor(
                self.root / "exec-protected", use_seatbelt=False,
                protected_paths=(self.root,))

    def test_repeated_destroy_has_no_additional_effects(self):
        self.executor.destroy(self.workspace)
        self.assertFalse(self.workspace.path.exists())
        self.executor.destroy(self.workspace)
        self.executor.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())

    def test_concurrent_execution_and_destroy_never_races_deletion(self):
        receipts, refusals = {}, []

        def run():
            try:
                receipts["receipt"] = self.executor.run(
                    self.workspace,
                    CommandSpec(
                        argv=(PY, "-c", "import time; time.sleep(30)"),
                        limits=fast_limits(wall_seconds=60)))
            except RunnerError as exc:
                refusals.append(str(exc))

        thread = threading.Thread(target=run)
        thread.start()
        for _ in range(200):
            if self.executor._live:
                break
            time.sleep(0.01)
        self.executor.destroy(self.workspace)
        thread.join(timeout=30)
        self.assertFalse(thread.is_alive())
        self.assertFalse(self.workspace.path.exists())
        self.assertTrue(self.sentinel.exists())
        self.assertTrue(receipts or refusals)
        if receipts:
            self.assertNotEqual(receipts["receipt"].exit_status, 0)

    def test_protected_material_cannot_enter_a_workspace(self):
        secret = self.root / "keys"
        secret.mkdir()
        (secret / "seed").write_text("SECRET")
        self.executor.protect(secret)
        with self.assertRaisesRegex(
                RunnerError, "overlaps_protected_material"):
            self.executor.prepare(secret)
        nested = self.root / "base-with-keys"
        (nested / "keys").mkdir(parents=True)
        (nested / "keys" / "seed").write_text("SECRET")
        self.executor.protect(nested / "keys")
        with self.assertRaisesRegex(
                RunnerError, "overlaps_protected_material"):
            self.executor.prepare(nested)

    def test_protected_path_cannot_overlap_the_executor_root(self):
        with self.assertRaisesRegex(RunnerError, "must not overlap"):
            self.executor.protect(self.executor.root / "inside")
        with self.assertRaisesRegex(RunnerError, "must not overlap"):
            self.executor.protect(self.root)

    def test_symlink_inside_workspace_is_rejected_before_execution(self):
        if not POSIX:
            self.skipTest("symlink fixture requires POSIX")
        (self.workspace.path / "escape").symlink_to("/etc/hosts")
        with self.assertRaisesRegex(RunnerError, "external symlinks"):
            self.executor.run(self.workspace, self.spec)

    def test_protected_overlap_helper_is_symmetric(self):
        protected = self.root / "keys"
        protected.mkdir()
        self.assertEqual(
            protected_overlap(protected / "nested", [protected]),
            protected.resolve())
        self.assertEqual(
            protected_overlap(self.root, [protected]), protected.resolve())
        self.assertIsNone(protected_overlap(self.base, [protected]))


class DockerOwnershipTests(Fixture):
    def setUp(self):
        super().setUp()
        self.log = self.root / "docker-args.log"
        self.payload = self.root / "payload.tar"
        self.write_payload([])
        self.fake = self.root / "fake-docker"
        self.fake.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$@\" >> {shlex.quote(str(self.log))}\n"
            "case \"$1\" in\n"
            "  inspect) echo true ;;\n"
            "  exec)\n"
            "    case \" $* \" in\n"
            f"      *\" tar \"*) cat {shlex.quote(str(self.payload))} ;;\n"
            "    esac\n"
            "    ;;\n"
            "esac\n"
            "exit 0\n",
            encoding="utf-8")
        self.fake.chmod(0o755)
        self.executor = self.make_executor()
        self.workspace = self.executor.prepare(self.base)
        self.spec = CommandSpec(argv=("python3", "-c", "print('ok')"))

    def make_executor(self, **kwargs):
        options = {
            "image": "sis-evaluator:3.3.8",
            "require_image_digest": False,
            "docker_binary": str(self.fake),
            "image_id": "0" * 64,
            "root": tempfile.mkdtemp(dir=self.temp.name, prefix="exec-"),
        }
        options.update(kwargs)
        with mock.patch.object(
                DockerSandboxExecutor, "_require_docker",
                return_value="test-server"):
            executor = DockerSandboxExecutor(**options)
        self.addCleanup(executor.terminate_all)
        return executor

    def write_payload(self, members):
        with tarfile.open(self.payload, "w") as archive:
            for info, data in members:
                archive.addfile(info, io.BytesIO(data) if data else None)

    def run_payload(self, members, *, executor=None):
        self.write_payload(members)
        executor = executor or self.executor
        workspace = executor.prepare(self.base)
        self.addCleanup(executor.destroy, workspace)
        return executor.run(workspace, self.spec), workspace

    def test_mount_uses_the_registry_path_not_the_handle(self):
        receipt = self.executor.run(self.workspace, self.spec)
        self.assertEqual(receipt.exit_status, 0)
        argv = self.log.read_text(encoding="utf-8").splitlines()
        mount = argv[argv.index("--mount") + 1]
        self.assertEqual(
            mount,
            f"type=bind,source={self.workspace.path.resolve()},"
            "target=/submission,readonly")

    def test_copy_out_replaces_the_workspace_with_the_payload(self):
        info = tarfile.TarInfo("copied.txt")
        data = b"from-container"
        info.size = len(data)
        receipt, workspace = self.run_payload([(info, data)])
        self.assertEqual(receipt.exit_status, 0)
        self.assertEqual(
            (workspace.path / "copied.txt").read_bytes(), data)

    def test_copy_out_does_not_stall_on_a_stderr_flood(self):
        flood = self.root / "flood-docker"
        flood.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  inspect) echo true ;;\n"
            "  exec)\n"
            "    case \" $* \" in\n"
            "      *\" tar \"*)\n"
            "        python3 -c \"import sys; sys.stderr.write('e' * 200000)\"\n"
            f"        cat {shlex.quote(str(self.payload))}\n"
            "        ;;\n"
            "    esac\n"
            "    ;;\n"
            "esac\n"
            "exit 0\n",
            encoding="utf-8")
        flood.chmod(0o755)
        executor = self.make_executor(docker_binary=str(flood))
        finished = {}

        def run():
            workspace = executor.prepare(self.base)
            try:
                finished["receipt"] = executor.run(workspace, self.spec)
            finally:
                executor.destroy(workspace)

        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=60)
        self.assertFalse(thread.is_alive(), "copy-out blocked on tar stderr")
        self.assertEqual(finished["receipt"].exit_status, 0)

    def test_copy_out_rejects_a_parent_escape(self):
        info = tarfile.TarInfo("../escape.txt")
        data = b"escape"
        info.size = len(data)
        with self.assertRaisesRegex(
                RunnerError, "workspace_copy_out_failed"):
            self.run_payload([(info, data)])
        self.assertFalse((self.root / "escape.txt").exists())
        self.assertFalse((self.root.parent / "escape.txt").exists())

    def test_copy_out_rejects_an_absolute_symlink(self):
        info = tarfile.TarInfo("link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        with self.assertRaisesRegex(
                RunnerError, "workspace_copy_out_failed"):
            self.run_payload([(info, None)])

    def test_copy_out_rejects_a_device_node(self):
        info = tarfile.TarInfo("dev")
        info.type = tarfile.CHRTYPE
        info.devmajor = 1
        info.devminor = 3
        with self.assertRaisesRegex(
                RunnerError, "workspace_copy_out_failed"):
            self.run_payload([(info, None)])

    def test_deleted_workspace_is_rejected_before_the_container_launches(self):
        shutil.rmtree(self.workspace.path)
        with self.assertRaisesRegex(RunnerError, "path_missing"):
            self.executor.run(self.workspace, self.spec)

    def test_forged_path_is_rejected_before_the_container_launches(self):
        forged = self.forged(self.workspace, self.outside)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.executor.run(forged, self.spec)
        self.assertFalse(self.log.exists())
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.executor.destroy(forged)
        self.assertTrue(self.sentinel.exists())

    def test_unknown_and_foreign_workspaces_are_rejected(self):
        unknown = Workspace(
            "ws-" + "4" * 16, self.outside,
            self.workspace.before_tree_digest,
            self.workspace.executor_identity)
        with self.assertRaisesRegex(RunnerError, "not_registered"):
            self.executor.run(unknown, self.spec)
        self.executor.destroy(unknown)
        self.assertTrue(self.sentinel.exists())
        other = self.make_executor()
        with self.assertRaisesRegex(RunnerError, "not_registered"):
            other.run(self.workspace, self.spec)
        other.destroy(self.workspace)
        self.assertTrue(self.workspace.path.exists())

    def test_symlink_redirected_workspace_is_rejected(self):
        shutil.rmtree(self.workspace.path)
        self.workspace.path.symlink_to(self.outside)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.executor.run(self.workspace, self.spec)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.executor.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())

    def test_repeated_destroy_has_no_additional_effects(self):
        self.executor.destroy(self.workspace)
        self.assertFalse(self.workspace.path.exists())
        self.executor.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())


class LinuxWorkerOwnershipTests(Fixture):
    def setUp(self):
        super().setUp()
        with mock.patch("sys.platform", "linux"), mock.patch(
                "sis.v3.linux_worker.shutil.which", return_value="/bin/true"):
            self.worker = LinuxRootlessWorker(
                self.root / "exec",
                config=LinuxWorkerConfig(
                    apply_seccomp=False, require_cgroups=False))
        self.workspace = self.worker.prepare(self.base)
        self.spec = CommandSpec(argv=(PY, "-c", "print('ok')"))

    def test_prepare_registers_inside_the_worker_root(self):
        self.assertEqual(
            self.workspace.path.parent,
            self.worker.root / "workspaces")
        self.assertTrue(self.workspace.path.is_dir())

    def test_forged_path_is_rejected_for_run_and_destroy(self):
        forged = self.forged(self.workspace, self.outside)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.worker.run(forged, self.spec)
        with self.assertRaisesRegex(RunnerError, "path_substituted"):
            self.worker.destroy(forged)
        self.assertTrue(self.sentinel.exists())
        self.assertTrue(self.workspace.path.exists())

    def test_unknown_workspace_id_is_rejected(self):
        unknown = Workspace(
            "ws-" + "5" * 16, self.outside,
            self.workspace.before_tree_digest,
            self.workspace.executor_identity)
        with self.assertRaisesRegex(RunnerError, "not_registered"):
            self.worker.run(unknown, self.spec)
        self.worker.destroy(unknown)
        self.assertTrue(self.sentinel.exists())

    def test_symlink_redirected_workspace_is_rejected(self):
        shutil.rmtree(self.workspace.path)
        self.workspace.path.symlink_to(self.outside)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.worker.run(self.workspace, self.spec)
        with self.assertRaisesRegex(RunnerError, "symlink_escape"):
            self.worker.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())

    def test_deleted_workspace_is_rejected_before_execution(self):
        shutil.rmtree(self.workspace.path)
        with self.assertRaisesRegex(RunnerError, "path_missing"):
            self.worker.run(self.workspace, self.spec)

    def test_repeated_destroy_has_no_additional_effects(self):
        self.worker.destroy(self.workspace)
        self.assertFalse(self.workspace.path.exists())
        self.worker.destroy(self.workspace)
        self.assertTrue(self.sentinel.exists())

    def test_protected_material_cannot_enter_a_workspace(self):
        secret = self.root / "keys"
        secret.mkdir()
        (secret / "seed").write_text("SECRET")
        self.worker.protect(secret)
        with self.assertRaisesRegex(
                RunnerError, "overlaps_protected_material"):
            self.worker.prepare(secret)


class CommandSpecStillValidates(unittest.TestCase):
    def test_unrelated_contract_error_is_unchanged(self):
        with self.assertRaises(ContractError):
            CommandSpec(argv=("../escape",))


if __name__ == "__main__":
    unittest.main()
