"""Gate 2 containment repairs.

Covers the four reproduced/confirmed defects from the Gate 2 audit:
copy-out extraction over the declared disk budget, workspace loss on a
failed copy-out swap, private acceptance material staged inside the graded
workspace, and a patch target that resolves outside its base tree. It also
covers the fail-closed execution default: Docker unless local execution is
explicitly authorized.

The private-material tests additionally pin the integrity boundary: the
graded workspace is not importable before the acceptance runner starts
(no ``PYTHONPATH``, trusted bootstrap), the staging bounds match
registration, and a rewritten private file classifies as a sandbox
failure rather than a pass.
"""
import io
import os
import shlex
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.docker_sandbox import CopyOutBudgetError, DockerSandboxExecutor
from sis.v3.evaluation_runtime import (
    SANDBOX_FAILURE,
    TASK_PASS,
    classify_execution,
)
from sis.v3.evaluator_worker import (
    EvaluatorWorkerError,
    build_worker_executor,
    evaluate_via_subprocess,
)
from sis.v3.patcher import propose_edit, verify_proposal
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    ResourceLimits,
    RunnerError,
    private_command_spec,
    stage_private_material,
    tree_digest,
)
from sis.v3.verifier import OutcomeVerifier

PY = sys.executable


def limits(**overrides):
    values = {"cpu_seconds": 10, "wall_seconds": 20,
              "memory_bytes": 256 << 20, "output_bytes": 1 << 20,
              "disk_bytes": 16 << 20, "process_count": 16}
    values.update(overrides)
    return ResourceLimits(**values)


class FakeDockerFixture(unittest.TestCase):
    """A Docker CLI double that logs argv and serves a chosen tar payload."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n", encoding="utf-8")
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

    def prepare(self, **kwargs):
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        return workspace

    def logged_args(self):
        return self.log.read_text(encoding="utf-8").splitlines()


class CopyOutBudgetTests(FakeDockerFixture):
    def test_archive_over_the_disk_budget_is_rejected_while_reading(self):
        data = b"x" * (1 << 20)
        info = tarfile.TarInfo("big.bin")
        info.size = len(data)
        self.write_payload([(info, data)])
        workspace = self.prepare()
        receipt = self.executor.run(
            workspace, CommandSpec(
                argv=("python3", "-c", "pass"),
                limits=limits(disk_bytes=4096)))
        self.assertIn("fs:disk_budget_exceeded", receipt.security_errors)
        self.assertIn("fs:workspace_state_unavailable",
                      receipt.security_errors)
        self.assertIn("fs:copy_out_rejected:disk_budget_exceeded",
                      receipt.security_errors)
        self.assertFalse((workspace.path / "big.bin").exists())
        self.assertTrue((workspace.path / "calc.py").is_file())

    def test_archive_over_the_member_budget_is_rejected(self):
        members = []
        for index in range(3):
            info = tarfile.TarInfo(f"f{index}.txt")
            data = b"x"
            info.size = len(data)
            members.append((info, data))
        self.write_payload(members)
        workspace = self.prepare()
        with mock.patch(
                "sis.v3.docker_sandbox._COPY_OUT_MAX_MEMBERS", 2):
            receipt = self.executor.run(
                workspace, CommandSpec(argv=("python3", "-c", "pass")))
        self.assertIn("fs:copy_out_rejected:file_count_exceeded",
                      receipt.security_errors)
        self.assertIn("fs:file_count_exceeded", receipt.security_errors)
        self.assertNotIn("fs:disk_budget_exceeded", receipt.security_errors)
        self.assertFalse((workspace.path / "f0.txt").exists())

    def test_in_budget_archive_still_replaces_the_workspace(self):
        data = b"from-container"
        info = tarfile.TarInfo("copied.txt")
        info.size = len(data)
        self.write_payload([(info, data)])
        workspace = self.prepare()
        receipt = self.executor.run(
            workspace, CommandSpec(argv=("python3", "-c", "pass")))
        self.assertEqual(receipt.exit_status, 0)
        self.assertNotIn("fs:disk_budget_exceeded", receipt.security_errors)
        self.assertEqual(
            (workspace.path / "copied.txt").read_bytes(), data)

    def test_swap_failure_preserves_the_prepared_workspace(self):
        data = b"new"
        info = tarfile.TarInfo("copied.txt")
        info.size = len(data)
        self.write_payload([(info, data)])
        workspace = self.prepare()
        real_rename = os.rename
        calls = {"count": 0}

        def flaky(source, destination):
            calls["count"] += 1
            if calls["count"] == 2:
                raise OSError("simulated swap failure")
            return real_rename(source, destination)

        with mock.patch(
                "sis.v3.docker_sandbox.os.rename", side_effect=flaky):
            with self.assertRaisesRegex(
                    RunnerError, "workspace_copy_out_failed"):
                self.executor.run(
                    workspace, CommandSpec(argv=("python3", "-c", "pass")))
        self.assertTrue((workspace.path / "calc.py").is_file())
        self.assertFalse((workspace.path / "copied.txt").exists())

    def test_archive_over_the_stream_budget_is_rejected(self):
        members = []
        for index in range(3_000):
            info = tarfile.TarInfo(f"d{index}")
            info.type = tarfile.DIRTYPE
            info.size = 0
            members.append((info, None))
        self.write_payload(members)
        workspace = self.prepare()
        receipt = self.executor.run(
            workspace, CommandSpec(
                argv=("python3", "-c", "pass"),
                limits=limits(disk_bytes=1)))
        self.assertIn("fs:copy_out_rejected:archive_budget_exceeded",
                      receipt.security_errors)
        self.assertIn("fs:disk_budget_exceeded", receipt.security_errors)
        self.assertIn("fs:workspace_state_unavailable",
                      receipt.security_errors)
        self.assertTrue((workspace.path / "calc.py").is_file())

    def test_failed_restore_keeps_the_only_workspace_copy(self):
        data = b"new"
        info = tarfile.TarInfo("copied.txt")
        info.size = len(data)
        self.write_payload([(info, data)])
        workspace = self.prepare()
        real_rename = os.rename
        calls = {"count": 0}

        def flaky(source, destination):
            calls["count"] += 1
            if calls["count"] >= 2:
                raise OSError("simulated restore failure")
            return real_rename(source, destination)

        with mock.patch(
                "sis.v3.docker_sandbox.os.rename", side_effect=flaky):
            with self.assertRaisesRegex(
                    RunnerError, "workspace_restore_failed"):
                self.executor.run(
                    workspace, CommandSpec(argv=("python3", "-c", "pass")))
        retired = list(
            workspace.path.parent.glob(workspace.path.name + ".retired-*"))
        self.assertEqual(len(retired), 1)
        self.assertTrue((retired[0] / "calc.py").is_file())
        # Restore the prepared tree so the registered destroy can run.
        real_rename(retired[0], workspace.path)


class DockerPrivateMaterialTests(FakeDockerFixture):
    def test_private_material_is_mounted_outside_the_workspace(self):
        workspace = self.prepare()
        receipt = self.executor.run(
            workspace, CommandSpec(argv=("python3", "acc.py")),
            private_files={"acc.py": b"print('private-ok')\n"})
        self.assertEqual(receipt.exit_status, 0)
        self.assertIn("evaluation:private_material_separated",
                      receipt.security_errors)
        self.assertFalse((workspace.path / "acc.py").exists())
        args = self.logged_args()
        mounts = [args[index + 1]
                  for index, value in enumerate(args) if value == "--mount"]
        self.assertTrue(
            any("target=/private,readonly" in mount for mount in mounts),
            mounts)
        self.assertIn("/private/acc.py", args)
        self.assertIn("/private/_sis_bootstrap.py", args)
        self.assertIn("/workspace", args)
        self.assertNotIn("PYTHONPATH=/workspace", args)

    def test_private_material_names_must_stay_relative(self):
        workspace = self.prepare()
        with self.assertRaises(ContractError):
            self.executor.run(
                workspace, CommandSpec(argv=("python3", "-c", "pass")),
                private_files={"../escape.py": b"x"})

    def test_unrepresentable_mount_path_fails_closed(self):
        workspace = self.prepare()
        with mock.patch(
                "sis.v3.docker_sandbox.stage_private_material",
                return_value=Path("/tmp/with,comma")):
            with self.assertRaisesRegex(
                    RunnerError, "private_material_path_unrepresentable"):
                self.executor.run(
                    workspace, CommandSpec(argv=("python3", "acc.py")),
                    private_files={"acc.py": b"print('x')\n"})


class LocalPrivateMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, self.workspace)

    def test_private_script_runs_from_outside_the_workspace(self):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=(PY, "acc.py")),
            private_files={"acc.py": (
                b"import calc\n"
                b"assert calc.scale(3, 4) == 12\n"
                b"print('private-ok')\n")})
        stdout, _ = self.executor.output(receipt.execution_id)
        self.assertEqual(receipt.exit_status, 0, stdout)
        self.assertEqual(stdout.strip(), b"private-ok")
        self.assertFalse((self.workspace.path / "acc.py").exists())
        self.assertIn("evaluation:private_material_separated",
                      receipt.security_errors)

    def test_private_material_names_must_stay_relative(self):
        with self.assertRaises(ContractError):
            self.executor.run(
                self.workspace,
                CommandSpec(argv=(PY, "-c", "pass")),
                private_files={"../escape.py": b"x"})


class VerifierPrivateMaterialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        self.verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                self.root / "exec", use_seatbelt=False),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-separated",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": (
                b"import os, sys\n"
                b"sys.exit(0 if not os.path.exists('acceptance.py') else 3)\n")})
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="task-separated",
            repo_snapshot_digest=tree_digest(self.submission),
            base_commit=None, task_statement_digest="0" * 64,
            permitted_commands=("x",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=10,
            actor_id="a", evaluator_task_ref="task-separated")

    def test_acceptance_material_is_not_in_the_graded_workspace(self):
        receipt = self.verifier.evaluate(
            actor_role="evaluator", task=self.task,
            submission_dir=self.submission, evaluation_nonce="separated-1")
        self.assertEqual(receipt.outcome, "pass")

    def test_registration_enforces_the_staging_bounds(self):
        with self.assertRaisesRegex(ContractError, "file-count bound"):
            self.verifier.register_task(
                actor_role="evaluator", task_id="too-many",
                criterion_version="v1", argv=(PY, "acceptance.py"),
                files={f"t{index}.py": b"x" for index in range(65)})
        with self.assertRaisesRegex(ContractError, "byte bound"):
            self.verifier.register_task(
                actor_role="evaluator", task_id="too-big",
                criterion_version="v1", argv=(PY, "acceptance.py"),
                files={f"t{index}.py": b"x" * (1 << 20)
                       for index in range(9)})


class PatchTargetContainmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.outside = Path(self.temp.name) / "outside.py"

    def test_verification_rejects_a_target_that_resolves_outside_base(self):
        if not hasattr(os, "symlink"):
            self.skipTest("symlink fixture requires POSIX")
        source = b"return a - b\n"
        (self.root / "m.py").write_bytes(source)
        result = propose_edit(
            self.root, "m.py", b"a - b", b"a * b",
            proposer_id="p", purpose="fix")
        self.outside.write_bytes(source)
        (self.root / "m.py").unlink()
        (self.root / "m.py").symlink_to(self.outside)
        report = verify_proposal(
            self.root, result.proposal,
            result.patched_content, result.unified_diff)
        self.assertFalse(report["ok"])
        self.assertIn("target_escapes_base", report["problems"])

    def test_verification_still_accepts_an_in_tree_target(self):
        (self.root / "m.py").write_bytes(b"return a - b\n")
        result = propose_edit(
            self.root, "m.py", b"a - b", b"a * b",
            proposer_id="p", purpose="fix")
        report = verify_proposal(
            self.root, result.proposal,
            result.patched_content, result.unified_diff)
        self.assertTrue(report["ok"], report)


class PrivateCommandSpecTests(unittest.TestCase):
    def test_registered_arguments_and_node_ids_are_rewritten(self):
        spec = CommandSpec(
            argv=(PY, "-m", "pytest", "eval_tests.py::test_case"),
            env={"PYTHONPATH": "/existing"})
        rewritten = private_command_spec(
            spec, names={"eval_tests.py"}, prefix="/private",
            workspace="/workspace")
        self.assertEqual(
            rewritten.argv,
            (PY, "/private/_sis_bootstrap.py", "/workspace",
             "-m", "pytest", "/private/eval_tests.py::test_case"))
        self.assertEqual(rewritten.env, {"PYTHONPATH": "/existing"})

    def test_dot_prefixed_argument_is_rewritten(self):
        spec = CommandSpec(argv=(PY, "./acc.py"))
        rewritten = private_command_spec(
            spec, names={"acc.py"}, prefix="/private", workspace="/workspace")
        self.assertEqual(rewritten.argv[-1], "/private/acc.py")

    def test_unregistered_arguments_are_unchanged(self):
        spec = CommandSpec(argv=(PY, "-m", "pytest", "-q"))
        rewritten = private_command_spec(
            spec, names={"eval_tests.py"}, prefix="/private",
            workspace="/workspace")
        self.assertEqual(
            rewritten.argv,
            (PY, "/private/_sis_bootstrap.py", "/workspace",
             "-m", "pytest", "-q"))

    def test_non_python_command_is_not_wrapped(self):
        spec = CommandSpec(argv=("/bin/echo", "acc.py"))
        rewritten = private_command_spec(
            spec, names={"acc.py"}, prefix="/private", workspace="/workspace")
        self.assertEqual(rewritten.argv, ("/bin/echo", "/private/acc.py"))


class PrivateMaterialBoundsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_file_count_is_bounded(self):
        files = {f"t{index}.py": b"x" for index in range(65)}
        with self.assertRaisesRegex(ContractError, "file-count bound"):
            stage_private_material(self.root, files)

    def test_total_bytes_are_bounded(self):
        files = {f"t{index}.py": b"x" * (1 << 20) for index in range(9)}
        with self.assertRaisesRegex(ContractError, "byte bound"):
            stage_private_material(self.root, files)

    def test_single_file_is_bounded(self):
        with self.assertRaisesRegex(ContractError, "bounded bytes"):
            stage_private_material(
                self.root, {"big.py": b"x" * ((1 << 20) + 1)})

    def test_names_must_be_normalized(self):
        with self.assertRaisesRegex(ContractError, "normalized relative"):
            stage_private_material(self.root, {"a//b.py": b"x"})

    def test_bootstrap_name_is_reserved(self):
        with self.assertRaisesRegex(ContractError, "reserved"):
            stage_private_material(
                self.root, {"_sis_bootstrap.py": b"x"}, bootstrap=True)


class BootstrapIsolationTests(unittest.TestCase):
    """The workspace must not be importable before the runner starts."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        (self.base / "sitecustomize.py").write_text(
            "import os\nos._exit(0)\n", encoding="utf-8")
        (self.base / "pytest.py").write_text(
            "import sys\nsys.exit(0)\n", encoding="utf-8")
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, self.workspace)

    def test_submission_cannot_hijack_startup_or_shadow_pytest(self):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=(PY, "-m", "pytest", "-q", "acc.py")),
            private_files={"acc.py": (
                b"import calc\n"
                b"def test_scale():\n"
                b"    assert calc.scale(3, 4) == 12\n"
                b"def test_fail():\n"
                b"    assert False\n")})
        stdout, stderr = self.executor.output(receipt.execution_id)
        self.assertEqual(receipt.exit_status, 1, (stdout, stderr))
        self.assertNotIn(b"sitecustomize", stdout)
        self.assertNotIn(b"shadowed", stdout)

    def test_private_test_can_still_import_the_submission(self):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=(PY, "-m", "pytest", "-q", "acc.py")),
            private_files={"acc.py": (
                b"import calc\n"
                b"def test_scale():\n"
                b"    assert calc.scale(3, 4) == 12\n")})
        self.assertEqual(receipt.exit_status, 0)


class PrivateMaterialTamperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n", encoding="utf-8")
        self.executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        self.workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, self.workspace)

    def test_rewritten_private_material_is_a_sandbox_failure(self):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=(PY, "acc.py")),
            private_files={"acc.py": (
                b"import os, sys\n"
                b"os.chmod(__file__, 0o644)\n"
                b"open(__file__, 'w').write('# tampered')\n"
                b"sys.exit(0)\n")})
        self.assertIn("sandbox:private_material_modified",
                      receipt.security_errors)
        self.assertEqual(classify_execution(receipt), SANDBOX_FAILURE)

    def test_untouched_private_material_is_not_marked(self):
        receipt = self.executor.run(
            self.workspace,
            CommandSpec(argv=(PY, "acc.py")),
            private_files={"acc.py": b"print('ok')\n"})
        self.assertNotIn("sandbox:private_material_modified",
                         receipt.security_errors)
        self.assertEqual(classify_execution(receipt), TASK_PASS)


class ExtractBoundedTests(unittest.TestCase):
    def test_sparse_member_is_rejected(self):
        member = mock.Mock()
        member.isdir.return_value = False
        member.isreg.return_value = True
        member.sparse = [object()]
        member.size = 1
        archive = mock.MagicMock()
        archive.__iter__.return_value = iter([member])
        archive.__enter__.return_value = archive
        with mock.patch(
                "sis.v3.docker_sandbox.tarfile.open", return_value=archive):
            with self.assertRaisesRegex(
                    CopyOutBudgetError, "sparse_member_rejected"):
                DockerSandboxExecutor._extract_bounded(
                    object(), Path("/tmp/staging"), 1024)


class WorkerExecutorDefaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key_dir = self.root / "keys"
        self.registry_dir = self.root / "registry"
        self.repo = self.root / "repo"
        self.key_dir.mkdir()
        self.registry_dir.mkdir()
        self.repo.mkdir()
        (self.repo / "calc.py").write_text("x = 1\n", encoding="utf-8")
        self.task = TaskEnvelopeV1(
            schema_version=1, task_id="t1",
            repo_snapshot_digest=tree_digest(self.repo), base_commit=None,
            task_statement_digest="0" * 64, permitted_commands=("x",),
            isolation_profile="unverified_local", time_budget_seconds=60,
            token_budget=1000, tool_budget=10, actor_id="a",
            evaluator_task_ref="t1")

    def test_worker_defaults_to_docker_and_requires_an_image(self):
        with self.assertRaisesRegex(
                EvaluatorWorkerError, "sandbox_image_required"):
            evaluate_via_subprocess(
                key_dir=self.key_dir, registry_dir=self.registry_dir,
                task=self.task, submission_dir=self.repo,
                evaluation_nonce="default-1")

    def test_worker_refuses_local_without_explicit_authorization(self):
        with self.assertRaisesRegex(
                EvaluatorWorkerError,
                "local_executor_requires_explicit_authorization"):
            evaluate_via_subprocess(
                key_dir=self.key_dir, registry_dir=self.registry_dir,
                task=self.task, submission_dir=self.repo,
                evaluation_nonce="default-2", executor="local")

    def test_executor_builder_refuses_local_without_authorization(self):
        with self.assertRaisesRegex(
                EvaluatorWorkerError,
                "local_executor_requires_explicit_authorization"):
            build_worker_executor(executor="local", executor_root=self.root)

    def test_executor_builder_refuses_docker_without_an_image(self):
        with self.assertRaisesRegex(
                EvaluatorWorkerError, "sandbox_image_required"):
            build_worker_executor(executor="docker", executor_root=self.root)


if __name__ == "__main__":
    unittest.main()
