"""Process-split custody for private acceptance material.

The Gate 2 repair separated the private directory from the graded
workspace, but the acceptance runner and the submitted code still shared
one process and one OS principal, so a submission could read the tests it
was graded against. These tests pin the split:

* the submission runs in a worker that cannot read the private directory,
  even when the acceptance test hands it the exact path;
* the evaluator-side proxy still returns values and propagates errors;
* a backend without a second principal fails closed instead of falling
  back to shared custody;
* the Docker backend runs the worker under a second numeric UID.
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

from sis.v3 import split_harness
from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.evaluation_runtime import EVALUATOR_BOOTSTRAP_ERROR, SANDBOX_FAILURE
from sis.v3.linux_worker import LinuxRootlessWorker
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    RunnerError,
    stage_private_material,
    tree_digest,
)
from sis.v3.split_harness import (
    MARKER_SEPARATE_UID,
    MARKER_SPLIT,
    MARKER_WORKER_LOST,
    SPLIT_BOOTSTRAP_NAME,
    SPLIT_BOOTSTRAP_SOURCE,
    SPLIT_INI_NAME,
    SPLIT_INI_SOURCE,
    SplitClient,
    SplitProtocolError,
)
from sis.v3.verifier import EvaluationRejected, OutcomeVerifier

PY = sys.executable

PROBE_SUBMISSION = (
    "import os\n"
    "\n"
    "def add(a, b):\n"
    "    return a + b\n"
    "\n"
    "def probe(path):\n"
    "    try:\n"
    "        with open(os.path.join(path, 'acceptance.py')) as handle:\n"
    "            handle.read()\n"
    "        return 'read'\n"
    "    except Exception as exc:\n"
    "        return type(exc).__name__\n"
    "\n"
    "def boom():\n"
    "    raise ValueError('worker-side')\n"
)


def probe_acceptance(expected):
    return (
        "import os\n"
        "import solution\n"
        "\n"
        "def test_add():\n"
        "    assert solution.add(2, 3) == 5\n"
        "\n"
        "def test_probe():\n"
        "    result = solution.probe(os.path.dirname(__file__))\n"
        f"    assert result == {expected!r}, result\n"
        "\n"
        "def test_error_propagates():\n"
        "    try:\n"
        "        solution.boom()\n"
        "    except ValueError as exc:\n"
        "        assert 'worker-side' in str(exc)\n"
        "    else:\n"
        "        raise AssertionError('no error')\n"
    )


class SplitFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.submission = self.root / "submission"
        self.submission.mkdir()
        (self.submission / "solution.py").write_text(
            PROBE_SUBMISSION, encoding="utf-8")

    def make_verifier(self, executor):
        return OutcomeVerifier(
            executor=executor, key_dir=self.root / "keys",
            registry_dir=self.root / "registry")

    def envelope(self, task_id):
        return TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(self.submission),
            base_commit=None, task_statement_digest="0" * 64,
            permitted_commands=("x",), isolation_profile="unverified_local",
            time_budget_seconds=60, token_budget=1000, tool_budget=10,
            actor_id="a", evaluator_task_ref=task_id)


class SplitStagingTests(unittest.TestCase):
    def test_private_mode_is_owner_only(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        material = stage_private_material(
            temp.name, {"acceptance.py": b"x = 1\n"},
            private_mode=True, split_bootstrap=True)
        self.assertEqual(os.stat(material).st_mode & 0o777, 0o700)
        self.assertEqual(
            os.stat(material / "acceptance.py").st_mode & 0o777, 0o400)
        self.assertEqual(
            os.stat(material / SPLIT_BOOTSTRAP_NAME).st_mode & 0o777, 0o400)
        self.assertTrue((material / "pytest.ini").is_file())

    def test_shared_mode_keeps_the_legacy_modes(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        material = stage_private_material(
            temp.name, {"acceptance.py": b"x = 1\n"}, bootstrap=True)
        self.assertEqual(os.stat(material).st_mode & 0o777, 0o755)
        self.assertEqual(
            os.stat(material / "acceptance.py").st_mode & 0o777, 0o444)


class LocalSplitCustodyTests(SplitFixture):
    def setUp(self):
        super().setUp()
        self.executor = LocalSubprocessExecutor(self.root / "exec")
        if not self.executor.supports_split_custody:
            self.skipTest("split custody requires seatbelt")
        self.addCleanup(self.executor.terminate_all)

    def evaluate(self, task_id, custody, expected):
        verifier = self.make_verifier(self.executor)
        verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="acceptance-v1",
            argv=(PY, "-m", "pytest", "-q", "acceptance.py"),
            files={"acceptance.py": probe_acceptance(expected).encode()},
            custody=custody)
        receipt = verifier.evaluate(
            actor_role="evaluator", task=self.envelope(task_id),
            submission_dir=self.submission, evaluation_nonce=task_id)
        return receipt, verifier

    def test_submission_cannot_read_the_private_tests(self):
        receipt, verifier = self.evaluate("split", "split", "PermissionError")
        self.assertEqual(receipt.outcome, "pass", verifier.last_outcome_class)
        self.assertEqual(verifier.last_outcome_class, "TASK_PASS")

    def test_shared_custody_can_read_the_same_file(self):
        # Control: the probe is not vacuous. Under shared custody the
        # submission runs beside the tests and reads them.
        receipt, verifier = self.evaluate("shared", "shared", "read")
        self.assertEqual(receipt.outcome, "pass", verifier.last_outcome_class)

    def test_package_submodules_are_proxied(self):
        # A submission laid out as a package keeps its submodules: the
        # proxy has to answer for them, or a valid submission is graded as
        # a failure it never made.
        (self.submission / "pkg" / "sub").mkdir(parents=True)
        (self.submission / "pkg" / "__init__.py").write_text(
            "def add(a, b):\n    return a + b\n", encoding="utf-8")
        (self.submission / "pkg" / "sub" / "__init__.py").write_text(
            "", encoding="utf-8")
        (self.submission / "pkg" / "sub" / "util.py").write_text(
            "def helper():\n    return 7\n", encoding="utf-8")
        acceptance = (
            "from pkg.sub import util\n"
            "import pkg\n"
            "\n"
            "def test_nested():\n"
            "    assert pkg.add(2, 3) == 5\n"
            "    assert util.helper() == 7\n"
        )
        verifier = self.make_verifier(self.executor)
        verifier.register_task(
            actor_role="evaluator", task_id="package",
            criterion_version="acceptance-v1",
            argv=(PY, "-m", "pytest", "-q", "acceptance.py"),
            files={"acceptance.py": acceptance.encode()},
            custody="split")
        receipt = verifier.evaluate(
            actor_role="evaluator", task=self.envelope("package"),
            submission_dir=self.submission, evaluation_nonce="package")
        self.assertEqual(receipt.outcome, "pass", verifier.last_outcome_class)

    def test_a_lost_worker_is_a_sandbox_failure(self):
        # A worker that dies is a harness failure. It must never be
        # recorded as the candidate's failure.
        with mock.patch.object(
                split_harness, "WORKER_SOURCE", "raise SystemExit(3)\n"):
            receipt, verifier = self.evaluate("lost", "split", "read")
        self.assertEqual(receipt.outcome, "error")
        self.assertEqual(verifier.last_outcome_class, SANDBOX_FAILURE)

    def test_the_receipt_names_the_lost_worker(self):
        workspace = self.executor.prepare(self.submission)
        self.addCleanup(self.executor.destroy, workspace)
        with mock.patch.object(
                split_harness, "WORKER_SOURCE", "raise SystemExit(3)\n"):
            receipt = self.executor.run(
                workspace, CommandSpec(argv=(PY, "-c", "pass")),
                private_files={"acceptance.py": b"x = 1\n"},
                split_custody=True)
        self.assertIn(MARKER_WORKER_LOST, receipt.security_errors)

    def test_backend_without_a_read_denial_fails_closed(self):
        plain = LocalSubprocessExecutor(
            self.root / "plain", use_seatbelt=False)
        self.addCleanup(plain.terminate_all)
        self.assertFalse(plain.supports_split_custody)
        verifier = self.make_verifier(plain)
        verifier.register_task(
            actor_role="evaluator", task_id="no-split",
            criterion_version="acceptance-v1",
            argv=(PY, "-m", "pytest", "-q", "acceptance.py"),
            files={"acceptance.py": probe_acceptance("read").encode()},
            custody="split")
        with self.assertRaisesRegex(
                EvaluationRejected, "split_custody_unavailable"):
            verifier.evaluate(
                actor_role="evaluator", task=self.envelope("no-split"),
                submission_dir=self.submission, evaluation_nonce="no-split")
        self.assertEqual(
            verifier.last_outcome_class, EVALUATOR_BOOTSTRAP_ERROR)

    def test_split_registration_requires_acceptance_files(self):
        verifier = self.make_verifier(self.executor)
        with self.assertRaisesRegex(
                ContractError, "requires registered acceptance files"):
            verifier.register_task(
                actor_role="evaluator", task_id="empty",
                criterion_version="v1", argv=(PY, "-c", "pass"),
                custody="split")

    def test_split_registration_requires_a_python_command(self):
        # A shell or test binary handed the Python bootstrap would fail
        # as if the submission had; refuse the registration instead.
        verifier = self.make_verifier(self.executor)
        with self.assertRaisesRegex(
                ContractError, "requires a Python acceptance command"):
            verifier.register_task(
                actor_role="evaluator", task_id="shell",
                criterion_version="v1",
                argv=("/bin/sh", "-c", "grep -q . acceptance.py"),
                files={"acceptance.py": b"x = 1\n"}, custody="split")

    def test_custody_is_bound_into_the_suite_commitment(self):
        verifier = self.make_verifier(self.executor)
        shared = verifier.register_task(
            actor_role="evaluator", task_id="shared-commitment",
            criterion_version="v1", argv=(PY, "acceptance.py"),
            files={"acceptance.py": b"x = 1\n"})
        split = verifier.register_task(
            actor_role="evaluator", task_id="split-commitment",
            criterion_version="v1", argv=(PY, "acceptance.py"),
            files={"acceptance.py": b"x = 1\n"}, custody="split")
        self.assertNotEqual(shared.suite_commitment, split.suite_commitment)

    def test_a_receipt_without_the_split_marker_is_rejected(self):
        verifier = self.make_verifier(self.executor)
        verifier.register_task(
            actor_role="evaluator", task_id="marker",
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "acceptance.py"),
            files={"acceptance.py": b"def test_ok():\n    assert True\n"},
            custody="split")
        # The bootstrap probe itself runs through the executor, so it is
        # satisfied directly; only the acceptance run is replaced.
        with mock.patch.object(
                type(verifier), "bootstrap",
                return_value=mock.Mock(ok=True, reason="ok")), \
                mock.patch.object(
                    LocalSubprocessExecutor, "run", autospec=True) as run:
            run.return_value = mock.Mock(
                security_errors=("isolation:unverified_local",),
                execution_id="exec-fake", exit_status=0, timeout=False)
            with self.assertRaisesRegex(
                    EvaluationRejected, "split_custody_unverified"):
                verifier.evaluate(
                    actor_role="evaluator", task=self.envelope("marker"),
                    submission_dir=self.submission,
                    evaluation_nonce="marker")


class ProxyCodecTests(unittest.TestCase):
    def test_unsupported_argument_types_are_refused(self):
        import socket as socket_module
        left, right = socket_module.socketpair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        client = SplitClient(left)
        with self.assertRaisesRegex(
                SplitProtocolError, "not transferable"):
            client.call(["solution", "add"], (object(),), {})


class DockerSplitCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "calc.py").write_text("x = 1\n", encoding="utf-8")
        self.log = self.root / "docker-args.log"
        self.payload = self.root / "payload.tar"
        with tarfile.open(self.payload, "w"):
            pass
        self.material_payload = self.root / "material.tar"
        self.set_material({})
        self.fake = self.root / "fake-docker"
        self.fake.write_text(
            "#!/bin/sh\n"
            # One log line per invocation: the worker source is a single
            # argv entry that itself contains newlines.
            f"printf '%s\\n' \"$*\" | tr '\\n' ' ' >> {shlex.quote(str(self.log))}\n"
            f"printf '\\n' >> {shlex.quote(str(self.log))}\n"
            "case \"$1\" in\n"
            "  inspect) echo true ;;\n"
            "  exec)\n"
            "    case \" $* \" in\n"
            f"      *\" tar -C /tmp/sis-private -cf - \"*) "
            f"cat {shlex.quote(str(self.material_payload))} ;;\n"
            f"      *\" tar -C /workspace -cf - \"*) "
            f"cat {shlex.quote(str(self.payload))} ;;\n"
            "    esac\n"
            "    ;;\n"
            "esac\n"
            "exit 0\n",
            encoding="utf-8")
        self.fake.chmod(0o755)
        options = {
            "image": "sis-evaluator:3.3.8",
            "require_image_digest": False,
            "docker_binary": str(self.fake),
            "image_id": "0" * 64,
            "root": tempfile.mkdtemp(dir=self.temp.name, prefix="exec-"),
            "user": "1000:1000",
            "split_user": "2002:2002",
        }
        with mock.patch.object(
                DockerSandboxExecutor, "_require_docker",
                return_value="test-server"):
            self.executor = DockerSandboxExecutor(**options)
        self.addCleanup(self.executor.terminate_all)

    def logged(self):
        return self.log.read_text(encoding="utf-8").splitlines()

    def set_material(self, files):
        """Stage the container copy the fake Docker CLI reports back."""
        entries = dict(files)
        entries[SPLIT_BOOTSTRAP_NAME] = SPLIT_BOOTSTRAP_SOURCE.encode("utf-8")
        entries[SPLIT_INI_NAME] = SPLIT_INI_SOURCE
        with tarfile.open(self.material_payload, "w") as archive:
            for name, data in entries.items():
                info = tarfile.TarInfo("./" + name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))

    def test_worker_runs_under_a_second_uid(self):
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        self.set_material({"acceptance.py": b"def test_ok():\n    pass\n"})
        receipt = self.executor.run(
            workspace, CommandSpec(argv=("python3", "-c", "pass")),
            private_files={"acceptance.py": b"def test_ok():\n    pass\n"},
            split_custody=True)
        lines = self.logged()
        self.assertIn(MARKER_SPLIT, receipt.security_errors)
        self.assertIn(MARKER_SEPARATE_UID, receipt.security_errors)
        self.assertNotIn(
            "sandbox:private_material_modified", receipt.security_errors)
        self.assertTrue(any(
            "exec -d --user 2002:2002" in line for line in lines), lines)
        self.assertTrue(any(
            f"test -S {self.executor._split_socket}" in line
            for line in lines), lines)
        self.assertTrue(any(
            line.startswith("run ") and "mode=0777" in line
            for line in lines), lines)
        self.assertTrue(any(
            "--user 2002:2002" in line and "tar -C /workspace" in line
            for line in lines), lines)

    def test_private_material_is_installed_not_mounted(self):
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        self.set_material({"acceptance.py": b"x = 1\n"})
        self.executor.run(
            workspace, CommandSpec(argv=("python3", "-c", "pass")),
            private_files={"acceptance.py": b"x = 1\n"},
            split_custody=True)
        lines = self.logged()
        self.assertFalse(any("target=/private" in line for line in lines),
                         lines)
        self.assertTrue(any(
            "mkdir -p /tmp/sis-private" in line and "chmod 700" in line
            for line in lines), lines)

    def test_a_modified_container_copy_is_flagged(self):
        # The host staging directory is not the copy the worker could
        # reach, so the receipt has to report the container copy.
        workspace = self.executor.prepare(self.base)
        self.addCleanup(self.executor.destroy, workspace)
        self.set_material({"acceptance.py": b"tampered\n"})
        receipt = self.executor.run(
            workspace, CommandSpec(argv=("python3", "-c", "pass")),
            private_files={"acceptance.py": b"def test_ok():\n    pass\n"},
            split_custody=True)
        self.assertIn(
            "sandbox:private_material_modified", receipt.security_errors)

    def test_split_requires_a_second_identity(self):
        with mock.patch.object(
                DockerSandboxExecutor, "_require_docker",
                return_value="test-server"):
            plain = DockerSandboxExecutor(
                image="sis-evaluator:3.3.8", require_image_digest=False,
                docker_binary=str(self.fake), image_id="0" * 64,
                root=tempfile.mkdtemp(dir=self.temp.name, prefix="plain-"))
        self.addCleanup(plain.terminate_all)
        self.assertFalse(plain.supports_split_custody)
        workspace = plain.prepare(self.base)
        self.addCleanup(plain.destroy, workspace)
        with self.assertRaisesRegex(
                RunnerError, "split_custody_unavailable"):
            plain.run(
                workspace, CommandSpec(argv=("python3", "-c", "pass")),
                private_files={"acceptance.py": b"x = 1\n"},
                split_custody=True)

    def test_split_user_must_differ_from_the_evaluator(self):
        with self.assertRaisesRegex(
                ContractError, "must differ from the evaluator user"):
            with mock.patch.object(
                    DockerSandboxExecutor, "_require_docker",
                    return_value="test-server"):
                DockerSandboxExecutor(
                    image="sis-evaluator:3.3.8", require_image_digest=False,
                    docker_binary=str(self.fake), image_id="0" * 64,
                    user="1000:1000", split_user="1000:1000",
                    root=tempfile.mkdtemp(dir=self.temp.name))


class LinuxWorkerSplitTests(unittest.TestCase):
    def test_bwrap_backend_declares_no_split_custody(self):
        # bwrap maps the caller's UID into the namespace, so the backend
        # has no second principal; it must never claim the capability.
        self.assertFalse(LinuxRootlessWorker.supports_split_custody)


if __name__ == "__main__":
    unittest.main()
