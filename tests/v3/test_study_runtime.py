"""Study runtime: executor choice, commit trees, hidden tests and the journal."""
from __future__ import annotations

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.contracts import ContractError
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.runner import LocalSubprocessExecutor
from sis.v3.study_runtime import (DEFAULT_SPLIT_USER, DEFAULT_STUDY_IMAGE,
                                  RunJournal, StudyRuntimeError,
                                  build_study_executor, executor_description,
                                  hidden_test_belongs, hidden_tests_digest,
                                  materialize_commit)
from tests.v3.study_fixtures import commit, git, make_bugfix_repository

GIT = shutil.which("git")


class ExecutorChoiceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_local_is_the_subprocess_executor(self):
        executor = build_study_executor(
            "local", self.root / "exec", protected_paths=(self.root / "k",))
        self.assertIsInstance(executor, LocalSubprocessExecutor)

    def test_local_refuses_docker_options(self):
        with self.assertRaises(ContractError):
            build_study_executor("local", self.root / "exec",
                                 runtime="runsc")

    def test_docker_has_split_custody_with_the_pinned_image(self):
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               return_value="test"):
            executor = build_study_executor(
                "docker", self.root / "exec",
                protected_paths=(self.root / "keys",), user="1000:1000")
        self.addCleanup(executor.terminate_all)
        self.assertTrue(executor.supports_split_custody)
        self.assertEqual(executor.split_user, DEFAULT_SPLIT_USER)
        self.assertIn((self.root / "keys").resolve(),
                      executor.protected_paths)
        facts = executor_description(executor)
        self.assertEqual(facts["image"], DEFAULT_STUDY_IMAGE)
        self.assertTrue(facts["supports_split_custody"])

    def test_an_unpinned_image_needs_the_explicit_opt_out(self):
        with mock.patch.object(DockerSandboxExecutor, "_require_docker",
                               return_value="test"):
            with self.assertRaises(ContractError):
                build_study_executor("docker", self.root / "exec",
                                     image="sis-evaluator:dev")
            executor = build_study_executor(
                "docker", self.root / "exec", image="sis-evaluator:dev",
                require_image_digest=False)
        self.addCleanup(executor.terminate_all)

    def test_a_runtime_is_passed_through_only_when_supported(self):
        calls = []

        def with_runtime(root, *, image, require_image_digest, split_user,
                         runtime=None, user=None):
            calls.append(runtime)
            return mock.Mock(spec=["protect"])

        def without_runtime(root, *, image, require_image_digest, split_user,
                            user=None):
            return mock.Mock(spec=["protect"])

        build_study_executor("docker", self.root / "e", runtime="runsc",
                             docker_factory=with_runtime)
        self.assertEqual(calls, ["runsc"])
        with self.assertRaisesRegex(ContractError, "runtime_unsupported"):
            build_study_executor("docker", self.root / "e", runtime="runsc",
                                 docker_factory=without_runtime)


@unittest.skipUnless(GIT, "git is required")
class CommitTreeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = make_bugfix_repository(self.root / "repo", "alpha",
                                           fixes=2)

    def test_materializes_the_commit_tree_without_git_metadata(self):
        target = materialize_commit(self.repo["path"], self.repo["base"],
                                    self.root / "tree")
        self.assertFalse((target / ".git").exists())
        self.assertIn("x - 1", (target / "mod_alpha.py").read_text())
        self.assertFalse((target / "tests" / "test_f0.py").exists())
        head = materialize_commit(self.repo["path"], self.repo["head"],
                                  self.root / "head")
        self.assertTrue((head / "tests" / "test_f1.py").exists())

    @unittest.skipIf(os.name == "nt",
                     "NTFS has no POSIX executable bit to preserve")
    def test_keeps_the_executable_bit(self):
        script = self.repo["path"] / "run.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        sha = commit(self.repo["path"], "script")
        target = materialize_commit(self.repo["path"], sha,
                                    self.root / "tree")
        self.assertTrue(os.stat(target / "run.sh").st_mode & stat.S_IXUSR)
        self.assertFalse(os.stat(target / "mod_alpha.py").st_mode
                         & stat.S_IXUSR)

    def test_symlinks_and_bad_inputs_are_refused(self):
        (self.repo["path"] / "link").symlink_to("mod_alpha.py")
        sha = commit(self.repo["path"], "link")
        with self.assertRaisesRegex(StudyRuntimeError, "symlink"):
            materialize_commit(self.repo["path"], sha, self.root / "t1")
        with self.assertRaisesRegex(StudyRuntimeError, "commit_missing"):
            materialize_commit(self.repo["path"], "1" * 40, self.root / "t2")
        with self.assertRaisesRegex(StudyRuntimeError, "commit_invalid"):
            materialize_commit(self.repo["path"], "HEAD", self.root / "t3")
        (self.root / "exists").mkdir()
        with self.assertRaisesRegex(StudyRuntimeError, "destination_exists"):
            materialize_commit(self.repo["path"], self.repo["base"],
                               self.root / "exists")

    def test_repository_filters_do_not_run(self):
        marker = self.root / "filter-ran"
        git(self.repo["path"], "config", "filter.evil.smudge",
            f"sh -c 'touch {marker}; cat'")
        (self.repo["path"] / ".gitattributes").write_text(
            "*.py filter=evil\n")
        sha = commit(self.repo["path"], "attributes")
        materialize_commit(self.repo["path"], sha, self.root / "tree")
        self.assertFalse(marker.exists())


class HiddenTestsTests(unittest.TestCase):
    def test_directory_digest_binds_paths_and_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "hidden"
            (root / "t1").mkdir(parents=True)
            (root / "t1" / "test_a.py").write_text("A")
            first = hidden_tests_digest(root)
            (root / "t1" / "test_a.py").write_text("B")
            self.assertNotEqual(hidden_tests_digest(root), first)
            self.assertTrue(hidden_test_belongs(root / "t1" / "test_a.py",
                                                root))
            self.assertFalse(hidden_test_belongs(Path(temp) / "x.py", root))
            single = Path(temp) / "single.py"
            single.write_text("C")
            self.assertTrue(hidden_test_belongs(single, single))
            (root / "link").symlink_to(single)
            with self.assertRaises(StudyRuntimeError):
                hidden_tests_digest(root)


class RunJournalTests(unittest.TestCase):
    ROW = {"outcome": "pass", "receipt_digest": "a" * 64, "wall_seconds": 3,
           "budget_exceeded": False, "tokens_used": 5, "tools_used": 1,
           "budget_accounting": "verified", "submission_digest": "b" * 64}

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "journal.jsonl"
        self.identity = {"manifest_digest": "c" * 64, "arms": ["A", "E"]}

    def test_rows_survive_a_reopen(self):
        journal = RunJournal(self.path, self.identity)
        journal.annotator = lambda task, arm: {"served": arm == "E"}
        journal.record("t1", "A", self.ROW)
        journal.record("t1", "E", self.ROW)
        reopened = RunJournal(self.path, self.identity)
        self.assertEqual(reopened.resumed_rows, 2)
        self.assertEqual(reopened.completed("t1", "A"), self.ROW)
        self.assertEqual(reopened.annotations("t1", "E"), {"served": True})
        self.assertIsNone(reopened.completed("t2", "A"))
        self.assertEqual(reopened.head, journal.head)

    def test_a_different_study_cannot_resume(self):
        RunJournal(self.path, self.identity).record("t1", "A", self.ROW)
        with self.assertRaisesRegex(StudyRuntimeError, "identity_mismatch"):
            RunJournal(self.path, {**self.identity, "arms": ["A"]})

    def test_a_crash_mid_line_drops_only_that_line(self):
        journal = RunJournal(self.path, self.identity)
        journal.record("t1", "A", self.ROW)
        with open(self.path, "ab") as handle:
            handle.write(b'{"task_id": "t1", "arm": "E", "ro')
        reopened = RunJournal(self.path, self.identity)
        self.assertEqual(reopened.resumed_rows, 1)
        reopened.record("t1", "E", self.ROW)
        self.assertEqual(RunJournal(self.path, self.identity).resumed_rows, 2)

    def test_an_edited_entry_breaks_the_chain(self):
        RunJournal(self.path, self.identity).record("t1", "A", self.ROW)
        lines = self.path.read_text().splitlines()
        entry = json.loads(lines[1])
        entry["row"]["outcome"] = "fail"
        lines[1] = json.dumps(entry)
        self.path.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(StudyRuntimeError, "chain_broken"):
            RunJournal(self.path, self.identity)

    def test_a_quarantined_arm_is_not_resumed(self):
        journal = RunJournal(self.path, self.identity)
        journal.record("t1", "A", {**self.ROW, "workspace_retained": True})
        self.assertIsNone(RunJournal(self.path, self.identity)
                          .completed("t1", "A"))


if __name__ == "__main__":
    unittest.main()
