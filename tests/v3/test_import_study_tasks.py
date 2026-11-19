"""Task-corpus importer and per-task base commits in the manifest."""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sis.v3.efficacy_manifest import validate_manifest
from tests.v3.study_fixtures import (commit, import_repository,
                                     imported_study, load_tool,
                                     make_bugfix_repository)

GIT = shutil.which("git")
POSIX = __import__("os").name == "posix"
builder = load_tool("build_efficacy_manifest")


@unittest.skipUnless(GIT and POSIX, "git and POSIX key custody are required")
class ImporterTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.importer = load_tool("import_study_tasks")

    def run_import(self, repo, **kwargs):
        output = self.root / "fragment.json"
        code = import_repository(
            self.importer, repo["path"], "alpha",
            partition=kwargs.pop("partition", "holdout"),
            hidden_dir=self.root / "private", output=output, **kwargs)
        return code, json.loads(output.read_text())

    def test_bug_fix_commits_become_verified_tasks(self):
        repo = make_bugfix_repository(self.root / "repo", "alpha", fixes=2)
        code, fragment = self.run_import(repo)
        self.assertEqual(code, 0)
        tasks = {task["source"]["fix_commit"]: task
                 for task in fragment["tasks"]}
        self.assertEqual(set(tasks), set(repo["fix_commits"]))
        first = tasks[repo["fix_commits"][0]]
        self.assertEqual(first["base_commit"], repo["base"])
        self.assertEqual(first["source"]["verification"],
                         {"base": "fail", "fix": "pass"})
        self.assertIn("Fix alpha_f0 returning the wrong value",
                      first["prompt"])
        self.assertIn("evaluator-owned test", first["prompt"])
        acceptance = first["acceptance"]
        self.assertEqual(acceptance["hidden_tests_target"],
                         "tests/test_f0.py")
        self.assertEqual(acceptance["argv"][-1], "tests/test_f0.py")
        hidden = Path(acceptance["hidden_tests_path"])
        self.assertTrue(hidden.is_file())
        self.assertIn("assert alpha_f0(1) == 2", hidden.read_text())
        # The hidden test lives outside the repository.
        self.assertNotIn(repo["path"].resolve(), hidden.resolve().parents)
        self.assertEqual(fragment["repository"]["hidden_tests"],
                         {"path": str((self.root / "private").resolve())})
        # The root commit has no parent and is reported, not imported.
        reasons = {item["commit"]: item["reason"]
                   for item in fragment["rejected"]}
        self.assertEqual(reasons[repo["base"]], "not_a_single_parent_commit")

    def test_commits_that_do_not_reproduce_are_rejected(self):
        repo = make_bugfix_repository(self.root / "repo", "alpha", fixes=1)
        path = repo["path"]
        # Says "fix", touches source and a test, but the test already
        # passes on its parent.
        (path / "mod_alpha.py").write_text(
            (path / "mod_alpha.py").read_text() + "\n# comment\n")
        (path / "tests" / "test_extra.py").write_text(
            "def test_extra():\n    assert True\n")
        no_repro = commit(path, "Fix a typo in a comment")
        # Not a fix by its message.
        (path / "mod_alpha.py").write_text(
            (path / "mod_alpha.py").read_text() + "\n# more\n")
        (path / "tests" / "test_more.py").write_text(
            "def test_more():\n    assert True\n")
        not_fix = commit(path, "Refactor the layout")
        code, fragment = self.run_import(repo)
        reasons = {item["commit"]: item["reason"]
                   for item in fragment["rejected"]}
        self.assertEqual(reasons[no_repro], "base_does_not_fail:pass")
        self.assertEqual(reasons[not_fix], "message_is_not_a_fix")
        self.assertEqual(len(fragment["tasks"]), 1)

    def test_merge_into_replaces_the_repository_entry(self):
        repo = make_bugfix_repository(self.root / "repo", "alpha", fixes=2)
        spec = self.root / "spec.json"
        spec.write_text(json.dumps({
            "repositories": [{"repository_id": "alpha", "path": "old"},
                             {"repository_id": "other", "path": "x"}],
            "tasks": [{"task_id": "stale", "repository_id": "alpha"},
                      {"task_id": "keep", "repository_id": "other"}]}))
        code, _ = self.run_import(repo, merge_into=spec)
        self.assertEqual(code, 0)
        merged = json.loads(spec.read_text())
        self.assertEqual([item["repository_id"]
                          for item in merged["repositories"]],
                         ["other", "alpha"])
        task_ids = [task["task_id"] for task in merged["tasks"]]
        self.assertIn("keep", task_ids)
        self.assertNotIn("stale", task_ids)
        self.assertTrue(all("source" not in task for task in merged["tasks"]))

    def test_induction_imports_record_the_learning_split(self):
        repo = make_bugfix_repository(self.root / "repo", "alpha", fixes=1)
        code, fragment = self.run_import(
            repo, partition="induction", learning_split="qualification",
            verify="none")
        self.assertEqual(code, 0)
        self.assertEqual(fragment["repository"]["learning_split"],
                         "qualification")
        self.assertNotIn("hidden_tests", fragment["repository"])
        self.assertIsNone(fragment["tasks"][0]["source"]["verification"])


@unittest.skipUnless(GIT and POSIX, "git and POSIX key custody are required")
class PerTaskBaseCommitTests(unittest.TestCase):
    """Imported tasks keep their own base commit inside one repository."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.study = imported_study(cls.root, holdout=5, induction=5,
                                   fixes=2)
        cls.document, cls.summary = builder.build_manifest(
            cls.study["spec"], check_agent=False)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_the_builder_binds_each_task_tree(self):
        self.assertTrue(self.summary["ready"])
        self.assertEqual(self.summary["study_tier"], "exploratory")
        self.assertEqual(self.document["agent"]["kind"], "claude-code")
        repositories = {item["repository_id"]: item
                        for item in self.document["repositories"]}
        for task in self.document["tasks"]:
            repository = repositories[task["repository_id"]]
            self.assertNotEqual(task["base_commit"],
                                repository["base_commit"])
            self.assertRegex(task["repo_snapshot_digest"], "^[0-9a-f]{64}$")
            self.assertRegex(task["repo_execution_digest"], "^[0-9a-f]{64}$")
            self.assertEqual(task["acceptance"]["hidden_tests_target"],
                             task["acceptance"]["argv"][-1])
        report = validate_manifest(self.document, check_paths=True)
        self.assertTrue(report["valid"], report["problems"])
        self.assertTrue(report["ready"])
        self.assertEqual(len(report["task_trees"]), 10)
        self.assertEqual(report["holdout_repositories_used"], 5)

    def test_a_wrong_task_tree_digest_is_refused(self):
        document = copy.deepcopy(self.document)
        document["tasks"][0]["repo_snapshot_digest"] = "0" * 64
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repo_snapshot_digest does not match" in problem
                            for problem in report["problems"]))

    def test_an_own_base_commit_must_bind_its_tree(self):
        document = copy.deepcopy(self.document)
        del document["tasks"][0]["repo_execution_digest"]
        report = validate_manifest(document)
        self.assertTrue(any("must declare its own repo_execution_digest"
                            in problem for problem in report["problems"]))

    def test_a_commit_outside_the_repository_history_is_refused(self):
        document = copy.deepcopy(self.document)
        other = next(task for task in document["tasks"]
                     if task["repository_id"]
                     != document["tasks"][0]["repository_id"])
        document["tasks"][0]["base_commit"] = other["base_commit"]
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(any("is not a commit of its repository" in problem
                            for problem in report["problems"]))

    def test_a_changed_hidden_tests_directory_is_refused(self):
        document = copy.deepcopy(self.document)
        hidden = Path(document["repositories"][-1]["hidden_tests"]["path"])
        extra = hidden / "extra.py"
        extra.write_text("x = 1\n")
        try:
            report = validate_manifest(document, check_paths=True)
        finally:
            extra.unlink()
        self.assertTrue(any("hidden tests directory does not match" in p
                            for p in report["problems"]))


if __name__ == "__main__":
    unittest.main()
