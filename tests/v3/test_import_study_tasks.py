"""Task-corpus importer and per-task base commits in the manifest."""
from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sis.v3.efficacy_manifest import validate_manifest
from tests.v3.study_fixtures import (commit, git, import_repository,
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

    def test_support_files_are_checked_with_the_task(self):
        import hashlib
        document = copy.deepcopy(self.document)
        task = document["tasks"][0]
        repository = next(item for item in document["repositories"]
                          if item["repository_id"] == task["repository_id"])
        hidden = Path(repository["hidden_tests"]["path"])
        outside = self.root / "outside_init.py"
        outside.write_text("x = 1\n")
        digest = hashlib.sha256(b"x = 1\n").hexdigest()
        task["acceptance"]["support_files"] = [
            {"target": "tests/__init__.py", "path": str(outside),
             "digest": digest},
            {"target": task["acceptance"]["hidden_tests_target"],
             "path": str(outside), "digest": "nope"}]
        report = validate_manifest(document, check_paths=True)
        problems = "\n".join(report["problems"])
        self.assertIn("support file target is repeated", problems)
        # Shape problems are reported first; a sound list is then checked
        # against the hidden-tests directory.
        task["acceptance"]["support_files"].pop()
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(any("tests/__init__.py is not in the repository's"
                            " hidden_tests" in problem
                            for problem in report["problems"]))
        # The builder reads each file back and checks its digest.
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "support_file_outside_hidden_tests"):
            builder._acceptance(task, repository, "task")
        inside = Path(task["acceptance"]["hidden_tests_path"]).parent / \
            "support" / "tests" / "__init__.py"
        inside.parent.mkdir(parents=True)
        self.addCleanup(shutil.rmtree, inside.parent.parent)
        inside.write_text("x = 1\n")
        task["acceptance"]["support_files"][0]["path"] = str(inside)
        self.assertIn(hidden.resolve(), inside.resolve().parents)
        repository = dict(repository, hidden_tests=dict(
            repository["hidden_tests"],
            digest=__import__("sis.v3.study_runtime", fromlist=["x"])
            .hidden_tests_digest(hidden)))
        result = builder._acceptance(task, repository, "task")
        self.assertEqual(result["support_files"][0]["target"],
                         "tests/__init__.py")
        inside.write_text("x = 2\n")
        repository["hidden_tests"]["digest"] = __import__(
            "sis.v3.study_runtime", fromlist=["x"]).hidden_tests_digest(hidden)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "support_file_digest_mismatch"):
            builder._acceptance(task, repository, "task")

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


def make_package_test_repository(path: Path) -> dict:
    """A fix whose test needs files beside it, as cachetools' and jmespath's.

    ``tests/`` is a package: ``tests/__init__.py`` defines a mixin the
    test imports with ``from . import``; ``tests/helpers.py`` is imported
    as ``from tests.helpers import``; ``tests/conftest.py`` and the root
    ``conftest.py`` provide fixtures. ``src/calc/tests/`` is a test
    package inside a source package, whose ``__init__.py`` must never be
    captured.
    """
    path.mkdir(parents=True)
    git(path, "init", "-q")
    (path / "calc.py").write_text("def add(x, y):\n    return x - y\n")
    tests = path / "tests"
    tests.mkdir()
    (tests / "__init__.py").write_text(
        "import calc\n"
        "class AddMixin:\n"
        "    def test_add_zero(self):\n"
        "        assert calc.add(1, 0) == 1\n")
    (tests / "helpers.py").write_text(
        "from .data import PAIRS\n"
        "def expected(x, y):\n    return x + y\n")
    (tests / "data.py").write_text("PAIRS = [(1, 2), (3, 4)]\n")
    (tests / "unused.py").write_text("UNUSED = 1\n")
    (tests / "conftest.py").write_text(
        "import pytest\n"
        "@pytest.fixture\n"
        "def pairs():\n"
        "    from tests.helpers import PAIRS\n"
        "    return PAIRS\n")
    (path / "conftest.py").write_text("ROOT = True\n")
    (tests / "test_public.py").write_text(
        "def test_public():\n    assert True\n")
    package = path / "src" / "calc2" / "tests"
    package.mkdir(parents=True)
    (path / "src" / "calc2" / "__init__.py").write_text("VALUE = 1\n")
    (package / "__init__.py").write_text("")
    (package / "helper.py").write_text("HELP = 1\n")
    (package / "test_calc2.py").write_text(
        "def test_value():\n    assert True\n")
    base = commit(path, "Initial layout")
    (path / "calc.py").write_text("def add(x, y):\n    return x + y\n")
    (tests / "test_add.py").write_text(
        "import unittest\n"
        "import calc\n"
        "from . import AddMixin\n"
        "from tests.helpers import expected\n"
        "class AddTest(unittest.TestCase, AddMixin):\n"
        "    pass\n"
        "def test_pairs(pairs):\n"
        "    for x, y in pairs:\n"
        "        assert calc.add(x, y) == expected(x, y)\n")
    fix = commit(path, "Fix add subtracting instead of adding")
    (path / "src" / "calc2" / "__init__.py").write_text("VALUE = 2\n")
    (package / "test_calc2.py").write_text(
        "from . import helper\n"
        "from .. import VALUE\n"
        "import calc2\n"
        "def test_value():\n    assert helper.HELP == 1\n")
    nested = commit(path, "Fix calc2 value")
    git(path, "remote", "add", "origin", "https://example.invalid/calc.git")
    head = git(path, "rev-parse", "HEAD")
    git(path, "update-ref", "refs/remotes/origin/main", head)
    return {"path": path, "base": base, "fix": fix, "nested": nested}


@unittest.skipUnless(GIT and POSIX, "git and POSIX key custody are required")
class SupportFileTests(unittest.TestCase):
    """Files the hidden test imports are registered with it."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.importer = load_tool("import_study_tasks")
        self.repo = make_package_test_repository(self.root / "repo")

    def describe(self, commit_id):
        import re
        return self.importer.describe_commit(
            self.repo["path"], commit_id, fix_pattern=re.compile("Fix"))

    def test_the_test_package_conftests_and_helpers_are_captured(self):
        info = self.describe(self.repo["fix"])
        self.assertEqual(info["test_path"], "tests/test_add.py")
        self.assertEqual(sorted(info["support"]), [
            "conftest.py", "tests/__init__.py", "tests/conftest.py",
            "tests/data.py", "tests/helpers.py"])
        # Bytes come from the fix commit.
        self.assertIn(b"def expected", info["support"]["tests/helpers.py"])
        self.assertEqual(
            sorted(self.importer.private_files(info)),
            sorted([*info["support"], "tests/test_add.py"]))

    def test_a_source_package_above_the_tests_is_never_captured(self):
        info = self.describe(self.repo["nested"])
        self.assertEqual(info["test_path"], "src/calc2/tests/test_calc2.py")
        # ``from .. import VALUE`` names the source package: the
        # submission's, not evaluator material.
        self.assertEqual(sorted(info["support"]), [
            "conftest.py", "src/calc2/tests/__init__.py",
            "src/calc2/tests/helper.py"])

    def test_links_are_never_captured(self):
        path = self.repo["path"]
        (path / "tests" / "linked.py").symlink_to("data.py")
        commit(path, "Add a link")
        (path / "calc.py").write_text("def add(x, y):\n    return y + x\n")
        (path / "tests" / "test_add.py").write_text(
            "from tests import linked, data\n"
            "def test_link():\n    assert linked.PAIRS == data.PAIRS\n")
        fix = commit(path, "Fix add argument order")
        info = self.describe(fix)
        self.assertIn("tests/data.py", info["support"])
        self.assertNotIn("tests/linked.py", info["support"])

    def test_support_files_are_bounded(self):
        original = self.importer.MAX_SUPPORT_FILES
        self.importer.MAX_SUPPORT_FILES = 2
        self.addCleanup(setattr, self.importer, "MAX_SUPPORT_FILES",
                        original)
        with self.assertRaisesRegex(self.importer.ImportError_,
                                    "support_files_exceed_the_bound"):
            self.describe(self.repo["fix"])

    def test_imported_tasks_record_and_verify_support_files(self):
        output = self.root / "fragment.json"
        hidden_dir = self.root / "private"
        code = import_repository(
            self.importer, self.repo["path"], "calc", partition="holdout",
            hidden_dir=hidden_dir, output=output)
        fragment = json.loads(output.read_text())
        self.assertEqual(code, 0, fragment["rejected"])
        task = next(item for item in fragment["tasks"]
                    if item["source"]["fix_commit"] == self.repo["fix"])
        self.assertEqual(task["source"]["verification"],
                         {"base": "fail", "fix": "pass"})
        acceptance = task["acceptance"]
        support = {entry["target"]: entry
                   for entry in acceptance["support_files"]}
        self.assertEqual(sorted(support), [
            "conftest.py", "tests/__init__.py", "tests/conftest.py",
            "tests/data.py", "tests/helpers.py"])
        for target, entry in support.items():
            stored = Path(entry["path"])
            self.assertIn(hidden_dir.resolve(), stored.resolve().parents)
            self.assertEqual(stored.read_bytes(), (
                self.repo["path"] / target).read_bytes())
        campaign = load_tool("five_arm_campaign")
        repository = {"hidden_tests": {
            "path": str(hidden_dir.resolve()),
            "digest": __import__("sis.v3.study_runtime", fromlist=["x"])
            .hidden_tests_digest(hidden_dir)}}
        material = campaign._acceptance_material(task, repository)
        self.assertEqual(sorted(material),
                         sorted([*support, "tests/test_add.py"]))
        # A support file changed after import is refused, as the primary
        # test file is.
        stored = Path(support["tests/helpers.py"]["path"])
        stored.write_text("def expected(x, y):\n    return x - y\n")
        repository["hidden_tests"]["digest"] = __import__(
            "sis.v3.study_runtime", fromlist=["x"]).hidden_tests_digest(
                hidden_dir)
        with self.assertRaisesRegex(ValueError, "support_file_digest"):
            campaign._acceptance_material(task, repository)

    def test_support_file_entries_are_validated(self):
        from sis.v3.study_runtime import (StudyRuntimeError,
                                          load_support_files,
                                          support_file_problems)
        hidden = self.root / "hidden"
        hidden.mkdir()
        good = hidden / "init.py"
        good.write_text("x = 1\n")
        outside = self.root / "outside.py"
        outside.write_text("x = 1\n")
        import hashlib
        digest = hashlib.sha256(b"x = 1\n").hexdigest()
        base = {"hidden_tests_path": "t.py",
                "hidden_tests_target": "tests/test_x.py"}

        def entry(**changes):
            item = {"target": "tests/__init__.py", "path": str(good),
                    "digest": digest}
            item.update(changes)
            return dict(base, support_files=[item])

        self.assertEqual(support_file_problems(entry()), [])
        self.assertEqual(load_support_files(entry(), hidden),
                         {"tests/__init__.py": b"x = 1\n"})
        for bad in (entry(target="../x.py"), entry(target="/etc/x.py"),
                    entry(target="tests/test_x.py"), entry(target="a.txt"),
                    entry(target="./a.py"), entry(digest="0" * 63),
                    entry(target="tests//x.py"), entry(target="tests/x.py/"),
                    entry(target="tests/./x.py"), entry(target="tests/"),
                    dict(base, support_files="x"),
                    {"support_files": []}):
            self.assertTrue(support_file_problems(bad), bad)
            with self.assertRaises(StudyRuntimeError):
                load_support_files(bad, hidden)
        # Without hidden_tests_target the primary test is staged under its
        # file name, as the campaign does: no support file may take it.
        untargeted = {"hidden_tests_path": str(hidden / "test_x.py"),
                      "support_files": [{"target": "test_x.py",
                                         "path": str(good),
                                         "digest": digest}]}
        self.assertTrue(support_file_problems(untargeted))
        with self.assertRaisesRegex(StudyRuntimeError, "repeated"):
            load_support_files(untargeted, hidden)
        with self.assertRaisesRegex(StudyRuntimeError, "outside_hidden"):
            load_support_files(entry(path=str(outside)), hidden)
        with self.assertRaisesRegex(StudyRuntimeError, "digest_mismatch"):
            load_support_files(entry(digest="0" * 64), hidden)
        link = hidden / "link.py"
        link.symlink_to(good)
        with self.assertRaisesRegex(StudyRuntimeError, "regular_file"):
            load_support_files(entry(path=str(link)), hidden)
        with self.assertRaisesRegex(StudyRuntimeError, "hidden_tests_dir"):
            load_support_files(entry(), None)


if __name__ == "__main__":
    unittest.main()
