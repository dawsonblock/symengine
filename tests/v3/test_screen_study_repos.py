"""Static split-custody screening of candidate study repositories."""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from tests.v3.study_fixtures import (commit, git, load_tool,
                                     make_bugfix_repository)

GIT = shutil.which("git")
screen = load_tool("screen_study_repos")


def write(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text).lstrip())


PACKAGE = {
    "pkg/__init__.py": """
        def apply(func, value):
            return func(value)

        def cached(cache):
            def wrap(func):
                return func
            return wrap

        class Base:
            pass

        def sort(values, key=None):
            return sorted(values, key=key)
        """,
}


@unittest.skipUnless(GIT, "git is required")
class ScreenTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def repo(self, files: dict[str, str], name="repo") -> Path:
        path = self.root / name
        path.mkdir()
        git(path, "init", "-q")
        write(path, files)
        commit(path, "Initial layout")
        return path

    def blockers(self, report: dict) -> dict[str, list[str]]:
        return report["module_blockers"]

    # ---- layout and verdicts -------------------------------------------- #
    def test_a_clean_flat_repository_is_likely(self):
        path = self.repo({**PACKAGE, "tests/test_ok.py": """
            import pkg

            def test_sort():
                assert pkg.sort([3, 1]) == [1, 3]
            """})
        report = screen.screen_repository(path)
        self.assertEqual(report["layout"], "flat")
        self.assertEqual(report["packages"], ["pkg"])
        self.assertEqual(report["verdict"], "likely")
        self.assertEqual(report["verdict_basis"], "head")
        self.assertEqual(self.blockers(report), {"tests/test_ok.py": []})

    def test_src_layout_is_recognised(self):
        path = self.repo({
            "src/lib/__init__.py": "VALUE = 1\n",
            "setup.py": "import setuptools\n",
            "tests/test_lib.py": """
                import lib

                def test_value():
                    assert lib.VALUE == 1
                """})
        report = screen.screen_repository(path)
        self.assertEqual(report["layout"], "src")
        self.assertEqual(report["packages"], ["lib"])
        self.assertEqual(report["verdict"], "likely")

    def test_unsupported_proxy_patterns_are_found_and_named(self):
        path = self.repo({**PACKAGE, "tests/test_bad.py": """
            import copy
            import pickle
            import pkg
            from pkg import cached

            def double(x):
                return 2 * x

            class Key:
                def __call__(self, value):
                    return value

            @cached({})
            def helper(x):
                return x

            class Mine(pkg.Base):
                pass

            def test_callables(monkeypatch):
                assert pkg.apply(double, 2) == 4
                assert pkg.sort([2, 1], key=lambda v: -v) == [2, 1]
                assert pkg.sort([1], key=Key()) == [1]
                base = pkg.Base()
                pickle.dumps(base)
                copy.deepcopy(base)
                monkeypatch.setattr(pkg, "apply", None)
            """})
        report = screen.screen_repository(path)
        kinds = set(report["signal_counts"])
        self.assertLessEqual({
            "callable_into_package", "package_decorator_on_test_function",
            "subclass_of_package_class", "pickle_or_copy_of_package_object",
            "patches_package"}, kinds)
        self.assertEqual(report["signal_counts"]["callable_into_package"], 3)
        self.assertEqual(report["verdict"], "unlikely")
        details = " ".join(report["examples"]["callable_into_package"])
        self.assertIn("key=lambda", details)
        self.assertIn("pkg.apply(double)", details)
        self.assertIn("key=Key()", details)

    def test_plain_data_and_stdlib_callbacks_are_not_flagged(self):
        path = self.repo({**PACKAGE, "tests/test_ok.py": """
            import copy
            import pkg

            def helper():
                return [3, 1]

            def test_data():
                values = helper()
                assert pkg.sort(values) == [1, 3]
                assert sorted(values, key=lambda v: v) == [1, 3]
                assert copy.copy(values) == values
                assert pkg.sort(helper()) == [1, 3]
            """})
        report = screen.screen_repository(path)
        self.assertEqual(report["signal_counts"], {})
        self.assertEqual(report["verdict"], "likely")

    def test_package_classes_bound_to_class_attributes_are_tracked(self):
        # The cachetools shape: a mixin calls self.Cache(...), and each
        # test case binds Cache to a package class.
        path = self.repo({**PACKAGE,
                          "tests/__init__.py": """
                              class Mixin:
                                  Cache = None

                                  def test_key(self):
                                      cache = self.Cache()
                                      self.assertTrue(cache)
                                      class Sub(self.Cache):
                                          pass
                              """,
                          "tests/test_base.py": """
                              import unittest
                              import pkg
                              from . import Mixin

                              class BaseTest(unittest.TestCase, Mixin):
                                  Cache = pkg.Base
                              """,
                          "tests/test_other.py": """
                              import pkg

                              def test_alone():
                                  assert pkg.sort([1]) == [1]
                              """})
        report = screen.screen_repository(path)
        blockers = self.blockers(report)
        self.assertIn("subclass_of_package_class",
                      blockers["tests/test_base.py"])
        # A module that does not import the mixin is not charged for it.
        self.assertEqual(blockers["tests/test_other.py"], [])

    # ---- dependencies --------------------------------------------------- #
    def test_third_party_test_imports_depend_on_the_image(self):
        path = self.repo({**PACKAGE, "tests/test_prop.py": """
            from hypothesis import given, strategies
            import pkg

            try:
                import numpy
            except ImportError:
                numpy = None

            @given(strategies.integers())
            def test_prop(x):
                assert pkg.sort([x]) == [x]

            def test_mock(mocker):
                import yaml
                assert yaml
            """})
        report = screen.screen_repository(path)
        imports = report["test_imports"]
        self.assertEqual(imports["missing_in_base_image"],
                         ["hypothesis", "pytest_mock"])
        self.assertEqual(imports["missing_in_testdeps_image"], [])
        self.assertEqual(imports["optional"], ["numpy", "yaml"])
        self.assertEqual(report["images"]["base"]["verdict"], "unlikely")
        self.assertEqual(report["images"]["testdeps"]["verdict"], "likely")

    def test_nose_is_missing_from_both_images(self):
        path = self.repo({**PACKAGE, "tests/test_nose.py": """
            from nose.tools import assert_equal
            import pkg

            def test_sort():
                assert_equal(pkg.sort([1]), [1])
            """})
        report = screen.screen_repository(path)
        self.assertEqual(report["test_imports"]["missing_in_testdeps_image"],
                         ["nose"])
        self.assertEqual(report["images"]["testdeps"]["verdict"], "unlikely")

    def test_a_package_runtime_dependency_blocks_every_module(self):
        path = self.repo({
            "pkg/__init__.py": """
                import sys
                import requests
                if sys.version_info >= (3, 14):
                    import annotationlib
                try:
                    import ujson as json
                except ImportError:
                    import json
                """,
            "tests/test_ok.py": "import pkg\n\ndef test_x():\n    pass\n"})
        report = screen.screen_repository(path)
        self.assertEqual(report["package_runtime_imports"], ["requests"])
        self.assertEqual(report["verdict"], "unlikely")
        self.assertIn("requests", " ".join(report["reasons"]))

    # ---- data files and removed APIs ------------------------------------ #
    def test_data_files_beside_tests_are_found(self):
        path = self.repo({**PACKAGE,
                          "tests/cases/one.json": "{}\n",
                          "tests/conftest.py": """
                              import os
                              import pytest

                              HERE = os.path.dirname(__file__)

                              @pytest.fixture
                              def case_path():
                                  return os.path.join(HERE, "cases")
                              """,
                          "tests/test_files.py": """
                              def test_case(case_path):
                                  assert case_path
                              """,
                          "tests/test_plain.py": """
                              def test_plain():
                                  assert True
                              """,
                          "tests/test_direct.py": """
                              import os

                              def test_direct():
                                  with open(os.path.join(
                                          os.path.dirname(__file__),
                                          "cases", "one.json")) as handle:
                                      assert handle.read()
                              """})
        report = screen.screen_repository(path)
        blockers = self.blockers(report)
        self.assertEqual(blockers["tests/test_files.py"], ["reads_data_files"])
        self.assertEqual(blockers["tests/test_direct.py"],
                         ["reads_data_files"])
        self.assertEqual(blockers["tests/test_plain.py"], [])
        self.assertIn("one.json", report["data_files_beside_tests"])

    def test_python2_and_nose_era_apis_are_found(self):
        path = self.repo({**PACKAGE, "tests/test_old.py": """
            import unittest
            import imp

            class OldTest(unittest.TestCase):
                def setup(self):
                    self.value = 1

                def test_equal(self):
                    self.assertEquals(1, 1)
                    with self.assertRaisesRegexp(ValueError, "x"):
                        raise ValueError("x")

            def test_generated():
                for value in (1, 2):
                    yield check, value

            def check(value):
                assert value

            def test_nested_generator_is_fine():
                def numbers():
                    yield 1
                assert list(numbers()) == [1]
            """})
        report = screen.screen_repository(path)
        details = " ".join(report["examples"]["removed_python_api"])
        self.assertIn("self.assertEquals", details)
        self.assertIn("self.assertRaisesRegexp", details)
        self.assertIn("import imp", details)
        nose = report["examples"]["nose_style_test"]
        self.assertEqual(len(nose), 2, nose)
        self.assertIn("yield test test_generated", " ".join(nose))
        self.assertIn("OldTest.setup()", " ".join(nose))

    def test_unparseable_test_files_are_reported(self):
        path = self.repo({**PACKAGE, "tests/test_py2.py": """
            def test_print():
                print "hello"
            """})
        report = screen.screen_repository(path)
        self.assertEqual(self.blockers(report),
                         {"tests/test_py2.py": ["unparseable"]})

    # ---- fix candidates and the empirical sample ------------------------ #
    def test_fix_candidates_are_screened_on_their_fix_commits(self):
        repo = make_bugfix_repository(self.root / "fixes", "alpha", fixes=3)
        importer = load_tool("import_study_tasks")
        report = screen.screen_repository(repo["path"], candidates=5,
                                          importer=importer)
        candidates = report["fix_candidates"]
        self.assertEqual(candidates["screened"], 3)
        self.assertEqual(
            [row["test_path"] for row in candidates["rows"]],
            ["tests/test_f2.py", "tests/test_f1.py", "tests/test_f0.py"])
        self.assertTrue(all(row["base"] == [] for row in candidates["rows"]))
        self.assertEqual(report["verdict_basis"], "fix_candidates")
        self.assertEqual(report["verdict"], "likely")

    def test_a_candidate_is_judged_on_its_own_commit(self):
        repo = make_bugfix_repository(self.root / "fixes", "beta", fixes=3)
        path = repo["path"]
        # A later fix whose test passes a lambda into the code under test;
        # HEAD's other test files are clean.
        (path / "mod_beta.py").write_text(
            (path / "mod_beta.py").read_text()
            + "\n\ndef call(func):\n    return func(1)\n")
        (path / "tests" / "test_call.py").write_text(
            "from mod_beta import call\n\n"
            "def test_call():\n    assert call(lambda x: x) == 1\n")
        commit(path, "Fix call ignoring its callback")
        importer = load_tool("import_study_tasks")
        report = screen.screen_repository(path, candidates=5,
                                          importer=importer)
        rows = {row["test_path"]: row["base"]
                for row in report["fix_candidates"]["rows"]}
        self.assertEqual(rows["tests/test_call.py"],
                         ["callable_into_package"])
        self.assertEqual(report["images"]["base"]["clean_fraction"], 0.75)

    def test_the_sample_grades_the_first_candidates_with_the_importer(self):
        repo = make_bugfix_repository(self.root / "fixes", "gamma", fixes=3)
        importer = load_tool("import_study_tasks")
        seen = {}

        def fake_import(args, *, executor_factory=None):
            seen["args"] = args
            return {"tasks": [{"source": {"fix_commit": args.commits[0]}}],
                    "rejected": [{"commit": args.commits[1],
                                  "reason": "base_does_not_fail:pass"}]}

        with mock.patch.object(importer, "import_repository", fake_import):
            sample = screen.sample_repository(
                repo["path"], 2, docker_image="img@sha256:" + "a" * 64,
                split_user="65533:65533", allow_unpinned=False,
                timeout=60, max_scan=50, importer=importer)
        args = seen["args"]
        self.assertEqual(args.verify, "docker")
        self.assertFalse(args.allow_shared_custody)
        self.assertEqual(args.commits, list(reversed(repo["fix_commits"]))[:2])
        self.assertEqual(args.docker_image, "img@sha256:" + "a" * 64)
        self.assertEqual(sample["candidates"], 2)
        self.assertEqual(sample["accepted"], 1)
        self.assertEqual(sample["acceptance_rate"], 0.5)
        self.assertEqual(sample["rejected"][0]["reason"],
                         "base_does_not_fail:pass")

    # ---- command line --------------------------------------------------- #
    def test_main_writes_a_heuristic_report_and_a_table(self):
        good = self.repo({**PACKAGE, "tests/test_ok.py":
                          "import pkg\n\ndef test_x():\n    pass\n"},
                         name="good")
        missing = self.root / "missing"
        output = self.root / "screen.json"
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = screen.main(["--repo", str(good), "--repo", str(missing),
                                "--candidates", "0", "-o", str(output)])
        self.assertEqual(code, 1)
        document = json.loads(output.read_text())
        self.assertTrue(document["heuristic"])
        self.assertIn("not decide", document["note"])
        reports = {item["repository"]: item
                   for item in document["repositories"]}
        self.assertEqual(reports["good"]["verdict"], "likely")
        self.assertIn("error", reports["missing"])
        text = stdout.getvalue()
        self.assertIn("good", text)
        self.assertIn("heuristic", text.lower())


class TestPathRuleTests(unittest.TestCase):
    def test_the_rule_matches_the_importer(self):
        importer = load_tool("import_study_tasks")
        for path in ("test_x.py", "x_test.py", "tests/helpers.py",
                     "pkg/tests/test_y.py", "src/pkg/core.py", "setup.py",
                     "extra/test_hypothesis.py", "test/data.json",
                     "tests/conftest.py", "docs/conf.py"):
            with self.subTest(path=path):
                self.assertEqual(screen.is_test_path(path),
                                 importer.is_test_path(path))


if __name__ == "__main__":
    unittest.main()
