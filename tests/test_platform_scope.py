"""On Windows only tests/v3 is left out of collection, and every run says so, even under -q."""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("sis_tests_conftest", TESTS / "conftest.py")
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)


class PlatformScopeTests(unittest.TestCase):
    def test_windows_leaves_out_only_the_v3_layer(self):
        with mock.patch.object(conftest.os, "name", "nt"):
            self.assertTrue(conftest.pytest_ignore_collect(TESTS / "v3", None))
            self.assertIsNone(conftest.pytest_ignore_collect(TESTS, None))
            self.assertIsNone(conftest.pytest_ignore_collect(
                TESTS / "test_system.py", None))
            self.assertIsNone(conftest.pytest_ignore_collect(
                TESTS / "v3" / "fixtures", None))
            self.assertIn("POSIX-only", conftest.pytest_report_header(None))

    def test_posix_collects_everything(self):
        with mock.patch.object(conftest.os, "name", "posix"):
            self.assertIsNone(conftest.pytest_ignore_collect(TESTS / "v3", None))
            self.assertIsNone(conftest.pytest_report_header(None))


    def test_quiet_runs_still_print_the_scope_note(self):
        # Render a real `pytest -q` run with this conftest's hooks and the
        # platform forced to Windows; the note must appear in the output.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "conftest.py").write_text(textwrap.dedent(f"""
                import importlib.util, os, types
                spec = importlib.util.spec_from_file_location(
                    "scope", {str(TESTS / "conftest.py")!r})
                scope = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(scope)
                scope.os = types.SimpleNamespace(
                    name="nt", path=os.path, fspath=os.fspath)
                pytest_report_header = scope.pytest_report_header
                pytest_terminal_summary = scope.pytest_terminal_summary
            """))
            (root / "test_ok.py").write_text("def test_ok():\n    pass\n")
            env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
            for flags in (["-q"], []):
                with self.subTest(flags=flags):
                    run = subprocess.run(
                        [sys.executable, "-m", "pytest", *flags,
                         "-p", "no:cacheprovider", str(root)],
                        cwd=temp, capture_output=True, text=True, env=env)
                    self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
                    self.assertIn(conftest.POSIX_ONLY_NOTE, run.stdout)


if __name__ == "__main__":
    unittest.main()
