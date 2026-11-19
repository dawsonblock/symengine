"""On Windows only tests/v3 is left out of collection, and the run header says so."""
from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
