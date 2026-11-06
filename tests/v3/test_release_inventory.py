"""Release inventory and release-tooling identity checks.

These cover defects that only appear when a developer runs the CLI in the
repository root: SQLite sidecar files were inventoried into the release
and made ``verify_release.py`` fail on an otherwise clean tree.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import package_release  # noqa: E402
from check_source_manifest import _included  # noqa: E402
from sis import __version__  # noqa: E402


class InventoryExclusionTests(unittest.TestCase):
    def test_sqlite_sidecars_are_not_inventoried(self):
        for name in ("sis.sqlite3-wal", "sis.sqlite3-shm",
                     "sis.sqlite3-journal", "sis.db-wal", "sis.db-shm",
                     "sis.db-journal"):
            with self.subTest(name=name):
                self.assertFalse(_included(name), name)

    def test_source_files_remain_inventoried(self):
        self.assertTrue(_included("README.md"))
        self.assertTrue(_included("src/sis/cli.py"))


class ReleaseToolingVersionTests(unittest.TestCase):
    def test_default_release_name_uses_package_version(self):
        self.assertEqual(package_release._package_version(ROOT), __version__)


if __name__ == "__main__":
    unittest.main()
