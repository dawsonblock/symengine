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

    def test_transient_coverage_files_are_not_inventoried(self):
        for name in (".coverage", ".coverage.hostname.12345"):
            with self.subTest(name=name):
                self.assertFalse(_included(name), name)

    def test_source_files_remain_inventoried(self):
        self.assertTrue(_included("README.md"))
        self.assertTrue(_included("src/sis/cli.py"))


class ReleaseToolingVersionTests(unittest.TestCase):
    def test_default_release_name_uses_package_version(self):
        self.assertEqual(package_release._package_version(ROOT), __version__)


class ArchivePreservationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.release = Path(self.temp.name) / "release"
        self.release.mkdir()
        self.archive = self.release / "SIS-v3.3.8.zip"

    def test_an_existing_archive_is_moved_to_history(self):
        self.archive.write_bytes(b"previous archive")
        moved = package_release._preserve_archive(self.archive)
        self.assertIsNotNone(moved)
        self.assertFalse(self.archive.exists())
        self.assertEqual(moved.read_bytes(), b"previous archive")
        self.assertEqual(moved.parent.name, "history")
        self.assertTrue(moved.name.startswith("SIS-v3.3.8."))

    def test_a_second_preserve_does_not_clobber_the_first(self):
        self.archive.write_bytes(b"previous archive")
        first = package_release._preserve_archive(self.archive)
        self.archive.write_bytes(b"previous archive")
        second = package_release._preserve_archive(self.archive)
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists())
        self.assertTrue(second.exists())

    def test_no_archive_is_a_no_op(self):
        self.assertIsNone(package_release._preserve_archive(self.archive))


if __name__ == "__main__":
    unittest.main()
