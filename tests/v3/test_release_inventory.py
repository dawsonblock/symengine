"""Release inventory and release-tooling identity checks.

These cover defects that only appear when a developer runs the CLI in the
repository root: SQLite sidecar files were inventoried into the release
and made ``verify_release.py`` fail on an otherwise clean tree.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "src"))

import package_release  # noqa: E402
import provenance  # noqa: E402
from check_source_manifest import _included  # noqa: E402
from sis import __version__  # noqa: E402
from sis.v3 import signatures  # noqa: E402


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
        self.archive = self.release / "SIS-v3.3.9.zip"

    def test_an_existing_archive_is_moved_to_history(self):
        self.archive.write_bytes(b"previous archive")
        moved = package_release._preserve_archive(self.archive)
        self.assertIsNotNone(moved)
        self.assertFalse(self.archive.exists())
        self.assertEqual(moved.read_bytes(), b"previous archive")
        self.assertEqual(moved.parent.name, "history")
        self.assertTrue(moved.name.startswith("SIS-v3.3.9."))

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


class ReleaseSigningBackendTests(unittest.TestCase):
    """The release seal is signed only by the constant-time backend."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "proj"
        self.root.mkdir()
        self.seed = bytes(range(32))

    def fallback(self):
        return mock.patch.object(signatures, "_HAS_CRYPTOGRAPHY", False)

    def test_the_seal_is_refused_before_anything_is_written(self):
        with self.fallback(), self.assertRaises(SystemExit) as caught:
            package_release.package(
                self.root, "SIS-test", status="test", passed=1,
                allow_dirty=True, provenance_seed=self.seed)
        message = str(caught.exception)
        self.assertIn("release provenance signing (tools/package_release.py"
                      " --provenance-key) requires the constant-time", message)
        self.assertIn("pip install -e .[production]", message)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_the_signing_step_refuses_the_vendored_fallback(self):
        statement = provenance.build_statement(
            archive_name="SIS-test.zip", archive_sha256="0" * 64,
            release="SIS-test", branch="test", source_commit="a" * 40)
        with self.fallback(), self.assertRaises(
                signatures.ConstantTimeBackendRequired):
            package_release.sign_provenance(
                statement, self.seed, "release-key",
                archive_path=self.root / "SIS-test.zip")

    def test_the_cli_refuses_a_provenance_key_on_the_fallback(self):
        key = self.root.parent / "release.key"
        key.write_text(self.seed.hex() + "\n")
        argv = ["package_release.py", "--root", str(self.root),
                "--release", "SIS-test", "--status", "test", "--passed", "1",
                "--allow-dirty", "--provenance-key", str(key)]
        with self.fallback(), mock.patch.object(sys, "argv", argv), \
                self.assertRaises(SystemExit) as caught:
            package_release.main()
        self.assertIn("pip install -e .[production]", str(caught.exception))
        self.assertEqual(list(self.root.iterdir()), [])

    @unittest.skipUnless(signatures.backend() == "cryptography",
                         "the cryptography package is not installed")
    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_the_cryptography_backend_signs_a_verifiable_seal(self):
        (self.root / "source.py").write_text("VALUE = 1\n")
        for args in (("init", "-q"), ("add", "source.py"),
                     ("-c", "user.name=t", "-c", "user.email=t@example.invalid",
                      "commit", "-q", "-m", "source")):
            subprocess.run(["git", "-C", str(self.root), *args], check=True,
                           capture_output=True)
        # The extracted tree has no test suite to smoke-test.
        with mock.patch.object(package_release, "fresh_extraction_checks",
                               return_value={"compileall_src": True}):
            result = package_release.package(
                self.root, "SIS-test", status="test", passed=1,
                allow_dirty=True, provenance_seed=self.seed)
        info = result["release_manifest"]["provenance"]
        self.assertTrue(info["signed"])
        statement = provenance.verify_file(
            self.root / "release" / "provenance.dsse.json",
            provenance.public_key_hex(self.seed),
            archive_path=self.root / "release" / "SIS-test.zip")
        self.assertEqual(statement["subject"][0]["digest"]["sha256"],
                         info["subject_sha256"])


if __name__ == "__main__":
    unittest.main()
