"""Regression coverage for SIS 2.4.0 custody and release hardening."""
import hashlib
import importlib.util
import json
import os
import subprocess
import stat
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from sis.errors import InvalidInput
from sis.vault_storage import private_sqlite_path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('verify_release', ROOT / 'tools' / 'verify_release.py')
verify_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify_release)


class TestPrivateVaultPath(unittest.TestCase):
    def test_creates_private_regular_file(self):
        with tempfile.TemporaryDirectory() as temp:
            path = private_sqlite_path(Path(temp) / 'nested' / 'vault.sqlite3', 'test vault')
            self.assertTrue(path.is_file())
            if os.name == 'posix':
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    @unittest.skipUnless(os.name == 'posix', 'POSIX directory permission check')
    def test_rejects_shared_parent_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / 'shared'
            parent.mkdir(mode=0o700)
            parent.chmod(0o755)
            with self.assertRaisesRegex(InvalidInput, 'parent permissions'):
                private_sqlite_path(parent / 'vault.sqlite3', 'test vault')

    def test_rejects_memory_symlink_directory_and_public_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(InvalidInput):
                private_sqlite_path(':memory:', 'test vault')
            directory = root / 'directory'
            directory.mkdir()
            with self.assertRaises(InvalidInput):
                private_sqlite_path(directory, 'test vault')
            if os.name == 'posix':
                linked = root / 'link.sqlite3'
                linked.symlink_to(root / 'missing.sqlite3')
                with self.assertRaises(InvalidInput):
                    private_sqlite_path(linked, 'test vault')
                exposed = root / 'exposed.sqlite3'
                exposed.write_bytes(b'')
                exposed.chmod(0o640)
                with self.assertRaises(InvalidInput):
                    private_sqlite_path(exposed, 'test vault')

    @unittest.skipUnless(os.name == 'nt', 'Windows ACL integration test')
    def test_windows_vault_file_is_created_and_reopened_with_verified_acl(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'vault.sqlite3'
            self.assertEqual(private_sqlite_path(path, 'test vault'), path)
            self.assertEqual(private_sqlite_path(path, 'test vault'), path)


class TestReleaseArchiveVerifier(unittest.TestCase):
    def archive(self, path, files=None, *, manifest=True, manifest_doc=None,
                duplicate=None, symlink=False):
        files = files or {'README.md': b'release fixture'}
        root = 'sis-release/'
        entries = dict(files)
        if manifest:
            doc = manifest_doc or {'schema': 1, 'files': {
                name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
            entries['SOURCE_SHA256.json'] = json.dumps(doc, sort_keys=True).encode()
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in entries.items():
                archive.writestr(root + name, data)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    archive.writestr(root + duplicate, b'duplicate')
            if symlink:
                info = zipfile.ZipInfo(root + 'linked')
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(info, 'target')

    def test_accepts_valid_archive_and_rejects_manifest_and_path_tampering(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'release.zip'
            self.archive(path)
            self.assertTrue(verify_release.verify(path)['valid'])

            self.archive(path, manifest=False)
            with self.assertRaisesRegex(ValueError, 'manifest'):
                verify_release.verify(path)

            self.archive(path, manifest_doc={'schema': 1, 'files': {'README.md': '0' * 64}})
            with self.assertRaisesRegex(ValueError, 'SOURCE_SHA256 mismatch'):
                verify_release.verify(path)

            self.archive(path, files={'../escape': b'bad'})
            with self.assertRaises(ValueError):
                verify_release.verify(path)

            self.archive(path, duplicate='README.md')
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', UserWarning)
                with self.assertRaisesRegex(ValueError, 'duplicate'):
                    verify_release.verify(path)

            self.archive(path, symlink=True)
            with self.assertRaisesRegex(ValueError, 'symlink'):
                verify_release.verify(path)

    def test_member_and_total_size_limits_are_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'release.zip'
            self.archive(path, files={'large.bin': b'12345'})
            with mock.patch.object(verify_release, 'MAX_MEMBER', 4):
                with self.assertRaisesRegex(ValueError, 'member exceeds'):
                    verify_release.verify(path)
            with mock.patch.object(verify_release, 'MAX_TOTAL', 10):
                with self.assertRaisesRegex(ValueError, 'total uncompressed'):
                    verify_release.verify(path)
            with mock.patch.object(verify_release, 'MAX_ARCHIVE', 1):
                with self.assertRaisesRegex(ValueError, 'compressed size'):
                    verify_release.verify(path)


class TestSourceManifestChecker(unittest.TestCase):
    def run_checker(self, root, manifest):
        tools = root / 'tools'
        tools.mkdir(exist_ok=True)
        checker = ROOT / 'tools' / 'check_source_manifest.py'
        checker_bytes = checker.read_bytes()
        (tools / checker.name).write_bytes(checker_bytes)
        (root / 'src').mkdir(exist_ok=True)
        payload = b'value = 1\n'
        (root / 'src' / 'module.py').write_bytes(payload)
        manifest_path = root / 'SOURCE_SHA256.json'
        manifest_path.write_text(json.dumps({'schema': 1, 'files': manifest}))
        return subprocess.run([sys.executable, str(tools / checker.name)],
                              capture_output=True, text=True, timeout=10)

    def test_complete_inventory_hash_and_unsafe_manifest_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            checker_hash = hashlib.sha256((ROOT / 'tools' / 'check_source_manifest.py').read_bytes()).hexdigest()
            payload_hash = hashlib.sha256(b'value = 1\n').hexdigest()
            manifest = {'tools/check_source_manifest.py': checker_hash,
                        'src/module.py': payload_hash}
            result = self.run_checker(root, manifest)
            self.assertEqual(result.returncode, 0, result.stderr)

            result = self.run_checker(root, {'tools/check_source_manifest.py': checker_hash})
            self.assertNotEqual(result.returncode, 0)

            result = self.run_checker(root, {'tools/check_source_manifest.py': checker_hash,
                                             '../escape.py': payload_hash})
            self.assertNotEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
