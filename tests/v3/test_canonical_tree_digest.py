"""Canonical repository fingerprint (SIS-FIX-01).

The legacy tree digest hashed entries in ``os.walk`` order, which is
filesystem-dependent. Identical contents could therefore receive
different identities, and staging an unchanged repository could fail.
Version 2 sorts every directory level and is the identity every new
record uses. Version 1 is retained only to re-verify historical
records; it must reproduce the old bytes exactly, order dependence
included.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3.benchmark import stage_repository
from sis.v3.runner import (
    CANONICAL_TREE_DIGEST_VERSION,
    RunnerError,
    TREE_DIGEST_VERSIONS,
    scan_tree,
    tree_digest,
    verify_tree_digest,
)

POSIX = os.name == "posix"

# Fixed vectors produced by the pre-canonical implementation. They pin
# the legacy format so a compatibility fix can never silently rewrite it.
LEGACY_SINGLE_FILE = "50273e6a7567babe06e4b9f37a4ffbba3a14f00b5cd0ec61cbcbed7ae6d12a21"
LEGACY_TWO_FILE_SORTED_WALK = (
    "a3b7ceb57e6166a1c6de3155465b8e7f7ba38a88c94efd671caeb0e51136833f")


class CanonicalTreeDigestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def _write(self, relative: str, content: bytes, root: Path | None = None):
        path = (root or self.root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def _fixed_walk(self, order):
        def walk(top, *_args, **_kwargs):
            for dirpath, dirnames, filenames in order:
                yield dirpath, list(dirnames), list(filenames)
        return walk

    def test_canonical_version_is_the_default(self):
        self._write("a.txt", b"one\n")
        scan = scan_tree(self.root)
        self.assertEqual(scan.version, CANONICAL_TREE_DIGEST_VERSION)
        self.assertEqual(CANONICAL_TREE_DIGEST_VERSION, 2)
        self.assertEqual(TREE_DIGEST_VERSIONS, (1, 2))

    def test_identical_contents_ignore_traversal_order(self):
        self._write("a.txt", b"one\n")
        self._write("b.txt", b"two\n")
        self._write("sub/c.txt", b"three\n")
        self._write("sub/d.txt", b"four\n")
        baseline = tree_digest(self.root)

        real_walk = os.walk

        def reversed_walk(top, *args, **kwargs):
            for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
                yield dirpath, list(reversed(dirnames)), list(reversed(filenames))

        with mock.patch("sis.v3.runner.os.walk", reversed_walk):
            self.assertEqual(tree_digest(self.root), baseline)

    def test_identical_trees_created_in_different_orders_share_identity(self):
        first = self.base / "first"
        second = self.base / "second"
        for name, content in (("a.txt", b"one\n"), ("b.txt", b"two\n"),
                              ("sub/c.txt", b"three\n")):
            self._write(name, content, root=first)
        for name, content in (("sub/c.txt", b"three\n"), ("b.txt", b"two\n"),
                              ("a.txt", b"one\n")):
            self._write(name, content, root=second)
        self.assertEqual(tree_digest(first), tree_digest(second))

    def test_legacy_single_file_vector_is_unchanged(self):
        self._write("a.txt", b"one\n")
        self.assertEqual(tree_digest(self.root, version=1),
                         LEGACY_SINGLE_FILE)
        self.assertEqual(scan_tree(self.root, version=1).version, 1)

    def test_legacy_multi_file_vector_is_unchanged(self):
        self._write("a.txt", b"one\n")
        self._write("sub/b.txt", b"two\n")
        order = [
            (str(self.root), ["sub"], ["a.txt"]),
            (str(self.root / "sub"), [], ["b.txt"]),
        ]
        with mock.patch("sis.v3.runner.os.walk", self._fixed_walk(order)):
            self.assertEqual(tree_digest(self.root, version=1),
                             LEGACY_TWO_FILE_SORTED_WALK)

    def test_legacy_format_remains_traversal_order_dependent(self):
        """The defect v2 fixes: v1 identity follows filesystem order."""
        self._write("a.txt", b"one\n")
        self._write("b.txt", b"two\n")
        order = [
            (str(self.root), [], ["a.txt", "b.txt"]),
            (str(self.root), [], ["b.txt", "a.txt"]),
        ]
        with mock.patch("sis.v3.runner.os.walk",
                        self._fixed_walk([order[0]])):
            sorted_digest = tree_digest(self.root, version=1)
        with mock.patch("sis.v3.runner.os.walk",
                        self._fixed_walk([order[1]])):
            reversed_digest = tree_digest(self.root, version=1)
        self.assertNotEqual(sorted_digest, reversed_digest)

    def test_canonical_digest_tracks_content_and_path(self):
        self._write("a.txt", b"one\n")
        first = tree_digest(self.root)
        self._write("a.txt", b"two\n")
        self.assertNotEqual(tree_digest(self.root), first)
        self._write("a.txt", b"one\n")
        self.assertEqual(tree_digest(self.root), first)
        (self.root / "a.txt").rename(self.root / "b.txt")
        self.assertNotEqual(tree_digest(self.root), first)

    def test_empty_directories_are_not_part_of_the_fingerprint(self):
        self._write("a.txt", b"one\n")
        first = tree_digest(self.root)
        (self.root / "empty").mkdir()
        self.assertEqual(tree_digest(self.root), first)

    @unittest.skipUnless(POSIX, "symlink semantics are POSIX-only")
    def test_symlink_target_changes_the_digest(self):
        self._write("target.txt", b"one\n")
        self._write("other.txt", b"two\n")
        (self.root / "link").symlink_to("target.txt")
        first = tree_digest(self.root)
        (self.root / "link").unlink()
        (self.root / "link").symlink_to("other.txt")
        self.assertNotEqual(tree_digest(self.root), first)
        (self.root / "link").unlink()
        (self.root / "link").symlink_to("/etc/hosts")
        self.assertIn("link", scan_tree(self.root).external_symlinks)
        self.assertIn("link", scan_tree(self.root, version=1).external_symlinks)

    @unittest.skipUnless(POSIX, "raw byte names are POSIX-only")
    def test_non_utf8_names_round_trip(self):
        raw = os.fsencode(self.root) + b"/\xff.txt"
        try:
            descriptor = os.open(raw, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError:
            self.skipTest("filesystem rejects non-UTF-8 names")
        try:
            os.write(descriptor, b"one\n")
        finally:
            os.close(descriptor)
        first = tree_digest(self.root)
        self.assertEqual(tree_digest(self.root), first)
        with self.assertRaises(UnicodeEncodeError):
            tree_digest(self.root, version=1)

    def test_verify_tree_digest_reports_the_matching_version(self):
        self._write("a.txt", b"one\n")
        canonical = tree_digest(self.root)
        legacy = tree_digest(self.root, version=1)
        self.assertEqual(verify_tree_digest(self.root, canonical), 2)
        self.assertEqual(verify_tree_digest(self.root, legacy), 1)
        with self.assertRaisesRegex(RunnerError, "tree_digest_mismatch"):
            verify_tree_digest(self.root, legacy, allow_legacy=False)
        with self.assertRaisesRegex(RunnerError, "tree_digest_mismatch"):
            verify_tree_digest(self.root, "0" * 64)

    def test_verify_tree_digest_rejects_malformed_input(self):
        self._write("a.txt", b"one\n")
        for value in ("", "0" * 63, "A" * 64, None):
            with self.assertRaisesRegex(RunnerError, "tree_digest_malformed"):
                verify_tree_digest(self.root, value)

    def test_unknown_digest_versions_are_refused(self):
        self._write("a.txt", b"one\n")
        for version in (0, 3, True, "2", None):
            with self.assertRaisesRegex(
                    RunnerError, "unsupported_tree_digest_version"):
                tree_digest(self.root, version=version)

    def test_stage_repository_binds_the_canonical_digest(self):
        self._write("a.txt", b"one\n")
        self._write("sub/b.txt", b"two\n")
        expected = tree_digest(self.root)
        staged = self.base / "staged"
        self.assertEqual(stage_repository(self.root, staged), expected)
        self.assertEqual(tree_digest(staged), expected)
        self.assertEqual(scan_tree(staged).version, 2)


if __name__ == "__main__":
    unittest.main()
