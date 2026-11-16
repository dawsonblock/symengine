"""An untrusted checkout must not run Git-configured programs during validation."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import gitquery
from sis.v3.efficacy_manifest import (verify_repository_binding,
                                      verify_repository_provenance)

ORIGIN = "https://example.invalid/repo.git"


def _git(repo: Path, *args: str) -> str:
    """Run a fixture Git command with the same hardening the tool uses."""
    completed = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.fsmonitor=false",
         "-c", f"core.hooksPath={os.devnull}", *args],
        capture_output=True, text=True, check=True)
    return completed.stdout.strip()


class _RepoFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)

    def repo(self, name: str, *, content: str = "same\n") -> Path:
        root = self.base / name
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        _git(root, "config", "user.email", "test@example.invalid")
        _git(root, "config", "user.name", "test")
        (root / "file.txt").write_text(content)
        _git(root, "add", "file.txt")
        _git(root, "commit", "-qm", name)
        return root

    def record(self, root: Path, *, base_commit: str | None = None) -> dict:
        return {"repository_id": root.name, "path": str(root),
                "origin": ORIGIN,
                "base_commit": base_commit or _git(root, "rev-parse", "HEAD")}


class GitQueryTests(_RepoFixture):
    def test_non_repository_returns_none(self):
        plain = self.base / "plain"
        plain.mkdir()
        self.assertIsNone(gitquery.query(plain, "rev-parse", "HEAD"))
        self.assertFalse(gitquery.predicate(plain, "rev-parse", "HEAD"))

    def test_repository_config_is_still_read(self):
        # Hardening must not disable the repository's own config: the
        # provenance check has to read remote.origin.url.
        root = self.repo("repo")
        _git(root, "remote", "add", "origin", ORIGIN)
        self.assertEqual(
            gitquery.query(root, "remote", "get-url", "origin"), ORIGIN)

    @unittest.skipUnless(sys.platform != "win32", "fsmonitor fixture is POSIX")
    def test_fsmonitor_config_cannot_execute(self):
        root = self.repo("repo")
        _git(root, "remote", "add", "origin", ORIGIN)
        _git(root, "update-ref", "refs/remotes/origin/main", "HEAD")
        marker = self.base / "fsmonitor-ran"
        script = self.base / "fsmonitor.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"echo ran >> {shlex.quote(str(marker))}\n"
            "printf '\\n'\n")
        script.chmod(0o755)
        _git(root, "config", "core.fsmonitor", str(script))

        # Prove the fixture is live: an unhardened status runs the hook.
        subprocess.run(
            ["git", "-C", str(root), "status", "--porcelain"],
            capture_output=True, text=True, check=True)
        self.assertTrue(marker.exists(), "fsmonitor fixture did not run")
        marker.unlink()

        record = self.record(root)
        self.assertEqual(verify_repository_provenance(record), [])
        self.assertFalse(marker.exists())
        head, problems = verify_repository_binding(record)
        self.assertEqual(problems, [])
        self.assertEqual(head, record["base_commit"])
        self.assertFalse(marker.exists())

    def test_environment_cannot_redirect_the_query(self):
        # A GIT_DIR inherited from the caller used to make every query
        # answer for another repository while --show-toplevel still named
        # the path under test, so a clean checkout could "prove" a commit
        # it never contained.
        a = self.repo("a")
        b = self.repo("b")
        head_a = _git(a, "rev-parse", "HEAD")
        head_b = _git(b, "rev-parse", "HEAD")
        self.assertNotEqual(head_a, head_b)
        with mock.patch.dict(os.environ, {
                "GIT_DIR": str(b / ".git"),
                "GIT_WORK_TREE": str(a),
                "GIT_INDEX_FILE": str(b / ".git" / "index")}):
            self.assertEqual(gitquery.query(a, "rev-parse", "HEAD"), head_a)
            head, problems = verify_repository_binding(
                self.record(a, base_commit=head_b))
        self.assertEqual(head, head_a)
        self.assertIn("repository_base_commit_mismatch: a", problems)


if __name__ == "__main__":
    unittest.main()
