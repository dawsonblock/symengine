"""Repository validation must not run repository-configured filter drivers."""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3 import gitquery
from sis.v3.efficacy_manifest import verify_repository_binding


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repo), "-c", "core.fsmonitor=false",
         "-c", f"core.hooksPath={os.devnull}", *args],
        capture_output=True, text=True, check=True)
    return completed.stdout.strip()


@unittest.skipUnless(sys.platform != "win32", "filter fixture is POSIX")
class FilterDriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "repo"
        self.root.mkdir()
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        _git(self.root, "config", "user.email", "test@example.invalid")
        _git(self.root, "config", "user.name", "test")
        (self.root / "file.txt").write_text("same\n")
        (self.root / "run.sh").write_text("#!/bin/sh\n")
        (self.root / "run.sh").chmod(0o755)
        _git(self.root, "add", "file.txt", "run.sh")
        _git(self.root, "commit", "-qm", "init")
        self.marker = self.base / "filter-ran"
        script = self.base / "evil.sh"
        script.write_text(
            "#!/bin/sh\n"
            f"echo ran >> {shlex.quote(str(self.marker))}\n"
            "cat\n")
        script.chmod(0o755)
        # The attack: an untracked .gitattributes in the checkout plus a
        # clean filter in its own .git/config.
        (self.root / ".git" / "info").mkdir(exist_ok=True)
        (self.root / ".git" / "info" / "attributes").write_text(
            "* filter=evil\n")
        _git(self.root, "config", "filter.evil.clean", str(script))
        _git(self.root, "config", "filter.evil.smudge", "cat")
        # Touch the file so the stat cache is stale and git must re-read it.
        os.utime(self.root / "file.txt", (1, 1))

    def record(self) -> dict:
        return {"repository_id": "repo", "path": str(self.root),
                "base_commit": _git(self.root, "rev-parse", "HEAD")}

    def test_fixture_filter_is_live(self):
        subprocess.run(
            ["git", "-C", str(self.root), "status", "--porcelain"],
            capture_output=True, check=True)
        self.assertTrue(self.marker.exists(), "filter fixture did not run")

    def test_binding_check_does_not_run_the_filter(self):
        head, problems = verify_repository_binding(self.record())
        self.assertEqual(problems, [])
        self.assertIsNotNone(head)
        self.assertFalse(self.marker.exists())

    def test_modified_untracked_and_mode_changes_are_dirty(self):
        self.assertTrue(gitquery.worktree_matches_head(self.root))
        (self.root / "file.txt").write_text("changed\n")
        self.assertFalse(gitquery.worktree_matches_head(self.root))
        _git(self.root, "checkout", "--", "file.txt")
        self.marker.unlink(missing_ok=True)
        self.assertTrue(gitquery.worktree_matches_head(self.root))
        (self.root / "run.sh").chmod(0o644)
        self.assertFalse(gitquery.worktree_matches_head(self.root))
        (self.root / "run.sh").chmod(0o755)
        (self.root / "new.py").write_text("x = 1\n")
        self.assertFalse(gitquery.worktree_matches_head(self.root))
        (self.root / ".gitignore").write_text("")
        (self.root / "new.py").unlink()
        self.assertFalse(gitquery.worktree_matches_head(self.root))
        (self.root / ".gitignore").unlink()
        (self.root / "file.txt").unlink()
        self.assertFalse(gitquery.worktree_matches_head(self.root))
        self.assertFalse(self.marker.exists())

    def test_staged_change_is_dirty(self):
        (self.root / "file.txt").write_text("staged\n")
        _git(self.root, "-c", "filter.evil.clean=cat", "add", "file.txt")
        (self.root / "file.txt").write_text("same\n")
        self.assertFalse(gitquery.worktree_matches_head(self.root))

    def test_replace_refs_cannot_swap_the_checked_tree(self):
        # A replace ref makes HEAD's object read as another commit whose
        # tree matches a modified checkout. Validation must ignore it.
        head = _git(self.root, "rev-parse", "HEAD")
        (self.root / "file.txt").write_text("changed\n")
        _git(self.root, "-c", "filter.evil.clean=cat", "add", "file.txt")
        _git(self.root, "commit", "-qm", "other")
        other = _git(self.root, "rev-parse", "HEAD")
        _git(self.root, "reset", "-q", "--soft", head)
        _git(self.root, "replace", head, other)
        self.marker.unlink(missing_ok=True)
        self.assertEqual(_git(self.root, "rev-parse", "HEAD"), head)
        self.assertFalse(gitquery.worktree_matches_head(self.root))

    def test_environment_disables_replace_objects_and_transports(self):
        env = gitquery.environment()
        self.assertEqual(env["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertIn("protocol.allow=never", gitquery._GLOBAL_OPTIONS)


if __name__ == "__main__":
    unittest.main()
