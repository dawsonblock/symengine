"""Inventory reconciliation: every drift from the seal is classified and attributed.

A small Git repository is sealed with a hand-made ``RELEASE_SHA256.json``,
then developed: one file modified, one deleted, one moved (after an edit
under its old name), one added through a pull-request merge. The tool
must attribute each of those to its commit, follow the move, and fail
the gate for anything Git history cannot explain.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "reconcile_inventory", ROOT / "tools" / "reconcile_inventory.py")
tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(tool)

GIT = shutil.which("git")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=SIS",
         "-c", "user.email=sis@example.invalid", *args],
        check=True, capture_output=True, text=True).stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "--short", "HEAD")


def _write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _inventory(files: dict[str, str]) -> str:
    """A hand-made inventory in the release manifest's exact format."""
    document = {"schema": 1, "files": {
        relative: hashlib.sha256(content.encode()).hexdigest()
        for relative, content in sorted(files.items())}}
    return json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"


def _run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = tool.main(list(argv))
    return code, out.getvalue(), err.getvalue()


def _record(report: dict, path: str) -> dict:
    for records in report["paths"].values():
        for record in records:
            if record["path"] == path:
                return record
    raise AssertionError(f"{path} is not in the report")


@unittest.skipUnless(GIT, "git is not installed")
class ReconcileInventoryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        repo = self.repo
        _git(repo, "init", "-q")
        sealed = {
            "same.txt": "same\n",
            "edit.txt": "before\n",
            "gone.txt": "gone\n",
            "docs/old.md": "# Old\n",
        }
        for relative, content in sealed.items():
            _write(repo, relative, content)
        # Out-of-band and generated paths never enter the inventory.
        _write(repo, "release/notes.json", "{}\n")
        _write(repo, ".gitignore", "*.pyc\n")
        sealed[".gitignore"] = "*.pyc\n"
        _commit(repo, "Initial layout")
        _write(repo, "RELEASE_SHA256.json", _inventory(sealed))
        self.seal = _commit(repo, "Seal v0.1")
        self.edit = (_write(repo, "edit.txt", "after\n"),
                     _commit(repo, "Change the edit file"))[1]
        self.remove = ((repo / "gone.txt").unlink(),
                       _commit(repo, "Remove the gone file"))[1]
        self.touch_old = (_write(repo, "docs/old.md", "# Old, edited\n"),
                          _commit(repo, "Edit the old doc in place"))[1]
        (repo / "docs" / "history").mkdir()
        _git(repo, "mv", "docs/old.md", "docs/history/old.md")
        self.move = _commit(repo, "Move the old doc into docs/history/")
        main = _git(repo, "symbolic-ref", "--short", "HEAD")
        _git(repo, "checkout", "-q", "-b", "feature")
        _write(repo, "new.txt", "new\n")
        self.add = _commit(repo, "Add the new file")
        _git(repo, "checkout", "-q", main)
        _git(repo, "merge", "-q", "--no-ff", "feature",
             "-m", "Merge pull request #12 from example/feature")
        self.merge = _git(repo, "rev-parse", "--short", "HEAD")

    def reconcile(self, **kwargs) -> dict:
        kwargs.setdefault("repo", self.repo)
        return tool.reconcile(**kwargs)

    def test_each_class_is_counted_and_attributed(self):
        report = self.reconcile()
        self.assertEqual(report["counts"]["unchanged"], 2)  # same, .gitignore
        self.assertEqual(report["counts"]["modified"], 1)
        self.assertEqual(report["counts"]["missing_from_tree"], 2)
        self.assertEqual(report["counts"]["extra_in_tree"], 2)
        self.assertEqual(report["counts"]["unattributed"], 0)
        self.assertTrue(report["gate"]["passed"], report["gate"])
        self.assertEqual(report["inventory"]["seal_commit"][:7],
                         self.seal[:7])
        self.assertTrue(report["inventory"]["matches_seal_commit"])
        self.assertTrue(report["inventory"]["seal_tree_matches_inventory"])

        modified = _record(report, "edit.txt")
        self.assertEqual([e["commit"] for e in modified["commits"]],
                         [self.edit])
        gone = _record(report, "gone.txt")
        self.assertEqual(gone["commits"],
                         [{"commit": self.remove, "status": "D"}])
        added = _record(report, "new.txt")
        self.assertEqual(added["commits"],
                         [{"commit": self.add, "status": "A"}])

    def test_the_release_filter_is_the_release_toolings(self):
        (self.repo / "cache.pyc").write_bytes(b"\0")
        report = self.reconcile()
        paths = {record["path"] for records in report["paths"].values()
                 for record in records}
        self.assertNotIn("release/notes.json", paths)
        self.assertNotIn("RELEASE_SHA256.json", paths)
        self.assertNotIn("cache.pyc", paths)
        self.assertTrue(report["gate"]["passed"], report["gate"])

    def test_a_move_is_followed_as_a_rename(self):
        report = self.reconcile()
        old = _record(report, "docs/old.md")
        self.assertEqual(old["renamed_to"], "docs/history/old.md")
        new = _record(report, "docs/history/old.md")
        self.assertEqual(new["renamed_from"], "docs/old.md")
        # The edit made under the old name is part of the moved file's
        # history.
        self.assertEqual([e["commit"] for e in new["commits"]],
                         [self.move, self.touch_old])
        self.assertEqual(new["commits"][0]["status"], "R")
        self.assertEqual(report["renames"], [
            {"from": "docs/old.md", "to": "docs/history/old.md",
             "commit": self.move}])

    def test_commits_are_grouped_by_the_pull_request_that_merged_them(self):
        report = self.reconcile()
        groups = {group["group"]: group for group in report["groups"]}
        self.assertEqual(set(groups), {"PR #12", "direct"})
        pr = groups["PR #12"]
        self.assertEqual(pr["merge"], self.merge)
        self.assertEqual([c["commit"] for c in pr["commits"]], [self.add])
        self.assertEqual(pr["paths"]["extra_in_tree"], 1)
        direct = [c["commit"] for c in groups["direct"]["commits"]]
        self.assertEqual(direct, [self.move, self.touch_old, self.remove,
                                  self.edit])

    def test_an_uncommitted_edit_is_unattributed(self):
        _write(self.repo, "same.txt", "edited but not committed\n")
        report = self.reconcile()
        self.assertFalse(report["gate"]["passed"])
        self.assertEqual(report["unattributed"], [{
            "path": "same.txt", "class": "modified",
            "reason": "bytes differ from the revision"}])

    def test_an_untracked_file_is_unattributed(self):
        _write(self.repo, "stray.txt", "stray\n")
        report = self.reconcile()
        self.assertEqual(report["unattributed"], [{
            "path": "stray.txt", "class": "extra_in_tree",
            "reason": "in neither the revision nor the inventory"}])

    def test_a_file_deleted_only_from_the_tree_is_unattributed(self):
        (self.repo / "same.txt").unlink()
        report = self.reconcile()
        self.assertEqual(report["unattributed"], [{
            "path": "same.txt", "class": "missing_from_tree",
            "reason": "absent from the tree but in the revision"}])

    def test_an_inventory_that_is_not_the_seal_fails_the_gate(self):
        document = json.loads((self.repo / "RELEASE_SHA256.json").read_text())
        document["files"]["same.txt"] = "0" * 64
        outside = self.base / "inventory.json"
        outside.write_text(json.dumps(document))
        report = self.reconcile(inventory_path=outside)
        self.assertFalse(report["inventory"]["matches_seal_commit"])
        self.assertFalse(report["gate"]["passed"])

    def test_a_seal_whose_tree_differs_from_its_inventory_is_unattributed(self):
        # Re-seal the current tree, but with a wrong hash for one file: no
        # commit since that seal explains the difference.
        document = {"schema": 1, "files": tool.inventory(self.repo)}
        document["files"]["same.txt"] = "0" * 64
        (self.repo / "RELEASE_SHA256.json").write_text(json.dumps(document))
        _commit(self.repo, "Seal with a wrong hash")
        report = self.reconcile()
        self.assertFalse(report["inventory"]["seal_tree_matches_inventory"])
        self.assertIn("same.txt", report["inventory"]["seal_tree_mismatches"])
        reasons = {item["path"]: item["reason"]
                   for item in report["unattributed"]}
        self.assertEqual(reasons, {
            "same.txt": "the seal commit's tree does not match the inventory"})

    def _export(self, revision: str) -> Path:
        """Extract a ``git archive`` zip, as a downloaded archive would be."""
        archive = self.base / f"{revision}.zip"
        subprocess.run(
            ["git", "-C", str(self.repo), "archive", "--format=zip",
             f"--prefix=project-{revision}/", "-o", str(archive), revision],
            check=True)
        target = self.base / "extract"
        with zipfile.ZipFile(archive) as handle:
            handle.extractall(target)
        return target / f"project-{revision}"

    def test_an_extracted_archive_of_an_earlier_commit(self):
        tree = self._export(self.remove)
        against_head = self.reconcile(tree=tree)
        self.assertFalse(against_head["gate"]["passed"])
        reasons = {item["path"]: item["reason"]
                   for item in against_head["unattributed"]}
        # edit.txt is already at its HEAD content; the moved and added
        # files are what the earlier tree cannot explain.
        self.assertNotIn("edit.txt", reasons)
        self.assertEqual(reasons["docs/old.md"], "not in the revision")
        self.assertEqual(reasons["new.txt"],
                         "in the revision but not in the tree")
        self.assertEqual(against_head["revision"]["revision_only"],
                         ["docs/history/old.md", "new.txt"])

        report = self.reconcile(tree=tree, revision=self.remove)
        self.assertTrue(report["gate"]["passed"], report["unattributed"])
        self.assertEqual(report["counts"]["modified"], 1)
        self.assertEqual(report["counts"]["missing_from_tree"], 1)
        self.assertEqual(report["counts"]["extra_in_tree"], 0)
        self.assertEqual(report["tree"]["name"], f"project-{self.remove}")
        self.assertFalse(report["tree"]["inside_repository"])

    def test_exit_codes_and_reports(self):
        out_json = self.base / "out" / "report.json"
        out_md = self.base / "out" / "report.md"
        code, stdout, _ = _run("--repo", str(self.repo),
                               "--json", str(out_json),
                               "--markdown", str(out_md))
        self.assertEqual(code, 0)
        self.assertIn("modified=1 missing_from_tree=2 extra_in_tree=2"
                      " unattributed=0", stdout)
        written = json.loads(out_json.read_text())
        self.assertEqual(written["kind"], "inventory_reconciliation")
        markdown = out_md.read_text()
        self.assertIn("The seal must be regenerated by the owner's signed"
                      " release process.", markdown)
        self.assertIn("| `unattributed` | 0 |", markdown)
        self.assertIn("PR #12", markdown)

        _write(self.repo, "stray.txt", "stray\n")
        code, _, stderr = _run("--repo", str(self.repo))
        self.assertEqual(code, 1)
        self.assertIn("unattributed: stray.txt", stderr)

        code, _, stderr = _run("--repo", str(self.base / "missing"))
        self.assertEqual(code, 2)
        bad = self.base / "bad.json"
        bad.write_text('{"schema": 2, "files": {}}')
        code, _, stderr = _run("--repo", str(self.repo),
                               "--inventory", str(bad))
        self.assertEqual(code, 2)
        self.assertIn("inventory is invalid", stderr)

    def test_an_explicit_seal_commit_is_used(self):
        report = self.reconcile(seal_commit=self.seal)
        self.assertTrue(report["gate"]["passed"], report["gate"])
        self.assertEqual(report["history"]["lineage_commits"], 6)


if __name__ == "__main__":
    unittest.main()
