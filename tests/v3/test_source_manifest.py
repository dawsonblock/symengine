import contextlib
import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = "daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"


def _baseline_available():
    try:
        subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", f"{BASELINE}^{{commit}}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return True


def _seal_commit():
    """The commit that last sealed RELEASE_SHA256.json, if Git history exists."""
    try:
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--",
             "RELEASE_SHA256.json"],
            capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return commit or None


def _checker():
    spec = importlib.util.spec_from_file_location(
        "check_source_manifest", ROOT / "tools" / "check_source_manifest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceManifestModeTests(unittest.TestCase):
    def test_pinned_baseline_verification_reports_dev_delta_separately(self):
        # The v2 baseline lives in the upstream SIS history. This
        # repository was imported at v3.3.2 without it, so here the test
        # cannot run; the seal-commit test below exercises the same mode.
        if not _baseline_available():
            self.skipTest(
                "pinned v2 Git baseline daf0ccc is not in this checkout's "
                "history (imported at v3.3.2, or an extracted archive)"
            )
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_source_manifest.py"), "--baseline-ref", BASELINE],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("138 source files SHA-256 verified at baseline", result.stdout)
        self.assertIn("baseline manifest does not cover these changes", result.stdout)

    def test_seal_commit_baseline_verification_reports_dev_delta_separately(self):
        seal = _seal_commit()
        if seal is None:
            self.skipTest("no Git history: an extracted archive has no seal commit")
        sealed = json.loads(subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{seal}:RELEASE_SHA256.json"],
            capture_output=True, check=True).stdout)
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools/check_source_manifest.py"),
             "--baseline-ref", seal],
            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        # The seal commit's own tree must hold every inventoried blob.
        self.assertIn(f"{len(sealed['files'])} source files SHA-256 verified"
                      f" at baseline {seal}", result.stdout, result.stderr)
        current = json.loads((ROOT / "RELEASE_SHA256.json").read_text())
        if current == sealed:
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("baseline manifest does not cover these changes",
                          result.stdout)


class SourceManifestSelectionTests(unittest.TestCase):
    """The release inventory is authoritative; the legacy name still works."""

    def _root(self, temp, manifest_name, files):
        root = Path(temp)
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        document = {
            "schema": 1,
            "files": {
                relative: hashlib.sha256(content.encode()).hexdigest()
                for relative, content in files.items()},
        }
        (root / manifest_name).write_text(json.dumps(document))
        return root

    def _main(self, checker, root):
        original = checker.ROOT
        checker.ROOT = root
        try:
            with contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                return checker.main([])
        finally:
            checker.ROOT = original

    def test_the_release_manifest_is_preferred(self):
        checker = _checker()
        with tempfile.TemporaryDirectory() as temp:
            root = self._root(temp, "RELEASE_SHA256.json", {"a.txt": "A"})
            self.assertEqual(self._main(checker, root), 0)

    def test_the_legacy_manifest_is_accepted_when_release_is_absent(self):
        checker = _checker()
        with tempfile.TemporaryDirectory() as temp:
            root = self._root(temp, "SOURCE_SHA256.json", {"a.txt": "A"})
            self.assertEqual(self._main(checker, root), 0)

    def test_a_missing_manifest_is_an_integrity_failure(self):
        checker = _checker()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.txt").write_text("A")
            self.assertEqual(self._main(checker, root), 1)


if __name__ == "__main__":
    unittest.main()
