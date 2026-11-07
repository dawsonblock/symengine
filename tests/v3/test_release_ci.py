"""Release CI fails closed; development drift is an explicit policy choice."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from build_release import write_manifest


class ReleaseCITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "source.py").write_text("VALUE = 1\n")
        write_manifest(self.root)

    def run_check(self, mode):
        return subprocess.run(
            [sys.executable, str(ROOT / "tools/check_release_ci.py"),
             "--mode", mode, "--source", str(self.root)],
            capture_output=True, text=True,
        )

    def test_matching_inventory_passes_both_modes(self):
        for mode in ("release", "development"):
            self.assertEqual(self.run_check(mode).returncode, 0)

    def test_stale_release_fails_without_rewriting_manifest(self):
        original = (self.root / "RELEASE_SHA256.json").read_bytes()
        (self.root / "source.py").write_text("VALUE = 2\n")
        self.assertNotEqual(self.run_check("release").returncode, 0)
        self.assertEqual((self.root / "RELEASE_SHA256.json").read_bytes(), original)

    def test_extra_untracked_source_fails_release(self):
        (self.root / "new_test.py").write_text("assert True\n")
        self.assertNotEqual(self.run_check("release").returncode, 0)

    def test_missing_source_fails_release(self):
        (self.root / "source.py").unlink()
        self.assertNotEqual(self.run_check("release").returncode, 0)

    def test_development_drift_is_explicitly_not_release_verification(self):
        (self.root / "source.py").write_text("VALUE = 2\n")
        result = self.run_check("development")
        self.assertEqual(result.returncode, 0)
        self.assertIn("not release verification", result.stdout)

    def test_missing_manifest_fails_both_modes(self):
        (self.root / "RELEASE_SHA256.json").unlink()
        for mode in ("release", "development"):
            self.assertNotEqual(self.run_check(mode).returncode, 0)

    def test_malformed_manifest_fails_both_modes(self):
        for body in ("{", json.dumps({"schema": 1, "files": {"../escape": "0" * 64}})):
            (self.root / "RELEASE_SHA256.json").write_text(body)
            for mode in ("release", "development"):
                self.assertNotEqual(self.run_check(mode).returncode, 0)

    def test_workflow_gates_by_event_not_inventory_success(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("types: [published]", workflow)
        self.assertIn("if: startsWith(github.ref, 'refs/tags/') || github.event_name == 'release'", workflow)
        self.assertIn("run: python tools/check_release_ci.py --mode release", workflow)
        self.assertNotIn("if python tools/build_release.py --check", workflow)
