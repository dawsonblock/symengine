"""Under a pytest other than the evaluator's pin the suite stops once, clearly.

The evaluator refuses any pytest but ``EvaluationRuntimeProfile``'s pin
(``runtime_pin_mismatch``), so a run under another pytest would report
every evaluator test as a failure. ``tests/conftest.py`` ends such a run
before collection with one message instead; ``SIS_ALLOW_UNPINNED_PYTEST=1``
runs it anyway.
"""
from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from sis.v3.evaluation_runtime import EvaluationRuntimeProfile

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
_spec = importlib.util.spec_from_file_location(
    "sis_tests_conftest_pin", TESTS / "conftest.py")
conftest = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(conftest)

ALLOW = "SIS_ALLOW_UNPINNED_PYTEST"
# A pin no installed pytest can match.
FAKE_PIN = "0.0.0"


class PytestPinTests(unittest.TestCase):
    def run_pytest(self, *, fake_pin: str | None, allow: bool):
        """Run a real ``pytest -q`` over one passing test with this hook."""
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        patch = (f"pin.required_pytest_version = lambda: {fake_pin!r}"
                 if fake_pin is not None else "")
        (root / "conftest.py").write_text(textwrap.dedent(f"""
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "pin", {str(TESTS / "conftest.py")!r})
            pin = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(pin)
            {patch}
            pytest_sessionstart = pin.pytest_sessionstart
        """))
        marker = root / "ran"
        (root / "test_ok.py").write_text(
            "import pathlib\n\n"
            "def test_ok():\n"
            f"    pathlib.Path({str(marker)!r}).write_text('ran')\n")
        env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1",
                   PYTHONPATH=os.pathsep.join(
                       [str(ROOT / "src"),
                        *filter(None, [os.environ.get("PYTHONPATH")])]))
        env.pop(ALLOW, None)
        if allow:
            env[ALLOW] = "1"
        run = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             str(root)],
            cwd=root, capture_output=True, text=True, env=env)
        return run, marker.exists()

    def test_a_mismatch_exits_before_collection_with_one_message(self):
        run, ran = self.run_pytest(fake_pin=FAKE_PIN, allow=False)
        output = run.stdout + run.stderr
        self.assertEqual(run.returncode, 4, output)
        self.assertFalse(ran, output)
        self.assertIn(f"SIS tests require pytest {FAKE_PIN}", output)
        self.assertIn(f"this interpreter has pytest "
                      f"{conftest.installed_pytest_version()}", output)
        self.assertIn("pip install -r requirements-lock.txt", output)
        self.assertIn("pip install -e .[dev]", output)
        self.assertIn(f"{ALLOW}=1", output)
        self.assertNotIn("passed", output)

    def test_the_override_runs_the_suite_anyway(self):
        run, ran = self.run_pytest(fake_pin=FAKE_PIN, allow=True)
        output = run.stdout + run.stderr
        self.assertEqual(run.returncode, 0, output)
        self.assertTrue(ran, output)
        self.assertIn("1 passed", run.stdout)
        self.assertNotIn("SIS tests require pytest", output)

    def test_the_real_pin_decides_without_a_fake(self):
        run, ran = self.run_pytest(fake_pin=None, allow=False)
        output = run.stdout + run.stderr
        required = EvaluationRuntimeProfile().pytest_version
        if conftest.installed_pytest_version() == required:
            self.assertEqual(run.returncode, 0, output)
            self.assertTrue(ran, output)
        else:
            self.assertEqual(run.returncode, 4, output)
            self.assertFalse(ran, output)
            self.assertIn(f"SIS tests require pytest {required}", output)

    def test_the_pin_has_one_home(self):
        required = EvaluationRuntimeProfile().pytest_version
        self.assertEqual(conftest.required_pytest_version(), required)
        source = (TESTS / "conftest.py").read_text(encoding="utf-8")
        self.assertNotIn(required, source)


if __name__ == "__main__":
    unittest.main()
