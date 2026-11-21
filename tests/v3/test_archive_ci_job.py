"""The archive CI job: the suite runs from an extracted canonical archive."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
EXTRACTED = "${{ runner.temp }}/extracted/sis-source"


def _job(name: str) -> str:
    text = WORKFLOW.read_text()
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text,
                      re.M | re.S)
    if match is None:
        raise AssertionError(f"job {name} missing")
    return match.group(1)


def _steps(job: str) -> list[str]:
    return re.split(r"^      - ", job, flags=re.M)[1:]


class ArchiveJobTests(unittest.TestCase):
    def setUp(self):
        self.job = _job("archive")

    def test_one_linux_python_312_runner(self):
        self.assertIn("runs-on: ubuntu-latest", self.job)
        self.assertIn("python-version: '3.12'", self.job)
        self.assertNotIn("matrix", self.job)
        self.assertNotIn("windows", self.job.lower())
        self.assertNotIn("secrets.", self.job)

    def test_the_archive_is_built_by_the_repositorys_tool_off_the_checkout(self):
        build = next(step for step in _steps(self.job)
                     if "build_canonical_zip.py" in step)
        # The tool rewrites RELEASE_SHA256.json in the tree it archives,
        # so it must build from a scratch worktree, and the checkout's
        # committed seal must be unchanged afterwards.
        self.assertIn('--source "$RUNNER_TEMP/staging"', build)
        self.assertIn("git worktree add --detach", build)
        self.assertIn("git diff --exit-code -- RELEASE_SHA256.json", build)
        self.assertNotIn("--allow-dirty", build)

    def test_install_and_suite_run_from_the_extracted_tree(self):
        steps = _steps(self.job)
        names = [step.splitlines()[0] for step in steps]
        extract = next(i for i, step in enumerate(steps)
                       if "python -m zipfile -e" in step)
        install = next(i for i, step in enumerate(steps)
                       if "requirements-lock.txt" in step)
        suite = next(i for i, step in enumerate(steps)
                     if "-m pytest tests/" in step)
        self.assertLess(extract, install, names)
        self.assertLess(install, suite, names)
        for index in (install, suite):
            self.assertIn(f"working-directory: {EXTRACTED}", steps[index])
        self.assertIn("pip install -e . --no-deps", steps[install])
        self.assertIn('PYTEST_DISABLE_PLUGIN_AUTOLOAD: "1"', steps[suite])
        self.assertIn('PYTHONNOUSERSITE: "1"', steps[suite])
        verify = next(step for step in steps if "verify_release.py" in step)
        self.assertIn(f"working-directory: {EXTRACTED}", verify)


if __name__ == "__main__":
    unittest.main()
