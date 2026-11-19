"""The sandbox-qualification CI job and its Docker runtime setup (C4)."""
from __future__ import annotations

import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import configure_docker_runsc  # noqa: E402

WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def _job(name: str) -> str:
    text = WORKFLOW.read_text()
    match = re.search(rf"^  {re.escape(name)}:\n(.*?)(?=^  \S|\Z)", text,
                      re.M | re.S)
    if match is None:
        raise AssertionError(f"job {name} missing")
    return match.group(1)


class WorkflowTests(unittest.TestCase):
    def test_gvisor_is_pinned_and_checksummed(self):
        job = _job("sandbox-qualification")
        self.assertIn("runs-on: ubuntu-latest", job)
        version = re.search(r'GVISOR_RELEASE: "(\d{8}\.\d+)"', job)
        self.assertIsNotNone(version)
        self.assertRegex(job, r'GVISOR_SHA512: "[0-9a-f]{128}"')
        self.assertIn("sha512sum -c -", job)
        self.assertIn("storage.googleapis.com/gvisor/releases/release/"
                      "${GVISOR_RELEASE}/", job)
        self.assertNotIn("/latest/", job)

    def test_job_runs_every_tool_under_runsc_and_fails_on_regression(self):
        job = _job("sandbox-qualification")
        for tool in ("probe_docker_sandbox.py", "redteam_sandbox.py",
                     "qualify_docker_isolation.py",
                     "configure_docker_runsc.py"):
            self.assertIn(f"tools/{tool}", job)
        self.assertIn("--trust-root qualification-only", job)
        self.assertIn("--redteam-report", job)
        self.assertIn("upload-artifact", job)
        self.assertIn("if: always()", job)
        self.assertIn("Fail on any containment regression", job)
        # The job must not see release signing material.
        self.assertNotIn("secrets.", job)

    def test_existing_jobs_are_kept(self):
        for name in ("tests", "test-evidence", "docker-absent", "lint",
                     "postgres"):
            _job(name)


class ConfigureRunscTests(unittest.TestCase):
    def test_merge_keeps_existing_configuration(self):
        current = {"log-driver": "json-file",
                   "runtimes": {"other": {"path": "/bin/other"}}}
        result = configure_docker_runsc.merged(current, "/opt/gvisor/runsc")
        self.assertEqual(result["log-driver"], "json-file")
        self.assertEqual(result["runtimes"]["other"], {"path": "/bin/other"})
        self.assertEqual(result["runtimes"]["runsc"], {
            "path": "/opt/gvisor/runsc", "runtimeArgs": ["--oci-seccomp"]})
        self.assertTrue(result["features"]["containerd-snapshotter"])
        self.assertNotIn("runsc", current["runtimes"])

    def test_cli_writes_the_file(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / "daemon.json"
            config.write_text('{"debug": true}')
            self.assertEqual(configure_docker_runsc.main(
                ["--runsc", "/opt/gvisor/runsc", "--config", str(config)]), 0)
            document = json.loads(config.read_text())
            self.assertTrue(document["debug"])
            self.assertIn("runsc", document["runtimes"])

    def test_relative_runsc_path_is_refused(self):
        with self.assertRaises(SystemExit):
            configure_docker_runsc.main(["--runsc", "runsc",
                                         "--config", "/nonexistent/x.json"])


if __name__ == "__main__":
    unittest.main()
