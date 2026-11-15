"""The real-agent gate executes a supplied manifest instead of blocking.

Before this repair ``tools/five_arm_campaign.py --real-agent --manifest``
always wrote ``BLOCKED_REAL_RUN_NOT_EXECUTED``: the manifest was read for
a status code and never turned into a campaign. These regressions pin the
executing path: a validated manifest becomes five arms of real harness
runs with evaluator-verified outcomes and receipt digests, and an
unusable manifest still fails closed.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.governed_eval import GOVERNED_ARMS, preregister
from sis.v3.runner import tree_digest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "five_arm_campaign", ROOT / "tools" / "five_arm_campaign.py")
campaign_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(campaign_tool)

PY = sys.executable
# The evaluator keystore refuses a private directory whose Windows ACL
# permits access outside the current user, SYSTEM and Administrators.
# GitHub's Windows runner inherits such an ACL from its temp directory, so
# verifier construction fails there; Windows is experimental for this
# release and the vault tests are skipped on the same condition.
POSIX_CUSTODY = sys.platform != "win32"

ACCEPTANCE = ("from pathlib import Path\n\n"
              "def test_solution():\n"
              "    assert 'OK' in Path('solution.py').read_text()\n")


def _status(available=True, authenticated=True):
    return {"agent": "codex-cli", "available": available,
            "authenticated": authenticated, "binary": "/usr/bin/false",
            "reason": "ok" if available and authenticated
            else "codex_not_authenticated"}


def _manifest(root: Path) -> dict:
    repositories = []
    for index in range(9):
        path = root / f"induction-{index}"
        path.mkdir()
        (path / "seed.py").write_text("SEED = 1\n")
        repositories.append({
            "repository_id": f"repo-induction-{index}",
            "path": str(path),
            "base_commit": f"{index:040x}",
            "repo_snapshot_digest": tree_digest(path),
            "partition": "induction",
        })
    holdout = root / "holdout"
    holdout.mkdir()
    (holdout / "solution.py").write_text("NO = 1\n")
    hidden = root / "private" / "hidden.py"
    hidden.parent.mkdir()
    hidden.write_text("def test_placeholder():\n    assert True\n")
    repositories.append({
        "repository_id": "repo-holdout",
        "path": str(holdout),
        "base_commit": "f" * 40,
        "repo_snapshot_digest": tree_digest(holdout),
        "partition": "holdout",
        "hidden_tests": {
            "path": str(hidden),
            "digest": hashlib.sha256(hidden.read_bytes()).hexdigest()},
    })
    protocol = preregister(
        primary_metric="paired solved_delta E vs A", method="mcnemar_exact",
        alpha=0.05, min_effect=1.0, sample_size=2, powered=False,
        budget={"wall_seconds": 30, "token_budget": 1000, "tool_budget": 10},
        arms=GOVERNED_ARMS)
    protocol["powered"] = False
    tasks = [{
        "task_id": f"task-{index}",
        "repository_id": "repo-holdout",
        "base_commit": "f" * 40,
        "prompt": f"make task {index} pass",
        "failure_class": "bug_fix",
        "partition": "holdout",
        "budgets": {"time_budget_seconds": 30, "token_budget": 1000,
                    "tool_budget": 10},
        "acceptance": {
            "argv": [sys.executable, "-m", "pytest", "-q",
                     "acceptance.py"],
            "files": {"acceptance.py": ACCEPTANCE}},
    } for index in range(2)]
    return {
        "schema_version": 1, "kind": "five_arm_efficacy_manifest",
        "protocol": protocol,
        "agent": {"kind": "codex-cli", "model": "test-model",
                  "cli_version": "test"},
        "partitions": {
            "induction": [item["repository_id"] for item in repositories
                          if item["partition"] == "induction"],
            "holdout": ["repo-holdout"]},
        "repositories": repositories,
        "preregistration": {
            "registered_at": "2026-11-14T00:00:00Z",
            "registered_by": "test",
            "protocol_digest": protocol["protocol_digest"]},
        "tasks": tasks,
    }


def _write(root: Path, document: dict) -> Path:
    path = root / "manifest.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def _scripted_agent(prompts, budget, model):
    def agent(ctx):
        if ctx.guidance is not None and ctx.guidance.helpful_next_checks:
            (ctx.workspace / "solution.py").write_text("OK = 1\n")
        return {"tokens_used": 5, "tools_used": 1}
    return agent


class RealAgentGateTests(unittest.TestCase):
    def setUp(self):
        self._status = campaign_tool.codex_agent_status
        campaign_tool.codex_agent_status = _status

    def tearDown(self):
        campaign_tool.codex_agent_status = self._status

    @unittest.skipUnless(
        POSIX_CUSTODY,
        "evaluator key custody is POSIX-only in this release")
    def test_supplied_manifest_executes_the_five_arms(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = _write(root, _manifest(root))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 0)
        analysis = report["learning_qualification"]
        self.assertEqual(analysis["tasks"], 2)
        self.assertTrue(analysis["real_agent"])
        self.assertEqual(analysis["evidence_class"], "exploratory")
        self.assertEqual(analysis["release_gate"],
                         "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")
        self.assertEqual(report["evidence_class"], "exploratory")
        self.assertEqual(report["release_gate"],
                         "IMPLEMENTED_NOT_EFFICACY_QUALIFIED")
        self.assertEqual(report["receipts_issued"], 4)
        rows = [arm for task in report["per_task"]
                for arm in task["arms"].values()]
        self.assertEqual(len(rows), 10)
        self.assertTrue(all(row["receipt_digest"] for row in rows))
        self.assertIn("bug_fix", report["guidance_bundles"])
        self.assertEqual(len(report["guidance_bundle_digest"]), 64)
        self.assertTrue(report["manifest"]["valid"])
        self.assertEqual(analysis["decisive_contrast"]["wins"], 2)
        self.assertEqual(analysis["decisive_contrast"]["losses"], 0)
        self.assertEqual(
            analysis["decisive_contrast"]["difference_interval_method"],
            "newcombe_paired")

    def test_missing_manifest_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            code = campaign_tool.run_real(output, None)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")

    def test_unauthenticated_agent_is_blocked(self):
        campaign_tool.codex_agent_status = lambda: _status(authenticated=False)
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "report.json"
            code = campaign_tool.run_real(output, None)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_REAL_AGENT")

    def test_manifest_without_powered_flag_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            del document["protocol"]["powered"]
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, _write(root, document), allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertFalse(report["manifest"]["valid"])

    @unittest.skipUnless(
        POSIX_CUSTODY,
        "evaluator key custody is POSIX-only in this release")
    def test_repository_drift_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            manifest = _write(root, document)
            (root / "holdout" / "solution.py").write_text("DRIFT = 1\n")
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertIn("repository_snapshot_mismatch", report["note"])


if __name__ == "__main__":
    unittest.main()
