"""``five_arm_campaign.run_real`` with an agent principal.

The principal is a stand-in (:class:`FakePrincipal`): these tests pin what
the campaign does with one (preflight before any turn, provenance, the run
journal identity, the one-turn-at-a-time rule), not the OS separation,
which ``test_agent_principal`` covers.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .test_agent_principal import FakePrincipal

POSIX = os.name == "posix"
ROOT = Path(__file__).resolve().parents[2]


def _campaign_tool():
    from . import test_five_arm_real_run as real_run
    return real_run


@unittest.skipUnless(POSIX and shutil.which("git"),
                     "POSIX key custody and git are required")
class CampaignPrincipalTests(unittest.TestCase):
    """``run_real`` records, checks and journals the agent principal."""

    def setUp(self):
        self.real_run = _campaign_tool()
        self.tool = self.real_run.campaign_tool
        saved = self.tool.codex_agent_status
        self.tool.codex_agent_status = lambda principal=None: {
            "agent": "codex-cli", "available": True, "authenticated": True,
            "binary": "/usr/bin/false", "reason": "ok"}
        self.addCleanup(setattr, self.tool, "codex_agent_status", saved)
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.manifest = self.real_run._write(self.root, self.real_run._manifest(
            self.root, arms=("A", "E"),
            kind="primary_contrast_efficacy_manifest"))
        self.factory_principals: list = []

    def factory(self, prompts, budget, model, principal=None):
        self.factory_principals.append(principal)

        def agent(ctx):
            with principal.checkout(ctx.workspace) as path:
                if ctx.guidance is not None and \
                        ctx.guidance.helpful_next_checks:
                    (Path(path) / "solution.py").write_text("OK = 1\n")
            return {"tokens_used": 5, "tools_used": 1}
        return agent

    def run_real(self, output, principal, manifest=None, **kwargs):
        return self.tool.run_real(
            output, manifest or self.manifest, allow_shared_custody=True,
            agent_factory=self.factory, agent_principal=principal,
            **kwargs)

    def test_the_principal_is_checked_recorded_and_used(self):
        principal = FakePrincipal(self.root)
        output = self.root / "report.json"
        trust = self.root / "trust.json"
        trust.write_text("{}")
        self.run_real(output, principal, private_paths=(trust,))
        report = json.loads(output.read_text())
        self.assertEqual(self.factory_principals, [principal])
        self.assertEqual(principal.checkouts, 18)
        record = report["learning_qualification"]["provenance"][
            "agent_principal"]
        self.assertTrue(record["separated"])
        self.assertEqual(record["user"], "sisagent")
        self.assertEqual(record["preflight"]["readable_paths"], 0)
        self.assertEqual(report["agent_principal"], record)
        # The checked set covers the state root, keys, registry, the trust
        # config and every hidden-test path of the manifest.
        checked = principal.checked
        self.assertIn(str(trust), checked)
        self.assertTrue(any(path.endswith("/keys") for path in checked))
        self.assertTrue(any(path.endswith("/registry") for path in checked))
        self.assertTrue(any("hidden-0.py" in path for path in checked))
        self.assertFalse(any(
            "agent principal not separated" in item
            for item in report["learning_qualification"]["limitations"]))
        self.assertEqual(report["learning_qualification"][
            "decisive_contrast"]["wins"], 9)

    def test_repositories_and_support_files_are_checked(self):
        # A clone's history holds the fix commit and a support file is
        # hidden material too: the agent must be unable to read either.
        document = {
            "repositories": [
                {"repository_id": "pkg", "path": "/study/repos/pkg",
                 "hidden_tests": {"path": "/study/private/pkg"}}],
            "tasks": [{"acceptance": {
                "hidden_tests_path": "/study/private/pkg/t1/test_x.py",
                "support_files": [
                    {"target": "tests/conftest.py",
                     "path": "/study/private/pkg/t1/support/tests/conftest.py",
                     "digest": "0" * 64}]}}],
        }
        checked = {str(path) for path in
                   self.tool.agent_private_paths(document)}
        self.assertIn("/study/repos/pkg", checked)
        self.assertIn("/study/private/pkg", checked)
        self.assertIn("/study/private/pkg/t1/test_x.py", checked)
        self.assertIn(
            "/study/private/pkg/t1/support/tests/conftest.py", checked)

    def test_an_unseparated_run_discloses_it(self):
        # The fixture manifest is exploratory: it still runs without a
        # principal, and says so.
        output = self.root / "report.json"
        self.tool.run_real(output, self.manifest, allow_shared_custody=True,
                           agent_factory=self.real_run._scripted_agent)
        report = json.loads(output.read_text())
        self.assertEqual(report["manifest"]["study_tier"], "exploratory")
        self.assertFalse(report["release_gate"].startswith("BLOCKED_"))
        self.assertEqual(report["receipts_issued"], 18)
        analysis = report["learning_qualification"]
        self.assertEqual(analysis["provenance"]["agent_principal"],
                         {"separated": False})
        self.assertTrue(any("agent principal not separated" in item
                            for item in analysis["limitations"]))

    def confirmatory_manifest(self) -> Path:
        # A confirmatory study needs MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES
        # (20) holdout repositories contributing tasks.
        root = self.root / "confirmatory"
        root.mkdir()
        document = self.real_run._manifest(
            root, arms=("A", "E"), kind="primary_contrast_efficacy_manifest",
            holdout_count=20, task_count=20, study_tier="confirmatory")
        return self.real_run._write(root, document)

    def test_a_confirmatory_run_without_a_principal_is_blocked(self):
        output = self.root / "report.json"
        turns = []

        def factory(prompts, budget, model):
            def agent(ctx):
                turns.append(ctx.task.task_id)
                return {"tokens_used": 5, "tools_used": 1}
            return agent

        code = self.tool.run_real(
            output, self.confirmatory_manifest(), allow_shared_custody=True,
            agent_factory=factory)
        report = json.loads(output.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"],
                         "BLOCKED_AGENT_PRINCIPAL_REQUIRED")
        self.assertEqual(report["evidence_class"], "invalid")
        self.assertEqual(report["manifest"]["study_tier"], "confirmatory")
        self.assertIn("--agent-user", report["note"])
        self.assertEqual(turns, [])

    def test_a_confirmatory_run_with_a_checked_principal_proceeds(self):
        principal = FakePrincipal(self.root)
        output = self.root / "report.json"
        self.run_real(output, principal, manifest=self.confirmatory_manifest())
        report = json.loads(output.read_text())
        self.assertFalse(report["release_gate"].startswith("BLOCKED_"),
                         report.get("note"))
        self.assertEqual(report["manifest"]["study_tier"], "confirmatory")
        self.assertTrue(principal.checked)
        self.assertEqual(self.factory_principals, [principal])
        self.assertEqual(principal.checkouts, 40)
        self.assertEqual(report["receipts_issued"], 40)
        analysis = report["learning_qualification"]
        self.assertTrue(analysis["provenance"]["agent_principal"]["separated"])
        self.assertFalse(any("agent principal not separated" in item
                             for item in analysis["limitations"]))

    def test_a_confirmatory_run_needs_a_principal_that_reports_separation(self):
        class Unseparated(FakePrincipal):
            def describe(self):
                return {"separated": False, "user": self.user}

        principal = Unseparated(self.root)
        output = self.root / "report.json"
        code = self.run_real(output, principal,
                             manifest=self.confirmatory_manifest())
        report = json.loads(output.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"],
                         "BLOCKED_AGENT_PRINCIPAL_REQUIRED")
        self.assertEqual(self.factory_principals, [])
        self.assertEqual(principal.checkouts, 0)

    def test_a_failed_preflight_blocks_before_any_agent_turn(self):
        principal = FakePrincipal(
            self.root, preflight_error="agent user sisagent can read"
            " evaluator material: /study/private")
        output = self.root / "report.json"
        code = self.run_real(output, principal)
        report = json.loads(output.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_AGENT_PRINCIPAL")
        self.assertIn("/study/private", report["note"])
        self.assertEqual(self.factory_principals, [])
        self.assertEqual(principal.checkouts, 0)

    def test_parallel_workers_are_refused(self):
        output = self.root / "report.json"
        code = self.run_real(output, FakePrincipal(self.root), workers=2)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.read_text())["release_gate"],
                         "BLOCKED_AGENT_PRINCIPAL")

    def test_a_resume_under_another_agent_user_is_refused(self):
        state = self.root / "state"
        first = self.root / "first.json"
        self.run_real(first, FakePrincipal(self.root), state_dir=state)
        self.assertIn(json.loads(first.read_text())["evidence_class"],
                      ("invalid", "exploratory"))
        for principal in (FakePrincipal(self.root, user="otheragent"),
                          None):
            output = self.root / "again.json"
            if principal is None:
                code = self.tool.run_real(
                    output, self.manifest, allow_shared_custody=True,
                    agent_factory=self.real_run._scripted_agent,
                    state_dir=state)
            else:
                code = self.run_real(output, principal, state_dir=state)
            report = json.loads(output.read_text())
            self.assertEqual(code, 2)
            self.assertEqual(report["release_gate"], "BLOCKED_RESUME")
            self.assertIn("journal_identity_mismatch", report["note"])
        # The same user resumes every row.
        output = self.root / "same.json"
        self.run_real(output, FakePrincipal(self.root), state_dir=state)
        self.assertEqual(json.loads(output.read_text())["run"][
            "resumed_rows"], 18)

    def test_agent_user_is_a_real_agent_option(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "five_arm_campaign.py"),
             "--demo", "-o", os.devnull, "--allow-local-executor",
             "--agent-user", "sisagent"],
            capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")})
        self.assertEqual(result.returncode, 2)
        self.assertIn("--agent-user applies to --real-agent", result.stderr)

    def test_an_unknown_agent_user_blocks(self):
        output = self.root / "report.json"
        code = self.tool.run_real(output, self.manifest,
                                  allow_shared_custody=True,
                                  agent_factory=self.factory,
                                  agent_user="sis-no-such-user-x")
        report = json.loads(output.read_text())
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_AGENT_PRINCIPAL")
        self.assertIn("does not exist", report["note"])




if __name__ == "__main__":
    unittest.main()
