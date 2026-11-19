"""End-to-end dry run of the pilot path on an imported corpus.

Temporary Git repositories with a bug-fix history are imported into an
exploratory A/E study (Claude Code pinned), the manifest is built, and
``run_real`` executes it with a scripted stand-in for the Claude Code
agent. The first run is killed with SIGKILL partway through; a second
run with the same state directory resumes from the journal. The resumed
report must equal an uninterrupted run's, and a run with parallel
workers must too.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from tests.v3.study_fixtures import (apply_fix, fix_target, imported_study,
                                     load_tool)

ROOT = Path(__file__).resolve().parents[2]
GIT = shutil.which("git")
POSIX = os.name == "posix"
KILL_AT = 6

STATUS = {"agent": "claude-code", "available": True, "authenticated": True,
          "binary": "/usr/bin/false", "reason": "ok"}


def scripted_claude(prompts, budget, model, *, calls=None):
    """Fixes the task only when governed guidance is served (arm E)."""
    def agent(ctx):
        if calls is not None:
            calls.append((ctx.task.task_id, ctx.arm))
        guided = ctx.guidance is not None and bool(
            ctx.guidance.helpful_next_checks)
        target = fix_target(prompts[ctx.task.task_id])
        if guided and target is not None:
            apply_fix(ctx.workspace, *target)
        ctx.usage_meter.record_tokens(1200)
        ctx.usage_meter.record_detail("cache_read_input_tokens", 9000)
        ctx.usage_meter.record_tool_call()
        return {"tokens_used": 1200, "tools_used": 1}
    return agent


KILLER = textwrap.dedent("""\
    import json, os, signal, sys
    sys.path[:0] = [{src!r}, {root!r}]
    from tests.v3.study_fixtures import load_tool
    from tests.v3 import test_efficacy_pilot_dry_run as dry
    tool = load_tool("five_arm_campaign")
    tool.claude_code_agent_status = lambda: dict(dry.STATUS)
    tool._installed_claude_version = lambda binary: "2.1.328"
    calls = []

    def factory(prompts, budget, model):
        inner = dry.scripted_claude(prompts, budget, model, calls=calls)

        def agent(ctx):
            if len(calls) + 1 == {kill_at}:
                os.kill(os.getpid(), signal.SIGKILL)
            return inner(ctx)
        return agent
    tool._claude_code_agent = factory
    tool.run_real({output!r}, {manifest!r}, allow_shared_custody=True,
                  state_dir={state!r})
    """)


@unittest.skipUnless(GIT and POSIX, "git and POSIX key custody are required")
class PilotDryRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        study = imported_study(cls.root, holdout=5, induction=5, fixes=2)
        builder = load_tool("build_efficacy_manifest")
        document, cls.summary = builder.build_manifest(
            study["spec"], check_agent=False)
        cls.manifest = cls.root / "manifest.json"
        cls.manifest.write_text(json.dumps(document, indent=2))
        cls.tool = load_tool("five_arm_campaign")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_in_process(self, name, *, state=None, workers=1, calls=None):
        output = self.root / f"{name}.json"
        tool = self.tool
        with mock.patch.object(tool, "claude_code_agent_status",
                               lambda: dict(STATUS)), \
                mock.patch.object(tool, "_installed_claude_version",
                                  lambda binary: "2.1.328"), \
                mock.patch.object(
                    tool, "_claude_code_agent",
                    lambda p, b, m: scripted_claude(p, b, m, calls=calls)), \
                contextlib.redirect_stdout(io.StringIO()):
            code = tool.run_real(output, self.manifest,
                                 allow_shared_custody=True, state_dir=state,
                                 workers=workers)
        return code, json.loads(output.read_text(encoding="utf-8"))

    @staticmethod
    def outcomes(report):
        return [(row["task_id"], row["repository_id"], row["arm_order"],
                 {arm: (value["outcome"], value["budget_exceeded"],
                        value["tokens_used"], value["budget_accounting"])
                  for arm, value in sorted(row["arms"].items())})
                for row in report["per_task"]]

    def test_kill_and_resume_equals_an_uninterrupted_run(self):
        self.assertTrue(self.summary["ready"])
        self.assertEqual(self.summary["tasks"], 10)
        state = self.root / "state"
        output = self.root / "killed.json"
        script = KILLER.format(src=str(ROOT / "src"), root=str(ROOT),
                               kill_at=KILL_AT, output=str(output),
                               manifest=str(self.manifest), state=str(state))
        killed = subprocess.run([sys.executable, "-c", script],
                                capture_output=True, text=True, timeout=600)
        self.assertEqual(killed.returncode, -9, killed.stderr[-2000:])
        self.assertFalse(output.exists())
        journal = (state / "journal.jsonl").read_text().splitlines()
        self.assertEqual(len(journal), KILL_AT)  # header + finished arms

        calls: list = []
        code, resumed = self.run_in_process("resumed", state=state,
                                            calls=calls)
        self.assertEqual(code, 0, resumed.get("note"))
        self.assertEqual(resumed["run"]["resumed_rows"], KILL_AT - 1)
        self.assertEqual(len(calls), 20 - (KILL_AT - 1))

        code, reference = self.run_in_process("reference")
        self.assertEqual(code, 0, reference.get("note"))
        self.assertEqual(self.outcomes(resumed), self.outcomes(reference))
        for report in (resumed, reference):
            analysis = report["learning_qualification"]
            self.assertEqual(analysis["provenance"]["agent"], "claude-code")
            self.assertTrue(analysis["provenance"]["cli_version_matches"])
            # A dry run is never more than exploratory: shared custody,
            # fixed control guidance and a manifest declared exploratory.
            self.assertEqual(analysis["evidence_class"], "exploratory")
            self.assertEqual(analysis["decisive_contrast"]["wins"], 10)
            self.assertEqual(analysis["primary_analysis"]["holdout_repositories"],
                             5)
            rows = [arm for row in report["per_task"]
                    for arm in row["arms"].values()]
            self.assertTrue(all(row["receipt_digest"] for row in rows))
            self.assertTrue(all(row["usage_detail"]
                                == {"cache_read_input_tokens": 9000}
                                for row in rows))
        # Every resumed row's receipt is in the exported evidence bundle.
        evidence = Path(resumed["evidence_bundle"]["path"])
        exported = {path.stem for path in (evidence / "receipts").iterdir()}
        for row in resumed["per_task"]:
            for arm in row["arms"].values():
                self.assertIn(arm["receipt_digest"], exported)

    def test_parallel_workers_equal_the_serial_run(self):
        code, serial = self.run_in_process("serial")
        self.assertEqual(code, 0, serial.get("note"))
        code, parallel = self.run_in_process("parallel", workers=4,
                                             state=self.root / "pstate")
        self.assertEqual(code, 0, parallel.get("note"))
        self.assertEqual(self.outcomes(serial), self.outcomes(parallel))
        self.assertEqual(serial["guidance"]["bundles"],
                         parallel["guidance"]["bundles"])
        self.assertEqual(
            serial["learning_qualification"]["decisive_contrast"],
            parallel["learning_qualification"]["decisive_contrast"])

    def test_the_pilot_power_plan_reads_the_report(self):
        from sis.v3.governed_eval import (pilot_planning_inputs,
                                          required_repositories)
        _, report = self.run_in_process("plan")
        inputs = pilot_planning_inputs(report)
        self.assertEqual(inputs["repositories"], 5)
        self.assertEqual(inputs["tasks_per_repository"], 2.0)
        plan = required_repositories(
            baseline_rate=0.3, treatment_rate=0.5,
            tasks_per_repository=int(inputs["tasks_per_repository"]),
            difference_icc=inputs["difference_icc"] or 0.0,
            simulations=100)
        self.assertTrue(plan["reached"])


class PilotTemplateTests(unittest.TestCase):
    """The committed pilot template preregisters the planned design."""

    def test_the_template_is_an_exploratory_claude_code_a_e_study(self):
        builder = load_tool("build_efficacy_manifest")
        spec = json.loads((ROOT / "docs" / "v3"
                           / "pilot_study_spec_template.json").read_text())
        self.assertEqual(spec["kind"], "primary_contrast_study_spec")
        self.assertEqual(builder._study_tier(spec), "exploratory")
        self.assertEqual(spec["agent"]["kind"], "claude-code")
        protocol = builder._protocol(spec)
        self.assertEqual(protocol["arms"], ["A", "E"])
        self.assertEqual(protocol["budget"], {
            "wall_seconds": 900, "token_budget": 150000, "tool_budget": 100})
        self.assertGreaterEqual(protocol["sample_size"],
                                protocol["power_analysis"]["required_n"])
        induction = [item for item in spec["repositories"]
                     if item["partition"] == "induction"]
        self.assertEqual(len(induction), 10)
        learning = json.loads((ROOT / "docs" / "v3"
                               / "pilot_learning_spec_template.json")
                              .read_text())
        self.assertEqual(learning["kind"], "guidance_learning_spec")
        self.assertEqual(learning["budget"], protocol["budget"])

    def test_the_runbook_names_existing_tools_and_options(self):
        runbook = (ROOT / "docs" / "v3" / "PILOT_RUNBOOK.md").read_text()
        for tool_name in ("import_study_tasks", "build_guidance_bundle",
                          "build_efficacy_manifest", "five_arm_campaign"):
            self.assertIn(f"tools/{tool_name}.py", runbook)
            self.assertTrue((ROOT / "tools" / f"{tool_name}.py").is_file())
        for option in ("--executor docker", "--state-dir", "--workers",
                       "--trust-config", "--exclude-spec"):
            self.assertIn(option, runbook)


if __name__ == "__main__":
    unittest.main()
