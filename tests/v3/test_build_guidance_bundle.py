"""Guidance bundle producer: learn on training, qualify on qualification, sign.

A scripted agent stands in for Claude Code: it fixes every training task
and fixes a qualification task only when guidance is served, so each
derived candidate shows paired wins on the qualification split. The
bundle is then loaded by the study runner under the same trust
configuration, and the qualification-provenance checks are exercised.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from sis.v3.runner import tree_digest
from tests.v3.study_fixtures import (apply_fix, fix_target, import_repository,
                                     load_tool, make_bugfix_repository)
from tests.v3.test_followup_campaign_keys import _protocol_document

GIT = shutil.which("git")
POSIX = os.name == "posix"
bundler = load_tool("build_guidance_bundle")
campaign = bundler.campaign


def scripted_factory(training_ids: set[str], *, solve_guided: bool = True):
    def factory(prompts, budget, model):
        def agent(ctx):
            target = fix_target(prompts[ctx.task.task_id])
            guided = ctx.guidance is not None and bool(
                ctx.guidance.helpful_next_checks)
            if target is not None and (
                    ctx.task.task_id in training_ids
                    or (guided and solve_guided)):
                apply_fix(ctx.workspace, *target)
            ctx.usage_meter.record_tokens(100)
            for _ in range(3):
                ctx.usage_meter.record_tool_call()
            return {"tokens_used": 100, "tools_used": 3,
                    "actions": ["Read", "Bash", "Edit"]}
        return agent
    return factory


@unittest.skipUnless(GIT and POSIX, "git and POSIX key custody are required")
class GuidanceBundleBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = cls.root = Path(cls.temp.name)
        importer = load_tool("import_study_tasks")
        spec = {"schema_version": 1, "kind": "guidance_learning_spec",
                "agent": {"kind": "claude-code", "model": "m",
                          "cli_version": "2.1.328"},
                "budget": {"wall_seconds": 60, "token_budget": 150000,
                           "tool_budget": 100},
                "repositories": [], "tasks": []}
        cls.spec_path = root / "learning.json"
        cls.spec_path.write_text(json.dumps(spec))
        cls.digests = {}
        for name, split in (("tra", "training"), ("trb", "training"),
                            ("qua", "qualification"),
                            ("qub", "qualification")):
            repo = make_bugfix_repository(root / "repos" / name, name,
                                          fixes=2)
            code = import_repository(
                importer, repo["path"], f"learn-{name}", partition="induction",
                learning_split=split, hidden_dir=root / "hidden" / name,
                output=root / "imports" / f"{name}.json",
                merge_into=cls.spec_path, verify="none")
            assert code == 0
            cls.digests[name] = tree_digest(repo["path"], version=3)
        cls.holdout = make_bugfix_repository(root / "repos" / "hold", "hold",
                                             fixes=1)
        cls.holdout_digest = tree_digest(cls.holdout["path"], version=3)
        cls.spec = json.loads(cls.spec_path.read_text())
        cls.training_ids = {task["task_id"] for task in cls.spec["tasks"]
                            if task["repository_id"] in ("learn-tra",
                                                         "learn-trb")}
        keys = bundler.signing_keys(root / "keys" / "evaluator",
                                    root / "keys" / "operator")
        cls.protocol = _protocol_document()
        cls.trust_path = root / "trust.json"
        cls.trust_path.write_text(json.dumps({
            "evaluator_keys": {keys["evaluator"][0]: keys["evaluator"][2]},
            "operator_keys": {keys["operator"][0]: keys["operator"][2]},
            "evaluation_protocol": cls.protocol}))
        cls.output = root / "bundle.json"
        cls.exit = cls.build(cls.output, root / "candidates.db",
                             root / "state")
        cls.bundle = json.loads(cls.output.read_text()) \
            if cls.output.exists() else None
        cls.report = json.loads(
            (root / "bundle.json.report.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def build(cls, output, registry, state, *, extra=(), factory=None):
        argv = ["--learning-spec", str(cls.spec_path),
                "--trust-config", str(cls.trust_path),
                "--candidate-registry", str(registry),
                "--evaluator-key-dir", str(cls.root / "keys" / "evaluator"),
                "--operator-key-dir", str(cls.root / "keys" / "operator"),
                "--state-dir", str(state), "--allow-local-executor",
                "--allow-shared-custody", "-o", str(output), *extra]
        with contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            return bundler.main(argv, agent_factory=factory
                                or scripted_factory(cls.training_ids))

    def load(self, bundle, *, holdout=None, study_tasks=()):
        path = self.root / "load.json"
        path.write_text(json.dumps(bundle))
        factory = campaign.trusted_registry_factory(
            campaign.load_trust_config(self.trust_path))
        registry = factory(self.root / "candidates.db")
        try:
            return campaign._load_guidance_bundle(
                path, induction_digests=tuple(self.digests.values()),
                holdout_digests=(holdout or self.holdout_digest,),
                precommitted_digest=bundle["bundle_digest"],
                registry=registry, study_task_ids=study_tasks,
                trusted_evaluator_key_ids=factory.trust_anchors[
                    "evaluator_key_ids"])
        finally:
            registry.close()

    def resign(self, bundle):
        bundle = json.loads(json.dumps(bundle))
        bundle["bundle_digest"] = campaign._bundle_digest(bundle)
        return bundle

    def test_the_build_qualifies_one_candidate_per_arm(self):
        self.assertEqual(self.exit, 0, self.report)
        self.assertEqual(set(self.bundle["components"]), {"B", "C", "D"})
        types = {arm: records[0]["candidate_id"].split("-")[0]
                 for arm, records in self.bundle["components"].items()}
        self.assertEqual(types, {"B": "experience", "C": "skill",
                                 "D": "symbolic"})
        self.assertIn("Add", self.bundle["components"]["D"][0]["text"])
        self.assertEqual(self.bundle["training"]["repository_digests"],
                         sorted([self.digests["tra"], self.digests["trb"]]))
        qualification = self.bundle["qualification"]
        self.assertEqual(qualification["repository_digests"],
                         sorted([self.digests["qua"], self.digests["qub"]]))
        self.assertEqual(len(qualification["tasks"]), 4)
        self.assertTrue(qualification["receipts"])
        for arm, summary in self.report["qualification"].items():
            self.assertTrue(summary["selected"], arm)
            self.assertEqual((summary["wins"], summary["losses"]), (4, 0))

    def test_the_runner_serves_the_bundle_as_learned(self):
        loaded = self.load(self.bundle)
        self.assertEqual(loaded["source"], "learned")
        self.assertTrue(loaded["candidates_verified"])
        self.assertEqual(loaded["qualification"]["tasks"], 4)
        self.assertEqual(len(loaded["components"]), 3)

    def test_qualification_on_a_holdout_repository_is_refused(self):
        bundle = json.loads(json.dumps(self.bundle))
        bundle["qualification"]["repository_digests"].append(
            self.holdout_digest)
        with self.assertRaisesRegex(ValueError, "uses_holdout"):
            self.load(self.resign(bundle))
        # A holdout that *is* a qualification repository is refused too.
        with self.assertRaisesRegex(ValueError, "uses_holdout"):
            self.load(self.bundle, holdout=self.digests["qua"])

    def test_qualification_must_not_reuse_study_tasks_or_training(self):
        task_id = self.bundle["qualification"]["tasks"][0]["task_id"]
        with self.assertRaisesRegex(ValueError, "uses_study_tasks"):
            self.load(self.bundle, study_tasks=(task_id,))
        bundle = json.loads(json.dumps(self.bundle))
        bundle["qualification"]["repository_digests"].append(
            self.digests["tra"])
        with self.assertRaisesRegex(ValueError, "overlaps_training"):
            self.load(self.resign(bundle))

    def test_undeclared_or_forged_receipts_are_refused(self):
        bundle = json.loads(json.dumps(self.bundle))
        receipts = bundle["qualification"]["receipts"]
        digest = sorted(receipts)[0]
        del receipts[digest]
        if receipts:
            with self.assertRaisesRegex(ValueError, "receipt_undeclared"):
                self.load(self.resign(bundle))
        bundle = json.loads(json.dumps(self.bundle))
        receipt = bundle["qualification"]["receipts"][digest]
        receipt["outcome"] = "fail"
        with self.assertRaisesRegex(ValueError, "digest_mismatch"):
            self.load(self.resign(bundle))
        bundle = json.loads(json.dumps(self.bundle))
        del bundle["qualification"]
        with self.assertRaisesRegex(ValueError, "qualification_missing"):
            self.load(self.resign(bundle))

    def test_a_study_holdout_in_the_learning_spec_is_refused(self):
        exclude = self.root / "study.json"
        exclude.write_text(json.dumps({"repositories": [{
            "repository_id": "h", "partition": "holdout",
            "path": str(self.root / "repos" / "qua")}], "tasks": []}))
        code = self.build(self.root / "excluded.json",
                          self.root / "excluded.db", self.root / "state-x",
                          extra=("--exclude-spec", str(exclude)))
        self.assertEqual(code, 1)
        self.assertFalse((self.root / "excluded.json").exists())

    def test_no_qualified_candidate_means_no_bundle(self):
        output = self.root / "none.json"
        code = self.build(output, self.root / "none.db",
                          self.root / "state-none",
                          factory=scripted_factory(self.training_ids,
                                                   solve_guided=False))
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())
        report = json.loads((self.root / "none.json.report.json").read_text())
        self.assertEqual(report["missing_arms"], ["B", "C", "D"])

    def test_untrusted_signing_keys_are_refused(self):
        other = self.root / "other-trust.json"
        trust = json.loads(self.trust_path.read_text())
        from sis.v3 import signatures
        _, public = signatures.generate_keypair()
        trust["operator_keys"] = {"key-other": public.hex()}
        other.write_text(json.dumps(trust))
        with contextlib.redirect_stderr(io.StringIO()) as stderr, \
                contextlib.redirect_stdout(io.StringIO()):
            code = bundler.main([
                "--learning-spec", str(self.spec_path),
                "--trust-config", str(other),
                "--candidate-registry", str(self.root / "u.db"),
                "--evaluator-key-dir", str(self.root / "keys" / "evaluator"),
                "--operator-key-dir", str(self.root / "keys" / "operator"),
                "--state-dir", str(self.root / "state-u"),
                "--allow-local-executor", "--allow-shared-custody",
                "-o", str(self.root / "u.json")],
                agent_factory=scripted_factory(self.training_ids))
        self.assertEqual(code, 1)
        self.assertIn("operator key", stderr.getvalue())

    def test_print_public_keys_emits_trust_entries(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = bundler.main([
                "--print-public-keys",
                "--evaluator-key-dir", str(self.root / "keys" / "evaluator"),
                "--operator-key-dir", str(self.root / "keys" / "operator")])
        self.assertEqual(code, 0)
        printed = json.loads(out.getvalue())
        trust = json.loads(self.trust_path.read_text())
        self.assertEqual(printed["evaluator_keys"], trust["evaluator_keys"])
        self.assertEqual(printed["operator_keys"], trust["operator_keys"])


if __name__ == "__main__":
    unittest.main()
