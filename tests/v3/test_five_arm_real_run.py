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
from types import SimpleNamespace

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
    for index in range(5):
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
    holdout_repos = []
    for index in range(5):
        holdout = root / f"holdout-{index}"
        holdout.mkdir()
        (holdout / "solution.py").write_text(f"NO = {index}\n")
        hidden = root / "private" / f"hidden-{index}.py"
        hidden.parent.mkdir(exist_ok=True)
        hidden.write_text("def test_placeholder():\n    assert True\n")
        item = {
            "repository_id": f"repo-holdout-{index}",
            "path": str(holdout),
            "base_commit": "f" * 40,
            "repo_snapshot_digest": tree_digest(holdout),
            "partition": "holdout",
            "hidden_tests": {
                "path": str(hidden),
                "digest": hashlib.sha256(hidden.read_bytes()).hexdigest()},
        }
        repositories.append(item)
        holdout_repos.append(item)
    protocol = preregister(
        primary_metric="paired solved_delta E vs A", method="mcnemar_exact",
        alpha=0.05, min_effect=1.0, sample_size=9, powered=True,
        expected_baseline=0.99, expected_treatment=0.01, power=0.8,
        budget={"wall_seconds": 30, "token_budget": 1000, "tool_budget": 10},
        arms=GOVERNED_ARMS)
    protocol["powered"] = True
    tasks = []
    for index in range(9):
        repo = holdout_repos[index % len(holdout_repos)]
        tasks.append({
            "task_id": f"task-{index}",
            "repository_id": repo["repository_id"],
            "base_commit": repo["base_commit"],
            "prompt": f"make task {index} pass",
            "failure_class": "bug_fix",
            "partition": "holdout",
            "budgets": {"time_budget_seconds": 30, "token_budget": 1000,
                        "tool_budget": 10},
            "acceptance": {
                "argv": [sys.executable, "-m", "pytest", "-q",
                         "acceptance.py"],
                "files": {"acceptance.py": ACCEPTANCE}},
        })
    return {
        "schema_version": 1, "kind": "five_arm_efficacy_manifest",
        "protocol": protocol,
        "agent": {"kind": "codex-cli", "model": "test-model",
                  "cli_version": "1.2.3"},
        "partitions": {
            "induction": [item["repository_id"] for item in repositories
                          if item["partition"] == "induction"],
            "holdout": [item["repository_id"] for item in holdout_repos]},
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


def _learned_bundle(document: dict) -> dict:
    induction = [item for item in document["repositories"]
                 if item["partition"] == "induction"]
    components = {}
    for arm in ("B", "C", "D"):
        components[arm] = [{
            "candidate_id": f"candidate-{arm}",
            "candidate_digest": hashlib.sha256(
                f"candidate-{arm}".encode()).hexdigest(),
            "content_digest": hashlib.sha256(
                f"content-{arm}".encode()).hexdigest(),
            "evidence_digest": hashlib.sha256(
                f"evidence-{arm}".encode()).hexdigest(),
            "text": f"{arm} learned step",
        }]
    bundle = {
        "schema_version": 2,
        "kind": "learned_guidance_bundle",
        "source": "learned",
        "training": {
            "repository_digests": sorted({
                item["repo_snapshot_digest"] for item in induction})},
        "components": components,
    }
    bundle["bundle_digest"] = campaign_tool._bundle_digest(bundle)
    document["guidance_bundle_digest"] = bundle["bundle_digest"]
    return bundle


def _scripted_agent(prompts, budget, model):
    def agent(ctx):
        if ctx.guidance is not None and ctx.guidance.helpful_next_checks:
            (ctx.workspace / "solution.py").write_text("OK = 1\n")
        return {"tokens_used": 5, "tools_used": 1}
    return agent


class CodexMeteringTests(unittest.TestCase):
    """The adapter nests usage under payload["summary"]; read that path."""

    @staticmethod
    def _agent(events, workspace):
        from sis.v3.learning_qualification import CodexCliAgent

        class Adapter:
            def start_task(self, prompt, workspace_path, **kwargs):
                (Path(workspace_path) / "out.txt").write_text("ok")
                yield from events

        agent = object.__new__(CodexCliAgent)
        agent._adapter = Adapter()
        agent._model = None
        agent._prompts = {"t1": "prompt"}
        return agent

    @staticmethod
    def _event(event_type, method, summary):
        return SimpleNamespace(
            event_type=event_type,
            payload={"sdk_method": method, "summary": summary})

    def test_token_usage_is_metered_from_the_nested_summary(self):
        from sis.v3.benchmark import UsageMeter
        events = [
            self._event("tool_result", "item.completed", {
                "item_type": "command_execution",
                "token_usage": {"input_tokens": 10, "output_tokens": 5}}),
            self._event("completion", "turn.completed", {}),
            self._event("completion", "sis/process_exit",
                        {"cli_exit_status": 0}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            agent = self._agent(events, temp)
            meter = UsageMeter()
            ctx = SimpleNamespace(
                task=SimpleNamespace(task_id="t1"), workspace=Path(temp),
                guidance=None, usage_meter=meter)
            usage = agent(ctx)
        self.assertEqual(usage["tokens_used"], 15)
        self.assertEqual(meter.tokens, 15)
        # One completed command is one tool call, not a start and a
        # completion event counted separately.
        self.assertEqual(meter.tools, 1)
        self.assertTrue(meter.tokens_verified)
        self.assertTrue(meter.tools_verified)

    def test_cumulative_turn_usage_is_not_double_counted(self):
        from sis.v3.benchmark import UsageMeter
        events = [
            self._event("tool_result", "item.completed", {
                "item_type": "command_execution"}),
            self._event("agent_event", "turn.completed", {
                "token_usage": {"input_tokens": 80, "output_tokens": 20}}),
            self._event("completion", "turn.completed", {
                "token_usage": {"input_tokens": 120, "output_tokens": 30}}),
            self._event("completion", "sis/process_exit",
                        {"cli_exit_status": 0}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            agent = self._agent(events, temp)
            meter = UsageMeter()
            ctx = SimpleNamespace(
                task=SimpleNamespace(task_id="t1"), workspace=Path(temp),
                guidance=None, usage_meter=meter)
            usage = agent(ctx)
        self.assertEqual(usage["tokens_used"], 150)
        self.assertEqual(meter.tokens, 150)

    def test_failed_cli_turn_is_not_a_completed_agent_call(self):
        events = [
            self._event("tool_result", "item.completed", {
                "item_type": "command_execution"}),
            self._event("agent_event", "turn.failed", {}),
            self._event("agent_event", "sis/process_exit",
                        {"cli_exit_status": 1}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            agent = self._agent(events, temp)
            ctx = SimpleNamespace(
                task=SimpleNamespace(task_id="t1"), workspace=Path(temp),
                guidance=None, usage_meter=None)
            with self.assertRaisesRegex(RuntimeError,
                                        "real_agent_error_event"):
                agent(ctx)

    def test_timed_out_cli_turn_is_not_a_completed_agent_call(self):
        events = [
            self._event("tool_result", "item.completed", {
                "item_type": "command_execution"}),
            self._event("agent_event", "sis/process_exit",
                        {"cli_exit_status": 137, "timed_out": True}),
        ]
        with tempfile.TemporaryDirectory() as temp:
            agent = self._agent(events, temp)
            ctx = SimpleNamespace(
                task=SimpleNamespace(task_id="t1"), workspace=Path(temp),
                guidance=None, usage_meter=None)
            with self.assertRaisesRegex(RuntimeError, "real_agent_timeout"):
                agent(ctx)

    def test_token_total_prefers_the_billed_pair(self):
        from sis.v3.learning_qualification import _token_total
        self.assertEqual(
            _token_total({"input_tokens": 10, "output_tokens": 5,
                          "total_tokens": 999}), 15)
        self.assertEqual(_token_total({"total_tokens": 42}), 42)
        self.assertIsNone(_token_total({}))


class GuidanceBundleLineageTests(unittest.TestCase):
    """A bundle is learned only when its candidate records resolve."""

    class _Registry:
        def __init__(self, bundle, *, corrupt=False):
            self.bundle = bundle
            self.corrupt = corrupt

        def _record(self, candidate_id):
            for records in self.bundle["components"].values():
                for record in records:
                    if record["candidate_id"] == candidate_id:
                        return record
            raise AssertionError(candidate_id)

        def get(self, candidate_id):
            record = self._record(candidate_id)
            digest = ("0" * 64 if self.corrupt
                      else record["candidate_digest"])
            return SimpleNamespace(
                digest=digest,
                content_digest=record["content_digest"]), "qualified"

        def serving_basis(self, candidate_id):
            record = self._record(candidate_id)
            return {"evidence_refs": (record["evidence_digest"],)}

    def _load(self, root, *, registry, document=None, bundle=None):
        document = document or _manifest(root)
        bundle = bundle or _learned_bundle(document)
        path = root / "guidance.json"
        path.write_text(json.dumps(bundle))
        induction = tuple(sorted({
            item["repo_snapshot_digest"] for item in document["repositories"]
            if item["partition"] == "induction"}))
        holdout = tuple(sorted({
            item["repo_snapshot_digest"] for item in document["repositories"]
            if item["partition"] == "holdout"}))
        return campaign_tool._load_guidance_bundle(
            path, induction_digests=induction,
            holdout_digests=holdout,
            precommitted_digest=bundle["bundle_digest"],
            registry=registry), bundle

    def test_a_qualified_registry_makes_the_bundle_learned(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            loaded, _ = self._load(
                root, registry=self._Registry(bundle),
                document=document, bundle=bundle)
        self.assertEqual(loaded["source"], "learned")
        self.assertTrue(loaded["candidates_verified"])
        self.assertEqual(loaded["bundles"]["B"], ["B learned step"])

    def test_a_candidate_digest_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            with self.assertRaisesRegex(ValueError,
                                        "candidate_digest_mismatch"):
                self._load(root, registry=self._Registry(
                    bundle, corrupt=True),
                    document=document, bundle=bundle)


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
            bundle_dir = Path(report["evidence_bundle"]["path"])
            bundle = json.loads(
                (bundle_dir / "bundle.json").read_text(encoding="utf-8"))
            receipt_files = sorted((bundle_dir / "receipts").iterdir())
            receipt_hashes = {
                path.stem: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in receipt_files}
            has_public_key = (bundle_dir / "public_key.json").is_file()
            has_manifest = (bundle_dir / "manifest.json").is_file()
            exported_manifest = (bundle_dir / "manifest.json").read_bytes()
            input_manifest = manifest.read_bytes()
        self.assertEqual(code, 1)
        analysis = report["learning_qualification"]
        self.assertEqual(analysis["tasks"], 9)
        self.assertTrue(analysis["real_agent"])
        # An injected agent is not a real codex-cli run.
        self.assertEqual(analysis["evidence_class"], "invalid")
        self.assertEqual(report["evidence_class"], "invalid")
        self.assertFalse(analysis["confirmatory_eligible"])
        self.assertEqual(analysis["provenance"]["agent"], "injected")
        self.assertEqual(report["receipts_issued"], 18)
        rows = [arm for task in report["per_task"]
                for arm in task["arms"].values()]
        self.assertEqual(len(rows), 45)
        self.assertTrue(all(row["receipt_digest"] for row in rows))
        for task in report["per_task"]:
            self.assertEqual(sorted(task["arm_order"]),
                             ["A", "B", "C", "D", "E"])
        self.assertEqual(report["guidance"]["source"], "fixed_control")
        self.assertIn("bug_fix", report["guidance"]["bundles"])
        self.assertEqual(len(report["guidance"]["digest"]), 64)
        self.assertTrue(report["manifest"]["valid"])
        self.assertTrue(report["manifest"]["ready"])
        self.assertEqual(report["manifest"]["holdout_repositories_used"], 5)
        self.assertEqual(analysis["decisive_contrast"]["wins"], 9)
        self.assertEqual(analysis["decisive_contrast"]["losses"], 0)
        self.assertEqual(len(analysis["per_repository"]), 5)
        self.assertEqual(
            analysis["repository_clustered_uncertainty"]["repositories"], 5)
        self.assertEqual(
            analysis["decisive_contrast"]["difference_interval_method"],
            "newcombe_paired")
        # Durable evidence: signed receipt bytes and the public key survive
        # the verifier's temporary directory.
        self.assertEqual(len(receipt_files), 18)
        self.assertEqual(set(bundle["receipts"]),
                         {path.stem for path in receipt_files})
        for digest, content_hash in receipt_hashes.items():
            self.assertEqual(bundle["receipts"][digest], content_hash)
        self.assertTrue(has_public_key)
        self.assertTrue(has_manifest)
        self.assertEqual(exported_manifest, input_manifest)
        self.assertEqual(len(bundle["bundle_digest"]), 64)
        self.assertEqual(
            bundle["manifest"]["digest"], report["manifest"]["digest"])

    @unittest.skipUnless(
        POSIX_CUSTODY,
        "evaluator key custody is POSIX-only in this release")
    def test_learned_guidance_bundle_is_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps(bundle))
            output = root / "report.json"
            campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        # Without a candidate registry the lineage is not verified; the
        # report says so instead of accepting the self-declaration.
        self.assertEqual(report["guidance"]["source"], "learned_unverified")
        self.assertEqual(report["guidance"]["bundle_digest"],
                         bundle["bundle_digest"])
        self.assertFalse(report["guidance"]["candidates_verified"])
        self.assertEqual(
            report["learning_qualification"]["provenance"]["guidance_source"],
            "learned_unverified")
        self.assertEqual(
            report["guidance"]["bundles"]["B"], ["B learned step"])

    def test_a_self_declared_learned_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            document["guidance_bundle_digest"] = "0" * 64
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps({
                "schema_version": 1,
                "source": "learned",
                "bundles": {"B": ["x"], "C": ["y"], "D": ["z"]}}))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("schema_version", report["note"])

    def test_a_bundle_without_manifest_precommitment_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            del document["guidance_bundle_digest"]
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps(bundle))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("precommit", report["note"])

    def test_a_tampered_bundle_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            bundle["components"]["B"][0]["text"] = "substituted text"
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps(bundle))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("digest", report["note"])

    def test_bundle_training_outside_the_induction_partition_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            bundle = _learned_bundle(document)
            bundle["training"]["repository_digests"] = ["f" * 64]
            bundle["bundle_digest"] = campaign_tool._bundle_digest(bundle)
            document["guidance_bundle_digest"] = bundle["bundle_digest"]
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps(bundle))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("induction partitions", report["note"])

    def test_candidate_registry_without_a_bundle_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            manifest = _write(root, _manifest(root))
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                candidate_registry=root / "registry.db",
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_GUIDANCE")
        self.assertIn("requires a guidance bundle", report["note"])

    def test_a_diagnostic_manifest_is_not_executed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            diagnostic = preregister(
                primary_metric="paired solved_delta E vs A",
                method="mcnemar_exact", alpha=0.05, min_effect=1.0,
                sample_size=4, powered=False,
                budget={"wall_seconds": 30, "token_budget": 1000,
                        "tool_budget": 10},
                arms=GOVERNED_ARMS)
            diagnostic["powered"] = False
            document["protocol"] = diagnostic
            document["preregistration"]["protocol_digest"] = (
                diagnostic["protocol_digest"])
            manifest = _write(root, document)
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertIn("manifest_not_ready", report["note"])

    def test_cli_version_mismatch_is_blocked(self):
        original = campaign_tool._installed_codex_version
        campaign_tool._installed_codex_version = lambda binary: "9.9.9"
        try:
            with tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                output = root / "report.json"
                code = campaign_tool.run_real(
                    output, _write(root, _manifest(root)),
                    allow_shared_custody=True)
                report = json.loads(output.read_text(encoding="utf-8"))
        finally:
            campaign_tool._installed_codex_version = original
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_AGENT_VERSION")
        self.assertIn("does not match", report["note"])

    def test_placeholder_manifest_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            document["notes"] = "<operator note>"
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, _write(root, document), allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertIn("placeholder", report["note"])

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
            (root / "holdout-0" / "solution.py").write_text("DRIFT = 1\n")
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertIn("repository_snapshot_mismatch", report["note"])

    @unittest.skipUnless(
        POSIX_CUSTODY,
        "evaluator key custody is POSIX-only in this release")
    def test_repository_custody_failure_is_blocked_not_crashed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            holdout = next(item for item in document["repositories"]
                           if item["partition"] == "holdout")
            outside = root / "private" / "secret.txt"
            outside.parent.mkdir(exist_ok=True)
            outside.write_text("EVALUATOR-ONLY")
            (Path(holdout["path"]) / "escape").symlink_to(outside)
            holdout["repo_snapshot_digest"] = tree_digest(
                Path(holdout["path"]))
            manifest = _write(root, document)
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_CUSTODY")
        self.assertIn("external_symlinks", report["note"])

    @unittest.skipUnless(POSIX_CUSTODY, "symlink fixture requires POSIX")
    def test_a_symlinked_repository_root_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            document = _manifest(root)
            holdout = next(item for item in document["repositories"]
                           if item["partition"] == "holdout")
            alias = root / "holdout-alias"
            alias.symlink_to(Path(holdout["path"]),
                             target_is_directory=True)
            holdout["path"] = str(alias)
            manifest = _write(root, document)
            output = root / "report.json"
            code = campaign_tool.run_real(
                output, manifest, allow_shared_custody=True,
                agent_factory=_scripted_agent)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(code, 2)
        self.assertEqual(report["release_gate"], "BLOCKED_MANIFEST")
        self.assertIn("plain_directory", report["note"])


if __name__ == "__main__":
    unittest.main()
