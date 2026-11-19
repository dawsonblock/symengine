"""Review fix: study guidance is served per task through SIS's gateway.

The five-arm tool used to give every task the same constant text. A
verified learned bundle is now routed through ``GovernedServingGateway``
with each task's own context, so tasks can receive different or no
guidance, and every rejection is recorded.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate

_TOOL = Path(__file__).resolve().parents[2] / "tools" / "five_arm_campaign.py"
_SPEC = importlib.util.spec_from_file_location("five_arm_campaign_serving",
                                               _TOOL)
campaign_tool = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(campaign_tool)


class PerTaskServingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.stack = CandidateStack(self.root / "candidates.db")
        self.addCleanup(self.stack.close)

    def _candidate(self, cid, step, predicate):
        candidate = make_candidate(
            cid=cid, payload={"title": cid, "steps": [step]},
            scope={"kind": "global", "value": ""})
        candidate = type(candidate).from_dict(
            {**candidate.to_dict(), "applicability_predicate": [predicate]})
        self.stack.prepare(candidate)
        self.stack.qualify(candidate)
        return candidate

    def test_tasks_receive_task_specific_guidance(self):
        self._candidate("cand-b", "Check the setup.cfg pins.",
                        {"kind": "file_present", "value": "setup.cfg"})
        self._candidate("cand-c", "Reproduce the parser failure first.",
                        {"kind": "failure_signature_is",
                         "value": "parser_bug"})
        bundle = {"components": {
            "B": [{"candidate_id": "cand-b"}],
            "C": [{"candidate_id": "cand-c"}],
            "D": []}}
        contexts = {
            "task-1": {"repository_id": "repo-1", "prompt": "fix it",
                       "failure_signatures": ("parser_bug",),
                       "files_present": ("setup.cfg", "pkg/a.py")},
            "task-2": {"repository_id": "repo-2", "prompt": "fix it",
                       "failure_signatures": ("other",),
                       "files_present": ("pkg/a.py",)},
        }
        served: dict = {}
        decisions: list = []
        provider = campaign_tool._serving_provider(
            self.stack.registry, bundle, task_contexts=contexts,
            repositories=[{"repository_id": "repo-1"},
                          {"repository_id": "repo-2"}],
            served=served, decisions=decisions)

        def task(task_id):
            return SimpleNamespace(task_id=task_id,
                                   repo_snapshot_digest="a" * 64,
                                   base_commit="abc1234")

        self.assertIsNone(provider(task("task-1"), "A"))
        first = provider(task("task-1"), "E")
        second = provider(task("task-2"), "E")
        only_b = provider(task("task-1"), "B")
        self.assertIn("Check the setup.cfg pins.", first.helpful_next_checks)
        self.assertIn("Reproduce the parser failure first.",
                      first.helpful_next_checks)
        # Neither candidate applies to task-2: it runs without guidance.
        self.assertIsNone(second)
        self.assertFalse(served[("task-2", "E")])
        self.assertTrue(served[("task-1", "E")])
        # Arm B draws only from its own component.
        self.assertNotIn("Reproduce the parser failure first.",
                         only_b.helpful_next_checks)
        record = next(item for item in decisions
                      if item["task_id"] == "task-2" and item["arm"] == "E")
        self.assertEqual(record["decision"], "abstain")
        self.assertEqual(
            sorted(item["reason"] for item in record["rejections"]),
            ["inapplicable", "inapplicable"])
        delivered = next(item for item in decisions
                         if item["task_id"] == "task-1" and item["arm"] == "E")
        self.assertEqual(len(delivered["candidates"]), 2)

    def test_an_unknown_repository_gets_no_guidance(self):
        self._candidate("cand-b", "Check the setup.cfg pins.",
                        {"kind": "language_is", "value": "python"})
        bundle = {"components": {"B": [{"candidate_id": "cand-b"}],
                                 "C": [], "D": []}}
        served: dict = {}
        decisions: list = []
        provider = campaign_tool._serving_provider(
            self.stack.registry, bundle,
            task_contexts={"task-1": {"repository_id": "elsewhere",
                                      "prompt": "p"}},
            repositories=[{"repository_id": "repo-1"}],
            served=served, decisions=decisions)
        guidance = provider(SimpleNamespace(
            task_id="task-1", repo_snapshot_digest="a" * 64,
            base_commit="abc1234"), "B")
        self.assertIsNone(guidance)
        self.assertEqual(decisions[0]["decision"], "abstain")


if __name__ == "__main__":
    unittest.main()


from tests.v3.test_five_arm_real_run import (  # noqa: E402
    GIT, POSIX_CUSTODY, _learned_bundle, _manifest, _scripted_agent, _status,
    _write)
from tests.v3.test_five_arm_real_run import (  # noqa: E402
    campaign_tool as real_run_tool)


@unittest.skipUnless(GIT and POSIX_CUSTODY,
                     "git and POSIX key custody are required")
class RealRunServingTests(unittest.TestCase):
    def setUp(self):
        self._status = real_run_tool.codex_agent_status
        real_run_tool.codex_agent_status = _status
        self.addCleanup(setattr, real_run_tool, "codex_agent_status",
                        self._status)

    def test_verified_bundle_is_served_through_the_gateway(self):
        import json
        from sis.v3.candidates import CandidateRegistry
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            stack = CandidateStack(root / "candidates.db")
            self.addCleanup(stack.close)
            document = _manifest(root)
            qualified = {}
            for arm in ("B", "C", "D"):
                candidate = make_candidate(
                    cid=f"candidate-{arm}",
                    payload={"title": arm, "steps": [f"{arm} served step"]},
                    scope={"kind": "global", "value": ""})
                stack.prepare(candidate)
                _, evidence, _ = stack.qualify(candidate)
                qualified[arm] = (candidate, evidence)
            # The bundle declares the qualification receipts it was
            # qualified on (induction repositories, never the holdout).
            bundle = _learned_bundle(
                document, receipts=list(stack.receipts.values()),
                signer=(stack.eval_key, stack.eval_public_hex))
            for arm, (candidate, evidence) in qualified.items():
                bundle["components"][arm][0].update({
                    "candidate_digest": candidate.digest,
                    "content_digest": candidate.content_digest,
                    "evidence_digest": evidence.digest})
            bundle.pop("bundle_digest")
            bundle["bundle_digest"] = real_run_tool._bundle_digest(bundle)
            document["guidance_bundle_digest"] = bundle["bundle_digest"]
            manifest = _write(root, document)
            guidance = root / "guidance.json"
            guidance.write_text(json.dumps(bundle))
            output = root / "report.json"

            def registry_factory(path):
                return CandidateRegistry(
                    path, receipt_authority=stack.resolve_receipt,
                    evidence_authority=stack.evidence_authority,
                    decision_authority=stack.decision_authority,
                    expected_evaluation_protocol_digest=stack.protocol)

            real_run_tool.run_real(
                output, manifest, allow_shared_custody=True,
                guidance_path=guidance, candidate_registry=root / "candidates.db",
                agent_factory=_scripted_agent,
                registry_factory=registry_factory)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(report["guidance"]["candidates_verified"])
        self.assertEqual(report["guidance"]["routing"], "governed_serving")
        provenance = report["learning_qualification"]["provenance"]
        self.assertEqual(provenance["guidance_routing"], "governed_serving")
        decisions = report["guidance"]["serving_decisions"]
        self.assertEqual({item["arm"] for item in decisions},
                         {"B", "C", "D", "E"})
        self.assertTrue(all(item["decision"] == "advisory"
                            for item in decisions))
        self.assertTrue(all(item["candidates"] for item in decisions))
        self.assertGreater(
            report["learning_qualification"]["decisive_contrast"]["wins"], 0)
