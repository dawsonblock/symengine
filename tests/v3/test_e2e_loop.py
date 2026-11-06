"""End-to-end machinery validation: capture→induce→promote→grant→serve.

This proves the loop wiring works under real signed authority — it is
NOT an efficacy result.
"""
import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import GuidanceRequestV1
from sis.v3.learning.pipeline import observe_strategy_proposals
from sis.v3.learning.strategies import EpisodeEvidence
from sis.v3.procedures import ProcedureStore
from sis.v3.secure_guidance import StrictGuidanceGateway
from tests.v3.authority_testkit import (TEST_TOKEN, drive, make_authority,
                                        evaluator_keypair,
                                        issue_and_commit_grant,
                                        make_grant_authority,
                                        make_registry, register_repo, seed,
                                        signed_receipt)


def _tree(repo: str) -> str:
    return hashlib.sha256(("tree:" + repo).encode()).hexdigest()


def _ep(i, repo, sig="sig-1"):
    return EpisodeEvidence(
        episode_id=f"ep{i}", repository_id=repo, failure_signature=sig,
        outcome="pass", receipt_digest=str(i) * 64,
        diagnostic_actions=("read_logs", "run_tests"), verified=True)


class EndToEndLoopTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.registry, self.reg_seed = make_registry()
        register_repo(self.registry, self.reg_seed, registry_id="repo-a")
        register_repo(self.registry, self.reg_seed, registry_id="repo-b")
        self.grants, self.grant_seed, self.grant_key = make_grant_authority(
            self.registry)
        self.receipt_store = {"1" * 64: {}, "2" * 64: {}}

    def _request(self, sig="sig-1"):
        return GuidanceRequestV1(
            schema_version=1, task_id="task-eval-1",
            repo_snapshot_digest=_tree("repo-b"), base_commit="a1b2c3d",
            namespace="calc", language="python", toolchain="pytest",
            lockfile_digests={}, task_summary="fix the bug",
            failure_signatures=(sig,), present_symbols=(),
            semantic_contract_digest="c" * 64)

    def test_learned_candidate_promoted_and_served_in_scope(self):
        episodes = [_ep(1, "repo-a"), _ep(2, "repo-c")]
        store = ProcedureStore(self.root / "learn")
        candidate_digests = observe_strategy_proposals(
            episodes, language="python", store=store,
            receipt_resolver=self.receipt_store.get)
        self.assertEqual(len(candidate_digests), 1)
        candidate = store.by_status("candidate")[0]
        self.assertEqual(candidate.status, "candidate")

        # Promote through real signed decisions in the authority store.
        seed_b, pub, kid = evaluator_keypair()
        db, controller = make_authority(
            self.root / "auth", token=TEST_TOKEN,
            evaluator_key_id=kid, evaluator_public_hex=pub.hex())
        receipt = signed_receipt(seed_b, kid)
        controller._resolve_receipt = {receipt.digest: receipt}.__getitem__
        seed(db, candidate)
        drive(db, controller, candidate.procedure_id, "qualified",
              token=TEST_TOKEN, seed=seed_b, key_id=kid, receipts=[receipt])
        qualified = db.get(candidate.procedure_id)
        self.assertEqual(qualified.status, "qualified")

        # Grant cross-repo scope to repo-b with distinct-identity transfer
        # evidence (repo digests must match registered base tree digests).
        transfer = [signed_receipt(seed_b, kid, task_id=f"tr-{r}",
                                   repo_digest=_tree(r))
                    for r in ("repo-a", "repo-b")]
        issue_and_commit_grant(
            db, controller, self.grants, record=qualified,
            source_registry_id="repo-a", target_registry_id="repo-b",
            seed=self.grant_seed, key_id=self.grant_key,
            evidence_receipts=tuple(transfer))
        gateway = StrictGuidanceGateway(
            db, controller, repository_registry=self.registry,
            grant_authority=self.grants)
        guidance = gateway.recommend(self._request(),
                                     repository_id="repo-b")
        self.assertNotEqual(guidance.decision, "abstain")
        self.assertIn(candidate.procedure_id, guidance.procedure_ids)

    def test_unresolved_receipt_blocks_learning(self):
        episodes = [_ep(1, "repo-a"), _ep(2, "repo-a")]
        store = ProcedureStore(self.root / "learn2")
        with self.assertRaises(ValueError):
            observe_strategy_proposals(
                episodes, language="python", store=store,
                receipt_resolver=lambda d: None)


if __name__ == "__main__":
    unittest.main()
