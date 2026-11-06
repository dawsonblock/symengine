"""Adversarial and transfer-focused tests for the upgraded SIS build."""
import tempfile
from dataclasses import replace
from pathlib import Path

import pytest

from sis.v3.benchmark import ArmResult, TaskResult, BenchmarkHarness, BudgetCaps
from sis.v3.learning import (EpisodeEvidence, induce_strategies,
                             induce_structural_change, CandidateTrial, select_improvement)
from sis.v3.nonce_store import NonceAlreadyConsumed, OutcomeNonceStore
from sis.v3.outcome_v2 import TrustedKey, TrustedKeyRegistry, issue_envelope
from sis.v3.verifier import EvaluatorKeyStore
from sis.v3.authority_db import AuthorityDB, AuthorityConflict
from sis.v3.procedures import ProcedureStore
from sis.v3.promotion import PromotionController
from sis.v3.secure_guidance import StrictGuidanceGateway
from tests.v3.test_retrieval import _proc, _request


def test_contrastive_strategy_requires_trusted_multirepo_evidence():
    ep = [EpisodeEvidence("ep-1", "repo-a", "pytest:exit_1", "pass", "a"*64,
                          ("isolate failing test", "inspect assertion"), verified=True),
          EpisodeEvidence("ep-2", "repo-b", "pytest:exit_1", "pass", "b"*64,
                          ("isolate failing test", "check regression"), verified=True),
          EpisodeEvidence("ep-3", "repo-c", "pytest:exit_1", "fail", "c"*64,
                          ("check regression",), verified=True)]
    (lesson,) = induce_strategies(ep)
    assert lesson.diagnostic_steps == ("isolate failing test",)
    assert lesson.status == "candidate" and len(lesson.negative_receipts) == 1
    with pytest.raises(ValueError, match="unverified"):
        induce_strategies([replace(ep[0], verified=False)])
    assert not induce_strategies(ep[:1])


def test_ast_induction_cannot_claim_causal_safety():
    candidate = induce_structural_change("def f(a,b):\n return a-b\n",
                                         "def f(a,b):\n return a+b\n",
                                         semantic_contract_digest="1"*64,
                                         independently_verified_receipt_digest="2"*64)
    assert candidate.old_operator == "Sub" and candidate.new_operator == "Add"
    assert candidate.status == "candidate"
    assert induce_structural_change("x=a-b", "x=a+b+1",
                                    semantic_contract_digest="1"*64,
                                    independently_verified_receipt_digest="2"*64) is None


def test_optimizer_requires_verified_paired_transfer():
    records = [CandidateTrial("a", "r1", "t1", False, True, True, "1"*64, True),
               CandidateTrial("a", "r2", "t2", False, True, True, "2"*64, True),
               CandidateTrial("b", "r3", "t3", True, False, True, "3"*64, True)]
    assert select_improvement(records) == ("a",)
    assert select_improvement(records[:1]) == ()
    with pytest.raises(ValueError, match="trial_not_independently_verified"):
        select_improvement([replace(records[0], evaluator_verified=False)])


def test_benchmark_excludes_invalid_success_from_all_stats():
    passing = ArmResult("t", "D", "pass", "1"*64, "2"*64, 2, True)
    failing = ArmResult("t", "A", "fail", "1"*64, "2"*64, 1)
    report = BenchmarkHarness.__new__(BenchmarkHarness)._report(
        [TaskResult("t", {"A": failing, "D": passing})],
        ("A", "D"), BudgetCaps(1,100,5))
    assert report["solved_counts"]["D"] == 0
    assert report["paired"]["D_vs_A"]["wins"] == 0


def test_nonce_admission_survives_reopen_and_rejects_replay(tmp_path):
    keys = EvaluatorKeyStore(tmp_path / "keys")
    _, pub = keys.load_or_create()
    registry = TrustedKeyRegistry({keys.key_id: TrustedKey(public_key=pub.hex())})
    env = issue_envelope(keystore=keys, task_id="t1", attempt_id="a1",
                         evaluated_repo_digest="1"*64, environment_digest="2"*64,
                         test_suite_commitment="3"*64, execution_receipt_digest="4"*64,
                         criterion_version="v1", outcome="pass")
    db_path = tmp_path / "nonces.db"
    assert OutcomeNonceStore(db_path).verify_and_consume(env, registry) == env.digest
    with pytest.raises(NonceAlreadyConsumed):
        OutcomeNonceStore(db_path).verify_and_consume(env, registry)


def test_strict_gateway_rejects_direct_qualified_catalog_seeding(tmp_path):
    """Three layers of the I-1 invariant: write-time rejection, fail-closed
    verification of injected rows, and abstention at the serving boundary."""
    db = AuthorityDB(tmp_path / "authority.db")
    rec = _proc(pid="rogue")  # fixture record carries status="qualified"
    # Layer 1: the intake interface cannot mint qualified state at all.
    with pytest.raises(AuthorityConflict, match="status_write_requires_committed_decision"):
        db.add_seed(rec)
    # Layer 2: a legacy JSONL catalog rejects it the same way.
    with pytest.raises(Exception, match="status_write_requires_committed_decision"):
        ProcedureStore(tmp_path / "catalog").add(rec)
    # Layer 3: raw-file injection past the API still cannot serve — the
    # unauthorized revision fails verification and the live gateway abstains.
    controller = PromotionController(db, operator_token_digest=None,
                                     trusted_evaluator_keys={})
    gateway = StrictGuidanceGateway(db, controller, procedure_owners={"rogue": "repo-a"})
    con = db._conn()
    con.execute(
        "INSERT INTO procedure_revision"
        " (procedure_id, revision, record_digest, status, record_json, committed_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("rogue", 1, rec.digest, "qualified",
         rec.canonical_bytes().decode("utf-8"), "2026-01-01T00:00:00Z"))
    assert not db.verify()["ok"]
    response = gateway.recommend(_request(), repository_id="repo-a")
    assert response.decision == "abstain"
    assert response.reason_code == "catalog_unavailable"
    db.close()


def test_trusted_promotion_can_be_served_by_strict_gateway(tmp_path):
    """End-to-end real evaluator -> promotion -> authorized guidance, not a fake record."""
    from sis.v3 import signatures
    from sis.v3.contracts import TaskEnvelopeV1
    from sis.v3.runner import LocalSubprocessExecutor, tree_digest
    from sis.v3.verifier import OutcomeVerifier
    from sis.v3.promotion import operator_token_digest
    import sys
    import hashlib

    store = AuthorityDB(tmp_path / "authority.db")
    store.add_seed(_proc(pid="p1", status="draft"))
    seed, public = signatures.generate_keypair()
    kid = "key-" + hashlib.sha256(public).hexdigest()[:24]
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(tmp_path / "exec", use_seatbelt=False),
        key_dir=tmp_path / "keys", registry_dir=tmp_path / "registry")
    verifier.register_task(actor_role="evaluator", task_id="t", criterion_version="v1",
                           argv=(sys.executable, "acc.py"),
                           files={"acc.py": b"print('ok')\n"})
    root = tmp_path / "repo"
    root.mkdir()
    (root / "x.py").write_text("x=1\n")
    task = TaskEnvelopeV1(schema_version=1, task_id="t", repo_snapshot_digest=tree_digest(root),
                          base_commit=None, task_statement_digest="0"*64,
                          permitted_commands=("x",), isolation_profile="unverified_local",
                          time_budget_seconds=60, token_budget=1000, tool_budget=10,
                          actor_id="agent", evaluator_task_ref="t")
    receipt = verifier.evaluate(actor_role="evaluator", task=task,
                                submission_dir=root, evaluation_nonce="test-t-1")
    controller = PromotionController(store,
                                     operator_token_digest=operator_token_digest("0123456789abcdef"),
                                     trusted_evaluator_keys={kid: public.hex(),
                                                             verifier.keystore.key_id: verifier.keystore.public.hex()},
                                     receipt_resolver=verifier.load_receipt)
    from tests.v3.authority_testkit import drive
    drive(store, controller, "p1", "evaluated",
          token="0123456789abcdef", seed=seed, key_id=kid, receipts=[receipt])
    controller.transition("p1", "qualified", actor_role="operator", actor_identity="operator-1",
                          operator_token="0123456789abcdef", receipt_digests=(receipt.digest,),
                          evaluator_signer=lambda body: (kid, signatures.sign(seed, body).hex()))
    gateway = StrictGuidanceGateway(store, controller, procedure_owners={"p1": "repo-1"})
    result = gateway.recommend(_request(), repository_id="repo-1")
    assert result.decision == "recommend"
    assert result.procedure_ids == ("p1",)
    assert gateway.recommend(_request(), repository_id="repo-2").decision == "abstain"
    # A raw-injected unauthorized qualification invalidates authority globally.
    rogue = _proc(pid="rogue")
    store._conn().execute(
        "INSERT INTO procedure_revision"
        " (procedure_id, revision, record_digest, status, record_json, committed_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        ("rogue", 1, rogue.digest, "qualified",
         rogue.canonical_bytes().decode("utf-8"), "2026-01-01T00:00:00Z"))
    assert gateway.recommend(_request(), repository_id="repo-1").reason_code == "catalog_unavailable"
    store.close()
