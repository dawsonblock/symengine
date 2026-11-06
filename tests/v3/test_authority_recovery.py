"""Fault-injection tests for the transactional authority store.

The legacy write-ahead journal replayed signed decisions into the catalog
after a crash; ``AuthorityDB`` commits decision+revision atomically, so there
is no pending-authority window at all. These tests prove the stronger
property: an injected fault anywhere in the commit leaves *zero* visible
qualification, corrupt or orphaned rows fail closed, and a stale controller
can never append.
"""
import pytest

from sis.v3.authority_db import AuthorityDB
from sis.v3.promotion import PromotionController, PromotionRejected, operator_token_digest
from sis.v3.secure_guidance import StrictGuidanceGateway
from tests.v3.test_retrieval import _proc, _request

TOKEN = "test-long-promotion-token-for-recovery"


def _controller(db, **over):
    params = dict(operator_token_digest=operator_token_digest(TOKEN),
                  trusted_evaluator_keys={})
    params.update(over)
    return PromotionController(db, **params)


def test_failed_commit_leaves_zero_state_and_retry_succeeds(tmp_path):
    """Crash mid-commit: neither decision nor revision becomes visible."""
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    controller = _controller(db)
    original = db._step_insert_decision

    def boom(con, decision, prior, provenance):
        raise OSError("injected fault after revision insert")

    db._step_insert_decision = boom
    try:
        with pytest.raises(OSError, match="injected fault"):
            controller.transition(
                "p1", "candidate", actor_role="operator",
                actor_identity="owner", operator_token=TOKEN)
    finally:
        db._step_insert_decision = original
    # Atomic rollback: no decision row, no materialized revision.
    assert db.decision_head() is None
    assert db.get("p1").status == "draft"
    assert db.get("p1").revision == 1
    # Retry is a fresh commit, not a replay — and it must succeed cleanly.
    controller.transition(
        "p1", "candidate", actor_role="operator",
        actor_identity="owner", operator_token=TOKEN)
    assert db.get("p1").status == "candidate"
    assert len(controller.decisions()) == 1

    # A cold-open controller sees a consistent store.
    disk = AuthorityDB(tmp_path / "authority.db")
    disk_controller = _controller(disk)
    assert disk_controller.verify()["ok"]
    assert disk.get("p1").status == "candidate"
    assert len(disk_controller.decisions()) == 1


def test_fail_closed_if_committed_revision_disappears(tmp_path):
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    controller = _controller(db)
    controller.transition(
        "p1", "candidate", actor_role="operator",
        actor_identity="owner", operator_token=TOKEN)
    # Delete the materialized revision the decision binds to.
    db._conn().execute("PRAGMA foreign_keys=OFF")
    db._conn().execute(
        "DELETE FROM procedure_revision WHERE procedure_id='p1' AND revision=2")
    db._conn().execute("PRAGMA foreign_keys=ON")
    report = db.verify()
    assert not report["ok"]
    with pytest.raises(PromotionRejected, match="authority_state_invalid"):
        _controller(db)


def test_fail_closed_if_seed_predecessor_disappears(tmp_path):
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    controller = _controller(db)
    controller.transition(
        "p1", "candidate", actor_role="operator",
        actor_identity="owner", operator_token=TOKEN)
    db._conn().execute(
        "DELETE FROM procedure_revision WHERE procedure_id='p1' AND revision=1")
    report = db.verify()
    assert not report["ok"]
    assert "noncontiguous_revisions:p1" in report["problems"]
    with pytest.raises(PromotionRejected, match="authority_state_invalid"):
        _controller(db)


def test_terminated_corrupt_row_never_silently_truncated(tmp_path):
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    controller = _controller(db)
    controller.transition(
        "p1", "candidate", actor_role="operator",
        actor_identity="owner", operator_token=TOKEN)
    db._conn().execute(
        "UPDATE signed_promotion_decision SET decision_json='{corrupt record'")
    report = db.verify()
    assert not report["ok"]
    with pytest.raises(PromotionRejected, match="authority_state_invalid"):
        _controller(db)
    # Corrupt bytes preserved — verify never silently repairs.
    assert db._conn().execute(
        "SELECT decision_json FROM signed_promotion_decision").fetchone()[0] \
        == "{corrupt record"


def test_stale_controller_cannot_append_after_independent_commit(tmp_path):
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    first = _controller(db)
    stale = _controller(db)
    first.transition("p1", "candidate", actor_role="operator",
                     actor_identity="owner", operator_token=TOKEN)
    with pytest.raises(PromotionRejected, match="stale_controller"):
        stale.transition("p1", "evaluated", actor_role="operator",
                         actor_identity="owner", operator_token=TOKEN)


def test_second_process_controller_is_stale_after_first_commits(tmp_path):
    """Two AuthorityDB handles on one file emulate two processes."""
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    first = _controller(db)
    second_db = AuthorityDB(tmp_path / "authority.db")
    stale = _controller(second_db)
    first.transition("p1", "candidate", actor_role="operator",
                     actor_identity="owner", operator_token=TOKEN)
    # The second handle observes the new committed head but its controller
    # still holds the old one: fail closed.
    assert second_db.decision_head() != stale._prior
    with pytest.raises(PromotionRejected, match="stale_controller"):
        stale.transition("p1", "evaluated", actor_role="operator",
                         actor_identity="owner", operator_token=TOKEN)
    second_db.close()


def test_strict_gateway_abstains_after_aborted_commit(tmp_path):
    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(status="draft"))
    controller = _controller(db)
    db._step_insert_revision = lambda *a, **k: (_ for _ in ()).throw(
        OSError("injected crash"))
    with pytest.raises(OSError):
        controller.transition("p1", "candidate", actor_role="operator",
                              actor_identity="owner", operator_token=TOKEN)
    gateway = StrictGuidanceGateway(db, controller, procedure_owners={"p1": "repo-a"})
    assert gateway.recommend(_request(), repository_id="repo-a").decision == "abstain"


def test_committed_qualification_serves_after_restart(tmp_path):
    """A real signed qualification survives restart and serves via the strict
    gateway; no replay or materialization step is needed — the commit was
    already atomic."""
    import hashlib
    import sys
    from sis.v3 import signatures
    from sis.v3.contracts import TaskEnvelopeV1
    from sis.v3.runner import LocalSubprocessExecutor, tree_digest
    from sis.v3.verifier import OutcomeVerifier
    from tests.v3.authority_testkit import drive

    db = AuthorityDB(tmp_path / "authority.db")
    db.add_seed(_proc(pid="p1", status="draft"))
    seed, pub = signatures.generate_keypair()
    signer_id = "key-" + hashlib.sha256(pub).hexdigest()[:24]
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(tmp_path / "exec", use_seatbelt=False),
        key_dir=tmp_path / "keys", registry_dir=tmp_path / "registry")
    verifier.register_task(actor_role="evaluator", task_id="recovery-task",
                           criterion_version="v1", argv=(sys.executable, "acc.py"),
                           files={"acc.py": b"print('ok')\n"})
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "example.py").write_text("value = 10\n")
    task = TaskEnvelopeV1(
        schema_version=1, task_id="recovery-task", repo_snapshot_digest=tree_digest(repo),
        base_commit=None, task_statement_digest="0" * 64, permitted_commands=("x",),
        isolation_profile="unverified_local", time_budget_seconds=60,
        token_budget=1000, tool_budget=10, actor_id="agent", evaluator_task_ref="recovery-task")
    receipt = verifier.evaluate(actor_role="evaluator", task=task,
                                submission_dir=repo, evaluation_nonce="recovery-nonce-1")
    params = dict(operator_token_digest=operator_token_digest(TOKEN),
                  trusted_evaluator_keys={signer_id: pub.hex(),
                                          verifier.keystore.key_id: verifier.keystore.public.hex()},
                  receipt_resolver=verifier.load_receipt)
    controller = PromotionController(db, **params)
    drive(db, controller, "p1", "evaluated",
          token=TOKEN, seed=seed, key_id=signer_id, receipts=[receipt])
    controller.transition(
        "p1", "qualified", actor_role="operator", actor_identity="owner",
        operator_token=TOKEN, receipt_digests=(receipt.digest,),
        evaluator_signer=lambda body: (signer_id, signatures.sign(seed, body).hex()))

    # Cold restart: fresh store handle + controller see the committed state.
    disk = AuthorityDB(tmp_path / "authority.db")
    fresh = PromotionController(disk, **params)
    assert fresh.verify()["ok"]
    assert disk.get("p1").status == "qualified"
    serving = StrictGuidanceGateway(disk, fresh, procedure_owners={"p1": "repo-a"})
    assert serving.recommend(_request(), repository_id="repo-a").decision == "recommend"
    assert serving.recommend(_request(), repository_id="repo-other").decision == "abstain"
    disk.close()
