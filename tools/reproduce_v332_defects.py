"""Reproduce the five v3.3.2 target defects against the current source.

Run from the release tree:

    PYTHONPATH=src:. python3 tools/reproduce_v332_defects.py

The same checks run against pristine v3.3.1 via
``evidence/v332/reproduce_v331_baseline.py``; that run reports all five
open. This run must report zero open.
"""
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sis.v3 import serving as serving_mod
from sis.v3.evidence_custody import EvidenceCustodyStore
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture

RESULTS = {}


def record(name, observed, expected):
    RESULTS[name] = {"observed": observed, "expected": expected,
                     "defect": any(observed.get(k) != v
                                   for k, v in expected.items())}


def defect_identity_disable(root):
    fx = ProductionFixture(root)
    try:
        try:
            GovernedServingGateway(
                fx.registry, repository_registry=fx.repo_registry,
                production=True,
                execution_identity_authority=fx.identity_authority,
                require_execution_identity=False,
                used_session_nonces=set(),
                control_plane=fx.control_plane)
            observed = {"constructed": True}
        except ValueError as exc:
            observed = {"constructed": False, "error": str(exc)}
        record("D1_identity_disableable_in_production",
               observed, {"constructed": False})
    finally:
        fx.close()


def defect_replay_across_replicas(root):
    fx = ProductionFixture(root)
    try:
        identity = fx.identity()
        replica_a = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set(),
            control_plane=fx.control_plane)
        replica_b = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set(),
            control_plane=fx.control_plane)
        first = replica_a.serve(_request(), repository_id="repo-1",
                                execution_identity=identity)
        second = replica_b.serve(_request(), repository_id="repo-1",
                                 execution_identity=identity)
        record("D2_same_nonce_two_replicas",
               {"a": first.reason_code, "b": second.reason_code},
               {"a": "no_qualified_procedure",
                "b": "catalog_unavailable"})
    finally:
        fx.close()


def defect_custody_rollback(root):
    fx = ProductionFixture(root)
    try:
        backup = root / "custody-backup"
        shutil.copytree(fx.custody.root, backup)
        fx.custody.revoke(
            fx.certificate.digest, kind="certificate", reason="evaluator error",
            seed=fx.custody_seed, key_id=fx.custody_key)
        revoked_status = fx.custody.status(fx.certificate.digest)
        shutil.rmtree(fx.custody.root)
        shutil.copytree(backup, fx.custody.root)
        restored = EvidenceCustodyStore(
            fx.custody.root,
            trusted_revocation_keys={fx.custody_key: fx.custody._keys[fx.custody_key]})
        restored_status = restored.status(fx.certificate.digest)
        try:
            fx.registry.authority_status()
            gate = "accepted"
        except Exception as exc:  # noqa: BLE001 - report the reason
            gate = f"rejected:{exc}"
        record("D3_revocation_history_rollback",
               {"after_revoke": revoked_status,
                "after_restore": restored_status,
                "custody_verify_ok": restored.verify()["ok"],
                "authority_gate": gate},
               {"after_revoke": "revoked",
                "authority_gate": "rejected:authority_checkpoint_rejected:custody_entry_count_regression"})
    finally:
        fx.close()


def defect_diamond(root):
    custody = EvidenceCustodyStore(root / "diamond")
    d = custody.put({"leaf": "d"})
    b = custody.put({"node": "b"})
    c = custody.put({"node": "c"})
    a = custody.put({"node": "a"})
    custody.link(b, receipts=(d,))
    custody.link(c, receipts=(d,))
    custody.link(a, receipts=(b, c))
    record("D4_diamond_dependency_graph",
           {"status_a": custody.status(a)},
           {"status_a": "active"})


def defect_revocation_race(root):
    fx = ProductionFixture(root)
    original = serving_mod.compose_guidance
    try:
        def compose_then_revoke(*args, **kwargs):
            fx.custody.revoke(
                fx.certificate.digest, kind="certificate",
                reason="committed mid-decision", seed=fx.custody_seed,
                key_id=fx.custody_key)
            return original(*args, **kwargs)

        serving_mod.compose_guidance = compose_then_revoke
        gateway = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set(),
            control_plane=fx.control_plane)
        guidance = gateway.serve(
            _request(), repository_id="repo-1",
            execution_identity=fx.identity())
        record("D5_revocation_during_decision",
               {"decision": guidance.decision,
                "reason": guidance.reason_code,
                "served_revoked_text": any(
                    "do the thing" in s for s in guidance.helpful_next_checks)},
               {"decision": "abstain", "reason": "catalog_unavailable",
                "served_revoked_text": False})
    finally:
        serving_mod.compose_guidance = original
        fx.close()


for fn in (defect_identity_disable, defect_replay_across_replicas,
           defect_custody_rollback, defect_diamond, defect_revocation_race):
    with tempfile.TemporaryDirectory() as tmp:
        fn(Path(tmp))

print()
for name, r in RESULTS.items():
    state = "OPEN" if r["defect"] else "CLOSED"
    print(f"{state:6} {name}")
    print(f"       observed={r['observed']}")
    print(f"       expected={r['expected']}")
print()
print("open defects:", sum(1 for r in RESULTS.values() if r["defect"]))
