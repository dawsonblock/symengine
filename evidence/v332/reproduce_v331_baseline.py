"""Executed v3.3.1 defect reproduction for the v3.3.2 plan (M0).

Copy this file into a pristine v3.3.1 checkout (for example
``tools/reproduce_v332_baseline.py``) and run it from that checkout root:

    PYTHONPATH=src:. python3 tools/reproduce_v332_baseline.py

It must be executed against v3.3.1 source; the v3.3.2 regression tests
cover the fixed behaviour.

Every check prints OBSERVED/EXPECTED. The v3.3.2 release is not
qualified unless these same checks pass in the fixed tree.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from sis.v3 import serving as serving_mod
from sis.v3.evidence_custody import EvidenceCustodyStore
from sis.v3.serving import GovernedServingGateway
from tests.v3.test_authority_checkpoints import _request
from tests.v3.test_execution_identity_custody import ProductionFixture

RESULTS = []


def record(name, observed, expected):
    RESULTS.append({"defect": name, "observed": observed,
                    "expected": expected,
                    "open": any(observed.get(k) != v for k, v in
                                expected.items())})


def d1_identity(root):
    fx = ProductionFixture(root)
    try:
        gateway = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            require_execution_identity=False, used_session_nonces=set())
        guidance = gateway.serve(_request(), repository_id="repo-1")
        record("D1_identity_disableable_in_production",
               {"decision": guidance.decision,
                "served_text": any("do the thing" in s
                                   for s in guidance.helpful_next_checks)},
               {"decision": "abstain", "served_text": False})
    finally:
        fx.close()


def d2_replay(root):
    fx = ProductionFixture(root)
    try:
        identity = fx.identity()
        first = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set()).serve(
                _request(), repository_id="repo-1",
                execution_identity=identity)
        second = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set()).serve(
                _request(), repository_id="repo-1",
                execution_identity=identity)
        record("D2_same_nonce_two_replicas",
               {"first": first.reason_code, "second": second.reason_code},
               {"first": "no_qualified_procedure",
                "second": "catalog_unavailable"})
    finally:
        fx.close()


def d3_rollback(root):
    fx = ProductionFixture(root)
    try:
        backup = root / "custody-backup"
        shutil.copytree(fx.custody.root, backup)
        fx.custody.revoke(
            fx.certificate.digest, kind="certificate",
            reason="evaluator error", seed=fx.custody_seed,
            key_id=fx.custody_key)
        shutil.rmtree(fx.custody.root)
        shutil.copytree(backup, fx.custody.root)
        restored = EvidenceCustodyStore(
            fx.custody.root,
            trusted_revocation_keys={
                fx.custody_key: fx.custody._keys[fx.custody_key]})
        try:
            mode = fx.registry.authority_status()["mode"]
        except Exception as exc:
            mode = f"rejected:{exc}"
        record("D3_revocation_history_rollback",
               {"after_restore": restored.status(fx.certificate.digest),
                "authority_gate": mode},
               {"after_restore": "revoked",
                "authority_gate": "rejected"})
    finally:
        fx.close()


def d4_diamond(root):
    custody = EvidenceCustodyStore(root / "diamond")
    leaf = custody.put({"leaf": "d"})
    left = custody.put({"node": "b"})
    right = custody.put({"node": "c"})
    top = custody.put({"node": "a"})
    custody.link(left, receipts=(leaf,))
    custody.link(right, receipts=(leaf,))
    custody.link(top, receipts=(left, right))
    record("D4_diamond_dependency_graph",
           {"status": custody.status(top)}, {"status": "active"})


def d5_ordering(root):
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
        guidance = GovernedServingGateway(
            fx.registry, repository_registry=fx.repo_registry,
            production=True,
            execution_identity_authority=fx.identity_authority,
            used_session_nonces=set()).serve(
                _request(), repository_id="repo-1",
                execution_identity=fx.identity())
        record("D5_revocation_during_decision",
               {"decision": guidance.decision,
                "served_text": any("do the thing" in s
                                   for s in guidance.helpful_next_checks)},
               {"decision": "abstain", "served_text": False})
    finally:
        serving_mod.compose_guidance = original
        fx.close()


for check in (d1_identity, d2_replay, d3_rollback, d4_diamond, d5_ordering):
    with tempfile.TemporaryDirectory() as tmp:
        check(Path(tmp))

print(json.dumps(RESULTS, indent=2, sort_keys=True))
print("open:", sum(1 for item in RESULTS if item["open"]))
