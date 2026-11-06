#!/usr/bin/env python3
"""Deterministic governed self-improvement campaign (SIS v3.3, M9).

End-to-end, no live model calls: a scripted agent stands in for Codex —
it writes the known-good source only when the task's convention keywords
appear in served guidance. This exercises the real machinery (verified
episodes -> memory induction -> skill evolution -> dev evaluation ->
holdout qualification -> governed serving -> revocation) with honest,
reproducible numbers. It is machinery evidence, NOT learning efficacy —
live campaigns supply that separately.

Usage: python3 tools/governed_campaign.py -o <evidence_dir>
Exit code: 0 when the pipeline reproduces its expected deterministic
outcome; 2 otherwise. Machine-readable evidence lands in <out>/.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sis.v3.authority_db import AuthorityDB
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.candidate_authority import (CandidateDecisionAuthority,
                                        CandidateEvidenceAuthority)
from sis.v3.candidates import CandidateRegistry
from sis.v3.contracts import (ExperienceRecordV1, GuidanceRequestV1,
                              GuidanceV1, ProcedureRecordV1,
                              TaskEnvelopeV1, canonical_digest)
from sis.v3.composition import compose_guidance
from sis.v3.evaluation import paired_summary
from sis.v3.evolution import (EvolutionBudget, SkillOptimizer,
                              DevEvalResult, append_step,
                              specialize_step)
from sis.v3.governed_eval import (EvaluationPartition,
                                  assert_partition_disjoint,
                                  preregister, run_candidate_probe,
                                  run_governed_evaluation,
                                  required_sample_size)
from sis.v3.memory import (MemoryStore, induce_candidate,
                           verify_experience_evidence)
from sis.v3.promotion import PromotionController, operator_token_digest
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.secure_guidance import StrictGuidanceGateway
from sis.v3.serving import GovernedServingGateway
from sis.v3.skill_package import export_bundle
from sis.v3.verifier import OutcomeVerifier
from tests.v3.authority_testkit import (TEST_TOKEN, drive, evaluator_keypair,
                                        issue_and_commit_grant,
                                        make_grant_authority, make_registry,
                                        register_repo, seed, signed_receipt)

# task: name, module, buggy source, convention statement, keyword the
# scripted agent needs to see in guidance, correct source, private test
TASKS = {
    "money": ("money.py",
              "def round_money(x):\n    return round(float(x), 2)\n",
              "round_money must use ROUND_HALF_UP decimal rounding",
              "decimal",
              "from decimal import Decimal, ROUND_HALF_UP\n"
              "def round_money(x):\n    return str(Decimal(str(x)).quantize("
              "Decimal('0.01'), rounding=ROUND_HALF_UP))\n",
              "from money import round_money\n"
              "def test_round():\n"
              "    assert str(round_money('2.675')) == '2.68'\n"
              "    assert str(round_money('1.1')) == '1.10'\n"),
    "slug": ("slug.py",
             "def slugify(s):\n    return s.lower().replace(' ', '-')\n",
             "slugify must strip non-alphanumerics and hyphenate",
             "non-alphanumeric",
             "import re\ndef slugify(s):\n    s = re.sub(r'[^a-z0-9]+',"
             " '-', s.lower())\n    return s.strip('-')\n",
             "from slug import slugify\n"
             "def test_slug():\n"
             "    assert slugify('Hello, World!') == 'hello-world'\n"
             "    assert slugify('a  b') == 'a-b'\n"),
    "dedup": ("dedup.py",
              "def unique_stable(xs):\n    return sorted(set(xs))\n",
              "unique_stable must preserve first-occurrence order",
              "first occurrence",
              "def unique_stable(xs):\n    seen = set(); out = []\n"
              "    for x in xs:\n        if x not in seen:\n"
              "            seen.add(x); out.append(x)\n    return out\n",
              "from dedup import unique_stable\n"
              "def test_dedup():\n"
              "    assert unique_stable([3,1,3,2,1]) == [3,1,2]\n"),
    "clamp": ("clamp.py",
              "def clamp(v, lo, hi):\n    return max(lo, min(hi, v))\n",
              "clamp must swap bounds when lo > hi",
              "swap",
              "def clamp(v, lo, hi):\n    if lo > hi:\n        lo, hi = hi, lo\n"
              "    return max(lo, min(hi, v))\n",
              "from clamp import clamp\n"
              "def test_clamp():\n"
              "    assert clamp(5, 3, 0) == 3\n"
              "    assert clamp(2, 5, 1) == 2\n"),
    # Unseen-repository variants of the dev conventions. The convention
    # knowledge learned on the dev repos legitimately transfers; the
    # repository, task, module and tests are all new.
    "money2": ("pricing.py",
               "def format_price(x):\n    return f'{float(x):.2f}'\n",
               "format_price must use ROUND_HALF_UP decimal rounding",
               "decimal",
               "from decimal import Decimal, ROUND_HALF_UP\n"
               "def format_price(x):\n"
               "    return str(Decimal(str(x)).quantize("
               "Decimal('0.01'), rounding=ROUND_HALF_UP))\n",
               "from pricing import format_price\n"
               "def test_price():\n"
               "    assert format_price('2.675') == '2.68'\n"
               "    assert format_price('1.005') == '1.01'\n"),
    "slug2": ("permalink.py",
              "def permalink(title):\n    return title.lower()\n",
              "permalink must strip non-alphanumerics and hyphenate",
              "non-alphanumeric",
              "import re\n"
              "def permalink(title):\n"
              "    return re.sub(r'[^a-z0-9]+', '-', title.lower())"
              ".strip('-')\n",
              "from permalink import permalink\n"
              "def test_link():\n"
              "    assert permalink('Hi There!') == 'hi-there'\n"
              "    assert permalink('a & b') == 'a-b'\n"),
}
DEV_TASKS = ("money", "slug")
HOLDOUT_TASKS = ("money2", "slug2")


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def scripted_agent(ctx, *, tasks):
    """Deterministic agent: writes good source iff guidance carries the
    task's keyword; otherwise leaves the buggy source unchanged."""
    name = ctx.task.task_id.split("-", 1)[1]
    module, _, _, keyword, good, _ = tasks[name]
    text = " ".join(ctx.guidance.helpful_next_checks) \
        if ctx.guidance is not None else ""
    if keyword.lower() in text.lower():
        (ctx.workspace / module).write_text(good)
    return {"tokens_used": 120 + len(text) // 8, "tools_used": 3}


def build_task(name, root, statements, verifier, registry, reg_seed):
    mod, buggy, statement, keyword, good, test = TASKS[name]
    task_id = "task-" + name
    repo = root / "fixtures" / name
    repo.mkdir(parents=True)
    (repo / mod).write_text(buggy)
    repo_tree = tree_digest(repo)
    register_repo(registry, reg_seed, registry_id="eval-" + name,
                  base_tree_digest=repo_tree)
    verifier.register_task(
        actor_role="evaluator", task_id=task_id, criterion_version="v1",
        argv=(sys.executable, "-m", "pytest", "-q", "eval_tests.py"),
        files={"eval_tests.py": test.encode()}, base_commit="a1b2c3d",
        statement_digest=hashlib.sha256(statement.encode()).hexdigest())
    env = TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest=repo_tree, base_commit="a1b2c3d",
        task_statement_digest=hashlib.sha256(statement.encode()).hexdigest(),
        permitted_commands=("pytest",), isolation_profile="unverified_local",
        time_budget_seconds=120, token_budget=100_000, tool_budget=1000,
        actor_id="campaign", evaluator_task_ref=task_id)
    statements[task_id] = (statement, keyword)
    return env, repo, repo_tree


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", type=Path, required=True)
    args = ap.parse_args()
    out_dir = args.output
    out_dir.mkdir(parents=True, exist_ok=True)

    root = Path(tempfile.mkdtemp(prefix="sis-campaign-"))
    registry, reg_seed = make_registry()
    grants, grant_seed, grant_key = make_grant_authority(registry)
    eval_seed, eval_pub, eval_key = evaluator_keypair()
    db = AuthorityDB(root / "authority.db")
    controller = PromotionController(
        db, operator_token_digest=operator_token_digest(TEST_TOKEN),
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    executor = LocalSubprocessExecutor(root / "exec")
    verifier = OutcomeVerifier(executor=executor,
                               key_dir=root / "eval-keys",
                               registry_dir=root / "eval-reg")

    def authenticated_receipt(digest):
        receipt = verifier.load_receipt(digest)
        if not verifier.verify_receipt(receipt):
            raise ValueError("receipt_signature_invalid")
        return receipt

    statements: dict = {}
    dev = [build_task(n, root, statements, verifier, registry, reg_seed)
           for n in DEV_TASKS]
    holdout = [build_task(n, root, statements, verifier, registry, reg_seed)
               for n in HOLDOUT_TASKS]
    partition = EvaluationPartition(
        induction=tuple(e for e, _, _ in dev),
        development=tuple(e for e, _, _ in dev),
        holdout=tuple(e for e, _, _ in holdout))
    assert_partition_disjoint(partition)

    protocol = preregister(
        primary_metric="paired solved_delta E vs A",
        method="mcnemar_exact",
        alpha=0.05, min_effect=1.0,
        sample_size=required_sample_size(0.7, 0.3),
        budget={"wall_seconds": 120, "token_budget": 100_000,
                "tool_budget": 1000})

    # Qualification needs three independent signatures: the evaluator
    # receipt, the evaluator's evidence binding to the exact candidate,
    # and the operator's transition decision. Test-custody keys here.
    op_seed, op_pub, op_key = evaluator_keypair()
    evidence_authority = CandidateEvidenceAuthority(
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    decision_authority = CandidateDecisionAuthority(
        trusted_operator_keys={op_key: op_pub.hex()})
    candidates = CandidateRegistry(
        root / "candidates.db", receipt_authority=authenticated_receipt,
        evidence_authority=evidence_authority,
        decision_authority=decision_authority,
        expected_evaluation_protocol_digest=protocol["protocol_digest"])
    memory = MemoryStore(root / "memory.db")
    audit_log: list[dict] = []

    harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")
    budget = BudgetCaps(wall_seconds=120, token_budget=100_000,
                        tool_budget=1000)

    # ---- phase 1: baseline induction episodes on dev tasks ------------- #
    base_report = harness.run(
        [(e, r) for e, r, _ in dev],
        lambda ctx: scripted_agent(ctx, tasks=TASKS),
        budget=budget, arms=("A",))
    episodes = []
    for entry in base_report["per_task"]:
        arm = entry["arms"]["A"]
        # The harness already issued a signed receipt for this arm; reuse
        # it rather than re-evaluating the identical submission tree.
        if not arm.get("receipt_digest"):
            continue
        receipt = verifier.load_receipt(arm["receipt_digest"])
        task_id = entry["task_id"]
        name = task_id.split("-", 1)[1]
        statement, keyword = statements[task_id]
        rec = ExperienceRecordV1(
            schema_version=1,
            experience_id="exp-" + name,
            episode_id="ep-" + name,
            repository_registry_id="eval-" + name,
            task_fingerprint=hashlib.sha256(
                (task_id + statement).encode()).hexdigest(),
            task_category=name,
            agent_config_digest=canonical_digest("agent_cfg", 1,
                                                 {"agent": "scripted"}),
            trace_digest=hashlib.sha256(
                ("trace:" + task_id).encode()).hexdigest(),
            outcome_receipt_digest=receipt.digest,
            outcome=receipt.outcome,
            failure_category="convention_unknown"
            if receipt.outcome != "pass" else None,
            lesson=("Project convention for " + name + ": " + statement),
            facts=("baseline arm failed without convention guidance",)
            if receipt.outcome != "pass" else ("baseline arm passed",),
            hypotheses=("convention guidance prevents this failure class",)
            if receipt.outcome != "pass" else (),
            applicability=({"kind": "language_is", "value": "python"},),
            counterexamples=(),
            provenance={"generator": "campaign-induction",
                        "method": "deterministic"},
            captured_at=_utcnow())
        memory.ingest(
            rec, evidence_check=lambda r: verify_experience_evidence(r, verifier))
        episodes.append(rec)

    # ---- phase 2: candidates (memory + evolved skills + procedure) ----- #
    mem_candidates = []
    for rec in episodes:
        # Family scope: the lesson may transfer to sibling repositories
        # in the same trusted family — registry_id scope would confine
        # it to the originating repo and could never serve holdouts.
        cand = induce_candidate(
            rec, repository_scope={"kind": "family_id", "value": "fam-a"})
        candidates.submit(cand, actor_role="learner")
        candidates.transition(cand.candidate_id, "validated",
                              actor_role="learner")
        mem_candidates.append(cand)

    def dev_eval(candidate, tasks):
        # Deterministic dev check: does the skill mention any needed
        # convention keyword for the dev task family?
        text = " ".join(candidate.payload.get("steps", ())).lower()
        needed = [TASKS[n][3].lower() for n in DEV_TASKS]
        hits = sum(1 for k in needed if k in text)
        return DevEvalResult(
            tasks=len(needed), solved=hits,
            regressions=0 if hits else 1,
            tokens=500, tool_calls=2, wall_seconds=1,
            receipt_refs=())

    optimizer = SkillOptimizer(
        evaluator=type("C", (), {"evaluate": staticmethod(dev_eval)}),
        mutators=(
            append_step("Use decimal rounding conventions (ROUND_HALF_UP)."),
            append_step("Slugify: lowercase, strip non-alphanumeric, hyphenate."),
            append_step("Preserve first occurrence order when deduplicating."),
            specialize_step(0, " per project convention."),
        ),
        budget=EvolutionBudget(max_iterations=2, max_evaluations=16,
                               frontier_size=3),
        registry_submit=lambda c: candidates.submit(c, actor_role="learner"))
    frontier = optimizer.optimize(
        [{"title": "base-skill", "steps": ["Follow project conventions."]}],
        [e for e, _, _ in dev],
        target_task_family="convention-fix",
        repository_scope={"kind": "family_id", "value": "fam-a"})
    skill_candidates = [e.candidate for e in frontier]
    for cand in skill_candidates:
        candidates.transition(cand.candidate_id, "validated",
                              actor_role="learner")

    # Symbolic procedure for one convention (qualified via real decisions)
    sig = "sig-money"
    proc = ProcedureRecordV1(
        schema_version=1, procedure_id="strat-money", revision=1,
        intent="Money rounding convention", language="python",
        frameworks=(), task_signatures=(), failure_signatures=(sig,),
        preconditions=({"kind": "language_is", "value": "python"},
                       {"kind": "failure_signature_is", "value": sig}),
        contraindications=(),
        steps=("Use decimal.Decimal with ROUND_HALF_UP for money.",),
        required_verification=("task acceptance suite",),
        counterexample_refs=(), evidence_refs=("1" * 64,),
        outcome_distribution={"tasks": 1, "successes": 1, "failures": 0,
                              "regressions": 0},
        status="candidate", expires_at=None)
    seed(db, proc)
    receipt_src = signed_receipt(eval_seed, eval_key, task_id="t-src",
                                 repo_digest="f" * 64)
    receipt_money = signed_receipt(eval_seed, eval_key, task_id="r-money",
                                   repo_digest=dev[0][2])
    receipts = {receipt_src.digest: receipt_src,
                receipt_money.digest: receipt_money}
    controller._resolve_receipt = receipts.__getitem__
    register_repo(registry, reg_seed, registry_id="repo-src",
                  base_tree_digest="f" * 64)
    drive(db, controller, proc.procedure_id, "qualified",
          token=TEST_TOKEN, seed=eval_seed, key_id=eval_key,
          receipts=[receipt_money])
    issue_and_commit_grant(
        db, controller, grants, record=db.get(proc.procedure_id),
        source_registry_id="repo-src", target_family_id="fam-a",
        seed=grant_seed, key_id=grant_key,
        evidence_receipts=(receipt_src, receipt_money),
        grant_nonce="g-money")
    strict = StrictGuidanceGateway(
        db, controller, repository_registry=registry,
        grant_authority=grants)
    gateway = GovernedServingGateway(
        candidates, repository_registry=registry, strict_gateway=strict,
        audit_sink=audit_log.append,
        receipt_authority=authenticated_receipt)

    # ---- phase 3: qualify candidates on holdout evidence --------------- #
    # Evaluate candidates on holdout via the harness arms, then qualify
    # only those with positive signed evidence.
    def guidance_for(env, arm):
        if arm == "A":
            return None
        request = GuidanceRequestV1(
            schema_version=1, task_id=env.task_id,
            repo_snapshot_digest=env.repo_snapshot_digest,
            base_commit=env.base_commit, namespace="ns",
            language="python", toolchain="pytest", lockfile_digests={},
            task_summary=statements[env.task_id][0],
            failure_signatures=(env.task_id.split("-", 1)[1],),
            present_symbols=(), semantic_contract_digest="c" * 64)
        if arm == "D":
            return strict.recommend(request, repository_id="eval-" +
                                    env.task_id.split("-", 1)[1])
        # B/C/E: measurement-run serving of the candidate pools under
        # evaluation; governed serving (qualified-only) is demonstrated
        # in phase 4 after the qualification decisions land.
        pool = []
        if arm in {"B", "E"}:
            pool += mem_candidates
        if arm in {"C", "E"}:
            pool += skill_candidates
        # Merge through the real composition policy — dedup, precedence,
        # budget — the same merge governed serving would produce.
        composed = compose_guidance(pool, token_budget=600, max_steps=12)
        served_map[(env.task_id, arm)] = bool(composed.steps)
        return _measure_guidance(composed) if composed.steps else None

    def _measure_guidance(composed):
        return GuidanceV1(
            schema_version=1, decision="recommend",
            procedure_ids=("measure",), revision="0" * 64,
            matched_preconditions=(
                {"kind": "language_is", "value": "python"},),
            contraindications=(), evidence_ids=("0" * 64,),
            policy_digest="0" * 64,
            helpful_next_checks=tuple(composed.steps)[:8],
            reason_code=None, approximate_tokens=200)

    served_map: dict = {}
    eval_report = run_governed_evaluation(
        harness, [(e, r) for e, r, _ in holdout],
        lambda ctx: scripted_agent(ctx, tasks=TASKS),
        budget=budget,
        context_provider=lambda t, a: guidance_for(t, a),
        protocol=protocol,
        learned_repo_digests=[d[2] for d in dev],
        served_map=served_map,
        arms=("A", "B", "C", "D", "E"))

    # Qualification evidence must name the candidate it qualifies. The
    # five-arm holdout receipts are collective (a pool was served), so
    # each candidate gets its own sealed-holdout probe: guidance composed
    # from that candidate alone, scored by the same independent verifier
    # under the same disjointness and protocol-conformance gates.
    candidate_by_id = {c.candidate_id: c
                       for c in mem_candidates + skill_candidates}
    qualified = []
    qualification_evidence = []
    for cand in mem_candidates + skill_candidates:
        candidates.transition(cand.candidate_id, "evaluating",
                              actor_role="evaluator")
        composed = compose_guidance([cand], token_budget=600, max_steps=12)
        if not composed.steps:
            qualification_evidence.append({
                "candidate_id": cand.candidate_id,
                "status": "no_guidance"})
            continue
        guidance = _measure_guidance(composed)
        probe = run_candidate_probe(
            harness, [(e, r) for e, r, _ in holdout],
            lambda ctx: scripted_agent(ctx, tasks=TASKS),
            budget=budget, protocol=protocol,
            learned_repo_digests=[d[2] for d in dev],
            context_provider=lambda t, a, g=guidance: g)
        conformance = probe["governed"]["conformance"]
        pass_receipts = []
        for entry in probe["per_task"]:
            arm = (entry.get("arms") or {}).get("E") or {}
            digest = arm.get("receipt_digest")
            if digest and arm.get("outcome") == "pass":
                pass_receipts.append(verifier.load_receipt(digest))
        if not pass_receipts:
            qualification_evidence.append({
                "candidate_id": cand.candidate_id,
                "status": "no_candidate_pass_evidence",
                "probe_conformance": conformance})
            continue
        receipt_refs = tuple(dict.fromkeys(r.digest for r in pass_receipts))
        evidence = evidence_authority.issue(
            seed=eval_seed, candidate=cand, receipt_refs=receipt_refs,
            evaluation_protocol_digest=protocol["protocol_digest"],
            partition="holdout", evaluator_identity="campaign-evaluator",
            signer_key_id=eval_key)
        decision = decision_authority.issue(
            seed=op_seed, candidate=cand, from_state="evaluating",
            to_state="qualified", actor_identity="campaign-operator",
            receipt_refs=receipt_refs, evidence_refs=(evidence.digest,),
            signer_key_id=op_key)
        candidates.qualify(
            cand.candidate_id, actor_role="operator",
            actor_identity="campaign-operator", receipt_refs=receipt_refs,
            evidence_refs=(evidence.digest,), decision_ref=decision.digest,
            note="candidate-specific holdout evidence")
        qualified.append(cand.candidate_id)
        qualification_evidence.append({
            "candidate_id": cand.candidate_id, "status": "qualified",
            "receipt_refs": list(receipt_refs),
            "evidence_digest": evidence.digest,
            "decision_digest": decision.digest,
            "probe_conformance": conformance})
    if not qualified:
        raise SystemExit(
            "no candidate had its own verified holdout pass evidence; "
            "refusing qualification")

    # ---- phase 4: governed serving + revocation demonstration ---------- #
    served = []
    for env, _, _ in holdout:
        req = GuidanceRequestV1(
            schema_version=1, task_id=env.task_id,
            repo_snapshot_digest=env.repo_snapshot_digest,
            base_commit=env.base_commit, namespace="ns",
            language="python", toolchain="pytest", lockfile_digests={},
            task_summary=statements[env.task_id][0],
            failure_signatures=(env.task_id.split("-", 1)[1],),
            present_symbols=(), semantic_contract_digest="c" * 64)
        g = gateway.serve(req, repository_id="eval-" +
                          env.task_id.split("-", 1)[1])
        entry = next((e for e in eval_report["per_task"]
                      if e["task_id"] == env.task_id), {})
        arm_e = (entry.get("arms") or {}).get("E") or {}
        if arm_e.get("receipt_digest") and arm_e.get("outcome"):
            gateway.record_outcome(
                task_id=env.task_id, served_digest=g.digest,
                receipt_digest=arm_e["receipt_digest"],
                outcome=arm_e["outcome"])
        served.append({"task_id": env.task_id, "decision": g.decision,
                       "checks": list(g.helpful_next_checks),
                       "outcome_receipt": arm_e.get("receipt_digest")})
    revoked = qualified[0] if qualified else None
    revoke_decision = None
    if revoked:
        revoke_decision = decision_authority.issue(
            seed=op_seed, candidate=candidate_by_id[revoked],
            from_state="qualified", to_state="revoked",
            actor_identity="campaign-operator", signer_key_id=op_key)
        candidates.revoke(revoked, actor_role="operator",
                          actor_identity="campaign-operator",
                          decision_ref=revoke_decision.digest,
                          note="demonstration revocation")
        req = GuidanceRequestV1(
            schema_version=1, task_id=holdout[0][0].task_id,
            repo_snapshot_digest=holdout[0][2],
            base_commit="a1b2c3d", namespace="ns", language="python",
            toolchain="pytest", lockfile_digests={},
            task_summary=statements[holdout[0][0].task_id][0],
            failure_signatures=(holdout[0][0].task_id.split("-", 1)[1],),
            present_symbols=(), semantic_contract_digest="c" * 64)
        post = gateway.serve(req, repository_id="eval-" +
                             holdout[0][0].task_id.split("-", 1)[1])
        served_post = {"task_id": holdout[0][0].task_id,
                       "decision": post.decision,
                       "checks": list(post.helpful_next_checks)}
    else:
        served_post = None

    bundle_dir = None
    if skill_candidates:
        bundle_dir = export_bundle(
            skill_candidates[0], out_dir / "skill-bundle",
            qualification_status="qualified")

    # ---- evidence ------------------------------------------------------ #
    evidence = {
        "schema_version": 1,
        "kind": "governed_campaign",
        "generated_at": _utcnow(),
        "protocol": protocol,
        "baseline_report_digest": report_digest(base_report),
        "evaluation": {
            "report_digest": report_digest(eval_report),
            "solved_counts": eval_report["solved_counts"],
            "governed_metrics": eval_report["governed"]["metrics"],
            "paired": eval_report["paired"],
        },
        "registry": {
            "qualified": qualified,
            "revoked": [revoked] if revoked else [],
            "qualification_evidence": qualification_evidence,
            "revocation_decision": (revoke_decision.digest
                                    if revoke_decision else None),
            "verify": candidates.verify(),
            "audit": candidates.audit(),
        },
        "served": served,
        "served_after_revocation": served_post,
        "serving_audit": audit_log,
        "skill_bundle": str(bundle_dir) if bundle_dir else None,
        "status_note": ("deterministic scripted agent — machinery "
                        "evidence only, not live efficacy"),
    }
    (out_dir / "campaign_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True))
    summary = paired_summary(eval_report, baseline_arm="A",
                             treatment_arm="E") \
        if "E" in eval_report["solved_counts"] else None
    print(json.dumps({
        "digest": evidence["evaluation"]["report_digest"],
        "solved": eval_report["solved_counts"],
        "qualified": len(qualified),
        "contrast": summary["contrast"] if summary else None,
    }, indent=2))
    ok = bool(qualified) and served_post is not None
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
