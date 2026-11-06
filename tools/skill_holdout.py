#!/usr/bin/env python3
"""Qualify imported skills through real holdout probes (worked examples).

This is the template for turning an ingested skill into served guidance.
For each example it runs the whole governed path:

    ingest (learner) -> evaluating (evaluator)
        -> holdout probe with only this skill's guidance (arm E)
        -> no-guidance baseline (arm A)
        -> CandidateEvidenceV1 (evaluator) + CandidateDecisionV1 (operator)
        -> qualified -> GovernedServingGateway -> recorded outcome

Examples live in ``tools/skill_holdouts.py`` (``--list`` shows the
registry, planned tiers and exclusions); registered today:

- ``write-skills``: the fixture asks for a skill file; the evaluator's
  private test asserts the artifact the skill prescribes (frontmatter
  ``name``/``description``, a heading and a bullet step).
- ``php2shell-check``: the fixture is a Dockerfile on a vulnerable,
  floating PHP tag; the private test asserts a pinned fixed tag and a
  findings file naming the CVE.
- ``write-tests``: the private test requires the submitted suite to pass
  on the original module and fail on a mutated implementation.

The acceptance tests live with the evaluator (registered with the
verifier) and are never placed in the served repository. The agent is a
deterministic stand-in that writes the prescribed artifact only when the
served guidance contains the skill's keyword, so the A/E contrast shows
that guidance made the difference — it is machinery evidence, not a claim
about real-agent efficacy.

Keys are test custody, generated per run. Replace them with the
deployment's evaluator/operator custody before trusting any of this.

This is the v3 candidate holdout template. The older ``sis.skill_holdout``
module and ``tools/demo_skill_holdout.py`` implement the v2 HMAC-sealed
procedural-skill holdouts and are unrelated to it.

Usage:
    python3 tools/skill_holdout.py \
        --skills-root ../skills/skills-main/skills \
        --skills-root "../skills/vskill-main 2/plugins" \
        -o evidence/skills/holdout.json
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
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.candidate_authority import (CandidateDecisionAuthority,  # noqa: E402
                                        CandidateEvidenceAuthority)
from sis.v3.candidates import CandidateError, CandidateRegistry  # noqa: E402
from sis.v3.composition import compose_guidance  # noqa: E402
from sis.v3.contracts import (ContractError, GuidanceRequestV1,  # noqa: E402
                              GuidanceV1, TaskEnvelopeV1)
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.governed_eval import preregister, run_candidate_probe  # noqa: E402
from sis.v3.runner import (LocalSubprocessExecutor,  # noqa: E402
                           ResourceLimits, tree_digest)
from sis.v3.serving import GovernedServingGateway  # noqa: E402
from sis.v3.skill_ingest import (SkillIngestError, discover_skills,  # noqa: E402
                                 ingest_skill, read_skill_name)
from sis.v3.verifier import OutcomeVerifier  # noqa: E402
from tests.v3.authority_testkit import (evaluator_keypair,  # noqa: E402
                                        make_registry, register_repo)

FAMILY = "skill-holdout"
OPERATOR = "skill-holdout-operator"
EVALUATOR = "skill-holdout-evaluator"
BASE_COMMIT = "a1b2c3d"


from skill_holdouts import (EXCLUDED, PLANNED, Holdout,  # noqa: E402
                            describe, select)


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _guidance(candidate):
    composed = compose_guidance([candidate], token_budget=600, max_steps=12)
    if not composed.steps:
        return None
    return GuidanceV1(
        schema_version=1, decision="recommend",
        procedure_ids=("skill-holdout",), revision="0" * 64,
        matched_preconditions=(
            {"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64,
        helpful_next_checks=tuple(composed.steps)[:8],
        reason_code=None, approximate_tokens=200)


def _agent(holdout: Holdout):
    def run(ctx):
        text = " ".join(ctx.guidance.helpful_next_checks) \
            if ctx.guidance is not None else ""
        if holdout.keyword.lower() in text.lower():
            for relative, content in holdout.good.items():
                target = ctx.workspace / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
        return {"tokens_used": 120 + len(text) // 8, "tools_used": 3}
    return run


def _family(holdout: Holdout) -> str:
    """One scope per example: a serve must see only this skill."""
    return "holdout-" + holdout.skill


def _build_task(holdout: Holdout, root: Path, verifier, registry, seed):
    repo = root / "fixtures" / holdout.task_id
    repo.mkdir(parents=True)
    for relative, content in holdout.fixture.items():
        target = repo / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
    repo_tree = tree_digest(repo)
    register_repo(registry, seed, registry_id="repo-" + holdout.task_id,
                  family_id=_family(holdout), base_tree_digest=repo_tree)
    statement_digest = hashlib.sha256(holdout.statement.encode()).hexdigest()
    verifier.register_task(
        actor_role="evaluator", task_id=holdout.task_id,
        criterion_version="v1",
        argv=(sys.executable, "-m", "pytest", "-q", "eval_tests.py"),
        files={"eval_tests.py": holdout.test.encode()},
        base_commit=BASE_COMMIT, statement_digest=statement_digest)
    env = TaskEnvelopeV1(
        schema_version=1, task_id=holdout.task_id,
        repo_snapshot_digest=repo_tree, base_commit=BASE_COMMIT,
        task_statement_digest=statement_digest,
        permitted_commands=("pytest",), isolation_profile="unverified_local",
        time_budget_seconds=120, token_budget=100_000, tool_budget=1000,
        actor_id="skill-holdout", evaluator_task_ref=holdout.task_id)
    return env, repo


def _request(env: TaskEnvelopeV1) -> GuidanceRequestV1:
    return GuidanceRequestV1(
        schema_version=1, task_id=env.task_id,
        repo_snapshot_digest=env.repo_snapshot_digest,
        base_commit=env.base_commit, namespace="ns", language="python",
        toolchain="pytest", lockfile_digests={},
        task_summary="follow the served skill",
        failure_signatures=("skill-holdout",), present_symbols=(),
        semantic_contract_digest="c" * 64)


def _skill_index(roots):
    """Index by directory name; parse frontmatter names only if needed."""
    by_dir: dict[str, Path] = {}
    paths: list[Path] = []
    for root in roots:
        for path in discover_skills(root):
            paths.append(path)
            by_dir.setdefault(path.name, path)
    return by_dir, paths


def _resolve(index, paths, name) -> Path | None:
    if name in index:
        return index[name]
    return next((path for path in paths
                 if read_skill_name(path) == name), None)


def _pass_receipts(report, arm, verifier) -> list:
    receipts = []
    for entry in report.get("per_task", []):
        result = (entry.get("arms") or {}).get(arm) or {}
        digest = result.get("receipt_digest")
        if digest and result.get("outcome") == "pass":
            receipts.append(verifier.load_receipt(digest))
    return receipts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skills-root", action="append", type=Path)
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--work", type=Path, default=None)
    parser.add_argument("--list", action="store_true",
                        help="print the registered/planned/excluded registry")
    parser.add_argument("--tier", choices=("A", "B"), default=None)
    parser.add_argument("--only", default=None)
    args = parser.parse_args()

    if args.list:
        print(json.dumps(describe(), indent=2, sort_keys=True))
        return 0
    selected = select(tier=args.tier, only=args.only)
    if not selected:
        if args.only in PLANNED:
            print(json.dumps({"error": "holdout_not_registered",
                              "skill": args.only,
                              "planned_tier": PLANNED[args.only]}))
        elif args.only in EXCLUDED:
            print(json.dumps({"error": "holdout_excluded",
                              "skill": args.only,
                              "reason": EXCLUDED[args.only]}))
        elif args.tier is not None:
            print(json.dumps({
                "error": "no_registered_holdouts_in_tier",
                "tier": args.tier,
                "planned": sorted(name for name, tier in PLANNED.items()
                                  if tier == args.tier)}))
        else:
            print(json.dumps({"error": "no_registered_holdouts_selected",
                              "tier": args.tier, "only": args.only}))
        return 2
    if not args.skills_root or args.output is None:
        parser.error("--skills-root and -o are required unless --list")

    root = args.work or Path(tempfile.mkdtemp(prefix="sis-skill-holdout-"))
    root.mkdir(parents=True, exist_ok=True)
    by_dir, paths = _skill_index(args.skills_root)
    resolved = {holdout.skill: _resolve(by_dir, paths, holdout.skill)
                for holdout in selected}
    missing = [name for name, path in resolved.items() if path is None]

    registry, reg_seed = make_registry()
    repo_registry, repo_seed = make_registry()
    eval_seed, eval_pub, eval_key = evaluator_keypair()
    op_seed, op_pub, op_key = evaluator_keypair()
    evidence_authority = CandidateEvidenceAuthority(
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    decision_authority = CandidateDecisionAuthority(
        trusted_operator_keys={op_key: op_pub.hex()})
    # The write-tests meta-test runs the submitted suite in a nested
    # process, which RLIMIT_NPROC=64 blocks on platforms that count every
    # process of the user (macOS). The limit is opt-out here only.
    runtime_profile = EvaluationRuntimeProfile(
        cpu_seconds=60, wall_seconds=120, process_count=None)
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(
            root / "exec",
            protected_paths=(root / "eval-keys", root / "eval-reg",
                             root / "candidates.db", root / "memory.db")),
        key_dir=root / "eval-keys", registry_dir=root / "eval-reg",
        limits=ResourceLimits(wall_seconds=120, cpu_seconds=60,
                              memory_bytes=runtime_profile.task_memory_bytes,
                              process_count=None),
        runtime_profile=runtime_profile)

    def authenticated_receipt(digest):
        receipt = verifier.load_receipt(digest)
        if not verifier.verify_receipt(receipt):
            raise ValueError("receipt_signature_invalid")
        return receipt

    # The protocol is per candidate: each skill is probed on its own
    # holdout task, so a conforming probe runs exactly one task.
    protocol = preregister(
        primary_metric="skill holdout pass rate (E vs A)",
        method="mcnemar_exact", alpha=0.05, min_effect=1.0,
        sample_size=1,
        budget={"wall_seconds": 120, "token_budget": 100_000,
                "tool_budget": 1000})
    candidates = CandidateRegistry(
        root / "candidates.db", receipt_authority=authenticated_receipt,
        evidence_authority=evidence_authority,
        decision_authority=decision_authority,
        expected_evaluation_protocol_digest=protocol["protocol_digest"])
    harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")
    budget = BudgetCaps(wall_seconds=120, token_budget=100_000,
                        tool_budget=1000)
    serving_audit: list[dict] = []
    gateway = GovernedServingGateway(
        candidates, repository_registry=repo_registry,
        audit_sink=serving_audit.append,
        receipt_authority=authenticated_receipt)

    results = []
    for holdout in selected:
        entry = {"skill": holdout.skill, "task_id": holdout.task_id}
        skill_path = resolved[holdout.skill]
        if skill_path is None:
            entry.update(status="missing_skill")
            results.append(entry)
            continue
        try:
            env, repo = _build_task(holdout, root, verifier, registry,
                                    reg_seed)
            family = _family(holdout)
            register_repo(repo_registry, repo_seed,
                          registry_id="serve-" + holdout.task_id,
                          family_id=family)
            ingested = ingest_skill(
                skill_path, candidates,
                scope_kind="family_id", scope_value=family,
                target_task_family=family)
            entry.update(candidate_id=ingested["candidate_id"],
                         candidate_digest=ingested["digest"],
                         scan_findings=ingested["scan_findings"])
            candidates.transition(ingested["candidate_id"], "validated",
                                  actor_role="learner")
            candidates.transition(ingested["candidate_id"], "evaluating",
                                  actor_role="evaluator")
            candidate, _ = candidates.get(ingested["candidate_id"])
            guidance = _guidance(candidate)
            if guidance is None:
                entry.update(status="no_guidance")
                results.append(entry)
                continue
            probe_e = run_candidate_probe(
                harness, [(env, repo)], _agent(holdout), budget=budget,
                protocol=protocol, learned_repo_digests=[],
                context_provider=lambda t, a, g=guidance: g)
            probe_a = run_candidate_probe(
                harness, [(env, repo)], _agent(holdout), budget=budget,
                protocol=protocol, learned_repo_digests=[], arm="A",
                context_provider=lambda t, a: None)
            receipts = _pass_receipts(probe_e, "E", verifier)
            entry["probe"] = {
                "solved": {
                    "A": probe_a.get("solved_counts", {}).get("A", 0),
                    "E": probe_e.get("solved_counts", {}).get("E", 0)},
                "conformance": probe_e["governed"]["conformance"],
                "guidance_steps": list(guidance.helpful_next_checks)[:3],
            }
            if not receipts:
                entry.update(status="no_pass_evidence")
                results.append(entry)
                continue
            refs = tuple(dict.fromkeys(r.digest for r in receipts))
            evidence = evidence_authority.issue(
                seed=eval_seed, candidate=candidate, receipt_refs=refs,
                evaluation_protocol_digest=protocol["protocol_digest"],
                partition="holdout", evaluator_identity=EVALUATOR,
                signer_key_id=eval_key)
            decision = decision_authority.issue(
                seed=op_seed, candidate=candidate, from_state="evaluating",
                to_state="qualified", actor_identity=OPERATOR,
                receipt_refs=refs, evidence_refs=(evidence.digest,),
                signer_key_id=op_key)
            candidates.qualify(
                candidate.candidate_id, actor_role="operator",
                actor_identity=OPERATOR, receipt_refs=refs,
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest,
                note="skill holdout qualified")
            served = gateway.serve(
                _request(env),
                repository_id="serve-" + holdout.task_id)
            delivered = any(step in served.helpful_next_checks
                            for step in guidance.helpful_next_checks)
            gateway.record_outcome(
                task_id=env.task_id, served_digest=served.digest,
                receipt_digest=refs[0], outcome="pass")
            entry.update(
                status="qualified",
                state=candidates.state_of(candidate.candidate_id),
                receipt_refs=list(refs),
                evidence_digest=evidence.digest,
                decision_digest=decision.digest,
                served={
                    "decision": served.decision,
                    "reason_code": served.reason_code,
                    "checks": list(served.helpful_next_checks)[:4],
                    "delivered_skill_steps": delivered,
                })
        except (SkillIngestError, ContractError, CandidateError,
                ValueError) as exc:
            entry.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        results.append(entry)

    report = {
        "schema_version": 1,
        "kind": "skill_holdout",
        "generated_at": _utcnow(),
        "custody": "test-custody keys generated for this run; not production",
        "evidence": ("deterministic scripted agent; machinery evidence only, "
                     "not a claim about real-agent efficacy"),
        "protocol_digest": protocol["protocol_digest"],
        "evaluator_runtime": runtime_profile.as_dict(),
        "evaluator_runtime_digest": runtime_profile.digest,
        "keys": {"evaluator": eval_key, "operator": op_key},
        "skills_roots": [str(path) for path in args.skills_root],
        "selected": [h.skill for h in selected],
        "tier": args.tier,
        "only": args.only,
        "missing_skills": missing,
        "results": results,
        "serving_audit": serving_audit,
        "registry": {"verify": candidates.verify(),
                     "audit": candidates.audit()},
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "kind": report["kind"],
        "selected": report["selected"],
        "missing_skills": missing,
        "results": [{k: r.get(k) for k in
                     ("skill", "status", "candidate_id", "probe")}
                    for r in results],
        "registry_ok": report["registry"]["verify"]["ok"],
    }, indent=2))
    candidates.close()
    ok = (not missing and all(r.get("status") == "qualified"
                              for r in results)
          and report["registry"]["verify"]["ok"]
          and all(r["probe"]["solved"]["E"] > r["probe"]["solved"]["A"]
                  for r in results if "probe" in r))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
