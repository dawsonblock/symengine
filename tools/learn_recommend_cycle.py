#!/usr/bin/env python3
"""One complete learn -> qualify -> recommend cycle with a real agent.

Sequence, all with real signatures and independent verification:

1. ``codex exec`` solves two same-class dev tasks; private acceptance tests
   are injected only at evaluation, so the agent never sees them.
2. The evaluator's signed pass receipts are the episode and transfer
   evidence. The failure class comes from the evaluator's task registry,
   not from this script.
3. ``experience_to_record`` derives a candidate procedure whose lesson is
   the verified convention and whose applicability is the *failure class*,
   not the dev task's own signature.
4. Signed promotion qualifies the procedure; a signed scope grant allows
   family transfer.
5. A sibling holdout task in the same failure class must receive
   ``decision="recommend"`` naming that procedure.
6. A holdout task in a different failure class must abstain — the
   over-generalization control.

Usage:
    python3 tools/learn_recommend_cycle.py -o evidence/qualification/learn_cycle.json
Exit 0 when the dev task passed and both serving decisions are the expected
ones. The with/without-guidance outcome contrast is recorded but not
required: one paired instance cannot establish efficacy, and a stochastic
agent may refuse or fail on either arm.

Both transfer witnesses are same-class dev runs and both are cited by the
qualified revision. The grant authority runs with
``require_cited_evidence=True``: a grant whose witnesses the revision does
not cite is rejected with ``evidence_not_cited_by_procedure``. The
registry still has no submission-identity concept, so each evaluated tree
is registered as a separate ``<repo>-evaluated`` identity rather than
overwriting the repository's base tree.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sis.v3.authority_db import AuthorityDB
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.contracts import GuidanceRequestV1, TaskEnvelopeV1
from sis.v3.learning.records import experience_to_record
from sis.v3.memory import (MemoryStore, issue_experience_record,
                           verify_experience_evidence)
from sis.v3.promotion import PromotionController, operator_token_digest
from sis.v3.runner import LocalSubprocessExecutor, tree_digest
from sis.v3.secure_guidance import StrictGuidanceGateway
from sis.v3.verifier import OutcomeVerifier
from tests.v3.authority_testkit import (TEST_TOKEN, drive, evaluator_keypair,
                                        issue_and_commit_grant,
                                        make_grant_authority, make_registry,
                                        register_repo, seed)

# The holdout prompt states the goal without the project convention; the
# convention is available only through served guidance. Without this, the
# prompt itself would leak the answer and the cycle would prove nothing.
TERSE = {
    "money3": "format_amount(x) must round a decimal amount to cents using "
              "the project's rounding convention.",
    "slug2": "permalink(title) must convert a title into the project's URL "
             "slug form.",
}

PROMPT = (
    "In the workspace there is a Python module {mod} and NO tests. "
    "Task: {statement} Edit the source so the described contract holds "
    "for all inputs. Follow the project's conventions. "
    "Do not create tests; do not ask questions.")

# name: module, buggy source, convention statement, private acceptance
# test, failure class, known-good source. The dev and sibling holdout share
# a class; the control holdout is a different class.
TASKS = {
    "money": (
        "money.py",
        "def round_money(x):\n    return round(float(x), 2)\n",
        "round_money must use ROUND_HALF_UP decimal rounding and return "
        "the cents string",
        "from money import round_money\n"
        "def test_round():\n"
        "    assert str(round_money('2.675')) == '2.68'\n"
        "    assert str(round_money('1.1')) == '1.10'\n",
        "convention_unknown:money",
        "from decimal import Decimal, ROUND_HALF_UP\n"
        "def round_money(x):\n"
        "    return str(Decimal(str(x)).quantize(Decimal('0.01'), "
        "rounding=ROUND_HALF_UP))\n"),
    "money2": (
        "pricing.py",
        "def format_price(x):\n    return f'{float(x):.2f}'\n",
        "format_price must use ROUND_HALF_UP decimal rounding and return "
        "the cents string",
        "from pricing import format_price\n"
        "def test_price():\n"
        "    assert format_price('2.675') == '2.68'\n"
        "    assert format_price('1.005') == '1.01'\n",
        "convention_unknown:money",
        "from decimal import Decimal, ROUND_HALF_UP\n"
        "def format_price(x):\n"
        "    return str(Decimal(str(x)).quantize(Decimal('0.01'), "
        "rounding=ROUND_HALF_UP))\n"),
    "money3": (
        "amount.py",
        "def format_amount(x):\n    return f'{float(x):.2f}'\n",
        "format_amount must use ROUND_HALF_UP decimal rounding and return "
        "the cents string",
        "from amount import format_amount\n"
        "def test_amount():\n"
        "    assert format_amount('2.675') == '2.68'\n"
        "    assert format_amount('1.005') == '1.01'\n",
        "convention_unknown:money",
        "from decimal import Decimal, ROUND_HALF_UP\n"
        "def format_amount(x):\n"
        "    return str(Decimal(str(x)).quantize(Decimal('0.01'), "
        "rounding=ROUND_HALF_UP))\n"),
    "slug2": (
        "permalink.py",
        "def permalink(title):\n    return title.lower()\n",
        "permalink must strip non-alphanumerics and hyphenate",
        "from permalink import permalink\n"
        "def test_link():\n"
        "    assert permalink('Hi There!') == 'hi-there'\n"
        "    assert permalink('a & b') == 'a-b'\n",
        "convention_unknown:slug",
        "import re\ndef permalink(title):\n"
        "    return re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')\n"),
}


def _utcnow() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z")


def codex_agent(ctx, *, tasks=TASKS):
    """Real coding agent: one `codex exec` turn in the arm workspace."""
    name = ctx.task.task_id.split("-", 1)[1]
    mod, _, statement, _, _, _ = tasks[name]
    prompt = PROMPT.format(mod=mod, statement=TERSE.get(name, statement))
    if ctx.guidance is not None and ctx.guidance.decision == "recommend":
        hints = "\n".join("- " + h for h in ctx.guidance.helpful_next_checks)
        prompt += "\n\nProject conventions (advisory):\n" + hints
    out = err = ""
    proc = subprocess.Popen(
        ["codex", "exec", "-C", str(ctx.workspace),
         "-s", "workspace-write", "--skip-git-repo-check", prompt],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        start_new_session=True)
    try:
        out, err = proc.communicate(
            timeout=max(5, int(ctx.budget.wall_seconds) - 15))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            out, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            pass
    (Path(ctx.workspace).parent /
     f"exec-log-{ctx.workspace.name}.log").write_text(
        (out or "") + "\n" + (err or ""))
    usage = {}
    lines = ((out or "") + "\n" + (err or "")).splitlines()
    marks = [i for i, line in enumerate(lines) if "tokens used" in line.lower()]
    if marks:
        for candidate in lines[marks[-1]:marks[-1] + 4]:
            digits = "".join(ch for ch in candidate if ch.isdigit())
            if digits:
                usage = {"tokens_used": int(digits)}
                break
    return usage


def scripted_agent(ctx, *, tasks=TASKS):
    """Offline plumbing check: a capable dev solver, a holdout that needs
    the convention. Dev tasks are written good unconditionally; the
    holdout is written good only when served guidance carries the
    convention. This is a wiring check, not an agent model."""
    name = ctx.task.task_id.split("-", 1)[1]
    text = " ".join(ctx.guidance.helpful_next_checks) \
        if ctx.guidance is not None else ""
    if name in {"money", "money2"} or "ROUND_HALF_UP" in text:
        (Path(ctx.workspace) / tasks[name][0]).write_text(tasks[name][5])
    return {"tokens_used": 100, "tools_used": 1}


def build_task(name, root, verifier, wall):
    mod, buggy, statement, test, _, _ = TASKS[name]
    task_id = "task-" + name
    repo = root / "fixtures" / name
    repo.mkdir(parents=True)
    (repo / mod).write_text(buggy)
    repo_tree = tree_digest(repo)
    # The envelope binds the statement the agent actually sees; the
    # convention may be withheld from the holdout prompt.
    visible_digest = hashlib.sha256(
        TERSE.get(name, statement).encode()).hexdigest()
    verifier.register_task(
        actor_role="evaluator", task_id=task_id, criterion_version="v1",
        argv=(sys.executable, "-m", "pytest", "-q", "eval_tests.py"),
        files={"eval_tests.py": test.encode()}, base_commit="a1b2c3d",
        statement_digest=visible_digest, failure_class=TASKS[name][4])
    env = TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest=repo_tree, base_commit="a1b2c3d",
        task_statement_digest=visible_digest,
        permitted_commands=("codex",), isolation_profile="unverified_local",
        time_budget_seconds=wall, token_budget=200_000, tool_budget=2_000,
        actor_id="learn-cycle", evaluator_task_ref=task_id)
    return env, repo, repo_tree, statement


def request_for(env, statement, failure_class):
    return GuidanceRequestV1(
        schema_version=1, task_id=env.task_id,
        repo_snapshot_digest=env.repo_snapshot_digest,
        base_commit=env.base_commit, namespace="ns", language="python",
        toolchain="pytest", lockfile_digests={}, task_summary=statement,
        failure_signatures=(failure_class,), present_symbols=(),
        semantic_contract_digest="c" * 64)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", type=Path, required=True)
    ap.add_argument("--wall", type=float, default=180,
                    help="per-turn wall budget seconds")
    ap.add_argument("--agent", choices=("codex", "scripted"), default="codex")
    args = ap.parse_args()
    wall = int(args.wall)

    root = Path(tempfile.mkdtemp(prefix="sis-learn-cycle-"))
    registry, reg_seed = make_registry()
    grants, grant_seed, grant_key = make_grant_authority(
        registry, require_cited_evidence=True)
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(root / "exec"),
        key_dir=root / "eval-keys", registry_dir=root / "eval-reg")
    # The promotion controller must trust the key that actually signed the
    # receipt, not a test key.
    eval_seed, eval_pub = verifier.keystore.load_or_create()
    eval_key = verifier.keystore.key_id
    db = AuthorityDB(root / "authority.db")
    controller = PromotionController(
        db, operator_token_digest=operator_token_digest(TEST_TOKEN),
        trusted_evaluator_keys={eval_key: eval_pub.hex()})
    harness = BenchmarkHarness(verifier=verifier, work_root=root / "work")
    budget = BudgetCaps(wall_seconds=wall, token_budget=200_000,
                        tool_budget=2_000)

    dev_env, dev_repo, dev_tree, dev_statement = build_task(
        "money", root, verifier, wall)
    ev_env, ev_repo, ev_tree, ev_statement = build_task(
        "money2", root, verifier, wall)
    sib_env, sib_repo, sib_tree, sib_statement = build_task(
        "money3", root, verifier, wall)
    ctl_env, ctl_repo, ctl_tree, ctl_statement = build_task(
        "slug2", root, verifier, wall)

    # ---- 1. real agent solves the dev tasks; evaluator verifies them ----- #
    agent = codex_agent if args.agent == "codex" else scripted_agent
    report = harness.run([(dev_env, dev_repo), (ev_env, ev_repo)],
                         lambda ctx: agent(ctx), budget=budget, arms=("A",))
    receipts = {}
    for entry in report["per_task"]:
        arm = entry["arms"]["A"]
        if not arm.get("receipt_digest"):
            raise SystemExit(f"{entry['task_id']} produced no verified receipt")
        receipts[entry["task_id"]] = verifier.load_receipt(arm["receipt_digest"])
    receipt = receipts["task-money"]
    second = receipts["task-money2"]
    execution_digest = verifier.execution_digest_for(receipt.digest)
    if receipt.outcome != "pass" or execution_digest is None:
        raise SystemExit(f"dev task did not pass: {receipt.outcome}")
    if second.outcome != "pass":
        raise SystemExit("second same-class dev task did not pass")

    # Repository base identities stay bound to their base trees. The trees
    # the evaluator actually scored get their own identities: the registry
    # has no submission-identity concept, and overwriting the base tree
    # would misstate the repository's identity.
    register_repo(registry, reg_seed, registry_id="eval-money",
                  base_tree_digest=dev_tree)
    register_repo(registry, reg_seed, registry_id="eval-money2",
                  base_tree_digest=ev_tree)
    register_repo(registry, reg_seed, registry_id="eval-money-evaluated",
                  base_tree_digest=receipt.evaluated_repo_digest)
    register_repo(registry, reg_seed, registry_id="eval-money2-evaluated",
                  base_tree_digest=second.evaluated_repo_digest)
    register_repo(registry, reg_seed, registry_id="eval-money3",
                  base_tree_digest=sib_tree)
    register_repo(registry, reg_seed, registry_id="eval-slug2",
                  base_tree_digest=ctl_tree)

    # ---- 2. verified episode -> candidate procedure ---------------------- #
    exp_seed, exp_pub, exp_key = evaluator_keypair()
    memory = MemoryStore(root / "memory.db",
                         trusted_signer_keys={exp_key: exp_pub.hex()},
                         chain_key=(exp_seed, exp_key))
    failure_class = verifier.failure_class_for("task-money")
    if failure_class is None:
        raise SystemExit("evaluator registry has no failure class for task-money")
    record = issue_experience_record(
        exp_seed, exp_key,
        experience_id="exp-money", episode_id="ep-money",
        repository_registry_id="eval-money",
        task_fingerprint=hashlib.sha256(
            ("task-money" + dev_statement).encode()).hexdigest(),
        task_category="money",
        agent_config_digest=hashlib.sha256(
            b"agent:codex-exec").hexdigest(),
        trace_digest=hashlib.sha256(
            ("trace:" + receipt.digest).encode()).hexdigest(),
        outcome_receipt_digest=receipt.digest, outcome=receipt.outcome,
        failure_category=failure_class,
        lesson=dev_statement,
        facts=("codex-exec solved the dev task without guidance",),
        hypotheses=(),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=(),
        provenance={"generator": "learn-cycle", "method": "codex-exec"},
        captured_at=_utcnow(), task_id=receipt.task_id,
        attempt_id=receipt.receipt_id,
        repo_snapshot_digest=receipt.evaluated_repo_digest,
        execution_receipt_digest=execution_digest)
    memory.ingest(
        record, evidence_check=lambda r: verify_experience_evidence(r, verifier))
    procedure = replace(
        experience_to_record(record, failure_class=failure_class),
        evidence_refs=(receipt.digest, second.digest))
    seed(db, procedure)

    # ---- 3. signed promotion + family scope grant ----------------------- #
    transfer = (receipt, second)
    controller._resolve_receipt = {r.digest: r for r in transfer}.__getitem__
    drive(db, controller, procedure.procedure_id, "qualified",
          token=TEST_TOKEN, seed=eval_seed, key_id=eval_key,
          receipts=[receipt])
    issue_and_commit_grant(
        db, controller, grants, record=db.get(procedure.procedure_id),
        source_registry_id="eval-money-evaluated", target_family_id="fam-a",
        seed=grant_seed, key_id=grant_key, evidence_receipts=transfer,
        grant_nonce="g-learn-cycle")
    strict = StrictGuidanceGateway(
        db, controller, repository_registry=registry, grant_authority=grants,
        procedure_owners={procedure.procedure_id: "eval-money-evaluated"})

    # ---- 4. same-class holdout must be recommended ---------------------- #
    sibling_class = verifier.failure_class_for("task-money3")
    control_class = verifier.failure_class_for("task-slug2")
    if sibling_class is None or control_class is None:
        raise SystemExit("evaluator registry is missing a failure class")
    sibling = strict.recommend(
        request_for(sib_env, sib_statement, sibling_class),
        repository_id="eval-money3")
    control = strict.recommend(
        request_for(ctl_env, ctl_statement, control_class),
        repository_id="eval-slug2")

    # ---- 5. same holdout with and without the learned guidance --------- #
    baseline_report = harness.run(
        [(sib_env, sib_repo)], lambda ctx: agent(ctx), budget=budget,
        arms=("A",))
    served_report = None
    if sibling.decision == "recommend":
        served_report = harness.run(
            [(sib_env, sib_repo)],
            lambda ctx: agent(ctx), budget=budget, arms=("A",),
            context_provider=lambda task, arm: sibling)

    def holdout_entry(report, env):
        arm = report["per_task"][0]["arms"]["A"]
        entry = {
            "outcome": arm.get("outcome"),
            "receipt_digest": arm.get("receipt_digest"),
            "report_digest": report_digest(report),
            "tokens_used": arm.get("tokens_used"),
        }
        if arm.get("receipt_digest"):
            evaluated = verifier.load_receipt(arm["receipt_digest"])
            entry["no_action"] = (
                evaluated.evaluated_repo_digest == env.repo_snapshot_digest)
        return entry

    evidence = {
        "schema_version": 1,
        "kind": "learn_recommend_cycle",
        "generated_at": _utcnow(),
        "agent": "codex-exec" if args.agent == "codex" else "scripted",
        "dev": {
            "task_id": dev_env.task_id,
            "outcome": receipt.outcome,
            "receipt_digest": receipt.digest,
            "report_digest": report_digest(report),
        },
        "transfer_evidence": [r.digest for r in transfer],
        "learned_procedure": {
            "procedure_id": procedure.procedure_id,
            "failure_class": failure_class,
            "steps": list(procedure.steps),
            "evidence_refs": list(procedure.evidence_refs),
            "status": db.get(procedure.procedure_id).status,
        },
        "same_class_holdout": {
            "task_id": sib_env.task_id,
            "decision": sibling.decision,
            "procedure_ids": list(sibling.procedure_ids),
            "reason_code": sibling.reason_code,
        },
        "cross_class_control": {
            "task_id": ctl_env.task_id,
            "decision": control.decision,
            "procedure_ids": list(control.procedure_ids),
            "reason_code": control.reason_code,
        },
        "baseline_holdout": holdout_entry(baseline_report, sib_env),
        "served_holdout": (holdout_entry(served_report, sib_env)
                           if served_report else None),
        "memory_chain_verified": memory.verify_chain(),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    logs = args.output.parent / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    for index, log in enumerate(sorted(root.rglob("exec-log-*.log"))):
        shutil.copy2(log, logs / f"{index:02d}-{log.name}")
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True))
    print(json.dumps({
        "dev_outcome": receipt.outcome,
        "same_class": sibling.decision,
        "cross_class": control.decision,
        "baseline_holdout": evidence["baseline_holdout"]["outcome"],
        "served_holdout": (evidence["served_holdout"] or {}).get("outcome"),
    }, indent=2))
    ok = (receipt.outcome == "pass"
          and sibling.decision == "recommend"
          and procedure.procedure_id in sibling.procedure_ids
          and control.decision == "abstain")
    shutil.rmtree(root, ignore_errors=True)
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
