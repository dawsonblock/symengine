#!/usr/bin/env python3
"""Five-arm learning qualification: demo machinery or real-agent gate.

The demo path runs the real five-arm harness, real signed receipts and
the real statistics on a tiny scripted task set. It is explicitly
labelled DEMONSTRATION and never claims learning efficacy.

The real path requires the Codex CLI to be installed and authenticated.
If it is not, the tool writes a BLOCKED_REAL_AGENT report and exits 2;
it never substitutes a scripted run for a confirmatory one. A powered
real run additionally requires a task manifest with repository paths,
prompts, evaluator-owned acceptance tests and a preregistered protocol;
the library interface is :class:`sis.v3.learning_qualification.FiveArmCampaign`
and :class:`sis.v3.learning_qualification.CodexCliAgent`.

Usage:
    python3 tools/five_arm_campaign.py --demo -o evidence/evaluation/demo.json
    python3 tools/five_arm_campaign.py --real-agent --manifest tasks.json \
        -o evidence/evaluation/real.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.contracts import GuidanceV1, TaskEnvelopeV1  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.governed_eval import GOVERNED_ARMS, preregister  # noqa: E402
from sis.v3.learning_qualification import (  # noqa: E402
    FiveArmCampaign, build_context_provider, codex_agent_status,
    write_report)
from sis.v3.runner import (LocalSubprocessExecutor, ResourceLimits,  # noqa: E402
                           tree_digest)
from sis.v3.verifier import OutcomeVerifier  # noqa: E402

PY = sys.executable


def _guidance(text="WRITE_OK"):
    return GuidanceV1(
        schema_version=1, decision="recommend", procedure_ids=("p",),
        revision="0" * 64,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64, helpful_next_checks=(text,),
        reason_code=None, approximate_tokens=20)


def _scripted_agent(ctx):
    text = " ".join(ctx.guidance.helpful_next_checks) \
        if ctx.guidance is not None else ""
    if "WRITE_OK" in text:
        (ctx.workspace / "solution.py").write_text("OK = 1\n")
    return {"tokens_used": 10, "tools_used": 1}


def _build_demo(root: Path):
    repo = root / "repo"
    repo.mkdir()
    (repo / "solution.py").write_text("NO = 1\n")
    profile = EvaluationRuntimeProfile(
        cpu_seconds=60, wall_seconds=120, process_count=None)
    verifier = OutcomeVerifier(
        executor=LocalSubprocessExecutor(
            root / "exec",
            protected_paths=(root / "keys", root / "registry")),
        key_dir=root / "keys", registry_dir=root / "registry",
        limits=ResourceLimits(wall_seconds=120, cpu_seconds=60,
                              memory_bytes=profile.task_memory_bytes,
                              process_count=None),
        runtime_profile=profile)
    tasks = []
    for index in range(2):
        task_id = f"demo-task-{index}"
        verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1",
            argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
            files={"eval_tests.py":
                   b"from pathlib import Path\n\n"
                   b"def test_solution():\n"
                   b"    assert 'OK' in Path('solution.py').read_text()\n"},
            base_commit="abc1234")
        tasks.append((TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(repo),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(
                task_id.encode()).hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=120, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref=task_id), repo))
    return verifier, tasks, profile


def run_demo(output: Path) -> int:
    with tempfile.TemporaryDirectory(prefix="sis-five-arm-demo-") as temp:
        root = Path(temp)
        verifier, tasks, profile = _build_demo(root)
        protocol = preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=len(tasks),
            budget={"wall_seconds": 120, "token_budget": 1000,
                    "tool_budget": 100},
            arms=GOVERNED_ARMS)
        served: dict = {}
        provider = build_context_provider(
            {"A": None, "B": _guidance(), "C": _guidance(),
             "D": _guidance(), "E": _guidance()}, served)
        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=verifier, work_root=root / "work"),
            tasks=tasks, agent=_scripted_agent,
            budget=BudgetCaps(wall_seconds=120, token_budget=1000,
                              tool_budget=100),
            protocol=protocol, context_provider=provider,
            served_map=served, learned_repo_digests=(), real_agent=False)
        report = campaign.run()
        report["kind"] = "five_arm_learning_qualification_demo"
        report["evidence"] = (
            "scripted demonstration; machinery evidence only, not a claim "
            "about real coding-agent efficacy")
        report["evaluator_runtime"] = profile.as_dict()
        report["evaluator_runtime_digest"] = profile.digest
        report["bootstrap"] = verifier.bootstrap().as_dict()
        report["codex_gate"] = codex_agent_status()
        report["receipts_issued"] = len(verifier.issued_receipts())
        write_report(report, output)
        analysis = report["learning_qualification"]
        print(json.dumps({
            "kind": report["kind"],
            "evidence_class": analysis["evidence_class"],
            "release_gate": analysis["release_gate"],
            "tasks": analysis["tasks"],
            "decisive_contrast": analysis["decisive_contrast"],
            "output": str(output),
        }, indent=2))
        return 0 if analysis["evidence_class"] == "demonstration" else 1


def run_real(output: Path, manifest_path: Path | None) -> int:
    status = codex_agent_status()
    report = {
        "schema_version": 1,
        "kind": "five_arm_learning_qualification_real_gate",
        "codex_gate": status,
        "evidence_class": "invalid",
        "release_gate": "BLOCKED_REAL_AGENT",
        "note": (
            "A confirmatory real-agent campaign was not run in this "
            "environment. The working interfaces are CodexCliAgent and "
            "FiveArmCampaign; a manifest and an authenticated agent are "
            "required. No scripted run is substituted."),
    }
    if not status["available"] or not status["authenticated"]:
        write_report(report, output)
        print(json.dumps(report, indent=2))
        return 2
    if manifest_path is None:
        report["release_gate"] = "BLOCKED_MANIFEST"
        report["note"] = (
            "Codex is available, but no task manifest was supplied. The "
            "manifest must provide repository paths, prompts, evaluator "
            "acceptance tests, base commits and a preregistered protocol.")
        write_report(report, output)
        print(json.dumps(report, indent=2))
        return 2
    report["release_gate"] = "BLOCKED_REAL_RUN_NOT_EXECUTED"
    report["note"] = (
        "A manifest was supplied, but this release did not execute a "
        "powered real-agent run. Run the documented campaign procedure "
        "with evaluator custody before claiming efficacy.")
    write_report(report, output)
    print(json.dumps(report, indent=2))
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--real-agent", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    args = parser.parse_args()
    if args.demo and args.real_agent:
        parser.error("choose --demo or --real-agent")
    if args.real_agent:
        return run_real(args.output, args.manifest)
    return run_demo(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
