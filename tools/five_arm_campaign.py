#!/usr/bin/env python3
"""Five-arm learning qualification: demo machinery or real-agent gate.

The demo path runs the real five-arm harness, real signed receipts and
the real statistics on a tiny scripted task set. It is explicitly
labelled DEMONSTRATION and never claims learning efficacy.

The real path requires the Codex CLI to be installed and authenticated.
If it is not, the tool writes a BLOCKED_REAL_AGENT report and exits 2;
it never substitutes a scripted run for a confirmatory one. A real run
requires a validated task manifest (repository paths, prompts,
evaluator-owned acceptance tests, base commits and a preregistered
protocol); the tool then executes the five arms with
:class:`sis.v3.learning_qualification.FiveArmCampaign` and
:class:`sis.v3.learning_qualification.CodexCliAgent` and writes the
paired report with per-arm receipt digests. Fixed guidance bundles are
frozen before the run and recorded in the report.

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
from collections.abc import Callable, Mapping
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.contracts import (  # noqa: E402
    GuidanceV1, TaskEnvelopeV1, canonical_digest)
from sis.v3.efficacy_manifest import validate_manifest  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.governed_eval import GOVERNED_ARMS, preregister  # noqa: E402
from sis.v3.learning_qualification import (  # noqa: E402
    CodexCliAgent, FiveArmCampaign, build_context_provider,
    codex_agent_status, write_report)
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
        allow_shared_custody=True,
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
            custody="shared",
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
        # Two scripted tasks exercise the plumbing, not a power claim:
        # the plan is registered as diagnostic so the demo report does
        # not pretend to be an underpowered experiment.
        protocol = preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=len(tasks), powered=False,
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


_COMPONENT_STEPS = {
    "B": ("Recall for {failure_class}: reproduce the failure, check empty, "
          "zero, negative and boundary inputs, and preserve the public API."),
    "C": ("Workflow for {failure_class}: read the task, locate the public "
          "symbol, make the smallest change, run a focused test, then check "
          "edge cases."),
    "D": ("Procedure for {failure_class}: compare expected with actual, "
          "change the smallest operator or constant, and verify two "
          "examples."),
}


def _fixed_guidance(failure_class: str, arm: str) -> GuidanceV1 | None:
    if arm == "A":
        return None
    steps = tuple(
        text.format(failure_class=failure_class)
        for source, text in _COMPONENT_STEPS.items()
        if source == arm or arm == "E")
    return GuidanceV1(
        schema_version=1, decision="recommend",
        procedure_ids=("real-agent-fixed-guidance",), revision="0" * 64,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64, helpful_next_checks=steps,
        reason_code=None, approximate_tokens=60 * len(steps))


def _load_manifest(path: Path) -> dict:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("manifest must be a JSON object")
    return document


def _acceptance_material(task: Mapping,
                         repository: Mapping) -> dict[str, bytes]:
    acceptance = task["acceptance"]
    if acceptance.get("files") is not None:
        material = {}
        for relative, source in acceptance["files"].items():
            payload = (source.encode("utf-8")
                       if isinstance(source, str) else source)
            if not isinstance(payload, (bytes, bytearray)):
                raise ValueError(f"acceptance file {relative} is not text")
            material[relative] = bytes(payload)
        return material
    hidden = Path(acceptance["hidden_tests_path"])
    payload = hidden.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if acceptance.get("hidden_tests_digest") != digest:
        raise ValueError("hidden_tests_digest does not match the file")
    bundle = (repository.get("hidden_tests") or {}).get("digest")
    if bundle is not None and bundle != digest:
        raise ValueError("repository hidden_tests.digest does not match")
    if hidden.name not in acceptance["argv"]:
        raise ValueError("hidden test file is not named by acceptance.argv")
    return {hidden.name: payload}


def _real_tasks(document: Mapping, verifier: OutcomeVerifier, *,
                custody: str | None):
    repositories = {item["repository_id"]: item
                    for item in document["repositories"]}
    tasks, prompts, classes = [], {}, {}
    for task in document["tasks"]:
        repository = repositories[task["repository_id"]]
        repo_path = Path(repository["path"]).resolve()
        snapshot = tree_digest(repo_path)
        if snapshot != repository["repo_snapshot_digest"]:
            raise ValueError("repository_snapshot_mismatch:"
                             + repository["repository_id"])
        material = _acceptance_material(task, repository)
        statement = hashlib.sha256(task["prompt"].encode("utf-8")).hexdigest()
        verifier.register_task(
            actor_role="evaluator", task_id=task["task_id"],
            criterion_version="v1", argv=tuple(task["acceptance"]["argv"]),
            files=material, base_commit=task["base_commit"],
            statement_digest=statement,
            failure_class=task["failure_class"], custody=custody)
        budgets = task["budgets"]
        tasks.append((TaskEnvelopeV1(
            schema_version=1, task_id=task["task_id"],
            repo_snapshot_digest=snapshot,
            base_commit=task["base_commit"],
            task_statement_digest=statement,
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=budgets["time_budget_seconds"],
            token_budget=budgets["token_budget"],
            tool_budget=budgets["tool_budget"],
            actor_id="agent", evaluator_task_ref=task["task_id"]), repo_path))
        prompts[task["task_id"]] = task["prompt"]
        classes[task["task_id"]] = task["failure_class"]
    return tasks, prompts, classes


def _codex_agent(prompts: Mapping[str, str], budget: BudgetCaps,
                 model: str | None):
    return CodexCliAgent(wall_seconds=budget.wall_seconds, model=model,
                         prompts=prompts)


def run_real(output: Path, manifest_path: Path | None, *,
             allow_shared_custody: bool = False,
             agent_factory: Callable | None = None) -> int:
    status = codex_agent_status()
    report: dict = {
        "schema_version": 1,
        "kind": "five_arm_learning_qualification_real_run",
        "codex_gate": status,
    }

    def blocked(gate: str, note: str) -> int:
        report["evidence_class"] = "invalid"
        report["release_gate"] = gate
        report["note"] = note
        write_report(report, output)
        print(json.dumps(report, indent=2))
        return 2

    if not status["available"] or not status["authenticated"]:
        return blocked(
            "BLOCKED_REAL_AGENT",
            "Codex CLI is unavailable or unauthenticated: " + status["reason"])
    if manifest_path is None:
        return blocked(
            "BLOCKED_MANIFEST",
            "A real run requires a manifest with repository paths, prompts, "
            "evaluator-owned acceptance tests, base commits and a "
            "preregistered protocol.")
    try:
        document = _load_manifest(manifest_path)
    except (OSError, ValueError) as exc:
        return blocked("BLOCKED_MANIFEST", f"manifest_unreadable:{exc}")
    validation = validate_manifest(document, check_paths=True)
    manifest_block = {
        "path": str(manifest_path),
        "digest": validation["manifest_digest"],
        "valid": validation["valid"],
        "ready": validation["ready"],
        "problems": validation["problems"],
        "tasks": validation["tasks"],
        "sample_size": validation["sample_size"],
    }
    report["manifest"] = manifest_block
    if not validation["valid"]:
        return blocked(
            "BLOCKED_MANIFEST",
            "manifest_invalid: " + "; ".join(validation["problems"]))

    protocol = document["protocol"]
    budget = BudgetCaps(
        wall_seconds=protocol["budget"]["wall_seconds"],
        token_budget=protocol["budget"]["token_budget"],
        tool_budget=protocol["budget"]["tool_budget"])
    custody = "shared" if allow_shared_custody else None
    learned = tuple(sorted(
        item["repo_snapshot_digest"] for item in document["repositories"]
        if item["partition"] == "induction"))
    with tempfile.TemporaryDirectory(prefix="sis-five-arm-real-") as temp:
        root = Path(temp)
        profile = EvaluationRuntimeProfile(
            cpu_seconds=budget.wall_seconds,
            wall_seconds=budget.wall_seconds, process_count=None)
        verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                root / "exec",
                protected_paths=(root / "keys", root / "registry")),
            key_dir=root / "keys", registry_dir=root / "registry",
            allow_shared_custody=allow_shared_custody,
            limits=ResourceLimits(
                wall_seconds=budget.wall_seconds,
                cpu_seconds=budget.wall_seconds,
                memory_bytes=profile.task_memory_bytes,
                process_count=None),
            runtime_profile=profile)
        try:
            tasks, prompts, classes = _real_tasks(
                document, verifier, custody=custody)
        except Exception as exc:
            gate = ("BLOCKED_SPLIT_CUSTODY" if "split_custody" in str(exc)
                    else "BLOCKED_MANIFEST")
            return blocked(
                gate, f"campaign_setup_failed:{type(exc).__name__}: {exc}")

        bundles = {
            failure_class: {
                arm: list(_fixed_guidance(failure_class, arm)
                          .helpful_next_checks)
                for arm in ("B", "C", "D", "E")}
            for failure_class in sorted(set(classes.values()))}
        served: dict = {}

        def provider(task, arm):
            guidance = _fixed_guidance(classes[task.task_id], arm)
            served[(task.task_id, arm)] = bool(
                guidance is not None and guidance.helpful_next_checks)
            return guidance

        factory = agent_factory or _codex_agent
        try:
            agent = factory(prompts, budget, document["agent"]["model"])
        except RuntimeError as exc:
            return blocked("BLOCKED_REAL_AGENT", str(exc))
        try:
            campaign = FiveArmCampaign(
                harness=BenchmarkHarness(
                    verifier=verifier, work_root=root / "work"),
                tasks=tasks, agent=agent, budget=budget, protocol=protocol,
                context_provider=provider, served_map=served,
                learned_repo_digests=learned, real_agent=True,
                hidden_holdout=True)
            campaign.validate()
        except Exception as exc:
            close = getattr(agent, "close", None)
            if callable(close):
                close()
            return blocked(
                "BLOCKED_MANIFEST",
                f"campaign_setup_failed:{type(exc).__name__}: {exc}")
        try:
            report = campaign.run()
        finally:
            close = getattr(agent, "close", None)
            if callable(close):
                close()
        analysis = report["learning_qualification"]
        report["kind"] = "five_arm_learning_qualification_real_run"
        report["manifest"] = manifest_block
        report["codex_gate"] = status
        report["evidence_class"] = analysis["evidence_class"]
        report["release_gate"] = analysis["release_gate"]
        report["evaluator_runtime"] = profile.as_dict()
        report["evaluator_runtime_digest"] = profile.digest
        report["bootstrap"] = verifier.bootstrap().as_dict()
        report["guidance_bundles"] = bundles
        report["guidance_bundle_digest"] = canonical_digest(
            "guidance_bundles", 1, bundles)
        report["receipts_issued"] = len(verifier.issued_receipts())
        report["note"] = (
            "Real Codex CLI execution over the supplied manifest. Guidance "
            "bundles are fixed before the run and recorded here; every arm "
            "row carries an evaluator-verified outcome and receipt digest. "
            "The evidence class follows the paired analysis, not this note.")
        write_report(report, output)
        print(json.dumps({
            "kind": report["kind"],
            "tasks": analysis["tasks"],
            "evidence_class": analysis["evidence_class"],
            "efficacy_claim": analysis["efficacy_claim"],
            "release_gate": analysis["release_gate"],
            "underpowered": analysis["underpowered"],
            "decisive_contrast": analysis["decisive_contrast"],
            "receipts_issued": report["receipts_issued"],
            "output": str(output),
        }, indent=2))
        return 0 if analysis["evidence_class"] in (
            "exploratory", "confirmatory") else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--real-agent", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--allow-local-executor", action="store_true",
                        help="local execution is development-only")
    parser.add_argument("--allow-shared-custody", action="store_true",
                        help="development-only: grade private acceptance "
                             "tests beside the submission instead of split "
                             "custody")
    args = parser.parse_args()
    if not args.allow_local_executor:
        parser.error("local executor requires --allow-local-executor")
    if args.demo and args.real_agent:
        parser.error("choose --demo or --real-agent")
    if args.real_agent:
        return run_real(args.output, args.manifest,
                        allow_shared_custody=args.allow_shared_custody)
    return run_demo(args.output)


if __name__ == "__main__":
    raise SystemExit(main())
