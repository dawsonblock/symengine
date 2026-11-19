#!/usr/bin/env python3
"""Learning qualification: demo machinery or real-agent gate.

The manifest selects the design: the five-arm set A,B,C,D,E or the A/E
primary contrast.

The demo path runs the real five-arm harness, real signed receipts and
the real statistics on a tiny scripted task set. It is explicitly
labelled DEMONSTRATION and never claims learning efficacy.

The real path requires the manifest's pinned agent (``agent.kind``:
``codex-cli`` or ``claude-code``) to be installed and authenticated.
If it is not, the tool writes a BLOCKED_REAL_AGENT report and exits 2;
it never substitutes a scripted run for a confirmatory one. A real run
requires a validated task manifest (repository paths, prompts,
evaluator-owned acceptance tests, base commits and a preregistered
protocol); the tool then executes the declared arms with
:class:`sis.v3.learning_qualification.FiveArmCampaign` and
:class:`sis.v3.learning_qualification.CodexCliAgent` and writes the
paired report with per-arm receipt digests.

Integrity rules for a confirmatory label:

- the installed CLI version must match the manifest;
- the manifest must be committed before the run (Git anchor);
- private acceptance tests must run under split custody;
- guidance must come from ``--guidance-bundle``: every step must name
  an immutable candidate record, the training snapshots must be the
  manifest's induction repositories, and the manifest must precommit
  the bundle digest. The built-in fixed control prompts can never
  qualify. ``--candidate-registry`` verifies every step against a
  qualified record and requires ``--trust-config`` (the evaluator and
  operator public keys and the pinned evaluation protocol, in the
  ``sis.v3.bootstrap`` config format). Without a registry the bundle is
  recorded as ``learned_unverified``; passing a registry without trust
  anchors is refused unless ``--record-unverified`` acknowledges that;
- guidance from a verified bundle is served per task through
  ``GovernedServingGateway`` (scope, applicability and counterexample
  gates decide what each task gets; every decision is recorded);
- token and tool usage must be fully metered by the agent runtime;
  agent timeouts and errors count as ordinary failures;
- the manifest must be ``ready`` (powered, preregistered, no
  placeholders, repository-covered). A manifest declared
  ``study_tier: confirmatory`` (the default for a powered protocol)
  needs at least 20 holdout repositories; one declared ``exploratory``
  needs five and can never be labelled confirmatory. The analysis labels
  a run confirmatory only when at least 20 holdout repositories
  contribute tasks and the manifest was declared confirmatory, and decides efficacy
  with a repository-level test plus a negative-transfer gate. Tasks may
  set ``"misleading": true`` to be reported separately.

The run also writes ``<report>.evidence/`` with the signed receipt
bytes, the evaluator public key, the exact manifest and a bundle digest,
so the report is auditable after the verifier's temporary directory is
gone.

Usage:
    python3 tools/five_arm_campaign.py --demo -o evidence/evaluation/demo.json
    python3 tools/five_arm_campaign.py --real-agent --manifest tasks.json \
        -o evidence/evaluation/real.json
    python3 tools/five_arm_campaign.py --real-agent --manifest tasks.json \
        --guidance-bundle bundle.json --candidate-registry candidates.db \
        --trust-config v3.json --allow-local-executor -o real.json
    # Linux split custody, resumable, two tasks at a time:
    python3 tools/five_arm_campaign.py --real-agent --executor docker \
        --manifest tasks.json --guidance-bundle bundle.json \
        --candidate-registry candidates.db --trust-config v3.json \
        --state-dir /study/state --workers 2 -o real.json

``--state-dir`` keeps the evaluator keys, receipts, per-task trees and a
``(task, arm)`` journal; rerunning the same command after an interruption
resumes from the journal (see docs/v3/PILOT_RUNBOOK.md).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3 import gitquery  # noqa: E402
from sis.v3.benchmark import (  # noqa: E402
    BenchmarkError, BenchmarkHarness, BudgetCaps)
from sis.v3.contracts import (  # noqa: E402
    ContractError, GuidanceV1, TaskEnvelopeV1, canonical_digest)
from sis.v3.efficacy_manifest import (  # noqa: E402
    validate_manifest, verify_repository_binding,
    verify_repository_execution, verify_repository_provenance)
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.governed_eval import (GOVERNED_ARMS, PRIMARY_CONTRAST_ARMS,  # noqa: E402
                                  preregister)
from sis.v3.learning_qualification import (  # noqa: E402
    AGENT_KINDS, ClaudeCodeAgent, CodexCliAgent, FiveArmCampaign,
    build_context_provider, claude_code_agent_status, codex_agent_status,
    write_report)
from sis.v3.runner import (LocalSubprocessExecutor, ResourceLimits,  # noqa: E402
                           RunnerError, repository_execution_digest,
                           tree_digest, verify_repository_digest)
from sis.v3.study_runtime import (DEFAULT_SPLIT_USER,  # noqa: E402
                                  DEFAULT_STUDY_IMAGE, EXECUTOR_KINDS,
                                  RunJournal, StudyRuntimeError,
                                  build_study_executor, executor_description,
                                  hidden_test_belongs, hidden_tests_digest,
                                  materialize_commit)
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
            repo_snapshot_digest=tree_digest(repo, version=3),
            base_commit="abc1234",
            task_statement_digest=hashlib.sha256(
                task_id.encode()).hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=120, token_budget=1000, tool_budget=100,
            actor_id="agent", evaluator_task_ref=task_id), repo))
    return verifier, tasks, profile


def run_demo(output: Path, *,
             arms: tuple[str, ...] = GOVERNED_ARMS) -> int:
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
            arms=arms)
        served: dict = {}
        guidance = {arm: _guidance() for arm in arms if arm != "A"}
        guidance["A"] = None
        provider = build_context_provider(guidance, served)
        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=verifier, work_root=root / "work"),
            tasks=tasks, agent=_scripted_agent,
            budget=BudgetCaps(wall_seconds=120, token_budget=1000,
                              tool_budget=100),
            protocol=protocol, context_provider=provider,
            served_map=served, learned_repo_digests=(), real_agent=False,
            arms=arms)
        report = campaign.run()
        report["kind"] = (
            "primary_contrast_learning_qualification_demo"
            if tuple(arms) == PRIMARY_CONTRAST_ARMS
            else "five_arm_learning_qualification_demo")
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


def _json_object(raw: bytes, label: str) -> dict:
    """Parse one JSON object, rejecting duplicate keys at every level."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"{label} has duplicate key: {key}")
            result[key] = value
        return result

    document = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs)
    if not isinstance(document, dict):
        raise ValueError(f"{label} must be a JSON object")
    return document


_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
# GuidanceV1 binds at most three procedure IDs and eight checks of 512
# characters; a bundle that exceeds those bounds could never be served.
_MAX_GUIDANCE_STEPS = 3
_MAX_STEP_TEXT = 512
_CANDIDATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


def _read_bounded(path: Path, limit: int, label: str) -> bytes:
    with path.open("rb") as handle:
        raw = handle.read(limit + 1)
    if len(raw) > limit:
        raise ValueError(f"{label} exceeds the size bound")
    return raw


def _load_manifest(path: Path) -> tuple[dict, bytes]:
    """Parse the manifest and keep the exact bytes that were validated."""
    raw = _read_bounded(path, _MAX_MANIFEST_BYTES, "manifest")
    return _json_object(raw, "manifest"), raw


_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _normalized_version(value) -> str | None:
    if not isinstance(value, str):
        return None
    match = _VERSION.search(value)
    return match.group(0) if match else None


def _agent_status(kind: str) -> dict:
    """The availability gate of the manifest's pinned agent kind.

    Looked up through the module globals so tests can replace either
    status function.
    """
    if kind == "claude-code":
        return claude_code_agent_status()
    return codex_agent_status()


def _peek_agent_kind(manifest_path: Path | None) -> str:
    """The manifest's ``agent.kind`` before full validation (gate choice)."""
    if manifest_path is None:
        return "codex-cli"
    try:
        document, _ = _load_manifest(manifest_path)
    except (OSError, ValueError):
        return "codex-cli"
    agent = document.get("agent")
    kind = agent.get("kind") if isinstance(agent, Mapping) else None
    return kind if kind in AGENT_KINDS else "codex-cli"


def _installed_cli_version(binary: str | None) -> str | None:
    """``<binary> --version`` normalized to ``X.Y.Z`` (both agent CLIs)."""
    if not binary:
        return None
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return _normalized_version((proc.stdout or "") + " " + (proc.stderr or ""))


def _installed_codex_version(binary: str | None) -> str | None:
    return _installed_cli_version(binary)


def _installed_claude_version(binary: str | None) -> str | None:
    """``claude --version`` prints ``X.Y.Z (Claude Code)``."""
    return _installed_cli_version(binary)


def _installed_version(kind: str, binary: str | None) -> str | None:
    if kind == "claude-code":
        return _installed_claude_version(binary)
    return _installed_codex_version(binary)


def _git_anchor(path: Path) -> dict:
    """Record the commit that last touched the manifest and its cleanliness."""
    parent = path.resolve().parent
    commit = gitquery.query(
        parent, "log", "-1", "--format=%H", "--", path.name)
    dirty = gitquery.query(
        parent, "status", "--porcelain", "--", path.name)
    if commit is None or dirty is None:
        return {"commit": None, "clean": False, "anchored": False}
    return {"commit": commit or None, "clean": not dirty,
            "anchored": bool(commit) and not dirty}


def _bundle_digest(document: Mapping) -> str:
    body = {key: value for key, value in document.items()
            if key != "bundle_digest"}
    normalized = json.loads(json.dumps(body, sort_keys=True))
    return canonical_digest("learned_guidance_bundle", 1, normalized)


def _verify_bundle_candidates(registry, components: Mapping) -> bool:
    """Require every step to resolve to a qualified candidate record."""
    for arm, records in components.items():
        for record in records:
            candidate_id = record["candidate_id"]
            candidate, state = registry.get(candidate_id)
            if state != "qualified":
                raise ValueError(
                    f"guidance_candidate_not_qualified:{candidate_id}")
            if candidate.digest != record["candidate_digest"]:
                raise ValueError(
                    f"guidance_candidate_digest_mismatch:{candidate_id}")
            if candidate.content_digest != record["content_digest"]:
                raise ValueError(
                    f"guidance_candidate_content_mismatch:{candidate_id}")
            basis = registry.serving_basis(candidate_id)
            evidence = set(basis.get("evidence_refs") or ())
            if record["evidence_digest"] not in evidence:
                raise ValueError(
                    f"guidance_evidence_not_bound:{candidate_id}")
    return True


def _check_bundle_qualification(qualification, *, induction_digests: set,
                                holdout_digests: set, training_digests: set,
                                study_task_ids: set,
                                trusted_evaluator_key_ids=None) -> dict:
    """Prove the bundle's qualification evidence came from induction repos.

    The bundle declares the qualification split it was qualified on: the
    repository snapshots, the tasks (each bound to one of those
    snapshots) and the signed outcome receipts. Every qualification
    repository must be an induction repository of the manifest, never a
    study holdout repository, and never a training repository (a
    candidate is not qualified on the material it was learned from). No
    qualification task may be a study task. Every receipt must hash to
    its address, name a declared qualification task and carry a valid
    signature from the declared evaluator key — a key the trust
    configuration trusts, when one is supplied.
    """
    from sis.v3.contracts import parse_outcome_receipt
    from sis.v3.verifier import verify_receipt_signature

    if not isinstance(qualification, Mapping):
        raise ValueError("guidance_qualification_invalid: not an object")
    repositories = qualification.get("repository_digests")
    if (not isinstance(repositories, list) or not repositories
            or any(not isinstance(item, str) or not _HEX64.match(item)
                   for item in repositories)):
        raise ValueError("guidance_qualification_invalid: repository_digests")
    repositories = set(repositories)
    if repositories & holdout_digests:
        raise ValueError(
            "guidance_qualification_uses_holdout: qualification evidence"
            " comes from a study holdout repository")
    if not repositories <= set(induction_digests):
        raise ValueError(
            "guidance_qualification_not_induction: qualification"
            " repositories are not induction partitions of the manifest")
    if repositories & training_digests:
        raise ValueError(
            "guidance_qualification_overlaps_training: candidates were"
            " qualified on the repositories they were learned from")
    tasks = qualification.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("guidance_qualification_invalid: tasks")
    task_repositories: dict[str, str] = {}
    for item in tasks:
        if (not isinstance(item, Mapping)
                or not isinstance(item.get("task_id"), str)
                or not item["task_id"]
                or item.get("repository_digest") not in repositories
                or item["task_id"] in task_repositories):
            raise ValueError("guidance_qualification_invalid: task record")
        task_repositories[item["task_id"]] = item["repository_digest"]
    shared = set(task_repositories) & study_task_ids
    if shared:
        raise ValueError(
            "guidance_qualification_uses_study_tasks: "
            + ", ".join(sorted(shared)[:5]))
    signer = qualification.get("receipt_signer")
    if (not isinstance(signer, Mapping)
            or not isinstance(signer.get("key_id"), str)
            or not isinstance(signer.get("public_key"), str)
            or not _HEX64.match(signer["public_key"])):
        raise ValueError("guidance_qualification_invalid: receipt_signer")
    if (trusted_evaluator_key_ids is not None
            and signer["key_id"] not in set(trusted_evaluator_key_ids)):
        raise ValueError(
            "guidance_qualification_signer_untrusted: " + signer["key_id"])
    receipts = qualification.get("receipts")
    if not isinstance(receipts, Mapping) or not receipts:
        raise ValueError("guidance_qualification_invalid: receipts")
    used: dict[str, str] = {}
    for digest, body in receipts.items():
        try:
            receipt = parse_outcome_receipt(body)
        except Exception as exc:  # noqa: BLE001 - surfaced as invalid
            raise ValueError(
                "guidance_qualification_invalid: receipt") from exc
        if receipt.digest != digest:
            raise ValueError("guidance_qualification_receipt_digest_mismatch")
        if receipt.task_id not in task_repositories:
            raise ValueError(
                "guidance_qualification_receipt_task_unknown: "
                + receipt.task_id)
        if receipt.signer_key_id != signer["key_id"] or \
                not verify_receipt_signature(receipt, signer["public_key"]):
            raise ValueError("guidance_qualification_receipt_signature")
        used[digest] = task_repositories[receipt.task_id]
    return {
        "repository_digests": sorted(repositories),
        "tasks": len(task_repositories),
        "receipt_count": len(used),
        "receipt_signer": signer["key_id"],
        "receipts": used,
    }


def _verify_qualification_receipts(registry, components: Mapping,
                                   receipts: Mapping | None) -> None:
    """Each candidate's qualifying receipts are declared qualification ones."""
    if receipts is None:
        raise ValueError("guidance_qualification_missing")
    for records in components.values():
        for record in records:
            basis = registry.serving_basis(record["candidate_id"])
            refs = set(basis.get("receipt_refs") or ())
            if not refs:
                raise ValueError(
                    "guidance_qualification_unbound:" + record["candidate_id"])
            outside = refs - set(receipts)
            if outside:
                raise ValueError(
                    "guidance_qualification_receipt_undeclared:"
                    + record["candidate_id"])


def _load_guidance_bundle(path: Path, *, induction_digests,
                          holdout_digests, precommitted_digest,
                          registry=None, study_task_ids=(),
                          trusted_evaluator_key_ids=None) -> dict:
    """Load a learned bundle only when its lineage is checkable.

    A file that merely says ``"source": "learned"`` is not evidence. The
    bundle must carry one immutable candidate record per guidance step,
    name the induction repository snapshots it was learned from, match
    the manifest's precommitted bundle digest, and — when a candidate
    registry is supplied — resolve every candidate to a qualified record
    whose evidence covers the declared digest.
    """
    raw = _read_bounded(path, _MAX_BUNDLE_BYTES, "guidance bundle")
    document = _json_object(raw, "guidance bundle")
    if document.get("schema_version") != 2:
        raise ValueError("guidance bundle schema_version must be 2")
    if document.get("kind") != "learned_guidance_bundle":
        raise ValueError(
            "guidance bundle kind must be learned_guidance_bundle")
    if document.get("source") != "learned":
        raise ValueError("guidance bundle source must be 'learned'")
    if not isinstance(precommitted_digest, str) \
            or not _HEX64.match(precommitted_digest):
        raise ValueError(
            "manifest does not precommit guidance_bundle_digest")
    training = document.get("training")
    if not isinstance(training, Mapping):
        raise ValueError("guidance bundle needs a training object")
    digests = training.get("repository_digests")
    if (not isinstance(digests, list) or not digests
            or any(not isinstance(item, str) or not _HEX64.match(item)
                   for item in digests)):
        raise ValueError(
            "training.repository_digests must be non-empty sha256 digests")
    if len(set(digests)) != len(digests):
        raise ValueError("training.repository_digests contains duplicates")
    allowed = set(induction_digests)
    if not set(digests) <= allowed:
        raise ValueError(
            "training repositories are not induction partitions of the"
            " manifest")
    if set(digests) & set(holdout_digests):
        raise ValueError("training repositories overlap the holdout")
    components = document.get("components")
    if not isinstance(components, Mapping):
        raise ValueError("guidance bundle needs a components object")
    steps_by_arm: dict[str, list[str]] = {}
    records_by_arm: dict[str, list[dict]] = {}
    for arm in ("B", "C", "D"):
        steps = components.get(arm)
        if not isinstance(steps, list) or not steps:
            raise ValueError(
                f"guidance bundle arm {arm} needs non-empty steps")
        texts: list[str] = []
        records: list[dict] = []
        for index, step in enumerate(steps):
            label = f"guidance bundle arm {arm} step {index}"
            if not isinstance(step, Mapping):
                raise ValueError(label + " must be an object")
            candidate_id = step.get("candidate_id")
            if (not isinstance(candidate_id, str)
                    or not _CANDIDATE_ID.fullmatch(candidate_id)):
                raise ValueError(
                    label + " candidate_id is not a contract identifier")
            record = {"candidate_id": candidate_id}
            for name in ("candidate_digest", "content_digest",
                         "evidence_digest"):
                value = step.get(name)
                if not isinstance(value, str) or not _HEX64.match(value):
                    raise ValueError(label + f".{name} is not a digest")
                record[name] = value
            text = step.get("text")
            if (not isinstance(text, str) or not text.strip()
                    or len(text) > _MAX_STEP_TEXT):
                raise ValueError(label + " has no bounded text")
            record["text"] = text
            texts.append(text)
            records.append(record)
        steps_by_arm[arm] = texts
        records_by_arm[arm] = records
    total_steps = sum(len(records) for records in records_by_arm.values())
    if total_steps > _MAX_GUIDANCE_STEPS:
        raise ValueError(
            f"guidance bundle has {total_steps} steps across arms B-D;"
            f" the guidance contract binds at most {_MAX_GUIDANCE_STEPS}"
            " procedure IDs and arm E serves all three arms")
    computed = _bundle_digest(document)
    if document.get("bundle_digest") != computed:
        raise ValueError("guidance bundle digest does not match its contents")
    if precommitted_digest != computed:
        raise ValueError(
            "guidance bundle digest does not match the manifest"
            " precommitment")
    for arm in ("B", "C", "D", "E"):
        try:
            _served_guidance(
                {"components": records_by_arm, "bundle_digest": computed}, arm)
        except ContractError as exc:
            raise ValueError(
                f"guidance bundle cannot serve arm {arm}: {exc}") from exc
    qualification = document.get("qualification")
    if qualification is None and registry is not None:
        raise ValueError(
            "guidance_qualification_missing: a verified bundle must declare"
            " the qualification split its evidence came from")
    qualification_summary = None
    if qualification is not None:
        qualification_summary = _check_bundle_qualification(
            qualification, induction_digests=allowed,
            holdout_digests=set(holdout_digests),
            training_digests=set(digests),
            study_task_ids=set(study_task_ids),
            trusted_evaluator_key_ids=trusted_evaluator_key_ids)
    verified = False
    if registry is not None:
        verified = _verify_bundle_candidates(registry, records_by_arm)
        _verify_qualification_receipts(
            registry, records_by_arm, qualification_summary["receipts"])
    return {"source": "learned" if verified else "learned_unverified",
            "qualification": (
                {key: value for key, value in qualification_summary.items()
                 if key != "receipts"}
                if qualification_summary is not None else None),
            "bundles": steps_by_arm,
            "components": records_by_arm,
            "bundle_digest": computed,
            "training_repository_digests": tuple(sorted(digests)),
            "candidates_verified": verified,
            "raw": raw}


def _served_guidance(bundle: Mapping, arm: str) -> GuidanceV1 | None:
    """Build the guidance served to one arm from its candidate records.

    Accepts either the loaded bundle or the raw bundle document: both
    carry ``components`` (candidate records) and ``bundle_digest``.
    """
    if arm == "A":
        return None
    sources = ("B", "C", "D") if arm == "E" else (arm,)
    records = [record for source in sources
               for record in bundle["components"][source]]
    checks = tuple(record["text"] for record in records)
    return GuidanceV1(
        schema_version=1, decision="recommend",
        procedure_ids=tuple(record["candidate_id"] for record in records),
        revision=bundle["bundle_digest"],
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(),
        evidence_ids=tuple(record["evidence_digest"] for record in records),
        policy_digest=bundle["bundle_digest"], helpful_next_checks=checks,
        reason_code=None, approximate_tokens=60 * len(checks))


class _ArmCatalogView:
    """One arm's slice of the candidate catalog, read through the registry.

    The gateway re-verifies the whole catalog on every serve; this view
    only narrows ``qualified_bases`` to the candidates the arm is allowed
    to draw from (B memory, C skills, D procedures, E all three), so the
    composition, scope, applicability and counterexample gates are the
    gateway's own.
    """

    def __init__(self, registry, candidate_ids) -> None:
        self._registry = registry
        self._ids = frozenset(candidate_ids)

    def qualified_bases(self, *args, **kwargs):
        return [(candidate, basis) for candidate, basis
                in self._registry.qualified_bases(*args, **kwargs)
                if candidate.candidate_id in self._ids]

    def __getattr__(self, name):
        return getattr(self._registry, name)


class _ManifestRepositories:
    """Resolve holdout repository ids from the validated, bound manifest.

    The evaluator's manifest is the authority for which repository a
    holdout task runs in; candidates learned on induction repositories
    reach it only through a ``global`` or matching ``family_id`` scope.
    """

    def __init__(self, repositories) -> None:
        self._by_id = {}
        for item in repositories:
            family = item.get("family_id")
            self._by_id[item["repository_id"]] = SimpleNamespace(
                registry_id=item["repository_id"],
                family_id=family if isinstance(family, str) and family
                else None)

    def resolve(self, repository_id):
        return self._by_id.get(repository_id)


_MAX_CONTEXT_FILES = 2000


def _files_present(path: Path) -> tuple[str, ...]:
    """Bounded relative file listing used by ``file_present`` predicates."""
    found: list[str] = []
    for item in sorted(Path(path).rglob("*")):
        if len(found) >= _MAX_CONTEXT_FILES:
            break
        relative = item.relative_to(path)
        if ".git" in relative.parts or item.is_symlink() \
                or not item.is_file():
            continue
        found.append(relative.as_posix())
    return tuple(found)


def _serving_provider(registry, bundle: Mapping, *,
                      task_contexts: Mapping[str, Mapping],
                      repositories, served: dict, decisions: list,
                      gateway_factory=None):
    """Route each (task, arm) through SIS's governed serving gateway.

    Every task is served from its own context — repository identity,
    failure class, prompt summary and the files in its snapshot — so
    candidates whose scope, applicability or counterexamples do not fit
    the task are rejected and the arm runs without guidance. Every
    decision, delivered candidate and rejection is recorded.
    """
    from sis.v3.contracts import GuidanceRequestV1
    from sis.v3.serving import GovernedServingGateway

    factory = gateway_factory or GovernedServingGateway
    resolver = _ManifestRepositories(repositories)
    gateways = {}
    audits: dict[str, list] = {}
    for arm in ("B", "C", "D", "E"):
        sources = ("B", "C", "D") if arm == "E" else (arm,)
        ids = [record["candidate_id"] for source in sources
               for record in bundle["components"].get(source, ())]
        audits[arm] = []
        gateways[arm] = factory(
            _ArmCatalogView(registry, ids), repository_registry=resolver,
            allow_global_scope=True, audit_sink=audits[arm].append)

    def provider(task, arm):
        if arm == "A":
            served[(task.task_id, arm)] = False
            return None
        context = task_contexts[task.task_id]
        request = GuidanceRequestV1(
            schema_version=1, task_id=task.task_id,
            repo_snapshot_digest=task.repo_snapshot_digest,
            base_commit=task.base_commit, namespace="five-arm-study",
            language=context.get("language", "python"),
            toolchain=context.get("toolchain") or "pytest",
            lockfile_digests={},
            task_summary=context["prompt"][:2000],
            failure_signatures=tuple(context.get("failure_signatures", ())),
            present_symbols=(), semantic_contract_digest=None)
        before = len(audits[arm])
        guidance = gateways[arm].serve(
            request, repository_id=context["repository_id"],
            files_present=context.get("files_present", ()))
        audit = audits[arm][before:]
        record = audit[-1] if audit else {}
        delivered = (guidance.decision != "abstain"
                     and bool(guidance.helpful_next_checks))
        served[(task.task_id, arm)] = delivered
        decisions.append({
            "task_id": task.task_id,
            "arm": arm,
            "decision": guidance.decision,
            "reason_code": guidance.reason_code,
            "guidance_digest": guidance.digest,
            "candidates": list(record.get("candidate_digests") or ()),
            "rejections": list(record.get("rejections") or ()),
            "integrity_error": record.get("integrity_error"),
        })
        return guidance if delivered else None
    return provider


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


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
    if hidden.is_symlink() or not hidden.is_file():
        raise ValueError("hidden test file is not a regular file")
    payload = hidden.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if acceptance.get("hidden_tests_digest") != digest:
        raise ValueError("hidden_tests_digest does not match the file")
    record = repository.get("hidden_tests") or {}
    root = record.get("path")
    if isinstance(root, str) and root and Path(root).is_dir():
        # A directory of per-task hidden tests (imported tasks): the task
        # file must live in it and the directory must still match the
        # digest the manifest recorded.
        if not hidden_test_belongs(hidden, root):
            raise ValueError(
                "hidden test file is not in the repository's hidden_tests")
        if record.get("digest") != hidden_tests_digest(root):
            raise ValueError("repository hidden_tests.digest does not match")
    elif record.get("digest") is not None and record["digest"] != digest:
        raise ValueError("repository hidden_tests.digest does not match")
    target = acceptance.get("hidden_tests_target") or hidden.name
    if target not in acceptance["argv"]:
        raise ValueError("hidden test file is not named by acceptance.argv")
    return {target: payload}


def _task_tree(task: Mapping, repository: Mapping,
               tree_root: Path | None) -> tuple[Path, str, str]:
    """Materialize a task's own base commit and verify its fingerprints.

    A task whose ``base_commit`` differs from its repository's checkout
    starts from that commit's tree, written by
    :func:`sis.v3.study_runtime.materialize_commit` under ``tree_root``
    (evaluator-owned, outside the repository). The tree must match the
    task's declared ``repo_snapshot_digest`` and ``repo_execution_digest``.
    A tree left by an interrupted run is reused only if it still matches.
    """
    if tree_root is None:
        raise ValueError("task_base_commit_requires_tree_root:"
                         + task["task_id"])
    target = tree_root / hashlib.sha256(
        f"{repository['repository_id']}\0{task['base_commit']}".encode()
    ).hexdigest()[:32]
    if target.exists():
        if (tree_digest(target, version=3) == task.get("repo_snapshot_digest")
                and repository_execution_digest(target)
                == task.get("repo_execution_digest")):
            return target, task["repo_snapshot_digest"], \
                task["repo_execution_digest"]
        shutil.rmtree(target)
    tree_root.mkdir(parents=True, exist_ok=True)
    try:
        materialize_commit(repository["path"], task["base_commit"], target)
    except StudyRuntimeError as exc:
        raise ValueError(f"task_tree_unavailable:{task['task_id']}:{exc}") \
            from exc
    snapshot = tree_digest(target, version=3)
    execution = repository_execution_digest(target)
    if snapshot != task.get("repo_snapshot_digest"):
        raise ValueError("task_snapshot_mismatch:" + task["task_id"])
    if execution != task.get("repo_execution_digest"):
        raise ValueError("task_execution_mismatch:" + task["task_id"])
    return target, snapshot, execution


def _real_tasks(document: Mapping, verifier: OutcomeVerifier, *,
                custody: str | None, tree_root: Path | None = None,
                executions: dict | None = None):
    """Register every task and build its envelope and starting tree.

    ``executions`` (when given) receives ``{resolved path: execution
    digest}`` for every starting tree, for the harness staging check.
    """
    repositories = {item["repository_id"]: item
                    for item in document["repositories"]}
    # Validation and execution are separated by guidance loading and
    # verifier setup. Re-bind every repository to its declared commit,
    # origin, history and execution fingerprint here so a checkout that
    # moved after validation cannot run.
    binding: list[str] = []
    for repository in repositories.values():
        _, found = verify_repository_binding(repository)
        binding.extend(found)
        binding.extend(verify_repository_provenance(repository))
        _, found = verify_repository_execution(repository)
        binding.extend(found)
    if binding:
        raise ValueError("; ".join(binding))
    snapshots: dict[str, str] = {}
    tasks, prompts, classes = [], {}, {}
    for task in document["tasks"]:
        repository = repositories[task["repository_id"]]
        raw_path = Path(repository["path"])
        repo_path = raw_path.resolve()
        if raw_path.is_symlink() or not repo_path.is_dir():
            raise ValueError("repository_path_is_not_a_plain_directory:"
                             + repository["repository_id"])
        snapshot = snapshots.get(repository["repository_id"])
        if snapshot is None:
            canonical = tree_digest(repo_path, version=3)
            declared = repository["repo_snapshot_digest"]
            if canonical == declared:
                snapshot = canonical
            else:
                # A pre-canonical manifest may carry a full-tree v2 or
                # legacy v1 digest; the repository is accepted only if
                # its exact tree matches that record.
                try:
                    verify_repository_digest(
                        repo_path, declared, canonical=canonical)
                except RunnerError as exc:
                    raise ValueError(
                        "repository_snapshot_mismatch:"
                        + repository["repository_id"]) from exc
                snapshot = declared
            snapshots[repository["repository_id"]] = snapshot
            execution = repository_execution_digest(repo_path)
            if execution != repository.get("repo_execution_digest"):
                raise ValueError(
                    "repository_execution_mismatch:"
                    + repository["repository_id"])
            if executions is not None:
                executions[str(repo_path)] = execution
        if task["base_commit"] != repository["base_commit"]:
            repo_path, snapshot, execution = _task_tree(
                task, repository, tree_root)
            if executions is not None:
                executions[str(repo_path.resolve())] = execution
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


def _task_contexts(document: Mapping, tasks) -> dict[str, dict]:
    """Per-task serving context: repository, failure class, prompt, files."""
    by_id = {task["task_id"]: task for task in document["tasks"]}
    listings: dict[Path, tuple[str, ...]] = {}
    contexts = {}
    for envelope, path in tasks:
        task = by_id[envelope.task_id]
        if path not in listings:
            listings[path] = _files_present(path)
        contexts[envelope.task_id] = {
            "repository_id": task["repository_id"],
            "prompt": task["prompt"],
            "failure_signatures": (task["failure_class"],),
            "language": task.get("language", "python")
            if isinstance(task.get("language"), str) else "python",
            "files_present": listings[path],
        }
    return contexts


def _codex_agent(prompts: Mapping[str, str], budget: BudgetCaps,
                 model: str | None):
    return CodexCliAgent(wall_seconds=budget.wall_seconds, model=model,
                         prompts=prompts)


def _claude_code_agent(prompts: Mapping[str, str], budget: BudgetCaps,
                       model: str | None):
    return ClaudeCodeAgent(wall_seconds=budget.wall_seconds, model=model,
                           prompts=prompts)


def _default_agent_factory(kind: str) -> Callable:
    return _claude_code_agent if kind == "claude-code" else _codex_agent


def _export_evidence(output: Path, report_sha256: str, verifier,
                     manifest_path: Path, manifest_digest: str,
                     manifest_bytes: bytes,
                     guidance: Mapping | None = None) -> dict:
    """Persist the signed receipts and verification material.

    The verifier's key and receipt store live in a temporary directory, so
    a report that only names receipt digests cannot be checked after the
    run. The bundle keeps the signed receipt bytes, the public key, the
    exact manifest and the report digest beside the report.
    """
    directory = output.with_name(output.name + ".evidence")
    receipts_dir = directory / "receipts"
    receipts_dir.mkdir(parents=True, exist_ok=True)
    receipts = {}
    for digest in verifier.issued_receipts():
        receipt = verifier.load_receipt(digest)
        if receipt.digest != digest:
            raise RuntimeError("receipt_digest_mismatch")
        payload = receipt.canonical_bytes()
        (receipts_dir / f"{digest}.json").write_bytes(payload)
        receipts[digest] = hashlib.sha256(payload).hexdigest()
    public = verifier.public_key_record()
    (directory / "public_key.json").write_text(
        json.dumps(public, indent=2, sort_keys=True) + "\n")
    (directory / "manifest.json").write_bytes(manifest_bytes)
    bundle = {
        "schema_version": 1,
        "kind": "five_arm_evidence_bundle",
        "generated_at": _utcnow(),
        "manifest": {"path": str(manifest_path),
                     "digest": manifest_digest},
        "report": {
            "path": str(output),
            "sha256": report_sha256,
            "excludes": "evidence_bundle",
        },
        "public_key": public,
        "receipts": receipts,
    }
    if guidance is not None:
        raw = guidance["bytes"]
        (directory / "guidance_bundle.json").write_bytes(raw)
        bundle["guidance"] = {
            "path": guidance["path"],
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bundle_digest": guidance["bundle_digest"],
        }
    bundle["bundle_digest"] = canonical_digest(
        "five_arm_evidence_bundle", 1, bundle)
    (directory / "bundle.json").write_text(
        json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    return {
        "path": str(directory),
        "bundle_digest": bundle["bundle_digest"],
        "receipts": len(receipts),
        "public_key": public,
    }


_MAX_TRUST_CONFIG_BYTES = 1024 * 1024
# The fields of the v3 bootstrap configuration (``sis.v3.bootstrap``) that
# re-authenticate a qualified candidate for serving. The same names and
# formats are accepted here, so the production config file itself can be
# passed; every other field is ignored.
_TRUST_FIELDS = ("evaluator_keys", "operator_keys", "evaluation_protocol")


class TrustConfigError(ValueError):
    """The candidate trust configuration is missing or invalid."""


def _trust_keys(config: Mapping, name: str) -> dict[str, str]:
    value = config.get(name)
    if not isinstance(value, Mapping) or not value or not all(
            isinstance(k, str) and k and isinstance(v, str)
            for k, v in value.items()):
        raise TrustConfigError(f"trust_config_invalid:{name}")
    return dict(value)


def _trust_path(value, base: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def load_trust_config(path: Path) -> dict:
    """Read candidate trust anchors from a bootstrap-format JSON file.

    ``evaluator_keys`` and ``operator_keys`` map key ids to Ed25519 public
    keys (hex); ``evaluation_protocol`` is the pinned protocol document,
    inline or as a path relative to the file. ``candidate_database``, when
    present, names the default candidate registry. The authorities are
    constructed here so a malformed key fails before anything runs.
    """
    from sis.v3.candidate_authority import (CandidateDecisionAuthority,
                                            CandidateEvidenceAuthority)
    from sis.v3.evaluation_certificate import ProtocolRegistry

    path = Path(path)
    try:
        config = _json_object(
            _read_bounded(path, _MAX_TRUST_CONFIG_BYTES, "trust config"),
            "trust config")
    except (OSError, ValueError) as exc:
        raise TrustConfigError(f"trust_config_unreadable:{exc}") from exc
    missing = [name for name in _TRUST_FIELDS
               if config.get(name) in (None, "")]
    if missing:
        raise TrustConfigError("trust_config_missing:" + ",".join(missing))
    base = path.resolve().parent
    evaluator_keys = _trust_keys(config, "evaluator_keys")
    operator_keys = _trust_keys(config, "operator_keys")
    protocol = config["evaluation_protocol"]
    if isinstance(protocol, str):
        try:
            protocol = _json_object(
                _read_bounded(_trust_path(protocol, base),
                              _MAX_TRUST_CONFIG_BYTES, "evaluation protocol"),
                "evaluation protocol")
        except (OSError, ValueError) as exc:
            raise TrustConfigError(
                "trust_config_unreadable:evaluation_protocol") from exc
    if not isinstance(protocol, Mapping):
        raise TrustConfigError("trust_config_invalid:evaluation_protocol")
    try:
        protocol_digest = ProtocolRegistry().register(protocol)
    except Exception as exc:  # noqa: BLE001 - surfaced as config error
        raise TrustConfigError(
            "trust_config_invalid:evaluation_protocol") from exc
    try:
        CandidateEvidenceAuthority(trusted_evaluator_keys=evaluator_keys)
    except Exception as exc:  # noqa: BLE001
        raise TrustConfigError("trust_config_invalid:evaluator_keys") from exc
    try:
        CandidateDecisionAuthority(trusted_operator_keys=operator_keys)
    except Exception as exc:  # noqa: BLE001
        raise TrustConfigError("trust_config_invalid:operator_keys") from exc
    database = config.get("candidate_database")
    if database is not None and (not isinstance(database, str)
                                 or not database):
        raise TrustConfigError("trust_config_invalid:candidate_database")
    return {
        "path": str(path),
        "evaluator_keys": evaluator_keys,
        "operator_keys": operator_keys,
        "evaluation_protocol_digest": protocol_digest,
        "candidate_database": (_trust_path(database, base)
                               if database is not None else None),
    }


def trusted_registry_factory(trust: Mapping) -> Callable:
    """``registry_factory`` that opens a registry under ``trust``.

    The registry re-authenticates every qualified candidate's operator
    decision and evaluator evidence against the configured public keys
    and the pinned evaluation protocol before it is verified or served.
    The factory carries ``trust_anchors`` (key ids and protocol digest)
    for the report.
    """
    from sis.v3.candidate_authority import (CandidateDecisionAuthority,
                                            CandidateEvidenceAuthority)
    from sis.v3.candidates import CandidateRegistry

    evaluator_keys = dict(trust["evaluator_keys"])
    operator_keys = dict(trust["operator_keys"])
    protocol_digest = trust["evaluation_protocol_digest"]

    def factory(path):
        return CandidateRegistry(
            path,
            evidence_authority=CandidateEvidenceAuthority(
                trusted_evaluator_keys=evaluator_keys),
            decision_authority=CandidateDecisionAuthority(
                trusted_operator_keys=operator_keys),
            expected_evaluation_protocol_digest=protocol_digest)

    factory.trust_anchors = {
        "evaluator_key_ids": sorted(evaluator_keys),
        "operator_key_ids": sorted(operator_keys),
        "evaluation_protocol_digest": protocol_digest,
    }
    return factory


class _StateRoot:
    """Context manager yielding a persistent state directory as is."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __enter__(self) -> str:
        return str(self.path)

    def __exit__(self, *_exc) -> None:
        return None


def _run_root(state_dir: Path | None):
    """The run's working root: a private state directory or a temp dir.

    A state directory holds evaluator keys and the task registry, so it is
    created private (0700) and an existing one must not be readable by
    others. Leftover arm workspaces from an interrupted run are removed;
    their arms are re-run from the journal.
    """
    if state_dir is None:
        return tempfile.TemporaryDirectory(prefix="sis-five-arm-real-")
    path = Path(state_dir).resolve()
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        mode = path.stat().st_mode & 0o777
        if mode & 0o077:
            raise ValueError(
                f"state directory {path} must not be accessible to group or"
                f" others (mode {mode:o}); chmod 700 it")
    shutil.rmtree(path / "work", ignore_errors=True)
    return _StateRoot(path)


def _verify_journal_receipts(journal: RunJournal, verifier) -> None:
    """Every journaled outcome must be a receipt this verifier issued.

    A journal row is reused only when its receipt reloads from the
    verifier's store under its digest and records the same outcome, so a
    resumed run cannot import outcomes that were never evaluated here.
    """
    issued = set(verifier.issued_receipts())
    for (task_id, arm), row in journal.rows().items():
        digest = row.get("receipt_digest")
        if digest is None:
            if row.get("outcome") in ("pass", "fail"):
                raise ValueError(f"journal_row_without_receipt:{task_id}:{arm}")
            continue
        if digest not in issued:
            raise ValueError(f"journal_receipt_not_issued:{task_id}:{arm}")
        receipt = verifier.load_receipt(digest)
        if receipt.outcome != row.get("outcome") or \
                receipt.task_id != task_id:
            raise ValueError(f"journal_receipt_mismatch:{task_id}:{arm}")


def run_real(output: Path, manifest_path: Path | None, *,
             allow_shared_custody: bool = False,
             guidance_path: Path | None = None,
             candidate_registry: Path | None = None,
             agent_factory: Callable | None = None,
             registry_factory: Callable | None = None,
             executor: str = "local",
             docker_image: str | None = None,
             docker_split_user: str | None = DEFAULT_SPLIT_USER,
             docker_user: str | None = None,
             docker_runtime: str | None = None,
             require_image_digest: bool = True,
             executor_factory: Callable | None = None,
             state_dir: Path | None = None,
             workers: int = 1) -> int:
    """Execute a validated manifest with the real agent.

    ``registry_factory(path)`` opens the candidate registry with trusted
    evaluator/operator authorities and a pinned evaluation protocol
    (:func:`trusted_registry_factory`; the CLI builds it from
    ``--trust-config``). A registry without them cannot re-authenticate
    a qualified candidate, so ``candidate_registry`` without a factory is
    blocked rather than run as a campaign that can never serve.

    The manifest's ``agent.kind`` (``codex-cli`` or ``claude-code``)
    selects the availability gate, the version check and the agent.

    ``executor="docker"`` grades in
    :class:`~sis.v3.docker_sandbox.DockerSandboxExecutor` with a second
    container identity (``docker_split_user``), which gives split custody
    on Linux; ``docker_image`` defaults to the pinned evaluator image and
    ``docker_runtime`` (for example ``runsc``) is passed through when the
    executor supports it. ``executor_factory(root, protected_paths)``
    replaces the backend in tests.

    ``state_dir`` keeps the evaluator keys, task registry, receipts,
    per-task trees and the run journal across runs: an interrupted run
    started again with the same ``state_dir`` and manifest resumes from
    the journal instead of starting over. ``workers`` runs that many tasks
    concurrently with results identical to a serial run.
    """
    output = Path(output)
    manifest_path = Path(manifest_path) if manifest_path is not None else None
    state_dir = Path(state_dir) if state_dir is not None else None
    kind = _peek_agent_kind(manifest_path)
    status = _agent_status(kind)
    report: dict = {
        "schema_version": 1,
        "kind": "five_arm_learning_qualification_real_run",
        "codex_gate": status,
        "agent_gate": status,
    }

    def blocked(gate: str, note: str) -> int:
        report["evidence_class"] = "invalid"
        report["release_gate"] = gate
        report["note"] = note
        write_report(report, output)
        print(json.dumps(report, indent=2))
        return 2

    if not status["available"] or not status["authenticated"]:
        label = "Claude Code" if kind == "claude-code" else "Codex CLI"
        return blocked(
            "BLOCKED_REAL_AGENT",
            f"{label} is unavailable or unauthenticated: " + status["reason"])
    if executor not in EXECUTOR_KINDS:
        return blocked("BLOCKED_EXECUTOR",
                       f"executor must be one of {', '.join(EXECUTOR_KINDS)}")
    if type(workers) is not int or not 1 <= workers <= 256:
        return blocked("BLOCKED_EXECUTOR", "workers must be in [1, 256]")
    if manifest_path is None:
        return blocked(
            "BLOCKED_MANIFEST",
            "A real run requires a manifest with repository paths, prompts, "
            "evaluator-owned acceptance tests, base commits and a "
            "preregistered protocol.")
    try:
        document, manifest_bytes = _load_manifest(manifest_path)
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
        "holdout_repositories_used": validation.get(
            "holdout_repositories_used"),
        "holdout_snapshots_used": validation.get("holdout_snapshots_used"),
        "tasks_per_holdout_repository": validation.get(
            "tasks_per_holdout_repository"),
        "placeholders": validation["placeholders"],
        "study_tier": validation.get("study_tier"),
    }
    report["manifest"] = manifest_block
    if not validation["valid"]:
        return blocked(
            "BLOCKED_MANIFEST",
            "manifest_invalid: " + "; ".join(validation["problems"]))
    if validation["placeholders"]:
        return blocked(
            "BLOCKED_MANIFEST",
            f"manifest still contains {validation['placeholders']} "
            "placeholder value(s)")
    if not validation["ready"]:
        return blocked(
            "BLOCKED_MANIFEST",
            "manifest_not_ready: the real-agent gate executes only a"
            " powered, preregistered, repository-covered study"
            + (" (" + "; ".join(validation["problems"]) + ")"
               if validation["problems"] else ""))

    injected = agent_factory is not None
    expected_version = _normalized_version(
        document["agent"].get("cli_version"))
    kind = document["agent"].get("kind")
    installed_version = (None if injected
                         else _installed_version(kind, status["binary"]))
    if not injected:
        if expected_version is None:
            return blocked(
                "BLOCKED_AGENT_VERSION",
                "manifest agent.cli_version is not a version string")
        if installed_version != expected_version:
            return blocked(
                "BLOCKED_AGENT_VERSION",
                f"installed {kind} version {installed_version!r} does not "
                f"match the manifest {expected_version!r}")
    anchor = _git_anchor(manifest_path)
    learned = tuple(sorted(
        item["repo_snapshot_digest"] for item in document["repositories"]
        if item["partition"] == "induction"))
    holdout_digests = tuple(sorted(
        item["repo_snapshot_digest"] for item in document["repositories"]
        if item["partition"] == "holdout"))
    learned_bundle = None
    if guidance_path is None and document.get("guidance_bundle_digest") is not None:
        return blocked(
            "BLOCKED_GUIDANCE",
            "manifest precommits a guidance bundle but none was supplied")
    if candidate_registry is not None and guidance_path is None:
        return blocked(
            "BLOCKED_GUIDANCE",
            "candidate_registry requires a guidance bundle")
    if candidate_registry is not None and registry_factory is None:
        return blocked(
            "BLOCKED_GUIDANCE",
            "candidate_registry_untrusted: a candidate registry needs "
            "trusted evaluator/operator keys and a pinned evaluation "
            "protocol (--trust-config) to verify or serve candidates")
    if guidance_path is not None:
        registry = None
        try:
            if candidate_registry is not None:
                registry = registry_factory(candidate_registry)
            learned_bundle = _load_guidance_bundle(
                guidance_path,
                induction_digests=learned,
                holdout_digests=holdout_digests,
                precommitted_digest=document.get("guidance_bundle_digest"),
                registry=registry,
                study_task_ids=[task["task_id"] for task in document["tasks"]],
                trusted_evaluator_key_ids=(
                    (getattr(registry_factory, "trust_anchors", None) or {})
                    .get("evaluator_key_ids")
                    if registry is not None else None))
        except (OSError, ValueError, RuntimeError) as exc:
            return blocked(
                "BLOCKED_GUIDANCE", f"guidance_bundle_unreadable:{exc}")
        finally:
            if registry is not None:
                registry.close()
    guidance_source = (learned_bundle["source"] if learned_bundle is not None
                       else "fixed_control")

    protocol = document["protocol"]
    design_arms = tuple(protocol.get("arms") or ())
    budget = BudgetCaps(
        wall_seconds=protocol["budget"]["wall_seconds"],
        token_budget=protocol["budget"]["token_budget"],
        tool_budget=protocol["budget"]["tool_budget"])
    custody = "shared" if allow_shared_custody else None
    provenance = {
        "agent": "injected" if injected else kind,
        "expected_cli_version": expected_version,
        "cli_version": installed_version,
        "cli_version_matches": bool(
            not injected and installed_version == expected_version),
        "custody": "shared" if allow_shared_custody else "split",
        # The tier the manifest declared before the run; only a manifest
        # declared confirmatory can yield a confirmatory label.
        "study_tier": validation.get("study_tier"),
        "guidance_source": guidance_source,
        "guidance_candidates_verified": bool(
            learned_bundle is not None
            and learned_bundle["candidates_verified"]),
        "preregistration": anchor,
        "preregistration_anchored": anchor["anchored"],
        "holdout_repositories": len(
            (document.get("partitions") or {}).get("holdout") or []),
        "holdout_repositories_used": validation.get(
            "holdout_repositories_used"),
        "manifest_digest": validation["manifest_digest"],
    }
    try:
        run_root = _run_root(state_dir)
    except (OSError, ValueError) as exc:
        return blocked("BLOCKED_STATE", f"state_dir_unusable:{exc}")
    with run_root as temp:
        root = Path(temp)
        profile = EvaluationRuntimeProfile(
            cpu_seconds=budget.wall_seconds,
            wall_seconds=budget.wall_seconds, process_count=None)
        protected = (root / "keys", root / "registry")
        try:
            if executor_factory is not None:
                backend = executor_factory(root / "exec", protected)
            else:
                backend = build_study_executor(
                    executor, root / "exec", protected_paths=protected,
                    image=docker_image if executor == "docker" else None,
                    split_user=docker_split_user,
                    user=docker_user, runtime=docker_runtime,
                    require_image_digest=require_image_digest)
            verifier = OutcomeVerifier(
                executor=backend,
                key_dir=root / "keys", registry_dir=root / "registry",
                allow_shared_custody=allow_shared_custody,
                limits=ResourceLimits(
                    wall_seconds=budget.wall_seconds,
                    cpu_seconds=budget.wall_seconds,
                    memory_bytes=profile.task_memory_bytes,
                    process_count=None),
                runtime_profile=profile)
        except Exception as exc:
            return blocked(
                "BLOCKED_EXECUTOR",
                f"executor_unavailable:{type(exc).__name__}: {exc}")
        executor_facts = executor_description(backend)
        executor_facts["kind"] = executor
        provenance["executor"] = executor_facts
        if not allow_shared_custody and not executor_facts[
                "supports_split_custody"]:
            provenance["custody"] = "unavailable"
        executions: dict[str, str] = {}
        try:
            tasks, prompts, classes = _real_tasks(
                document, verifier, custody=custody,
                tree_root=root / "trees", executions=executions)
        except Exception as exc:
            gate = ("BLOCKED_SPLIT_CUSTODY" if "split_custody" in str(exc)
                    else "BLOCKED_MANIFEST")
            return blocked(
                gate, f"campaign_setup_failed:{type(exc).__name__}: {exc}")
        arm_order_seed = int(validation["manifest_digest"][:16], 16)
        journal = None
        if state_dir is not None:
            identity = {
                "manifest_digest": validation["manifest_digest"],
                "protocol_digest": protocol.get("protocol_digest"),
                "arms": list(design_arms),
                "arm_order_seed": str(arm_order_seed),
                "agent": provenance["agent"],
                "custody": provenance["custody"],
                "executor": executor,
                "guidance_bundle_digest": (learned_bundle["bundle_digest"]
                                           if learned_bundle is not None
                                           else None),
                "guidance_source": guidance_source,
                "evaluator_key_id": verifier.public_key_record()["key_id"],
            }
            try:
                journal = RunJournal(root / "journal.jsonl", identity)
                _verify_journal_receipts(journal, verifier)
            except (StudyRuntimeError, BenchmarkError, ValueError) as exc:
                return blocked("BLOCKED_RESUME", f"journal_unusable:{exc}")

        served: dict = {}
        serving_decisions: list = []
        serving_registry = None
        if learned_bundle is not None and learned_bundle["candidates_verified"]:
            # Verified candidates are served the way SIS serves them: per
            # task, through the governed gateway, so scope, applicability
            # and counterexample gates decide what each task receives.
            bundle_payload = learned_bundle["bundles"]
            try:
                serving_registry = registry_factory(candidate_registry)
                provider = _serving_provider(
                    serving_registry, learned_bundle,
                    task_contexts=_task_contexts(document, tasks),
                    repositories=document["repositories"], served=served,
                    decisions=serving_decisions)
            except Exception as exc:
                if serving_registry is not None:
                    serving_registry.close()
                return blocked(
                    "BLOCKED_GUIDANCE",
                    f"guidance_serving_unavailable:{type(exc).__name__}:"
                    f" {exc}")
        elif learned_bundle is not None:
            bundle_payload = learned_bundle["bundles"]

            def provider(task, arm):
                guidance = _served_guidance(learned_bundle, arm)
                served[(task.task_id, arm)] = bool(
                    guidance is not None and guidance.helpful_next_checks)
                return guidance
        else:
            bundle_payload = {
                failure_class: {
                    arm: list(_fixed_guidance(failure_class, arm)
                              .helpful_next_checks)
                    for arm in design_arms if arm != "A"}
                for failure_class in sorted(set(classes.values()))}

            def provider(task, arm):
                guidance = _fixed_guidance(classes[task.task_id], arm)
                served[(task.task_id, arm)] = bool(
                    guidance is not None and guidance.helpful_next_checks)
                return guidance

        guidance_routing = ("governed_serving" if serving_registry is not None
                            else "static_bundle" if learned_bundle is not None
                            else "fixed_control")
        provenance["guidance_routing"] = guidance_routing
        misleading = frozenset(
            task["task_id"] for task in document["tasks"]
            if task.get("misleading") is True)

        def close_serving():
            if serving_registry is not None:
                serving_registry.close()

        resumed_rows = 0
        if journal is not None:
            # Restore what the provider recorded for journaled arms, then
            # record it for every new arm as soon as the arm finishes.
            for (task_id, arm), _ in sorted(journal.rows().items()):
                notes = journal.annotations(task_id, arm)
                served[(task_id, arm)] = bool(notes.get("served"))
                if isinstance(notes.get("decision"), Mapping):
                    serving_decisions.append(dict(notes["decision"]))
            resumed_rows = journal.resumed_rows

            def annotate(task_id, arm):
                decision = next(
                    (item for item in reversed(serving_decisions)
                     if item.get("task_id") == task_id
                     and item.get("arm") == arm), None)
                return {"served": bool(served.get((task_id, arm))),
                        "decision": decision}
            journal.annotator = annotate

        factory = agent_factory or _default_agent_factory(kind)
        try:
            agent = factory(prompts, budget, document["agent"]["model"])
        except RuntimeError as exc:
            close_serving()
            return blocked("BLOCKED_REAL_AGENT", str(exc))
        try:
            expected_execution = {
                str(Path(repo["path"]).resolve()):
                    repo["repo_execution_digest"]
                for repo in document["repositories"]}
            expected_execution.update(executions)
            campaign = FiveArmCampaign(
                harness=BenchmarkHarness(
                    verifier=verifier, work_root=root / "work",
                    expected_execution=expected_execution),
                tasks=tasks, agent=agent, budget=budget, protocol=protocol,
                context_provider=provider, served_map=served,
                misleading_tasks=misleading,
                learned_repo_digests=learned, real_agent=True,
                hidden_holdout=True, provenance=provenance, arms=design_arms,
                arm_order_seed=arm_order_seed,
                repository_ids={
                    task["task_id"]: task["repository_id"]
                    for task in document["tasks"]},
                journal=journal, workers=workers)
            campaign.validate()
        except Exception as exc:
            close = getattr(agent, "close", None)
            if callable(close):
                close()
            close_serving()
            return blocked(
                "BLOCKED_MANIFEST",
                f"campaign_setup_failed:{type(exc).__name__}: {exc}")
        try:
            report = campaign.run()
        except BenchmarkError as exc:
            return blocked(
                "BLOCKED_CUSTODY",
                f"campaign_custody_failure:{type(exc).__name__}: {exc}")
        except Exception as exc:
            return blocked(
                "BLOCKED_CAMPAIGN",
                f"campaign_failed:{type(exc).__name__}: {exc}")
        finally:
            close = getattr(agent, "close", None)
            if callable(close):
                close()
            close_serving()
        analysis = report["learning_qualification"]
        # Serving decisions in serial run order (task order, then each
        # task's seeded arm order), whether the run was resumed or ran
        # tasks in parallel.
        position = {}
        for index, row in enumerate(report.get("per_task", [])):
            for offset, arm in enumerate(row.get("arm_order") or ()):
                position[(row["task_id"], arm)] = (index, offset)
        serving_decisions.sort(key=lambda item: position.get(
            (item.get("task_id"), item.get("arm")), (len(position), 0)))
        report["kind"] = (
            "primary_contrast_learning_qualification_real_run"
            if design_arms == PRIMARY_CONTRAST_ARMS
            else "five_arm_learning_qualification_real_run")
        report["manifest"] = manifest_block
        report["codex_gate"] = status
        report["agent_gate"] = status
        report["executor"] = executor_facts
        report["run"] = {
            "workers": workers,
            "state_dir": str(state_dir) if state_dir is not None else None,
            "resumed_rows": resumed_rows,
            "journal_head": journal.head if journal is not None else None,
        }
        report["evidence_class"] = analysis["evidence_class"]
        report["release_gate"] = analysis["release_gate"]
        report["evaluator_runtime"] = profile.as_dict()
        report["evaluator_runtime_digest"] = profile.digest
        report["bootstrap"] = verifier.bootstrap().as_dict()
        report["guidance"] = {
            "source": guidance_source,
            "bundles": bundle_payload,
            "digest": canonical_digest("guidance_bundles", 1, bundle_payload),
            "bundle_digest": (learned_bundle["bundle_digest"]
                              if learned_bundle is not None else None),
            "candidates_verified": (learned_bundle["candidates_verified"]
                                    if learned_bundle is not None else None),
            "training_repository_digests": (
                list(learned_bundle["training_repository_digests"])
                if learned_bundle is not None else None),
            "routing": guidance_routing,
            "qualification": (learned_bundle.get("qualification")
                              if learned_bundle is not None else None),
            "trust_anchors": (getattr(registry_factory, "trust_anchors",
                                      None)
                              if candidate_registry is not None else None),
            "serving_decisions": serving_decisions,
            "misleading_tasks": sorted(misleading),
        }
        report["arm_order_seed"] = int(
            validation["manifest_digest"][:16], 16)
        report["receipts_issued"] = len(verifier.issued_receipts())
        report["note"] = (
            "Real-agent execution over the supplied manifest. Guidance is "
            "recorded with its source; fixed prompts are a control "
            "condition, not learned components. Every arm row carries an "
            "evaluator-verified outcome and receipt digest. The evidence "
            "class follows the paired analysis and provenance, not this "
            "note.")
        report_sha256 = hashlib.sha256(
            (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        ).hexdigest()
        guidance_export = None
        if learned_bundle is not None:
            guidance_export = {
                "path": str(guidance_path),
                "bytes": learned_bundle["raw"],
                "bundle_digest": learned_bundle["bundle_digest"],
            }
        try:
            bundle = _export_evidence(
                output, report_sha256, verifier, manifest_path,
                validation["manifest_digest"], manifest_bytes,
                guidance=guidance_export)
        except Exception as exc:
            report["evidence_bundle"] = {
                "error": f"{type(exc).__name__}: {exc}"}
            report["evidence_class"] = "invalid"
            report["release_gate"] = "INVALID_EVIDENCE_BUNDLE"
            write_report(report, output)
            print(json.dumps(report["evidence_bundle"], indent=2))
            return 1
        report["evidence_bundle"] = bundle
        write_report(report, output)
        print(json.dumps({
            "kind": report["kind"],
            "tasks": analysis["tasks"],
            "evidence_class": analysis["evidence_class"],
            "efficacy_claim": analysis["efficacy_claim"],
            "release_gate": analysis["release_gate"],
            "underpowered": analysis["underpowered"],
            "confirmatory_eligible": analysis["confirmatory_eligible"],
            "decisive_contrast": analysis["decisive_contrast"],
            "receipts_issued": report["receipts_issued"],
            "evidence_bundle": bundle["path"],
            "output": str(output),
        }, indent=2))
        return 0 if analysis["evidence_class"] in (
            "exploratory", "confirmatory") else 1


def _registry_options(parser: argparse.ArgumentParser, args):
    """Resolve ``(candidate_registry, registry_factory)`` or exit 2.

    A candidate registry is only useful with trust anchors: without them
    no qualified candidate re-authenticates and nothing can be served, so
    that combination is refused unless ``--record-unverified``
    acknowledges recording the bundle as ``learned_unverified``.
    """
    if args.trust_config is not None:
        if args.record_unverified:
            parser.error("--record-unverified contradicts --trust-config")
        try:
            trust = load_trust_config(args.trust_config)
        except TrustConfigError as exc:
            parser.error(f"--trust-config {args.trust_config}: {exc}")
        registry = args.candidate_registry or trust["candidate_database"]
        if registry is None:
            parser.error("--trust-config requires --candidate-registry (or"
                         " candidate_database in the trust config)")
        if args.guidance_bundle is None:
            parser.error("--trust-config requires --guidance-bundle")
        return registry, trusted_registry_factory(trust)
    if args.record_unverified:
        if args.guidance_bundle is None:
            parser.error("--record-unverified requires --guidance-bundle")
        if args.candidate_registry is not None:
            print("five_arm_campaign: --record-unverified: candidate registry"
                  f" {args.candidate_registry} is not consulted; the bundle"
                  " is recorded as learned_unverified", file=sys.stderr)
        return None, None
    if args.candidate_registry is not None:
        parser.error(
            "--candidate-registry requires --trust-config: without trusted"
            " evaluator/operator keys and a pinned evaluation protocol no"
            " candidate can be verified or served (pass --record-unverified"
            " instead to record the bundle as learned_unverified)")
    return None, None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--real-agent", action="store_true")
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--arms", choices=("five", "primary"),
                        default="five",
                        help="demo design; a real-agent manifest declares"
                             " its own arms")
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--allow-local-executor", action="store_true",
                        help="local execution is development-only")
    parser.add_argument("--allow-shared-custody", action="store_true",
                        help="development-only: grade private acceptance "
                             "tests beside the submission instead of split "
                             "custody")
    parser.add_argument("--guidance-bundle", type=Path,
                        help="frozen learned guidance bundle (JSON); omit "
                             "for the fixed control prompts")
    parser.add_argument("--candidate-registry", type=Path,
                        help="candidate registry that must resolve every"
                             " bundle step to a qualified record, which is"
                             " then served per task; requires"
                             " --trust-config")
    parser.add_argument("--trust-config", type=Path,
                        help="JSON trust anchors in the v3 bootstrap format"
                             " (evaluator_keys, operator_keys,"
                             " evaluation_protocol; optional"
                             " candidate_database); the production v3"
                             " config file may be passed as is")
    parser.add_argument("--record-unverified", action="store_true",
                        help="acknowledge recording-only mode: the guidance"
                             " bundle is recorded as learned_unverified and"
                             " no candidate is verified or served")
    parser.add_argument("--executor", choices=EXECUTOR_KINDS,
                        default="local",
                        help="evaluator backend for --real-agent: local"
                             " (development; Linux needs"
                             " --allow-shared-custody) or docker (bounded"
                             " container with a second identity: split"
                             " custody on Linux)")
    parser.add_argument("--docker-image", default=None,
                        help="evaluator image (default: the pinned"
                             f" {DEFAULT_STUDY_IMAGE})")
    parser.add_argument("--docker-split-user", default=DEFAULT_SPLIT_USER,
                        help="numeric uid:gid that runs the submission under"
                             " split custody (default %(default)s)")
    parser.add_argument("--docker-user", default=None,
                        help="numeric uid:gid of the evaluator identity in"
                             " the container (default: the executor's)")
    parser.add_argument("--docker-runtime", default=None,
                        help="OCI runtime for the containers, e.g. runsc;"
                             " refused if the executor cannot set one")
    parser.add_argument("--allow-unpinned-image", action="store_true",
                        help="development-only: accept a --docker-image that"
                             " is not digest-pinned")
    parser.add_argument("--state-dir", type=Path, default=None,
                        help="private directory for evaluator keys,"
                             " receipts, task trees and the run journal;"
                             " rerunning with the same directory resumes an"
                             " interrupted run")
    parser.add_argument("--workers", type=int, default=1,
                        help="tasks run concurrently (arms of one task stay"
                             " sequential; results equal a serial run)")
    args = parser.parse_args(argv)
    if args.executor == "local" and not args.allow_local_executor:
        parser.error("local executor requires --allow-local-executor")
    if args.demo and args.real_agent:
        parser.error("choose --demo or --real-agent")
    if args.real_agent:
        if args.arms != "five":
            parser.error("--arms applies to --demo; the manifest declares"
                         " the real-agent arms")
        if args.executor == "docker" and args.allow_shared_custody:
            parser.error("--executor docker grades under split custody;"
                         " drop --allow-shared-custody")
        candidate_registry, registry_factory = _registry_options(
            parser, args)
        return run_real(args.output, args.manifest,
                        allow_shared_custody=args.allow_shared_custody,
                        guidance_path=args.guidance_bundle,
                        candidate_registry=candidate_registry,
                        registry_factory=registry_factory,
                        executor=args.executor,
                        docker_image=args.docker_image,
                        docker_split_user=args.docker_split_user,
                        docker_user=args.docker_user,
                        docker_runtime=args.docker_runtime,
                        require_image_digest=not args.allow_unpinned_image,
                        state_dir=args.state_dir,
                        workers=args.workers)
    if args.executor != "local" or args.state_dir is not None \
            or args.workers != 1:
        parser.error("--executor, --state-dir and --workers apply to"
                     " --real-agent")
    if args.trust_config is not None or args.record_unverified:
        parser.error("--trust-config and --record-unverified apply to"
                     " --real-agent")
    selected = (PRIMARY_CONTRAST_ARMS if args.arms == "primary"
                else GOVERNED_ARMS)
    return run_demo(args.output, arms=selected)


if __name__ == "__main__":
    raise SystemExit(main())
