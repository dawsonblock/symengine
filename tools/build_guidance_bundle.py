#!/usr/bin/env python3
"""Learn, qualify and sign a ``learned_guidance_bundle`` (schema v2).

The bundle that ``tools/five_arm_campaign.py --guidance-bundle`` serves to
arms B (memory), C (skills), D (symbolic procedures) and E (all three) is
produced here, from the **induction** partition only:

1. **Training split.** The pinned agent runs every training task without
   guidance (arm A). Each run is graded by the evaluator; passing runs
   are verified episodes. The submission's source change is captured
   before its workspace is removed.
2. **Derivation** (``sis.v3.learning``), deterministic and evidence-bound:

   - C, skill: :func:`~sis.v3.learning.induce_strategies` over the tool
     actions every verified solve shared (two solves in two repositories
     at least, by default);
   - D, symbolic procedure: :func:`~sis.v3.learning.induce_structural_change`
     on each verified single-file source change, the most frequent
     operator substitution becoming a :func:`~sis.v3.learning.structure_to_record`
     procedure;
   - B, experience memory: the size of the verified fixes (source files
     and lines changed) per failure class.

3. **Qualification split** (other induction repositories, disjoint from
   training). Arm A once, then every candidate alone; a candidate is
   kept when :func:`~sis.v3.learning.select_improvement` finds net paired
   wins across ``--min-repositories`` repositories (``--rule
   non_inferior`` accepts wins >= losses with at least one assisted pass).
4. **Signing.** Each kept candidate is submitted to the candidate
   registry and qualified with evaluator-signed evidence and an
   operator-signed decision. The keys are real keys from ``--trust-config``:
   the evaluator key directory signs the outcome receipts and the
   evidence, the operator key directory signs the decision, and both
   public keys must be listed in the trust configuration.
5. **Bundle.** One candidate per arm B/C/D, its training repositories,
   and the qualification split (repository snapshots, tasks and the
   signed receipts) — the runner refuses a bundle whose qualification
   evidence came from a study holdout repository, from its own training
   repositories, or from a study task.

The learning spec (``kind: guidance_learning_spec``) lists the induction
repositories (``learning_split``: ``training`` or ``qualification``), their
tasks (the format ``tools/import_study_tasks.py --partition induction``
writes), the pinned agent and the per-task budget. ``--exclude-spec``
names the study spec or manifest whose holdout repositories must not
appear here, by snapshot or by Git lineage.

Usage:
    # print the public keys to put in the trust configuration
    PYTHONPATH=src python3 tools/build_guidance_bundle.py --print-public-keys \\
        --evaluator-key-dir /secure/keys/evaluator \\
        --operator-key-dir /secure/keys/operator
    PYTHONPATH=src python3 tools/build_guidance_bundle.py \\
        --learning-spec /study/learning.json --exclude-spec /study/spec.json \\
        --trust-config /secure/v3.json --candidate-registry /secure/candidates.db \\
        --evaluator-key-dir /secure/keys/evaluator \\
        --operator-key-dir /secure/keys/operator \\
        --executor docker --state-dir /study/state/bundle \\
        -o /study/guidance_bundle.json

Exit 0 writes the bundle; exit 1 writes only ``<output>.report.json``
(for example when no candidate of some arm qualified). Nothing here
claims efficacy: the bundle is the frozen treatment for a study.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import importlib.util
import json
import os
import sys
import tempfile
from collections import Counter
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sis.v3 import gitquery  # noqa: E402
from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.candidate_authority import (  # noqa: E402
    CandidateDecisionAuthority, CandidateEvidenceAuthority)
from sis.v3.candidates import CandidateRegistry, content_digest  # noqa: E402
from sis.v3.contracts import (CandidateV1, GuidanceV1,  # noqa: E402
                              TaskEnvelopeV1, canonical_digest)
from sis.v3.efficacy_manifest import _git_lineage  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.learning import (CandidateTrial, EpisodeEvidence,  # noqa: E402
                             induce_strategies, induce_structural_change,
                             select_improvement, structure_to_record)
from sis.v3.learning_qualification import AGENT_KINDS  # noqa: E402
from sis.v3.runner import (ResourceLimits, repository_execution_digest,  # noqa: E402
                           tree_digest)
from sis.v3.study_runtime import (DEFAULT_SPLIT_USER, EXECUTOR_KINDS,  # noqa: E402
                                  StudyRuntimeError, build_study_executor,
                                  materialize_commit)
from sis.v3.verifier import (EvaluatorKeyStore, OutcomeVerifier,  # noqa: E402
                             verify_receipt_signature)


def _campaign_module():
    spec = importlib.util.spec_from_file_location(
        "sis_five_arm_campaign_tool", ROOT / "tools" / "five_arm_campaign.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaign = _campaign_module()

ARM_TYPES = {"B": "experience_memory", "C": "skill_instruction",
             "D": "symbolic_procedure"}
GENERATOR = "sis-build-guidance-bundle-v1"
MAX_SPEC_BYTES = 8 << 20


class BundleBuildError(RuntimeError):
    """The learning spec or the learning run cannot produce a bundle."""


def _require(condition, message: str) -> None:
    if not condition:
        raise BundleBuildError(message)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _is_test_path(path: str) -> bool:
    parts = path.split("/")
    name = parts[-1]
    return name.endswith(".py") and (
        name.startswith("test_") or name.endswith("_test.py")
        or any(part in ("test", "tests") for part in parts[:-1]))


# --------------------------------------------------------------------- #
# keys
# --------------------------------------------------------------------- #
def signing_keys(evaluator_key_dir: Path, operator_key_dir: Path) -> dict:
    """Load (or create) the evaluator and operator signing keys."""
    evaluator = EvaluatorKeyStore(evaluator_key_dir)
    eval_seed, eval_public = evaluator.load_or_create()
    operator = EvaluatorKeyStore(operator_key_dir)
    op_seed, op_public = operator.load_or_create()
    _require(evaluator.key_id != operator.key_id,
             "evaluator and operator keys must differ")
    return {
        "evaluator": (evaluator.key_id, eval_seed, eval_public.hex()),
        "operator": (operator.key_id, op_seed, op_public.hex()),
    }


def check_keys_trusted(keys: Mapping, trust: Mapping) -> None:
    """Both signing keys must be the ones the trust configuration names."""
    key_id, _, public = keys["evaluator"]
    _require(trust["evaluator_keys"].get(key_id) == public,
             f"evaluator key {key_id} ({public}) is not in the trust"
             " configuration's evaluator_keys; run --print-public-keys and"
             " add it")
    key_id, _, public = keys["operator"]
    _require(trust["operator_keys"].get(key_id) == public,
             f"operator key {key_id} ({public}) is not in the trust"
             " configuration's operator_keys; run --print-public-keys and"
             " add it")


# --------------------------------------------------------------------- #
# spec
# --------------------------------------------------------------------- #
def load_learning_spec(path: Path) -> dict:
    raw = Path(path).read_bytes()
    _require(len(raw) <= MAX_SPEC_BYTES, "learning spec exceeds the size bound")
    document = campaign._json_object(raw, "learning spec")
    _require(document.get("schema_version") == 1,
             "learning spec schema_version must be 1")
    _require(document.get("kind") == "guidance_learning_spec",
             "learning spec kind must be guidance_learning_spec")
    return document


def _repositories(spec: Mapping) -> dict[str, dict]:
    items = spec.get("repositories")
    _require(isinstance(items, list) and items,
             "learning spec needs repositories")
    by_id: dict[str, dict] = {}
    for index, item in enumerate(items):
        label = f"repositories[{index}]"
        _require(isinstance(item, Mapping), label + " must be an object")
        repository_id = item.get("repository_id")
        _require(isinstance(repository_id, str) and repository_id
                 and repository_id not in by_id,
                 label + " needs a unique repository_id")
        _require(item.get("partition", "induction") == "induction",
                 label + " must be an induction repository")
        split = item.get("learning_split")
        _require(split in ("training", "qualification"),
                 label + ".learning_split must be training or qualification")
        raw = Path(str(item.get("path") or ""))
        _require(raw.is_dir() and not raw.is_symlink(),
                 label + ".path is not a directory")
        root = raw.resolve()
        toplevel = gitquery.query(root, "rev-parse", "--show-toplevel")
        _require(toplevel is not None and Path(toplevel).resolve() == root,
                 label + " is not the root of a Git checkout")
        _require(gitquery.worktree_matches_head(root) is True,
                 label + " has uncommitted changes")
        head = gitquery.query(root, "rev-parse", "HEAD")
        by_id[repository_id] = {
            "repository_id": repository_id,
            "path": str(root),
            "split": split,
            "head": head,
            "repo_snapshot_digest": tree_digest(root, version=3),
            "lineage": _git_lineage(root),
            "hidden_tests": item.get("hidden_tests"),
        }
    splits = {item["split"] for item in by_id.values()}
    _require(splits == {"training", "qualification"},
             "the learning spec needs training and qualification"
             " repositories")
    training = {item["repo_snapshot_digest"] for item in by_id.values()
                if item["split"] == "training"}
    qualification = {item["repo_snapshot_digest"]
                     for item in by_id.values()
                     if item["split"] == "qualification"}
    _require(not training & qualification,
             "a qualification repository has the same snapshot as a"
             " training repository")
    lineages = {}
    for item in by_id.values():
        if item["lineage"] is None:
            continue
        other = lineages.setdefault(item["lineage"], item)
        _require(other is item or other["split"] == item["split"],
                 f"{item['repository_id']} and {other['repository_id']}"
                 " share a lineage across the training/qualification split")
    return by_id


def _excluded(exclude: Mapping | None) -> tuple[set[str], set[str], set[str]]:
    """Holdout snapshot digests, lineages and task ids of the study."""
    if exclude is None:
        return set(), set(), set()
    digests, lineages = set(), set()
    for item in exclude.get("repositories") or ():
        if not isinstance(item, Mapping) or item.get("partition") != "holdout":
            continue
        declared = item.get("repo_snapshot_digest")
        if isinstance(declared, str):
            digests.add(declared)
        path = item.get("path")
        if isinstance(path, str) and Path(path).is_dir():
            digests.add(tree_digest(Path(path), version=3))
            lineage = _git_lineage(Path(path))
            if lineage is not None:
                lineages.add(lineage)
    tasks = {item.get("task_id") for item in exclude.get("tasks") or ()
             if isinstance(item, Mapping)}
    return digests, lineages, tasks


# --------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------- #
def _hidden_digest(acceptance: Mapping, material: Mapping[str, bytes]) -> str:
    """The task's acceptance contract: its test, and any support files.

    A task without support files keeps its test file's own SHA-256, as
    before; support files (verified by ``_acceptance_material``) change
    what the test does, so a task with them binds every file by path.
    """
    if not acceptance.get("support_files") and acceptance.get(
            "hidden_tests_digest"):
        return acceptance["hidden_tests_digest"]
    if acceptance.get("support_files"):
        return canonical_digest("acceptance_material", 1, {
            name: hashlib.sha256(data).hexdigest()
            for name, data in sorted(material.items())})
    return hashlib.sha256(b"".join(material.values())).hexdigest()


class LearningRun:
    """Verifier, task trees and harness for the learning and qualification runs."""

    def __init__(self, spec: Mapping, repositories: Mapping[str, dict], *,
                 state_dir: Path, evaluator_key_dir: Path, executor: str,
                 allow_shared_custody: bool, docker_image, docker_split_user,
                 docker_runtime, require_image_digest: bool,
                 executor_factory: Callable | None = None) -> None:
        budget = spec.get("budget")
        _require(isinstance(budget, Mapping), "learning spec needs a budget")
        self.budget = BudgetCaps(
            wall_seconds=budget.get("wall_seconds"),
            token_budget=budget.get("token_budget"),
            tool_budget=budget.get("tool_budget"))
        self.repositories = repositories
        self.state_dir = state_dir
        protected = (evaluator_key_dir, state_dir / "registry")
        if executor_factory is not None:
            backend = executor_factory(state_dir / "exec", protected)
        else:
            backend = build_study_executor(
                executor, state_dir / "exec", protected_paths=protected,
                image=docker_image if executor == "docker" else None,
                split_user=docker_split_user, runtime=docker_runtime,
                require_image_digest=require_image_digest)
        profile = EvaluationRuntimeProfile(
            cpu_seconds=self.budget.wall_seconds,
            wall_seconds=self.budget.wall_seconds, process_count=None)
        self.verifier = OutcomeVerifier(
            executor=backend, key_dir=evaluator_key_dir,
            registry_dir=state_dir / "registry",
            allow_shared_custody=allow_shared_custody,
            limits=ResourceLimits(
                wall_seconds=self.budget.wall_seconds,
                cpu_seconds=self.budget.wall_seconds,
                memory_bytes=profile.task_memory_bytes, process_count=None),
            runtime_profile=profile)
        self.custody = "shared" if allow_shared_custody else None
        self.harness = BenchmarkHarness(verifier=self.verifier,
                                        work_root=state_dir / "work")
        self.tasks: dict[str, dict] = {}

    def register(self, task: Mapping) -> tuple[TaskEnvelopeV1, Path]:
        task_id = task["task_id"]
        repository = self.repositories[task["repository_id"]]
        tree = self.state_dir / "trees" / hashlib.sha256(
            task_id.encode()).hexdigest()[:24]
        if tree.exists():
            import shutil
            shutil.rmtree(tree)
        tree.parent.mkdir(parents=True, exist_ok=True)
        commit = task.get("base_commit") or repository["head"]
        try:
            materialize_commit(repository["path"], commit, tree)
        except StudyRuntimeError as exc:
            raise BundleBuildError(f"{task_id}: {exc}") from exc
        material = campaign._acceptance_material(
            task, {"hidden_tests": repository.get("hidden_tests") or {}})
        statement = hashlib.sha256(task["prompt"].encode("utf-8")).hexdigest()
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id, criterion_version="v1",
            argv=tuple(task["acceptance"]["argv"]), files=material,
            base_commit=commit, statement_digest=statement,
            failure_class=task["failure_class"], custody=self.custody)
        envelope = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(tree, version=3),
            base_commit=commit, task_statement_digest=statement,
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=self.budget.wall_seconds,
            token_budget=self.budget.token_budget,
            tool_budget=self.budget.tool_budget,
            actor_id="agent", evaluator_task_ref=task_id)
        self.tasks[task_id] = {
            "task": dict(task), "tree": tree,
            "repository_id": task["repository_id"],
            "repository_digest": repository["repo_snapshot_digest"],
            "hidden_digest": _hidden_digest(task["acceptance"], material),
            "execution": repository_execution_digest(tree),
        }
        return envelope, tree

    def run(self, tasks, agent, *, arm: str, provider=None, observer=None):
        return self.harness.run(
            list(tasks), agent, budget=self.budget, arms=(arm,),
            context_provider=provider, submission_observer=observer)

    def receipt(self, digest: str):
        receipt = self.verifier.load_receipt(digest)
        public = self.verifier.public_key_record()["public_key"]
        if not verify_receipt_signature(receipt, public):
            raise BundleBuildError("receipt_signature_invalid")
        return receipt


# --------------------------------------------------------------------- #
# derivation
# --------------------------------------------------------------------- #
def capture_change(base: Path, workspace: Path) -> dict:
    """Source files a verified submission changed, with operator changes."""
    changed, lines, structures = [], 0, []
    for path in sorted(workspace.rglob("*.py")):
        relative = path.relative_to(workspace).as_posix()
        if ".git" in relative.split("/") or _is_test_path(relative):
            continue
        before_path = base / relative
        after = path.read_bytes()
        before = before_path.read_bytes() if before_path.is_file() else None
        if before == after:
            continue
        changed.append(relative)
        before_text = (before or b"").decode("utf-8", "replace").splitlines()
        after_text = after.decode("utf-8", "replace").splitlines()
        lines += sum(1 for line in difflib.unified_diff(
            before_text, after_text, lineterm="", n=0)
            if line[:1] in "+-" and not line.startswith(("+++", "---")))
        if before is not None:
            structures.append((relative, before, after))
    return {"files": changed, "lines": lines, "pairs": structures}


def derive_candidates(episodes: list[dict], *, min_support: int) -> dict:
    """At most one candidate per arm B/C/D from verified training episodes."""
    verified = [item for item in episodes if item["outcome"] in ("pass", "fail")]
    passes = [item for item in verified if item["outcome"] == "pass"]
    candidates: dict[str, dict] = {}
    reasons: dict[str, str] = {}
    # C — recurring tool actions of verified solves.
    evidence = [EpisodeEvidence(
        episode_id=item["task_id"], repository_id=item["repository_id"],
        failure_signature=item["failure_class"], outcome=item["outcome"],
        receipt_digest=item["receipt_digest"],
        diagnostic_actions=tuple(sorted(set(item["actions"])))[:32],
        verified=True) for item in verified]
    strategies = induce_strategies(
        evidence, min_successes=min_support,
        min_distinct_repositories=min_support)
    if strategies:
        best = max(strategies, key=lambda s: (len(s.supporting_receipts),
                                              s.candidate_id))
        candidates["C"] = {
            "title": f"Workflow for {best.failure_signature}",
            "text": (f"In {len(best.supporting_receipts)} verified"
                     f" {best.failure_signature} fixes across"
                     f" {best.repository_count} repositories, every"
                     " successful run used these tools: "
                     + ", ".join(best.diagnostic_steps) + ". Reproduce the"
                     " failure with them before changing code."),
            "receipts": list(best.supporting_receipts),
            "failure_class": best.failure_signature,
        }
    else:
        reasons["C"] = "no tool workflow recurs in enough verified solves"
    # D — the most frequent verified operator substitution.
    changes = []
    for item in passes:
        for relative, before, after in item["change"]["pairs"]:
            try:
                change = induce_structural_change(
                    before.decode("utf-8"), after.decode("utf-8"),
                    semantic_contract_digest=item["hidden_digest"],
                    independently_verified_receipt_digest=item[
                        "receipt_digest"])
            except (ValueError, SyntaxError, UnicodeDecodeError):
                continue
            if change is not None:
                changes.append((change, item))
    by_kind: dict[tuple[str, str], list] = {}
    for change, item in changes:
        by_kind.setdefault((change.old_operator, change.new_operator),
                           []).append((change, item))
    ranked = sorted(by_kind.items(), key=lambda entry: (
        -len({item["repository_id"] for _, item in entry[1]}), entry[0]))
    if ranked and len({item["repository_id"] for _, item in ranked[0][1]}) \
            >= min(min_support, len({i["repository_id"] for i in passes})):
        (old, new), group = ranked[0]
        record = structure_to_record(group[0][0])
        candidates["D"] = {
            "title": f"Operator substitution {old} to {new}",
            "text": " ".join(record.steps)
            + f" (seen in {len(group)} verified fixes across"
              f" {len({item['repository_id'] for _, item in group})}"
              " repositories.)",
            "receipts": sorted({item["receipt_digest"] for _, item in group}),
            "failure_class": group[0][1]["failure_class"],
        }
    else:
        reasons["D"] = "no verified single-operator source change"
    # B — what verified fixes looked like, per failure class.
    classes = Counter(item["failure_class"] for item in passes)
    if passes and len({item["repository_id"] for item in passes}) \
            >= min_support:
        failure_class = sorted(classes, key=lambda c: (-classes[c], c))[0]
        group = [item for item in passes
                 if item["failure_class"] == failure_class]
        files = sorted(len(item["change"]["files"]) for item in group)
        lines = sorted(item["change"]["lines"] for item in group)
        median_files = files[len(files) // 2]
        median_lines = lines[len(lines) // 2]
        candidates["B"] = {
            "title": f"Experience for {failure_class}",
            "text": (f"Recall: {len(group)} verified {failure_class} fixes"
                     f" across {len({i['repository_id'] for i in group})}"
                     f" repositories changed a median of {median_files}"
                     f" source file(s) and {median_lines} line(s) and left"
                     " the tests untouched; keep the fix that small."),
            "receipts": sorted(item["receipt_digest"] for item in group),
            "failure_class": failure_class,
        }
    else:
        reasons["B"] = "too few verified solves for an experience record"
    return {"candidates": candidates, "reasons": reasons}


def make_candidate(arm: str, proposal: Mapping, *, agent_kind: str,
                   source_tasks) -> CandidateV1:
    ctype = ARM_TYPES[arm]
    payload = {"title": proposal["title"], "steps": [proposal["text"]]}
    digest = content_digest(ctype, payload)
    return CandidateV1(
        schema_version=1,
        candidate_id=f"{ctype.replace('_', '-')}-{digest[:16]}",
        candidate_type=ctype, content_digest=digest,
        parent_candidate_ids=(),
        source_episode_ids=tuple(sorted(source_tasks))[:64] or ("none",),
        generator_identity=GENERATOR, target_agent=agent_kind,
        target_task_family=proposal["failure_class"],
        repository_scope={"kind": "global", "value": ""},
        applicability_predicate=({"kind": "language_is", "value": "python"},),
        known_counterexamples=(), payload=payload, created_at=_utcnow())


def candidate_guidance(candidate: CandidateV1) -> GuidanceV1:
    return GuidanceV1(
        schema_version=1, decision="recommend",
        procedure_ids=(candidate.candidate_id,),
        revision=candidate.content_digest,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=(candidate.content_digest,),
        policy_digest=candidate.content_digest,
        helpful_next_checks=tuple(candidate.payload["steps"]),
        reason_code=None, approximate_tokens=60)


def _qualification_attempt(row: Mapping, task_id: str,
                           arm: str) -> tuple[bool, str | None, bool]:
    """Classify one qualification arm as ``(passed, receipt, agent_failure)``.

    An evaluated attempt passes only with a passing receipt inside its
    budget, the study's own success rule. An agent that timed out, raised
    or reported invalid usage produced no submission to evaluate: that is
    an ordinary failed attempt and must count, or a candidate whose
    guidance makes the agent fail would look like it never lost. An
    evaluation that could not run is not evidence about the agent at all,
    so qualification stops rather than guess.
    """
    receipt = row.get("receipt_digest")
    if receipt is not None:
        return (row.get("outcome") == "pass"
                and not row.get("budget_exceeded"), receipt, False)
    error = str(row.get("error") or "")
    if not error or error.startswith("evaluation:"):
        raise BundleBuildError(
            f"qualification_evaluation_error:{task_id}:{arm}")
    return False, None, True


def _selected(trials: list[CandidateTrial], *, rule: str,
              min_repositories: int) -> bool:
    if rule == "net_wins":
        return bool(select_improvement(trials,
                                       min_repositories=min_repositories))
    valid = [trial for trial in trials if trial.budget_valid]
    wins = sum(t.assisted_passed and not t.baseline_passed for t in valid)
    losses = sum(t.baseline_passed and not t.assisted_passed for t in valid)
    return (len({t.repository_id for t in valid}) >= min_repositories
            and wins >= losses and any(t.assisted_passed for t in valid))


# --------------------------------------------------------------------- #
# main pipeline
# --------------------------------------------------------------------- #
def build_bundle(spec: Mapping, *, trust: Mapping, keys: Mapping,
                 registry_path: Path, state_dir: Path,
                 exclude: Mapping | None = None,
                 executor: str = "local", allow_shared_custody: bool = False,
                 docker_image=None, docker_split_user=DEFAULT_SPLIT_USER,
                 docker_runtime=None, require_image_digest: bool = True,
                 rule: str = "net_wins", min_repositories: int = 2,
                 min_support: int = 2, actor_identity: str = "study-operator",
                 agent_factory: Callable | None = None,
                 executor_factory: Callable | None = None) -> dict:
    """Run the pipeline; return ``{"bundle": ..., "report": ...}``.

    ``bundle`` is ``None`` when some arm has no qualified candidate.
    """
    check_keys_trusted(keys, trust)
    repositories = _repositories(spec)
    holdout_digests, holdout_lineages, study_tasks = _excluded(exclude)
    for item in repositories.values():
        _require(item["repo_snapshot_digest"] not in holdout_digests,
                 f"{item['repository_id']} is a study holdout repository")
        _require(item["lineage"] is None
                 or item["lineage"] not in holdout_lineages,
                 f"{item['repository_id']} shares a lineage with a study"
                 " holdout repository")
    agent_spec = spec.get("agent")
    _require(isinstance(agent_spec, Mapping)
             and agent_spec.get("kind") in AGENT_KINDS,
             "learning spec agent.kind must be one of "
             + ", ".join(AGENT_KINDS))
    kind = agent_spec["kind"]
    injected = agent_factory is not None
    installed = None
    if not injected:
        status = campaign._agent_status(kind)
        _require(status["available"] and status["authenticated"],
                 f"{kind} is unavailable: {status['reason']}")
        installed = campaign._installed_version(kind, status["binary"])
        _require(installed == campaign._normalized_version(
            agent_spec.get("cli_version")),
            f"installed {kind} {installed!r} does not match the learning"
            f" spec {agent_spec.get('cli_version')!r}")
    tasks = spec.get("tasks")
    _require(isinstance(tasks, list) and tasks, "learning spec needs tasks")
    for task in tasks:
        _require(isinstance(task, Mapping)
                 and task.get("repository_id") in repositories,
                 "every task must name a learning-spec repository")
        _require(task.get("task_id") not in study_tasks,
                 f"task {task.get('task_id')} is a study task")
    state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    run = LearningRun(
        spec, repositories, state_dir=state_dir,
        evaluator_key_dir=Path(keys["evaluator_key_dir"]),
        executor=executor, allow_shared_custody=allow_shared_custody,
        docker_image=docker_image, docker_split_user=docker_split_user,
        docker_runtime=docker_runtime,
        require_image_digest=require_image_digest,
        executor_factory=executor_factory)
    _require(run.verifier.public_key_record()["key_id"]
             == keys["evaluator"][0],
             "the verifier does not sign with the evaluator key")
    envelopes = {"training": [], "qualification": []}
    for task in tasks:
        split = repositories[task["repository_id"]]["split"]
        envelopes[split].append(run.register(task))
    _require(envelopes["training"] and envelopes["qualification"],
             "both splits need tasks")
    prompts = {task["task_id"]: task["prompt"] for task in tasks}
    factory = agent_factory or campaign._default_agent_factory(kind)
    agent = factory(prompts, run.budget, agent_spec.get("model"))
    actions: dict[tuple[str, str], tuple[str, ...]] = {}

    def recorded(ctx):
        usage = agent(ctx)
        if isinstance(usage, Mapping):
            actions[(ctx.task.task_id, ctx.arm)] = tuple(
                str(item)[:128] for item in (usage.get("actions") or ())
            )[:256]
        return usage

    changes: dict[str, dict] = {}

    def observe(task, arm, workspace, result, usage):
        if result.outcome == "pass":
            changes[task.task_id] = capture_change(
                run.tasks[task.task_id]["tree"], workspace)

    try:
        training = run.run(envelopes["training"], recorded, arm="A",
                           observer=observe)
        episodes = []
        for row in training["per_task"]:
            result = row["arms"]["A"]
            info = run.tasks[row["task_id"]]
            if result.get("receipt_digest") is None:
                continue
            outcome = ("pass" if result["outcome"] == "pass"
                       and not result.get("budget_exceeded") else "fail")
            episodes.append({
                "task_id": row["task_id"],
                "repository_id": info["repository_id"],
                "failure_class": info["task"]["failure_class"],
                "outcome": outcome,
                "receipt_digest": result["receipt_digest"],
                "actions": actions.get((row["task_id"], "A"), ()),
                "hidden_digest": info["hidden_digest"],
                "change": changes.get(row["task_id"],
                                      {"files": [], "lines": 0, "pairs": []}),
            })
        derived = derive_candidates(episodes, min_support=min_support)
        proposals = {
            arm: make_candidate(
                arm, proposal, agent_kind=kind,
                source_tasks=[e["task_id"] for e in episodes
                              if e["receipt_digest"] in proposal["receipts"]])
            for arm, proposal in derived["candidates"].items()}
        baseline = run.run(envelopes["qualification"], recorded, arm="A")
        base_rows = {row["task_id"]: row["arms"]["A"]
                     for row in baseline["per_task"]}
        trials_by_arm: dict[str, list[CandidateTrial]] = {}
        failures_by_arm: dict[str, tuple[dict, int]] = {}
        assisted_by_arm: dict[str, dict] = {}
        for arm, candidate in sorted(proposals.items()):
            guidance = candidate_guidance(candidate)
            assisted = run.run(envelopes["qualification"], recorded, arm="E",
                               provider=lambda task, a, g=guidance: g)
            rows = {row["task_id"]: row["arms"]["E"]
                    for row in assisted["per_task"]}
            assisted_by_arm[arm] = rows
            trials = []
            failures = {"assisted": 0, "baseline": 0}
            unevidenced = 0
            for task_id, row in sorted(rows.items()):
                base_passed, base_receipt, base_failed = \
                    _qualification_attempt(base_rows[task_id], task_id, "A")
                passed, receipt, failed = _qualification_attempt(
                    row, task_id, "E")
                failures["baseline"] += base_failed
                failures["assisted"] += failed
                evidence = receipt or base_receipt
                if evidence is None:
                    # Both agents failed before evaluation: a neutral pair
                    # with no signed evidence. Leaving it out cannot add a
                    # win or a loss, and adds no repository coverage.
                    unevidenced += 1
                    continue
                # Over-budget attempts are already failures (above), so
                # every evaluated pair is a valid comparison.
                trials.append(CandidateTrial(
                    candidate_id=candidate.candidate_id,
                    repository_id=run.tasks[task_id]["repository_id"],
                    task_id=task_id,
                    baseline_passed=base_passed,
                    assisted_passed=passed,
                    budget_valid=True,
                    signed_evidence_digest=evidence,
                    evaluator_verified=True))
            trials_by_arm[arm] = trials
            failures_by_arm[arm] = (failures, unevidenced)
    finally:
        close = getattr(agent, "close", None)
        if callable(close):
            close()
    selected = {arm: proposals[arm] for arm, trials in trials_by_arm.items()
                if trials and _selected(trials, rule=rule,
                                        min_repositories=min_repositories)}
    report = {
        "schema_version": 1,
        "kind": "guidance_bundle_build_report",
        "generated_at": _utcnow(),
        "agent": {"kind": kind, "injected": injected,
                  "cli_version": installed,
                  "model": agent_spec.get("model")},
        "selection": {"rule": rule, "min_repositories": min_repositories,
                      "min_support": min_support},
        "training": {"tasks": len(envelopes["training"]),
                     "verified_episodes": len(episodes),
                     "verified_passes": sum(e["outcome"] == "pass"
                                            for e in episodes)},
        "derivation": {"proposed": {arm: c.candidate_id
                                    for arm, c in proposals.items()},
                       "not_proposed": derived["reasons"]},
        "qualification": {
            arm: {"candidate_id": proposals[arm].candidate_id,
                  "trials": len(trials),
                  "wins": sum(t.assisted_passed and not t.baseline_passed
                              for t in trials),
                  "losses": sum(t.baseline_passed and not t.assisted_passed
                                for t in trials),
                  "agent_failures": failures_by_arm[arm][0],
                  "unevidenced_pairs": failures_by_arm[arm][1],
                  "selected": arm in selected}
            for arm, trials in trials_by_arm.items()},
        "executor": campaign.executor_description(run.verifier.executor),
    }
    missing = [arm for arm in ("B", "C", "D") if arm not in selected]
    if missing:
        report["bundle"] = None
        report["missing_arms"] = missing
        return {"bundle": None, "report": report}
    # Sign: evidence by the evaluator key, the decision by the operator key.
    eval_id, eval_seed, eval_public = keys["evaluator"]
    op_id, op_seed, op_public = keys["operator"]
    evidence_authority = CandidateEvidenceAuthority(
        trusted_evaluator_keys={eval_id: eval_public})
    decision_authority = CandidateDecisionAuthority(
        trusted_operator_keys={op_id: op_public})
    registry = CandidateRegistry(
        registry_path, receipt_authority=run.receipt,
        evidence_authority=evidence_authority,
        decision_authority=decision_authority,
        expected_evaluation_protocol_digest=trust[
            "evaluation_protocol_digest"])
    components: dict[str, list[dict]] = {}
    qualification_receipts: dict[str, dict] = {}
    try:
        for arm in ("B", "C", "D"):
            candidate = selected[arm]
            refs = sorted(row["receipt_digest"]
                          for row in assisted_by_arm[arm].values()
                          if row.get("receipt_digest")
                          and row["outcome"] == "pass")
            existing = registry.lookup(candidate.candidate_id)
            if existing is None:
                registry.submit(candidate, actor_role="learner")
                registry.transition(candidate.candidate_id, "validated",
                                    actor_role="learner")
                registry.transition(candidate.candidate_id, "evaluating",
                                    actor_role="evaluator")
            else:
                _require(existing[0].digest == candidate.digest,
                         f"registry already holds a different"
                         f" {candidate.candidate_id}")
            evidence = evidence_authority.issue(
                seed=eval_seed, candidate=candidate, receipt_refs=refs,
                evaluation_protocol_digest=trust["evaluation_protocol_digest"],
                partition="holdout", signer_key_id=eval_id)
            decision = decision_authority.issue(
                seed=op_seed, candidate=candidate, from_state="evaluating",
                to_state="qualified", receipt_refs=refs,
                evidence_refs=(evidence.digest,),
                actor_identity=actor_identity, signer_key_id=op_id)
            registry.qualify(
                candidate.candidate_id, actor_role="operator",
                actor_identity=actor_identity, receipt_refs=refs,
                evidence_refs=(evidence.digest,), decision_ref=decision.digest)
            components[arm] = [{
                "candidate_id": candidate.candidate_id,
                "candidate_digest": candidate.digest,
                "content_digest": candidate.content_digest,
                "evidence_digest": evidence.digest,
                "text": candidate.payload["steps"][0],
            }]
            for ref in refs:
                qualification_receipts[ref] = run.receipt(ref).to_dict()
    finally:
        registry.close()
    training_repos = [item for item in repositories.values()
                      if item["split"] == "training"]
    qualification_repos = [item for item in repositories.values()
                           if item["split"] == "qualification"]
    bundle = {
        "schema_version": 2,
        "kind": "learned_guidance_bundle",
        "source": "learned",
        "generator": GENERATOR,
        "agent": {"kind": kind, "cli_version": agent_spec.get("cli_version"),
                  "model": agent_spec.get("model")},
        "training": {
            "repository_digests": sorted({
                item["repo_snapshot_digest"] for item in training_repos}),
            "repository_ids": sorted(item["repository_id"]
                                     for item in training_repos),
            "task_ids": sorted(task.task_id
                               for task, _ in envelopes["training"]),
        },
        "qualification": {
            "rule": rule,
            "min_repositories": min_repositories,
            "repository_digests": sorted({
                item["repo_snapshot_digest"]
                for item in qualification_repos}),
            "repository_ids": sorted(item["repository_id"]
                                     for item in qualification_repos),
            "tasks": [{"task_id": task.task_id,
                       "repository_digest":
                           run.tasks[task.task_id]["repository_digest"]}
                      for task, _ in envelopes["qualification"]],
            "receipt_signer": {"key_id": eval_id, "public_key": eval_public},
            "receipts": qualification_receipts,
        },
        "trust_anchors": {
            "evaluator_key_id": eval_id, "operator_key_id": op_id,
            "evaluation_protocol_digest": trust["evaluation_protocol_digest"],
        },
        "components": components,
    }
    bundle["bundle_digest"] = campaign._bundle_digest(bundle)
    report["bundle"] = {"bundle_digest": bundle["bundle_digest"],
                        "candidates": {arm: records[0]["candidate_id"]
                                       for arm, records in components.items()}}
    return {"bundle": bundle, "report": report}


def _write_json(path: Path, document: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".bundle-",
                                             dir=path.parent)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def main(argv=None, *, agent_factory=None, executor_factory=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--learning-spec", type=Path)
    parser.add_argument("--exclude-spec", type=Path,
                        help="study spec or manifest whose holdout"
                             " repositories and tasks must not be used")
    parser.add_argument("--trust-config", type=Path)
    parser.add_argument("--candidate-registry", type=Path)
    parser.add_argument("--evaluator-key-dir", type=Path, required=True)
    parser.add_argument("--operator-key-dir", type=Path, required=True)
    parser.add_argument("--print-public-keys", action="store_true",
                        help="print the trust-config key entries and exit")
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--executor", choices=EXECUTOR_KINDS, default="local")
    parser.add_argument("--allow-local-executor", action="store_true")
    parser.add_argument("--allow-shared-custody", action="store_true")
    parser.add_argument("--docker-image")
    parser.add_argument("--docker-split-user", default=DEFAULT_SPLIT_USER)
    parser.add_argument("--docker-runtime")
    parser.add_argument("--allow-unpinned-image", action="store_true")
    parser.add_argument("--rule", choices=("net_wins", "non_inferior"),
                        default="net_wins")
    parser.add_argument("--min-repositories", type=int, default=2)
    parser.add_argument("--min-support", type=int, default=2)
    parser.add_argument("--actor-identity", default="study-operator")
    parser.add_argument("--output", "-o", type=Path)
    args = parser.parse_args(argv)
    try:
        keys = signing_keys(args.evaluator_key_dir, args.operator_key_dir)
    except Exception as exc:  # noqa: BLE001 - reported to the operator
        print(f"build_guidance_bundle: keys unusable: {exc}", file=sys.stderr)
        return 2
    if args.print_public_keys:
        print(json.dumps({
            "evaluator_keys": {keys["evaluator"][0]: keys["evaluator"][2]},
            "operator_keys": {keys["operator"][0]: keys["operator"][2]},
        }, indent=2, sort_keys=True))
        return 0
    for name in ("learning_spec", "trust_config", "candidate_registry",
                 "state_dir", "output"):
        if getattr(args, name) is None:
            parser.error(f"--{name.replace('_', '-')} is required")
    if args.executor == "local" and not args.allow_local_executor:
        parser.error("local executor requires --allow-local-executor")
    if args.executor == "docker" and args.allow_shared_custody:
        parser.error("--executor docker grades under split custody")
    keys["evaluator_key_dir"] = str(args.evaluator_key_dir)
    try:
        trust = campaign.load_trust_config(args.trust_config)
        spec = load_learning_spec(args.learning_spec)
        exclude = (campaign._json_object(
            args.exclude_spec.read_bytes(), "exclude spec")
            if args.exclude_spec is not None else None)
        result = build_bundle(
            spec, trust=trust, keys=keys,
            registry_path=args.candidate_registry, state_dir=args.state_dir,
            exclude=exclude, executor=args.executor,
            allow_shared_custody=args.allow_shared_custody,
            docker_image=args.docker_image,
            docker_split_user=args.docker_split_user,
            docker_runtime=args.docker_runtime,
            require_image_digest=not args.allow_unpinned_image,
            rule=args.rule, min_repositories=args.min_repositories,
            min_support=args.min_support, actor_identity=args.actor_identity,
            agent_factory=agent_factory, executor_factory=executor_factory)
    except (BundleBuildError, ValueError, OSError, RuntimeError) as exc:
        print(f"build_guidance_bundle: {exc}", file=sys.stderr)
        return 1
    report_path = args.output.with_name(args.output.name + ".report.json")
    _write_json(report_path, result["report"])
    if result["bundle"] is None:
        print(json.dumps({"bundle": None,
                          "missing_arms": result["report"]["missing_arms"],
                          "report": str(report_path)}, indent=2))
        return 1
    _write_json(args.output, result["bundle"])
    print(json.dumps({"bundle": str(args.output),
                      "bundle_digest": result["bundle"]["bundle_digest"],
                      "report": str(report_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
