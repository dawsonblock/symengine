#!/usr/bin/env python3
"""Build and validate a five-arm efficacy manifest from a study spec.

The spec is a declarative description of the study: protocol parameters,
the pinned agent, preregistration identity, repository paths, and tasks.
This tool does not invent repositories, prompts, or hidden tests. It
computes the canonical repository digests, execution fingerprints, Git
base commits, origin URLs, lineage metadata and hidden-test digests,
assembles the manifest, and refuses to write it unless
``validate_manifest(check_paths=True)`` reports both ``valid`` and
``ready``. Every repository must be a clean Git checkout at its root
with a configured origin and a complete history; a path that cannot
prove its commit or origin is refused.

Usage:
    PYTHONPATH=src python3 tools/build_efficacy_manifest.py \
      --spec /secure/study/spec.json \
      --output /secure/study/manifest.json

The output manifest is the input to ``tools/five_arm_campaign.py
--real-agent --manifest``. A confirmatory label also requires a learned
guidance bundle and split custody; this tool binds the bundle digest when
one is named but does not create or qualify the bundle.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Mapping

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sis.v3 import gitquery  # noqa: E402
from sis.v3.contracts import ContractError, canonical_digest  # noqa: E402
from sis.v3.efficacy_manifest import validate_manifest  # noqa: E402
from sis.v3.governed_eval import GOVERNED_ARMS, preregister  # noqa: E402
from sis.v3.learning_qualification import codex_agent_status  # noqa: E402
from sis.v3.runner import (RunnerError, external_symlinks,
                           repository_execution_digest, tree_digest)  # noqa: E402

MAX_SPEC_BYTES = 4 << 20
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
SAFE_REL = re.compile(
    r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")
VERSION = re.compile(r"\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b")
KIND = "five_arm_study_spec"


class StudySpecError(ValueError):
    """The study spec cannot produce a ready manifest."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise StudySpecError(message)


def _text(value, name: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()),
             f"{name} must be nonempty text")
    return value


def _identifier(value, name: str) -> str:
    _require(isinstance(value, str) and bool(IDENTIFIER.fullmatch(value)),
             f"{name} is not a valid identifier")
    return value


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise StudySpecError("duplicate JSON object key: " + key)
        result[key] = value
    return result


def load_spec(path: Path) -> dict:
    """Read a bounded UTF-8 spec and reject duplicate object keys."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise StudySpecError(f"spec is unreadable: {exc}") from exc
    _require(len(raw) <= MAX_SPEC_BYTES, "spec exceeds the size bound")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except StudySpecError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise StudySpecError(f"spec is not valid UTF-8 JSON: {exc}") from exc
    _require(isinstance(document, Mapping), "spec must be a JSON object")
    _require(document.get("schema_version") == 1,
             "spec schema_version must be 1")
    _require(document.get("kind") == KIND, f"spec kind must be {KIND}")
    return document


def _git(root: Path, *args: str) -> str | None:
    return gitquery.query(root, *args)


def _normalized_version(value: str) -> str | None:
    match = VERSION.search(value or "")
    return match.group(1) if match else None


def _agent(spec: Mapping, *, check_agent: bool) -> tuple[dict, dict]:
    agent = spec.get("agent")
    _require(isinstance(agent, Mapping), "agent must be an object")
    kind = _text(agent.get("kind"), "agent.kind")
    _require(kind == "codex-cli",
             "agent.kind must be codex-cli for the current harness")
    model = _text(agent.get("model"), "agent.model")
    declared = _text(agent.get("cli_version"), "agent.cli_version")
    status = codex_agent_status()
    report = {
        "available": bool(status.get("available")),
        "authenticated": bool(status.get("authenticated")),
        "binary": status.get("binary"),
        "version": None,
        "declared": declared,
        "matches": None,
    }
    if not check_agent:
        return {"kind": kind, "model": model, "cli_version": declared}, report
    _require(report["available"],
             "codex CLI is unavailable: " + str(status.get("reason")))
    _require(report["authenticated"],
             "codex CLI is unauthenticated: " + str(status.get("reason")))
    binary = status.get("binary")
    _require(isinstance(binary, str) and binary,
             "codex CLI binary is unknown")
    try:
        completed = subprocess.run(
            [binary, "--version"], capture_output=True, text=True,
            timeout=30, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise StudySpecError(f"codex CLI version is unreadable: {exc}") from exc
    installed = _normalized_version(
        (completed.stdout or "") + " " + (completed.stderr or ""))
    _require(installed is not None,
             "codex CLI did not report a version")
    report["version"] = installed
    report["matches"] = installed == _normalized_version(declared)
    _require(report["matches"],
             f"installed codex CLI {installed} does not match the spec"
             f" {declared}; pass --skip-agent-check only to build off-host")
    return {"kind": kind, "model": model, "cli_version": declared}, report


def _protocol(spec: Mapping) -> dict:
    protocol = spec.get("protocol")
    _require(isinstance(protocol, Mapping), "protocol must be an object")
    _require(protocol.get("powered") is True,
             "study kit builds a powered confirmatory manifest; a diagnostic"
             " protocol must use the demo path")
    _require(protocol.get("allow_underpowered") is not True,
             "an explicitly underpowered protocol cannot be confirmatory")
    arms = protocol.get("arms", list(GOVERNED_ARMS))
    _require(list(arms) == list(GOVERNED_ARMS),
             "protocol arms must be exactly A,B,C,D,E")
    budget = protocol.get("budget")
    _require(isinstance(budget, Mapping), "protocol.budget must be an object")
    try:
        registered = preregister(
            primary_metric=_text(protocol.get("primary_metric"),
                                 "protocol.primary_metric"),
            method=_text(protocol.get("method"), "protocol.method"),
            alpha=float(protocol.get("alpha")),
            min_effect=float(protocol.get("min_effect")),
            sample_size=protocol.get("sample_size"),
            budget=dict(budget),
            arms=tuple(arms),
            notes=str(protocol.get("notes", "")),
            expected_baseline=float(protocol.get("expected_baseline", 0.4)),
            expected_treatment=float(protocol.get("expected_treatment", 0.6)),
            power=float(protocol.get("power", 0.8)),
            powered=True,
            allow_underpowered=False,
        )
    except (ContractError, TypeError, ValueError) as exc:
        raise StudySpecError(f"protocol is not preregistrable: {exc}") from exc
    registered["powered"] = True
    declared = protocol.get("protocol_digest")
    if declared is not None:
        _require(declared == registered["protocol_digest"],
                 "protocol.protocol_digest does not match the protocol")
    _require(protocol.get("analysis_kind") is None,
             "protocol.analysis_kind is not valid for a powered study")
    return registered


def _base_commit(root: Path, declared) -> str:
    if declared is not None:
        _require(isinstance(declared, str)
                 and (HEX40.fullmatch(declared) or HEX64.fullmatch(declared)),
                 "repository.base_commit must be a 40- or 64-hex commit")
    head = _git(root, "rev-parse", "HEAD")
    _require(head is not None
             and (HEX40.fullmatch(head) or HEX64.fullmatch(head)),
             "repository is not a Git checkout; its base_commit cannot be"
             " verified")
    if declared is not None:
        _require(head.lower() == declared.lower(),
                 "repository.base_commit does not match the checkout HEAD")
    return head


def _hidden_tests(repository: Mapping, root: Path, label: str) -> dict:
    hidden = repository.get("hidden_tests")
    _require(isinstance(hidden, Mapping),
             f"{label}.hidden_tests must be an object for a holdout")
    raw = Path(_text(hidden.get("path"), f"{label}.hidden_tests.path"))
    _require(not raw.is_symlink(), f"{label} hidden tests must not be a symlink")
    path = raw.resolve()
    _require(path.is_file(), f"{label} hidden tests are not a regular file")
    _require(path != root and root not in path.parents,
             f"{label} hidden tests are inside the public repository")
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise StudySpecError(
            f"{label} hidden tests are unreadable: {exc}") from exc
    digest = hashlib.sha256(payload).hexdigest()
    declared = hidden.get("digest")
    if declared is not None:
        _require(isinstance(declared, str) and HEX64.fullmatch(declared),
                 f"{label}.hidden_tests.digest must be a SHA-256 digest")
        _require(declared == digest,
                 f"{label}.hidden_tests.digest does not match the file")
    return {"path": str(path), "digest": digest}


def _repositories(spec: Mapping) -> tuple[list[dict], dict]:
    items = spec.get("repositories")
    _require(isinstance(items, list) and bool(items),
             "repositories must be a nonempty list")
    repositories, by_id = [], {}
    for index, item in enumerate(items):
        label = f"repositories[{index}]"
        _require(isinstance(item, Mapping), label + " must be an object")
        repository_id = _identifier(item.get("repository_id"),
                                    label + ".repository_id")
        _require(repository_id not in by_id,
                 "duplicate repository_id: " + repository_id)
        partition = item.get("partition")
        _require(partition in {"induction", "holdout"},
                 f"{label}.partition must be induction or holdout")
        raw = Path(_text(item.get("path"), label + ".path"))
        _require(not raw.is_symlink(), f"{label} path must not be a symlink")
        root = raw.resolve()
        _require(root.is_dir(), f"{label} path is not a directory")
        toplevel = _git(root, "rev-parse", "--show-toplevel")
        _require(toplevel is not None, f"{label} is not a Git checkout")
        _require(Path(toplevel).resolve() == root,
                 f"{label} is not the repository root")
        configured_origin = _git(root, "remote", "get-url", "origin")
        declared_origin = item.get("origin")
        if declared_origin is not None:
            _require(isinstance(declared_origin, str)
                     and bool(declared_origin)
                     and len(declared_origin) <= 2048
                     and not any(ord(char) < 32 or ord(char) == 127
                                 for char in declared_origin),
                     f"{label}.origin is not a valid origin")
            _require(configured_origin is not None,
                     f"{label} has no origin remote")
            _require(configured_origin == declared_origin,
                     f"{label}.origin does not match the checkout remote")
        else:
            _require(configured_origin is not None,
                     f"{label} has no origin remote; declare one")
            declared_origin = configured_origin
        _require(_git(root, "rev-parse", "--is-shallow-repository") != "true",
                 f"{label} has a shallow history; fetch the complete history")
        external = external_symlinks(root)
        _require(not external,
                 f"{label} contains external symlinks: "
                 + ", ".join(external))
        try:
            digest = tree_digest(root, version=3)
            execution = repository_execution_digest(root)
        except (OSError, RunnerError) as exc:
            raise StudySpecError(
                f"{label} cannot be fingerprinted: {exc}") from exc
        lineage = item.get("lineage_id")
        if lineage is not None:
            lineage = _identifier(lineage, label + ".lineage_id")
        entry = {
            "repository_id": repository_id,
            "path": str(root),
            "base_commit": _base_commit(root, item.get("base_commit")),
            "repo_snapshot_digest": digest,
            "repo_execution_digest": execution,
            "origin": declared_origin,
            "partition": partition,
        }
        if lineage is not None:
            entry["lineage_id"] = lineage
        if partition == "holdout":
            entry["hidden_tests"] = _hidden_tests(item, root, label)
        else:
            _require(item.get("hidden_tests") is None,
                     f"{label} induction repository must not carry hidden tests")
        by_id[repository_id] = entry
        repositories.append(entry)
    for item in repositories:
        if "hidden_tests" not in item:
            continue
        hidden = Path(item["hidden_tests"]["path"])
        for other in repositories:
            root = Path(other["path"])
            _require(hidden != root and root not in hidden.parents,
                     f"{item['repository_id']} hidden tests are inside"
                     f" repository {other['repository_id']}")
    return repositories, by_id


def _acceptance(task: Mapping, repository: Mapping, label: str) -> dict:
    acceptance = task.get("acceptance")
    _require(isinstance(acceptance, Mapping),
             f"{label}.acceptance must be an object")
    argv = acceptance.get("argv")
    _require(isinstance(argv, list) and bool(argv)
             and all(isinstance(item, str) and item for item in argv),
             f"{label}.acceptance.argv must be a nonempty string list")
    files = acceptance.get("files")
    hidden_path = acceptance.get("hidden_tests_path")
    _require((files is None) != (hidden_path is None),
             f"{label}.acceptance needs exactly one of files or"
             " hidden_tests_path")
    result = {"argv": list(argv)}
    if files is not None:
        _require(isinstance(files, Mapping) and bool(files),
                 f"{label}.acceptance.files must be a nonempty object")
        for relative, content in files.items():
            _require(isinstance(relative, str) and SAFE_REL.fullmatch(relative),
                     f"{label} has an unsafe acceptance path")
            _require(isinstance(content, str),
                     f"{label} acceptance file {relative} is not text")
        result["files"] = dict(files)
        return result
    raw = Path(_text(hidden_path, f"{label}.acceptance.hidden_tests_path"))
    _require(not raw.is_symlink(),
             f"{label} hidden tests must not be a symlink")
    path = raw.resolve()
    expected = Path(repository["hidden_tests"]["path"])
    _require(path == expected,
             f"{label} acceptance hidden tests must be the repository's"
             " hidden tests file")
    _require(path.name in argv,
             f"{label}.acceptance.argv must name {path.name}")
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise StudySpecError(
            f"{label} hidden tests are unreadable: {exc}") from exc
    _require(digest == repository["hidden_tests"]["digest"],
             f"{label} hidden tests changed during manifest construction")
    declared = acceptance.get("hidden_tests_digest")
    if declared is not None:
        _require(declared == digest,
                 f"{label}.acceptance.hidden_tests_digest does not match")
    result["hidden_tests_path"] = str(path)
    result["hidden_tests_digest"] = digest
    return result


def _tasks(spec: Mapping, repositories: Mapping[str, dict],
           protocol: Mapping) -> list[dict]:
    items = spec.get("tasks")
    _require(isinstance(items, list) and bool(items),
             "tasks must be a nonempty list")
    budget = protocol["budget"]
    tasks, seen = [], set()
    for index, item in enumerate(items):
        label = f"tasks[{index}]"
        _require(isinstance(item, Mapping), label + " must be an object")
        task_id = _identifier(item.get("task_id"), label + ".task_id")
        _require(task_id not in seen, "duplicate task_id: " + task_id)
        seen.add(task_id)
        repository_id = item.get("repository_id")
        _require(isinstance(repository_id, str) and repository_id,
                 f"{label} has no repository_id")
        repository = repositories.get(repository_id)
        _require(repository is not None,
                 f"{label} names an unknown repository")
        _require(repository["partition"] == "holdout",
                 f"{label} must target a holdout repository")
        tasks.append({
            "task_id": task_id,
            "repository_id": repository_id,
            "base_commit": repository["base_commit"],
            "prompt": _text(item.get("prompt"), label + ".prompt"),
            "failure_class": _text(item.get("failure_class"),
                                   label + ".failure_class"),
            "partition": "holdout",
            "budgets": {
                "time_budget_seconds": budget["wall_seconds"],
                "token_budget": budget["token_budget"],
                "tool_budget": budget["tool_budget"],
            },
            "acceptance": _acceptance(item, repository, label),
        })
    return tasks


def _preregistration(spec: Mapping, protocol: Mapping) -> dict:
    preregistration = spec.get("preregistration")
    _require(isinstance(preregistration, Mapping),
             "preregistration must be an object")
    registered_at = _text(preregistration.get("registered_at"),
                          "preregistration.registered_at")
    try:
        parsed = datetime.fromisoformat(
            registered_at[:-1] + "+00:00"
            if registered_at.endswith("Z") else registered_at)
    except ValueError as exc:
        raise StudySpecError(
            "preregistration.registered_at is not ISO-8601") from exc
    _require(parsed.tzinfo is not None,
             "preregistration.registered_at needs a timezone")
    now = datetime.now(parsed.tzinfo)
    _require(parsed <= now.replace(microsecond=0) + timedelta(minutes=5),
             "preregistration.registered_at must not be in the future")
    declared = preregistration.get("protocol_digest")
    if declared is not None:
        _require(declared == protocol["protocol_digest"],
                 "preregistration.protocol_digest does not match the protocol")
    return {
        "registered_at": registered_at,
        "registered_by": _text(preregistration.get("registered_by"),
                               "preregistration.registered_by"),
        "protocol_digest": protocol["protocol_digest"],
    }


def _bundle_digest(document: Mapping) -> str:
    """Match tools/five_arm_campaign.py's canonical bundle commitment."""
    body = {key: value for key, value in document.items()
            if key != "bundle_digest"}
    normalized = json.loads(json.dumps(body, sort_keys=True))
    return canonical_digest("learned_guidance_bundle", 1, normalized)


def _guidance(spec: Mapping, *, induction: set[str],
              holdout: set[str]) -> str | None:
    raw_value = spec.get("guidance_bundle")
    if raw_value is None:
        return None
    raw_path = Path(_text(raw_value, "guidance_bundle"))
    _require(not raw_path.is_symlink(),
             "guidance_bundle must not be a symlink")
    path = raw_path.resolve()
    _require(path.is_file(), "guidance_bundle is not a regular file")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StudySpecError(f"guidance_bundle is unreadable: {exc}") from exc
    _require(len(raw) <= MAX_SPEC_BYTES, "guidance_bundle exceeds the size bound")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except StudySpecError:
        raise
    except (UnicodeDecodeError, ValueError) as exc:
        raise StudySpecError(
            f"guidance_bundle is not valid UTF-8 JSON: {exc}") from exc
    _require(isinstance(document, Mapping),
             "guidance_bundle must be a JSON object")
    _require(document.get("schema_version") == 2,
             "guidance_bundle schema_version must be 2")
    _require(document.get("kind") == "learned_guidance_bundle",
             "guidance_bundle kind must be learned_guidance_bundle")
    _require(document.get("source") == "learned",
             "guidance_bundle source must be learned")
    training = document.get("training")
    _require(isinstance(training, Mapping),
             "guidance_bundle needs a training object")
    digests = training.get("repository_digests")
    _require(isinstance(digests, list) and bool(digests)
             and all(isinstance(item, str) and HEX64.fullmatch(item)
                     for item in digests),
             "guidance_bundle training.repository_digests must be non-empty"
             " sha256 digests")
    _require(len(set(digests)) == len(digests),
             "guidance_bundle training repositories contain duplicates")
    _require(set(digests) <= induction,
             "guidance_bundle training repositories are not induction"
             " partitions of the manifest")
    _require(not (set(digests) & holdout),
             "guidance_bundle training repositories overlap the holdout")
    digest = _bundle_digest(document)
    _require(document.get("bundle_digest") == digest,
             "guidance_bundle digest does not match its contents")
    return digest


def build_manifest(spec: Mapping, *, check_agent: bool = True
                   ) -> tuple[dict, dict]:
    """Assemble and validate a manifest; raise unless it is ready."""
    protocol = _protocol(spec)
    agent, agent_report = _agent(spec, check_agent=check_agent)
    repositories, by_id = _repositories(spec)
    tasks = _tasks(spec, by_id, protocol)
    preregistration = _preregistration(spec, protocol)
    bundle_path = spec.get("guidance_bundle")
    if bundle_path is not None:
        owner = _inside_any(Path(_text(bundle_path, "guidance_bundle")).resolve(),
                            repositories)
        _require(owner is None,
                 f"guidance_bundle must not be inside repository {owner}")
    for item in repositories:
        root = Path(item["path"])
        if _git(root, "rev-parse", "--show-toplevel") is not None:
            _require(_git(root, "status", "--porcelain",
                          "--untracked-files=all") == "",
                     f"{item['repository_id']} has uncommitted changes")
    guidance_digest = _guidance(
        spec,
        induction={item["repo_snapshot_digest"] for item in repositories
                   if item["partition"] == "induction"},
        holdout={item["repo_snapshot_digest"] for item in repositories
                 if item["partition"] == "holdout"})
    document = {
        "schema_version": 1,
        "kind": "five_arm_efficacy_manifest",
        "protocol": protocol,
        "agent": agent,
        "partitions": {
            "induction": [item["repository_id"] for item in repositories
                          if item["partition"] == "induction"],
            "holdout": [item["repository_id"] for item in repositories
                        if item["partition"] == "holdout"],
        },
        "repositories": repositories,
        "tasks": tasks,
        "preregistration": preregistration,
    }
    if guidance_digest is not None:
        document["guidance_bundle_digest"] = guidance_digest
    try:
        report = validate_manifest(document, check_paths=True)
    except ContractError as exc:
        raise StudySpecError(f"manifest cannot be validated: {exc}") from exc
    if not report["valid"] or not report["ready"]:
        problems = report["problems"] or [
            "manifest is not ready for a confirmatory run"]
        raise StudySpecError("; ".join(problems))
    summary = {
        "manifest_digest": report["manifest_digest"],
        "ready": report["ready"],
        "repositories": len(repositories),
        "holdout_repositories_used": report["holdout_repositories_used"],
        "holdout_snapshots_used": report["holdout_snapshots_used"],
        "distinct_holdout_lineages": report["distinct_holdout_lineages"],
        "tasks": len(tasks),
        "sample_size": protocol["sample_size"],
        "required_sample_size": report["required_sample_size"],
        "guidance_bundle_digest": guidance_digest,
        "codex_cli": agent_report,
    }
    return document, summary


def _inside_any(path: Path, repositories: list[dict]) -> str | None:
    for item in repositories:
        root = Path(item["path"])
        if path == root or root in path.parents:
            return item["repository_id"]
    return None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument(
        "--skip-agent-check", action="store_true",
        help="build off-host without requiring an installed, matching"
             " codex CLI; the run host still enforces it")
    args = parser.parse_args(argv)
    try:
        spec = load_spec(args.spec)
        document, summary = build_manifest(
            spec, check_agent=not args.skip_agent_check)
        spec_owner = _inside_any(args.spec.resolve(), document["repositories"])
        if spec_owner is not None:
            raise StudySpecError(
                f"spec must not be inside repository {spec_owner}")
        output = args.output.resolve()
        owner = _inside_any(output, document["repositories"])
        if owner is not None:
            raise StudySpecError(
                f"output must not be written inside repository {owner}")
        output.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".manifest-", dir=output.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(document, indent=2, sort_keys=True))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, output)
        except BaseException:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except (StudySpecError, OSError) as exc:
        print(f"study spec rejected: {exc}", file=sys.stderr)
        return 1
    summary["manifest"] = str(output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
