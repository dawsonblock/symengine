"""Validation for the real-agent efficacy manifest (Phase 6).

This module does not run a study and does not read hidden tests. It checks
that a manifest is structurally ready for the existing ``FiveArmCampaign``:
the protocol is preregistered and powered, the manifest's ``study_tier``
agrees with the protocol and its holdout covers that tier's repository
floor, the declared arms are fixed
(the five-arm design or the A/E primary contrast), the
holdout is repository-disjoint from induction material, hidden tests live
outside the public repository, and every task carries an evaluator-owned
acceptance command and equal budget fields. With ``check_paths`` it also
re-fingerprints every repository path, verifies the declared snapshot
digest and execution fingerprint, verifies that the path is the clean Git
checkout of its declared base commit with a matching origin and complete
history, and rejects two holdout entries (or an induction and a holdout
entry) that resolve to the same codebase.

A valid manifest is a prerequisite, not evidence. The efficacy claim still
requires a completed real-agent run with independently verified outcomes.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from pathlib import Path

from . import gitquery
from .contracts import ContractError, canonical_digest
from .governed_eval import (GOVERNED_ARMS, PRIMARY_CONTRAST_ARMS,
                            preregister, required_sample_size)
from .learning_qualification import MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES
from .runner import (RunnerError, repository_execution_digest, tree_digest,
                     verify_repository_digest)

PLACEHOLDER = re.compile(r"^<[^<>]+>$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_SAFE_REL = re.compile(
    r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")
MIN_REPOSITORIES = 10
# Tasks drawn from one or two holdout repositories are correlated draws,
# not independent evidence. A floor keeps a study from meeting its task
# count while concentrating every outcome in a handful of codebases.
# This is the floor for every manifest, and the whole floor for an
# ``exploratory`` or ``diagnostic`` study.
MIN_HOLDOUT_REPOSITORIES = 5
# A ``confirmatory`` study (the default for a powered protocol) must have
# at least MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES holdout repositories
# contributing tasks — the same floor ``analyze_report`` applies before it
# will label a run confirmatory (an exact repository-level sign-flip test
# over R repositories cannot reach p below 2**(1 - R)). Re-exported here;
# ``learning_qualification`` is the single source of truth.
CONFIRMATORY = "confirmatory"
EXPLORATORY = "exploratory"
DIAGNOSTIC = "diagnostic"
STUDY_TIERS = (CONFIRMATORY, EXPLORATORY, DIAGNOSTIC)
MANIFEST_ARMS = {
    "five_arm_efficacy_manifest": GOVERNED_ARMS,
    "primary_contrast_efficacy_manifest": PRIMARY_CONTRAST_ARMS,
}


def _placeholder(value) -> bool:
    return isinstance(value, str) and bool(PLACEHOLDER.match(value))


def _valid_origin(value) -> bool:
    return (isinstance(value, str) and bool(value.strip())
            and len(value) <= 2048
            and not any(ord(char) < 32 or ord(char) == 127
                        for char in value))


def _canonical(value) -> str:
    normalized = json.loads(
        json.dumps(value, sort_keys=True),
        parse_float=lambda item: f"float:{item}")
    return canonical_digest("efficacy_manifest", 1, normalized)


def _problem(problems: list[str], message: str) -> None:
    problems.append(message)


def _validate_protocol(protocol, problems: list[str],
                       allow_placeholders: bool, *,
                       expected_arms: Sequence[str] = GOVERNED_ARMS) -> dict:
    if not isinstance(protocol, Mapping):
        _problem(problems, "protocol must be an object")
        return {}
    required = (
        "primary_metric", "method", "alpha", "min_effect", "sample_size",
        "budget", "arms", "powered",
    )
    missing = [name for name in required if name not in protocol]
    if missing:
        _problem(problems, "protocol is missing: " + ", ".join(missing))
        return {}
    if list(protocol.get("arms") or []) != list(expected_arms):
        _problem(problems, "protocol arms must be exactly "
                           + ",".join(expected_arms))
    budget = protocol.get("budget")
    if not isinstance(budget, Mapping) or any(
            type(budget.get(name)) is not int or budget[name] < 1
            for name in ("wall_seconds", "token_budget", "tool_budget")):
        _problem(problems, "protocol budget must name positive integer"
                           " wall_seconds, token_budget and tool_budget")
    powered = protocol.get("powered")
    if type(powered) is not bool:
        _problem(problems, "protocol powered must be a bool")
        # Never let a malformed flag register as a powered plan; the
        # problem already makes the manifest invalid.
        powered = False
    analysis = protocol.get("power_analysis")
    if not isinstance(analysis, Mapping):
        analysis = {}
    try:
        registered = preregister(
            primary_metric=str(protocol.get("primary_metric", "")),
            method=str(protocol.get("method", "")),
            alpha=float(protocol.get("alpha", 0.05)),
            min_effect=float(protocol.get("min_effect", 0.2)),
            sample_size=int(protocol.get("sample_size", 0)),
            budget=dict(budget or {}),
            arms=tuple(protocol.get("arms") or ()),
            notes=str(protocol.get("notes", "")),
            expected_baseline=float(
                protocol.get("expected_baseline",
                             analysis.get("expected_baseline", 0.4))),
            expected_treatment=float(
                protocol.get("expected_treatment",
                             analysis.get("expected_treatment", 0.6))),
            power=float(protocol.get("power", analysis.get("power", 0.8))),
            powered=powered,
            allow_underpowered=bool(protocol.get("allow_underpowered", False)),
        )
    except (ContractError, TypeError, ValueError) as exc:
        _problem(problems, f"protocol is not preregistrable: {exc}")
        return {}
    registered = dict(registered)
    registered["powered"] = powered
    declared_kind = protocol.get("analysis_kind")
    expected_kind = None if powered else "diagnostic"
    if declared_kind is not None and declared_kind != expected_kind:
        _problem(problems,
                 "protocol analysis_kind does not match its powered flag")
    if not powered and isinstance(protocol.get("power_analysis"), Mapping):
        _problem(problems,
                 "a diagnostic protocol must not carry power_analysis")
    if registered.get("power_analysis", {}).get("underpowered_declared"):
        _problem(problems, "protocol is explicitly underpowered and cannot"
                           " be confirmatory")
    declared = protocol.get("protocol_digest")
    if declared is None or _placeholder(declared):
        if not allow_placeholders:
            _problem(problems, "protocol_digest is missing")
    elif declared != registered["protocol_digest"]:
        _problem(problems, "protocol_digest does not match the protocol")
    analysis = protocol.get("power_analysis")
    if isinstance(analysis, Mapping):
        required_n = registered.get("power_analysis", {}).get("required_n")
        if analysis.get("required_n") != required_n:
            _problem(problems, "power_analysis.required_n is inconsistent")
    elif powered and not allow_placeholders:
        _problem(problems, "power_analysis is missing")
    return registered


def _validate_repositories(document, problems: list[str],
                           allow_placeholders: bool) -> dict:
    repositories = document.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        _problem(problems, "repositories must be a nonempty list")
        return {}
    if not allow_placeholders and len(repositories) < MIN_REPOSITORIES:
        _problem(problems, f"at least {MIN_REPOSITORIES} repositories are"
                           " required for a repository-disjoint study")
    by_id: dict[str, dict] = {}
    for index, repository in enumerate(repositories):
        label = f"repositories[{index}]"
        if not isinstance(repository, Mapping):
            _problem(problems, label + " must be an object")
            continue
        repository_id = repository.get("repository_id")
        if not isinstance(repository_id, str) or not repository_id:
            _problem(problems, label + " has no repository_id")
            continue
        if repository_id in by_id:
            _problem(problems, "duplicate repository_id: " + repository_id)
        by_id[repository_id] = repository
        partition = repository.get("partition")
        if partition not in {"induction", "holdout"}:
            _problem(problems, label + " partition must be induction or"
                                    " holdout")
        for name, pattern in (("base_commit", _HEX40),
                              ("repo_snapshot_digest", _HEX64),
                              ("repo_execution_digest", _HEX64)):
            value = repository.get(name)
            if _placeholder(value) and allow_placeholders:
                continue
            if not isinstance(value, str) or not pattern.match(value):
                _problem(problems, f"{label}.{name} is not a valid digest")
        path = repository.get("path")
        if not isinstance(path, str) or not path:
            _problem(problems, label + " has no path")
        lineage = repository.get("lineage_id")
        if lineage is not None:
            if _placeholder(lineage) and allow_placeholders:
                pass
            elif (not isinstance(lineage, str)
                  or not _IDENTIFIER.fullmatch(lineage)):
                _problem(problems,
                         label + ".lineage_id is not a valid identifier")
        origin = repository.get("origin")
        if _placeholder(origin):
            if not allow_placeholders:
                _problem(problems, label + ".origin is still a placeholder")
        elif not _valid_origin(origin):
            _problem(problems, label + ".origin is not a valid origin")
        hidden = repository.get("hidden_tests")
        if partition == "holdout":
            if not isinstance(hidden, Mapping):
                _problem(problems, label + " has no hidden_tests record")
            else:
                hidden_path = hidden.get("path")
                hidden_digest = hidden.get("digest")
                if not isinstance(hidden_path, str) or not hidden_path:
                    _problem(problems, label + ".hidden_tests.path is missing")
                if (_placeholder(hidden_digest) and allow_placeholders):
                    pass
                elif (not isinstance(hidden_digest, str)
                      or not _HEX64.match(hidden_digest)):
                    _problem(problems,
                             label + ".hidden_tests.digest is invalid")
                if (isinstance(hidden_path, str) and isinstance(path, str)
                        and not _placeholder(hidden_path)
                        and not _placeholder(path)):
                    public = Path(path).resolve()
                    private = Path(hidden_path).resolve()
                    if private == public or public in private.parents:
                        _problem(problems,
                                 label + " hidden tests are inside the"
                                         " public repository")
    partitions = document.get("partitions")
    if not isinstance(partitions, Mapping):
        _problem(problems, "partitions must be an object")
    else:
        induction = set(partitions.get("induction") or [])
        holdout = set(partitions.get("holdout") or [])
        if not induction or not holdout:
            _problem(problems, "partitions need nonempty induction and"
                               " holdout lists")
        overlap = induction & holdout
        if overlap:
            _problem(problems, "repository partitions overlap: "
                               + ", ".join(sorted(overlap)))
        unknown = (induction | holdout) - set(by_id)
        if unknown:
            _problem(problems, "partitions name unknown repositories: "
                               + ", ".join(sorted(unknown)))
        if (not allow_placeholders
                and len(holdout) < MIN_HOLDOUT_REPOSITORIES):
            _problem(problems,
                     f"at least {MIN_HOLDOUT_REPOSITORIES} holdout "
                     "repositories are required; a task count met from "
                     "fewer repositories overstates independent evidence")
        for repository_id, repository in by_id.items():
            declared = repository.get("partition")
            if declared == "induction" and repository_id not in induction:
                _problem(problems, repository_id + " is not in induction")
            if declared == "holdout" and repository_id not in holdout:
                _problem(problems, repository_id + " is not in holdout")
    return by_id


def _verify_repository_trees(by_id: dict[str, dict],
                             problems: list[str]
                             ) -> tuple[dict[str, str], dict[str, str],
                                        dict[str, str]]:
    """Re-fingerprint every repository path and reject duplicate codebases.

    A declared snapshot digest is a claim. When paths are available the
    validator recomputes the repository-content digest (working tree,
    VCS metadata excluded), verifies the declared digest (full-tree v2
    and legacy v1 records are accepted read-only), and groups
    repositories by the *computed* digest. Two holdout entries — or an
    induction and a holdout entry — that resolve to the same tree are
    the same codebase, however they are named and whatever digests they
    declare. Identical induction repositories are permitted: they only
    duplicate training material.

    The execution fingerprint is recomputed and verified separately: it
    binds permission bits, entry types and symlink targets, which the
    content digest deliberately ignores.
    """
    digests: dict[str, str] = {}
    versions: dict[str, str] = {}
    execution: dict[str, str] = {}
    for repository_id, repository in by_id.items():
        path = repository.get("path")
        if not isinstance(path, str) or not path:
            continue
        root = Path(path)
        if root.is_symlink() or not root.is_dir():
            _problem(problems,
                     "repository_path_is_not_a_plain_directory: "
                     + repository_id)
            continue
        declared = repository.get("repo_snapshot_digest")
        try:
            canonical = tree_digest(root, version=3)
            versions[repository_id] = verify_repository_digest(
                root, declared, canonical=canonical)
        except (OSError, RunnerError):
            _problem(problems,
                     "repository_snapshot_mismatch: " + repository_id)
            continue
        digests[repository_id] = canonical
        try:
            state = repository_execution_digest(root)
        except (OSError, RunnerError):
            _problem(problems,
                     "repository_execution_unverifiable: " + repository_id)
            continue
        execution[repository_id] = state
        declared_execution = repository.get("repo_execution_digest")
        if (not isinstance(declared_execution, str)
                or state != declared_execution):
            _problem(problems,
                     "repository_execution_mismatch: " + repository_id)
    groups: dict[str, list[str]] = {}
    for repository_id, digest in digests.items():
        groups.setdefault(digest, []).append(repository_id)
    for ids in groups.values():
        if len(ids) < 2:
            continue
        partitions = {by_id[repository_id].get("partition")
                      for repository_id in ids}
        if "holdout" in partitions:
            _problem(problems,
                     "repositories resolve to the same codebase: "
                     + ", ".join(sorted(ids)))
    return digests, versions, execution


def _git(root: Path, *args: str) -> str | None:
    """Run a read-only Git query, or return ``None`` when it cannot answer."""
    return gitquery.query(root, *args)


def _git_ok(root: Path, *args: str) -> bool:
    """Return whether a Git predicate exits zero."""
    return gitquery.predicate(root, *args)


def verify_repository_binding(repository: Mapping
                              ) -> tuple[str | None, list[str]]:
    """Verify that a repository path is the clean checkout of its commit.

    ``base_commit`` is a claim until it is matched against the checkout.
    The path must be the root of a Git work tree whose HEAD is the
    declared commit and whose working tree has no staged, unstaged or
    untracked changes. Anything else is unverifiable provenance: the
    manifest could name a commit the code never came from, or the run
    could execute files that are not in the commit at all. Returns the
    verified HEAD (or ``None``) and the problems found.
    """
    repository_id = str(repository.get("repository_id"))
    path = repository.get("path")
    if not isinstance(path, str) or not path:
        return None, ["repository has no path: " + repository_id]
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        return None, [
            "repository_path_is_not_a_plain_directory: " + repository_id]
    toplevel = _git(root, "rev-parse", "--show-toplevel")
    if toplevel is None:
        return None, ["repository_head_unverifiable: " + repository_id]
    problems: list[str] = []
    try:
        same_root = Path(toplevel).resolve() == root.resolve()
    except OSError:
        same_root = False
    if not same_root:
        problems.append("repository_is_not_the_root: " + repository_id)
    head = _git(root, "rev-parse", "HEAD")
    if head is None or not (_HEX40.fullmatch(head)
                            or _HEX64.fullmatch(head)):
        problems.append("repository_head_unverifiable: " + repository_id)
        head = None
    declared = repository.get("base_commit")
    if head is not None and (not isinstance(declared, str)
                             or head.lower() != declared.lower()):
        problems.append("repository_base_commit_mismatch: " + repository_id)
    # Never ``git status``: it runs the checkout's configured clean
    # filters. The comparison below runs no repository-configured program.
    clean = gitquery.worktree_matches_head(root)
    if clean is None:
        problems.append("repository_status_unverifiable: " + repository_id)
    elif not clean:
        problems.append("repository_is_dirty: " + repository_id)
    return head, problems


def verify_repository_provenance(repository: Mapping) -> list[str]:
    """Verify a repository's declared origin and complete history.

    The manifest names the origin the checkout must have, and the base
    commit must be reachable from at least one remote-tracking ref. A
    shallow clone is refused: its history boundary is reported as a
    root commit, so two shallow clones of one repository could look
    unrelated to the lineage check. This is local consistency, not
    proof that the upstream contains the commit; that requires fetching
    from the declared origin or a signed attestation.
    """
    repository_id = str(repository.get("repository_id"))
    path = repository.get("path")
    if not isinstance(path, str) or not path:
        return ["repository has no path: " + repository_id]
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        return ["repository_path_is_not_a_plain_directory: "
                + repository_id]
    problems: list[str] = []
    declared_origin = repository.get("origin")
    configured = _git(root, "remote", "get-url", "origin")
    if configured is None:
        problems.append("repository_origin_unverifiable: " + repository_id)
    elif not isinstance(declared_origin, str) or configured != declared_origin:
        problems.append("repository_origin_mismatch: " + repository_id)
    shallow = _git(root, "rev-parse", "--is-shallow-repository")
    if shallow is None:
        problems.append("repository_history_unverifiable: " + repository_id)
    elif shallow == "true":
        problems.append("repository_history_is_shallow: " + repository_id)
    head = _git(root, "rev-parse", "HEAD")
    if head is None or not (_HEX40.fullmatch(head)
                            or _HEX64.fullmatch(head)):
        problems.append("repository_head_unverifiable: " + repository_id)
        return problems
    refs = _git(root, "for-each-ref", "--format=%(refname)", "refs/remotes")
    if not refs:
        problems.append("repository_has_no_remote_refs: " + repository_id)
    elif not any(_git_ok(root, "merge-base", "--is-ancestor", head, ref)
                 for ref in refs.splitlines()):
        problems.append("repository_commit_not_on_remote: " + repository_id)
    return problems


def verify_repository_execution(repository: Mapping
                                ) -> tuple[str | None, list[str]]:
    """Verify a repository path against its execution fingerprint.

    The content digest binds bytes; this fingerprint binds the metadata
    that decides how those bytes execute: permission bits, entry types
    and symlink targets. A checkout whose modes changed after the
    manifest was built is rejected even when its content is identical.
    Returns the computed fingerprint (or ``None``) and the problems.
    """
    repository_id = str(repository.get("repository_id"))
    path = repository.get("path")
    if not isinstance(path, str) or not path:
        return None, ["repository has no path: " + repository_id]
    root = Path(path)
    if root.is_symlink() or not root.is_dir():
        return None, [
            "repository_path_is_not_a_plain_directory: " + repository_id]
    try:
        computed = repository_execution_digest(root)
    except (OSError, RunnerError):
        return None, [
            "repository_execution_unverifiable: " + repository_id]
    declared = repository.get("repo_execution_digest")
    if not isinstance(declared, str) or computed != declared:
        return computed, [
            "repository_execution_mismatch: " + repository_id]
    return computed, []


def _verify_repository_commits(by_id: dict[str, dict],
                               problems: list[str]) -> dict[str, str]:
    """Re-verify every repository's commit, worktree and provenance.

    A path that is missing, not a plain directory or unreadable was
    already reported by :func:`_verify_repository_trees`; this pass
    binds the declared commit to the checkout that will be executed and
    checks its declared origin, history depth and remote reachability.
    """
    commits: dict[str, str] = {}
    for repository_id, repository in by_id.items():
        path = repository.get("path")
        if not isinstance(path, str) or not path:
            continue
        root = Path(path)
        if root.is_symlink() or not root.is_dir():
            continue
        head, found = verify_repository_binding(repository)
        if head is not None:
            commits[repository_id] = head
        problems.extend(found)
        problems.extend(verify_repository_provenance(repository))
    return commits


def _git_lineage(root: Path) -> str | None:
    """Fingerprint a Git checkout's history, or return ``None``.

    Two revisions or clones of one repository share their root commit
    (or commits, after a merged history); unrelated repositories do not.
    The fingerprint is therefore the sorted root-commit set. A shallow
    clone reports its shallow boundary as a root, so lineage is only
    exact for full clones; a repository that cannot be read as Git falls
    back to the declared ``lineage_id``.
    """
    output = gitquery.query(
        root, "rev-list", "--max-parents=0", "HEAD", timeout=10)
    if output is None:
        return None
    roots = sorted(set(output.split()))
    if not roots or any(not (_HEX40.fullmatch(item)
                             or _HEX64.fullmatch(item)) for item in roots):
        return None
    return "git:" + canonical_digest(
        "repository_lineage", 1, {"roots": roots})


def _verify_repository_lineage(by_id: dict[str, dict], problems: list[str],
                               *, derive_git: bool,
                               required: bool
                               ) -> tuple[dict[str, list[str]], dict[str, str]]:
    """Reject holdout entries that share a repository lineage.

    Every repository contributes the lineage keys it can prove: a
    Git-derived history fingerprint when the path is a checkout, and the
    declared ``lineage_id`` when present. Entries connected by any key
    are one lineage. Two holdout entries — or an induction and a holdout
    entry — in one lineage are not independent codebases, even when
    their contents differ (two revisions of one repository). A
    confirmatory manifest must supply a lineage for every repository:
    either a readable Git history or a declared ``lineage_id``.
    """
    keys: dict[str, set[str]] = {}
    for repository_id, repository in by_id.items():
        own: set[str] = set()
        path = repository.get("path")
        if (derive_git and isinstance(path, str) and path
                and not Path(path).is_symlink() and Path(path).is_dir()):
            derived = _git_lineage(Path(path))
            if derived is not None:
                own.add(derived)
        declared = repository.get("lineage_id")
        if isinstance(declared, str) and _IDENTIFIER.fullmatch(declared):
            own.add(declared)
        keys[repository_id] = own
        if required and not own:
            _problem(problems,
                     "repository has no lineage_id: " + repository_id)
    parent = {repository_id: repository_id for repository_id in by_id}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    owners: dict[str, list[str]] = {}
    for repository_id, own in keys.items():
        for key in own:
            owners.setdefault(key, []).append(repository_id)
    for ids in owners.values():
        root = find(ids[0])
        for other in ids[1:]:
            parent[find(other)] = root
    components: dict[str, list[str]] = {}
    for repository_id in by_id:
        components.setdefault(find(repository_id), []).append(repository_id)
    for ids in components.values():
        if len(ids) < 2:
            continue
        partitions = {by_id[repository_id].get("partition")
                      for repository_id in ids}
        if "holdout" in partitions:
            _problem(problems,
                     "repositories share a lineage: "
                     + ", ".join(sorted(ids)))
    return ({repository_id: sorted(own)
             for repository_id, own in keys.items()},
            {repository_id: find(repository_id) for repository_id in by_id})


def _validate_tasks(document, by_id: dict[str, dict], problems: list[str],
                    allow_placeholders: bool, sample_size: int,
                    protocol_budget: Mapping | None = None) -> list:
    tasks = document.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        _problem(problems, "tasks must be a nonempty list")
        return []
    if not allow_placeholders and len(tasks) < sample_size:
        _problem(problems, f"tasks={len(tasks)} is below the preregistered"
                           f" sample_size={sample_size}")
    budget_floor = protocol_budget if isinstance(protocol_budget, Mapping) else {}
    expected_budget = {
        "time_budget_seconds": budget_floor.get("wall_seconds"),
        "token_budget": budget_floor.get("token_budget"),
        "tool_budget": budget_floor.get("tool_budget"),
    }
    seen: set[str] = set()
    for index, task in enumerate(tasks):
        label = f"tasks[{index}]"
        if not isinstance(task, Mapping):
            _problem(problems, label + " must be an object")
            continue
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            _problem(problems, label + " has no task_id")
        elif task_id in seen:
            _problem(problems, "duplicate task_id: " + task_id)
        else:
            seen.add(task_id)
        repository_id = task.get("repository_id")
        repository = by_id.get(repository_id)
        if repository is None:
            _problem(problems, label + " names an unknown repository")
        elif repository.get("partition") != "holdout":
            _problem(problems, label + " must target a holdout repository")
        if task.get("partition") != "holdout":
            _problem(problems, label + ".partition must be holdout")
        base_commit = task.get("base_commit")
        if (not _placeholder(base_commit) or not allow_placeholders):
            if (not isinstance(base_commit, str)
                    or not (_HEX40.match(base_commit)
                            or _HEX64.match(base_commit))):
                _problem(problems, label + ".base_commit is invalid")
            elif (repository is not None
                  and base_commit != repository.get("base_commit")):
                _problem(problems,
                         label + ".base_commit does not match the repository")
        for name in ("prompt", "failure_class"):
            value = task.get(name)
            if not isinstance(value, str) or not value:
                _problem(problems, f"{label}.{name} is missing")
        budgets = task.get("budgets")
        if not isinstance(budgets, Mapping) or any(
                type(budgets.get(name)) is not int or budgets[name] < 1
                for name in ("time_budget_seconds", "token_budget",
                             "tool_budget")):
            _problem(problems, label + ".budgets must name positive integer"
                                     " time_budget_seconds, token_budget and"
                                     " tool_budget")
        elif not allow_placeholders:
            for name, expected in expected_budget.items():
                if expected is not None and budgets.get(name) != expected:
                    _problem(
                        problems,
                        f"{label}.budgets.{name}={budgets.get(name)!r} does"
                        f" not match the preregistered protocol"
                        f" ({expected!r})")
        acceptance = task.get("acceptance")
        if not isinstance(acceptance, Mapping):
            _problem(problems, label + " has no acceptance record")
            continue
        argv = acceptance.get("argv")
        if (not isinstance(argv, list) or not argv
                or any(not isinstance(item, str) or not item for item in argv)):
            _problem(problems, label + ".acceptance.argv is invalid")
        files = acceptance.get("files")
        hidden_path = acceptance.get("hidden_tests_path")
        if files is None and hidden_path is None:
            _problem(problems, label + " needs acceptance.files or"
                                     " acceptance.hidden_tests_path")
        if files is not None:
            if not isinstance(files, Mapping) or not files:
                _problem(problems, label + ".acceptance.files is invalid")
            else:
                for relative in files:
                    if (not isinstance(relative, str)
                            or not _SAFE_REL.match(relative)):
                        _problem(problems,
                                 label + " has an unsafe acceptance path")
        if hidden_path is not None:
            if not isinstance(hidden_path, str) or not hidden_path:
                _problem(problems,
                         label + ".acceptance.hidden_tests_path is invalid")
            digest = acceptance.get("hidden_tests_digest")
            if (_placeholder(digest) and allow_placeholders):
                pass
            elif (not isinstance(digest, str)
                  or not _HEX64.match(digest)):
                _problem(problems,
                         label + ".acceptance.hidden_tests_digest is invalid")
    return tasks


def _study_tier(document: Mapping, powered_plan: bool, protocol_ok: bool,
                problems: list[str], allow_placeholders: bool) -> str:
    """Resolve the study tier the manifest is built for.

    ``study_tier`` is optional. Absent, a powered protocol is a
    ``confirmatory`` study and a diagnostic protocol a ``diagnostic`` one.
    A powered study that cannot meet the confirmatory repository floor
    must say so by declaring ``exploratory``; it is still executable, but
    it never claims more than its holdout can support.
    """
    implied = CONFIRMATORY if powered_plan else DIAGNOSTIC
    declared = document.get("study_tier")
    if declared is None or (allow_placeholders and _placeholder(declared)):
        return implied
    if not isinstance(declared, str) or declared not in STUDY_TIERS:
        _problem(problems, "study_tier must be one of "
                           + ", ".join(STUDY_TIERS))
        return implied
    if protocol_ok and (declared == DIAGNOSTIC) == powered_plan:
        _problem(problems,
                 f"study_tier {declared} does not match the protocol: a"
                 " powered protocol backs a confirmatory or exploratory"
                 " study, a diagnostic protocol only a diagnostic one")
        return implied
    return declared


def validate_manifest(document, *, allow_placeholders: bool = False,
                      check_paths: bool = False) -> dict:
    """Validate one manifest without executing or reading hidden tests."""
    problems: list[str] = []
    if not isinstance(document, Mapping):
        return {"valid": False, "ready": False,
                "problems": ["manifest must be an object"]}
    if document.get("schema_version") != 1:
        _problem(problems, "schema_version must be 1")
    kind = document.get("kind")
    if isinstance(kind, str) and kind in MANIFEST_ARMS:
        expected_arms = MANIFEST_ARMS[kind]
    else:
        expected_arms = GOVERNED_ARMS
        _problem(problems, "kind must be five_arm_efficacy_manifest or "
                           "primary_contrast_efficacy_manifest")
    protocol = _validate_protocol(
        document.get("protocol"), problems, allow_placeholders,
        expected_arms=expected_arms)
    by_id = _validate_repositories(document, problems, allow_placeholders)
    repository_trees, repository_tree_versions, repository_execution = (
        ({}, {}, {}) if allow_placeholders or not check_paths
        else _verify_repository_trees(by_id, problems))
    repository_commits = (
        {} if allow_placeholders or not check_paths
        else _verify_repository_commits(by_id, problems))
    sample_size = int(protocol.get("sample_size", 0) or 0)
    tasks = _validate_tasks(
        document, by_id, problems, allow_placeholders, sample_size,
        protocol_budget=protocol.get("budget"))
    document_protocol = document.get("protocol")
    declared_kind = (document_protocol.get("analysis_kind")
                     if isinstance(document_protocol, Mapping) else None)
    powered_plan = bool(protocol.get("powered") is True
                        and declared_kind != "diagnostic")
    study_tier = _study_tier(document, powered_plan, bool(protocol),
                             problems, allow_placeholders)
    confirmatory = powered_plan and study_tier == CONFIRMATORY
    min_holdout = (MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES if confirmatory
                   else MIN_HOLDOUT_REPOSITORIES)
    repository_lineage, lineage_components = _verify_repository_lineage(
        by_id, problems,
        derive_git=check_paths and not allow_placeholders,
        required=powered_plan and not allow_placeholders)
    holdout_ids = {
        repository_id for repository_id, repository in by_id.items()
        if repository.get("partition") == "holdout"}
    used: dict[str, int] = {}
    for task in tasks:
        if not isinstance(task, Mapping):
            continue
        repository_id = task.get("repository_id")
        if repository_id in holdout_ids:
            used[repository_id] = used.get(repository_id, 0) + 1
    used_snapshots = {
        by_id[repository_id].get("repo_snapshot_digest")
        for repository_id in used
        if isinstance(by_id[repository_id].get("repo_snapshot_digest"), str)}
    if powered_plan and not allow_placeholders:
        reason = (
            " — a confirmatory study needs that many for its"
            " repository-level sign-flip test (R repositories cannot reach"
            " p below 2^(1-R)); declare study_tier exploratory for a"
            f" smaller study (floor {MIN_HOLDOUT_REPOSITORIES})"
            if confirmatory else
            " — a task count concentrated in fewer repositories overstates"
            " independent evidence")
        if len(used) < min_holdout:
            _problem(
                problems,
                f"tasks use only {len(used)} holdout repositories; at least "
                f"{min_holdout} must contribute tasks to a {study_tier}"
                f" study{reason}")
        if len(used_snapshots) < min_holdout:
            _problem(
                problems,
                f"tasks use only {len(used_snapshots)} distinct holdout"
                f" repository snapshots; at least {min_holdout}"
                f" independent codebases are required for a {study_tier}"
                " study (distinct repository IDs with identical snapshots"
                " are the same codebase)")
        declared = set(
            (document.get("partitions") or {}).get("holdout") or []) \
            if isinstance(document.get("partitions"), Mapping) else set()
        unused = sorted(declared - set(used))
        if unused:
            _problem(problems,
                     "declared holdout repositories contribute no tasks: "
                     + ", ".join(unused))
    guidance_digest = document.get("guidance_bundle_digest")
    if guidance_digest is not None:
        if _placeholder(guidance_digest) and allow_placeholders:
            pass
        elif (not isinstance(guidance_digest, str)
              or not _HEX64.match(guidance_digest)):
            _problem(problems,
                     "guidance_bundle_digest is not a valid digest")
    agent = document.get("agent")
    if not isinstance(agent, Mapping):
        _problem(problems, "agent must be an object")
    else:
        for name in ("kind", "model", "cli_version"):
            value = agent.get(name)
            if not isinstance(value, str) or not value:
                _problem(problems, f"agent.{name} is missing")
        if agent.get("kind") not in (None, "codex-cli") and not (
                _placeholder(agent.get("kind")) and allow_placeholders):
            _problem(problems, "agent.kind must be codex-cli for the"
                               " current harness")
    preregistration = document.get("preregistration")
    if not isinstance(preregistration, Mapping):
        _problem(problems, "preregistration must be an object")
    else:
        for name in ("registered_at", "registered_by"):
            value = preregistration.get(name)
            if (not isinstance(value, str) or not value) and not (
                    allow_placeholders and _placeholder(value)):
                _problem(problems, f"preregistration.{name} is missing")
        if (preregistration.get("protocol_digest")
                != protocol.get("protocol_digest")
                and not (allow_placeholders
                         and _placeholder(
                             preregistration.get("protocol_digest")))):
            _problem(problems,
                     "preregistration.protocol_digest does not match the"
                     " protocol")
    if check_paths and not allow_placeholders:
        for repository_id, repository in by_id.items():
            path = repository.get("path")
            if isinstance(path, str) and not Path(path).exists():
                _problem(problems,
                         f"repository path does not exist: {repository_id}")
            hidden = repository.get("hidden_tests")
            if isinstance(hidden, Mapping):
                hidden_path = hidden.get("path")
                if (isinstance(hidden_path, str)
                        and not Path(hidden_path).exists()):
                    _problem(problems,
                             f"hidden tests path does not exist:"
                             f" {repository_id}")
    placeholder_count = sum(
        1 for value in _walk(document) if _placeholder(value))
    # ``ready`` means executable by the real-agent gate: any powered
    # study, confirmatory or declared exploratory. Only ``confirmatory``
    # manifests meet the repository floor a confirmatory label needs.
    ready = (not problems and not placeholder_count and powered_plan
             and len(tasks) >= sample_size)
    return {
        "schema_version": 1,
        "kind": "efficacy_manifest_validation",
        "valid": not problems,
        "ready": ready,
        "problems": problems,
        "protocol_digest": protocol.get("protocol_digest"),
        "required_sample_size": (
            protocol.get("power_analysis", {}).get("required_n")
            if isinstance(protocol.get("power_analysis"), Mapping)
            else required_sample_size(0.6, 0.4)),
        "sample_size": sample_size,
        "tasks": len(tasks),
        "repositories": len(by_id),
        "holdout_repositories": len(
            (document.get("partitions") or {}).get("holdout") or [])
        if isinstance(document.get("partitions"), Mapping) else 0,
        "holdout_repositories_used": len(used),
        "holdout_snapshots_used": len(used_snapshots),
        "tasks_per_holdout_repository": dict(sorted(used.items())),
        "repository_trees": dict(sorted(repository_trees.items())),
        "repository_tree_versions": dict(
            sorted(repository_tree_versions.items())),
        "repository_execution": dict(sorted(repository_execution.items())),
        "repository_commits": dict(sorted(repository_commits.items())),
        "repository_origins": dict(sorted(
            (repository_id, repository.get("origin"))
            for repository_id, repository in by_id.items())),
        "distinct_repository_trees": len(set(repository_trees.values())),
        "repository_lineage": dict(sorted(repository_lineage.items())),
        "distinct_holdout_lineages": len(
            {lineage_components[repository_id] for repository_id in used
             if repository_id in holdout_ids}),
        "placeholders": placeholder_count,
        "confirmatory": confirmatory,
        "study_tier": study_tier,
        "min_holdout_repositories": min_holdout,
        "manifest_digest": _canonical(document),
    }


def _walk(value):
    if isinstance(value, Mapping):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk(item)
    else:
        yield value


__all__ = ["CONFIRMATORY", "DIAGNOSTIC", "EXPLORATORY",
           "MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES",
           "MIN_HOLDOUT_REPOSITORIES", "MIN_REPOSITORIES", "STUDY_TIERS",
           "validate_manifest", "verify_repository_binding",
           "verify_repository_execution", "verify_repository_provenance"]
