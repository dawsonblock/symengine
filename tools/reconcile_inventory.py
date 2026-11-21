#!/usr/bin/env python3
"""Reconcile a source tree against the sealed release inventory.

``RELEASE_SHA256.json`` is rewritten only by the owner's release process,
so on a development revision it describes the last seal, not the tree.
``tools/build_release.py --check`` then reports "release manifest is
stale". This tool does not rehash the inventory. It explains the drift:

1. Every path the release tooling inventories (``build_release.inventory``
   and its ``check_source_manifest._included`` filter, unchanged) is put
   into one class: ``unchanged``, ``modified`` (hash differs),
   ``missing_from_tree`` (inventoried, absent) or ``extra_in_tree``
   (present, not inventoried).
2. The seal commit is the last commit that touched the inventory file
   (or ``--seal-commit``). The inventory must be byte-identical to the
   file at that commit, and the seal commit's tree must hold exactly the
   inventoried files with their recorded hashes.
3. Each path that is not ``unchanged`` is attributed to the commits that
   descend from the seal, are ancestors of the revision, and changed it,
   following renames (``--name-status -M``). Merge commits are reported
   by the pull request they merged.
4. Each tree file is compared with the revision (``HEAD`` or
   ``--revision``). A file whose bytes differ from the revision, a file
   in neither the revision nor the inventory, an inventoried file the
   tree lacks but the revision has, a revision file the tree lacks, and
   a changed path no commit since the seal touched are ``unattributed``.

The tree may be the checkout itself or an extracted archive (point
``--tree`` at the project directory inside it). The gate fails (exit 1)
when any path is unattributed or the inventory is not the seal; exit 2
is a usage or Git error.

Usage:
    python3 tools/reconcile_inventory.py
    python3 tools/reconcile_inventory.py --tree /tmp/x/symengine-main \\
        --revision <commit> --json report.json --markdown report.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "src"))
from build_release import MANIFEST_NAME, inventory  # noqa: E402
from check_source_manifest import _included, _valid_manifest  # noqa: E402
from sis.v3 import gitquery  # noqa: E402

CLASSES = ("unchanged", "modified", "missing_from_tree", "extra_in_tree")
CHANGED_CLASSES = CLASSES[1:]
SOURCE_INVENTORY = "release/source_inventory.json"
RELEASE_MANIFEST = "release/release_manifest.json"
_PR = re.compile(r"pull request #(\d+)|\(#(\d+)\)")
_DIRECT = "direct"


class ReconcileError(Exception):
    """The inputs cannot be reconciled (exit 2)."""


# -- Git ---------------------------------------------------------------


def _git(repo: Path, *args: str, stdin: bytes | None = None) -> bytes:
    """Run one read-only Git command with the hardened query settings."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo), *gitquery._GLOBAL_OPTIONS, *args],
            input=stdin, capture_output=True, timeout=300, check=False,
            env=gitquery.environment())
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReconcileError(f"git {args[0]} failed: {exc}") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", "replace").strip()
        raise ReconcileError(f"git {args[0]} failed: {message[:300]}")
    return completed.stdout


def _text(repo: Path, *args: str) -> str:
    return _git(repo, *args).decode("utf-8", "replace").strip()


def _commit(repo: Path, revision: str) -> str:
    return _text(repo, "rev-parse", "--verify", "--end-of-options",
                 revision + "^{commit}")


def _show(repo: Path, commit: str, path: str) -> bytes | None:
    try:
        return _git(repo, "cat-file", "blob", f"{commit}:{path}")
    except ReconcileError:
        return None


def _blob_id(algorithm: str, data: bytes) -> str:
    hasher = hashlib.new(algorithm)
    hasher.update(b"blob %d\0" % len(data))
    hasher.update(data)
    return hasher.hexdigest()


def revision_files(repo: Path, commit: str) -> dict[str, str]:
    """Inventoried paths of ``commit`` (release filter) -> blob id."""
    files: dict[str, str] = {}
    output = _git(repo, "ls-tree", "-r", "-z", "--full-tree", commit)
    for record in output.split(b"\0"):
        if not record:
            continue
        meta, _, raw = record.partition(b"\t")
        mode, kind, oid = meta.decode("ascii").split()
        relative = raw.decode("utf-8", "surrogateescape")
        # The release inventory excludes symlinks and submodules.
        if kind == "blob" and mode != "120000" and _included(relative):
            files[relative] = oid
    return files


def _blob_sha256(repo: Path, oids: list[str]) -> dict[str, str]:
    """SHA-256 of each blob's content, read in one ``cat-file`` batch."""
    unique = sorted(set(oids))
    if not unique:
        return {}
    output = _git(repo, "cat-file", "--batch",
                  stdin="".join(oid + "\n" for oid in unique).encode())
    digests: dict[str, str] = {}
    offset = 0
    for oid in unique:
        end = output.index(b"\n", offset)
        header = output[offset:end].split()
        if len(header) != 3 or header[1] != b"blob":
            raise ReconcileError(f"cannot read blob {oid}")
        size = int(header[2])
        start = end + 1
        digests[oid] = hashlib.sha256(output[start:start + size]).hexdigest()
        offset = start + size + 1
    return digests


def _commits(repo: Path, *args: str) -> list[dict]:
    """Commits in topological order, newest first."""
    output = _text(repo, "log", "--topo-order",
                   "--format=%H%x1f%h%x1f%P%x1f%s", *args)
    commits = []
    for line in output.splitlines():
        full, short, parents, subject = line.split("\x1f", 3)
        commits.append({"commit": full, "short": short,
                        "parents": parents.split(), "subject": subject})
    return commits


def history(repo: Path, seal: str, commit: str) -> dict:
    """Commits from the seal to ``commit`` and the paths each changed.

    The lineage is ``--ancestry-path seal..commit``: commits that descend
    from the seal and are ancestors of the revision. Other commits in
    ``seal..commit`` (history the seal never saw, joined by a merge) are
    counted but attributed nothing; a merge is attributed only what
    differs from every lineage parent it has, so content it took from
    outside the lineage is still attributed to it.
    """
    ancestor = gitquery.predicate(
        repo, "merge-base", "--is-ancestor", seal, commit)
    if seal == commit:
        in_range, lineage = [], []
    else:
        in_range = _commits(repo, f"{seal}..{commit}")
        lineage = (_commits(repo, "--ancestry-path", f"{seal}..{commit}")
                   if ancestor else in_range)
    members = {item["commit"] for item in lineage}
    pairs: list[tuple[str, str | None]] = []
    for item in lineage:
        parents = item["parents"]
        if len(parents) <= 1:
            pairs.append((item["commit"], None))
            continue
        bases = [p for p in parents if p in members or p == seal] or parents
        pairs.extend((item["commit"], base) for base in bases)
    changes = _diff_pairs(repo, pairs)
    for item in lineage:
        found = changes.get(item["commit"]) or [[]]
        if len(found) == 1:
            item["changes"] = found[0]
            continue
        # A merge keeps only what differs from every lineage parent.
        common = set.intersection(*(
            {path for entry in entries for path in entry[1:]}
            for entries in found))
        item["changes"] = [entry for entry in found[0]
                           if common & set(entry[1:])]
    return {"in_range": len(in_range), "lineage": lineage,
            "seal_is_ancestor": ancestor}


def _diff_pairs(repo: Path, pairs: list[tuple[str, str | None]]) -> dict:
    """``diff-tree -M --name-status`` for each (commit, base) pair."""
    if not pairs:
        return {}
    lines = "".join(
        commit + ("" if base is None else " " + base) + "\n"
        for commit, base in pairs)
    output = _git(repo, "diff-tree", "--stdin", "--always", "--root", "-r",
                  "-M", "--name-status", "-z", stdin=lines.encode())
    tokens = output.decode("utf-8", "surrogateescape").split("\0")
    if tokens and tokens[-1] == "":
        tokens.pop()
    result: dict[str, list[list[tuple]]] = {}
    index = 0
    for position, (commit, _base) in enumerate(pairs):
        following = pairs[position + 1][0] if position + 1 < len(pairs) else None
        if index >= len(tokens) or tokens[index] != commit:
            raise ReconcileError(f"unexpected diff-tree output for {commit}")
        index += 1
        entries: list[tuple] = []
        # A status token is a letter and an optional score, never a
        # commit id, so the next header is recognised without ambiguity.
        while index < len(tokens) and tokens[index] != following:
            status = tokens[index]
            if status[:1] in ("R", "C"):
                entries.append((status, tokens[index + 1], tokens[index + 2]))
                index += 3
            else:
                entries.append((status, tokens[index + 1]))
                index += 2
        result.setdefault(commit, []).append(entries)
    return result


def _follow(path: str, lineage: list[dict]) -> list[dict]:
    """Commits that changed ``path``, following renames backwards."""
    names = {path}
    events = []
    for item in lineage:
        for entry in item["changes"]:
            status, paths = entry[0], entry[1:]
            if not names & set(paths):
                continue
            event = {"commit": item["short"], "status": status[:1]}
            if len(paths) == 2:
                event["from"], event["to"] = paths
                if status.startswith("R") and paths[1] in names:
                    names.add(paths[0])
            events.append(event)
    return events


def _pull_request(subject: str) -> int | None:
    match = _PR.search(subject)
    return int(match.group(1) or match.group(2)) if match else None


def _groups(repo: Path, lineage: list[dict]) -> dict[str, dict]:
    """Assign each lineage commit to the innermost pull request merging it."""
    members = {item["commit"] for item in lineage}
    merges = []
    for item in lineage:
        number = _pull_request(item["subject"])
        if len(item["parents"]) > 1 and number is not None:
            merged = set(_text(repo, "rev-list", item["commit"], "--not",
                               item["parents"][0]).split()) & members
            merges.append((item, number, merged))
    owner: dict[str, dict] = {}
    for item in lineage:
        containing = [(len(merged), merge, number)
                      for merge, number, merged in merges
                      if item["commit"] in merged]
        if containing:
            _size, merge, number = min(containing, key=lambda c: c[0])
            owner[item["commit"]] = {"pr": number, "merge": merge["short"],
                                     "merge_subject": merge["subject"]}
        else:
            owner[item["commit"]] = {"pr": None, "merge": None,
                                     "merge_subject": None}
    return owner


# -- Reconciliation ------------------------------------------------------


def load_inventory(path: Path) -> tuple[bytes, dict[str, str]]:
    try:
        raw = path.read_bytes()
        document = json.loads(raw)
    except (OSError, ValueError) as exc:
        raise ReconcileError(f"inventory is unreadable: {exc}") from exc
    try:
        return raw, dict(_valid_manifest(document))
    except ValueError as exc:
        raise ReconcileError(f"inventory is invalid: {exc}") from exc


def classify(recorded: dict[str, str], actual: dict[str, str]) -> dict[str, str]:
    classes = {}
    for path in sorted(set(recorded) | set(actual)):
        if path not in actual:
            classes[path] = "missing_from_tree"
        elif path not in recorded:
            classes[path] = "extra_in_tree"
        elif actual[path] != recorded[path]:
            classes[path] = "modified"
        else:
            classes[path] = "unchanged"
    return classes


def _seal_metadata(repo: Path, seal: str, recorded: dict[str, str]) -> dict:
    """What the seal commit records about the release it sealed."""
    result: dict = {"release": None, "source_commit": None,
                    "source_inventory_agrees": None, "status": None,
                    "provenance_signed": None, "test_evidence_signed": None}
    raw = _show(repo, seal, SOURCE_INVENTORY)
    if raw is not None:
        try:
            document = json.loads(raw)
            result["release"] = document.get("release")
            result["source_commit"] = document.get("source_commit")
            result["source_inventory_agrees"] = {
                path: entry.get("sha256")
                for path, entry in document.get("files", {}).items()
            } == recorded
        except (ValueError, AttributeError):
            result["source_inventory_agrees"] = False
    raw = _show(repo, seal, RELEASE_MANIFEST)
    if raw is not None:
        try:
            document = json.loads(raw)
            result["release"] = result["release"] or document.get("release")
            result["status"] = document.get("status")
            result["provenance_signed"] = (
                document.get("provenance") or {}).get("signed")
            result["test_evidence_signed"] = (
                (document.get("test_result") or {}).get("evidence") or {}
            ).get("signed")
        except (ValueError, AttributeError):
            pass
    return result


def _inventory_name(repo: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(repo).as_posix()
    except ValueError:
        return MANIFEST_NAME


def _tree_label(repo: Path, tree: Path) -> dict:
    if tree == repo:
        return {"name": ".", "inside_repository": True,
                "is_repository_root": True}
    try:
        return {"name": tree.relative_to(repo).as_posix(),
                "inside_repository": True, "is_repository_root": False}
    except ValueError:
        return {"name": tree.name, "inside_repository": False,
                "is_repository_root": False}


def reconcile(*, repo: Path, tree: Path | None = None,
              inventory_path: Path | None = None,
              revision: str = "HEAD",
              seal_commit: str | None = None) -> dict:
    top = _text(Path(repo), "rev-parse", "--show-toplevel")
    repo = Path(top).resolve()
    tree = repo if tree is None else Path(tree).resolve()
    if not tree.is_dir():
        raise ReconcileError(f"tree is not a directory: {tree}")
    inventory_path = (repo / MANIFEST_NAME if inventory_path is None
                      else Path(inventory_path))
    raw_inventory, recorded = load_inventory(inventory_path)
    algorithm = _text(repo, "rev-parse", "--show-object-format")
    if algorithm not in ("sha1", "sha256"):
        raise ReconcileError(f"unsupported object format: {algorithm}")
    commit = _commit(repo, revision)
    # An inventory outside the checkout (an extracted archive's copy) is
    # looked up under the release manifest's own name.
    name = _inventory_name(repo, inventory_path)
    if seal_commit is None:
        found = _text(repo, "log", "-1", "--format=%H", commit, "--", name)
        if not found:
            raise ReconcileError(
                f"no commit at {revision} touched {name}; pass --seal-commit")
        seal = found
    else:
        seal = _commit(repo, seal_commit)
    seal_subject = _text(repo, "log", "-1", "--format=%s", seal)
    problems: list[str] = []
    matches_seal = _show(repo, seal, name) == raw_inventory
    if not matches_seal:
        problems.append(
            f"the inventory is not byte-identical to {name} at the seal"
            f" commit {seal[:12]}")

    # The seal commit's tree must be what the inventory describes.
    seal_tree = revision_files(repo, seal)
    seal_digests = _blob_sha256(repo, list(seal_tree.values()))
    seal_mismatch = sorted(
        path for path in set(seal_tree) | set(recorded)
        if path not in seal_tree or path not in recorded
        or seal_digests[seal_tree[path]] != recorded[path])

    actual = inventory(tree)  # the release tooling's own walk and filter
    classes = classify(recorded, actual)
    rev_tree = revision_files(repo, commit)
    tree_oids = {path: _blob_id(algorithm, (tree / path).read_bytes())
                 for path in actual}

    walk = history(repo, seal, commit)
    lineage = walk["lineage"]
    owners = _groups(repo, lineage)

    unattributed: dict[str, str] = {}
    for path in sorted(actual):
        if path not in rev_tree:
            unattributed[path] = (
                "in neither the revision nor the inventory"
                if path not in recorded else "not in the revision")
        elif tree_oids[path] != rev_tree[path]:
            unattributed[path] = "bytes differ from the revision"
    for path in sorted(set(recorded) - set(actual)):
        if path in rev_tree:
            unattributed[path] = "absent from the tree but in the revision"
    revision_only = sorted(set(rev_tree) - set(actual) - set(recorded))
    for path in revision_only:
        unattributed[path] = "in the revision but not in the tree"
    for path in seal_mismatch:
        unattributed.setdefault(
            path, "the seal commit's tree does not match the inventory")

    entries: dict[str, list[dict]] = {cls: [] for cls in CLASSES}
    renames = []
    for path, cls in classes.items():
        if cls == "unchanged":
            record = {"path": path}
            if path in unattributed:
                record["unattributed"] = unattributed[path]
            entries[cls].append(record)
            continue
        events = _follow(path, lineage)
        if not events:
            unattributed.setdefault(
                path, "no commit since the seal changed it")
        record = {"path": path, "commits": events}
        for event in events:
            if event["status"] != "R":
                continue
            if event["to"] == path and cls == "extra_in_tree" \
                    and event["from"] in recorded:
                record["renamed_from"] = event["from"]
            if event["from"] == path and cls == "missing_from_tree":
                record["renamed_to"] = event["to"]
                renames.append({"from": path, "to": event["to"],
                                "commit": event["commit"]})
        if path in unattributed:
            record["unattributed"] = unattributed[path]
        entries[cls].append(record)

    groups = _group_report(lineage, owners, entries)
    counts = {cls: len(entries[cls]) for cls in CLASSES}
    counts["unattributed"] = len(unattributed)
    counts["renamed"] = len(renames)
    release = _seal_metadata(repo, seal, recorded)
    if seal_mismatch:
        problems.append(
            f"{len(seal_mismatch)} paths differ between the seal commit's"
            " tree and the inventory")
    if unattributed:
        problems.append(f"{len(unattributed)} paths are unattributed")
    return {
        "schema_version": 1,
        "kind": "inventory_reconciliation",
        "generated_at": datetime.now(timezone.utc).isoformat(
            timespec="seconds").replace("+00:00", "Z"),
        "inventory": {
            "path": name,
            "sha256": hashlib.sha256(raw_inventory).hexdigest(),
            "files": len(recorded),
            "seal_commit": seal,
            "seal_subject": seal_subject,
            "matches_seal_commit": matches_seal,
            "seal_tree_matches_inventory": not seal_mismatch,
            "seal_tree_mismatches": seal_mismatch[:50],
            **release,
        },
        "tree": {**_tree_label(repo, tree), "files": len(actual)},
        "revision": {
            "requested": revision,
            "commit": commit,
            "subject": _text(repo, "log", "-1", "--format=%s", commit),
            "revision_files": len(rev_tree),
            "revision_only": revision_only,
        },
        "history": {
            "commits_since_seal": walk["in_range"],
            "lineage_commits": len(lineage),
            "lineage_merges": sum(1 for c in lineage if len(c["parents"]) > 1),
            "outside_lineage": walk["in_range"] - len(lineage)
            if walk["seal_is_ancestor"] else 0,
            "seal_is_ancestor": walk["seal_is_ancestor"],
        },
        "counts": counts,
        "renames": renames,
        "paths": entries,
        "unattributed": [{"path": path, "class": classes.get(path),
                          "reason": reason}
                         for path, reason in sorted(unattributed.items())],
        "groups": groups,
        "statement": _statement(release, commit),
        "reproduce": _reproduce(repo, tree, commit),
        "gate": {"passed": not problems, "problems": problems},
    }


def _group_report(lineage, owners, entries) -> list[dict]:
    touched: dict[str, dict[str, list[str]]] = {}
    for cls in CHANGED_CLASSES:
        for record in entries[cls]:
            for event in record["commits"]:
                bucket = touched.setdefault(event["commit"], {})
                bucket.setdefault(cls, []).append(record["path"])
    groups: dict[str, dict] = {}
    order: list[str] = []
    for item in lineage:
        owner = owners[item["commit"]]
        key = _DIRECT if owner["pr"] is None else f"PR #{owner['pr']}"
        if key not in groups:
            order.append(key)
            groups[key] = {"group": key, "pr": owner["pr"],
                           "merge": owner["merge"],
                           "merge_subject": owner["merge_subject"],
                           "commits": [], "commits_total": 0,
                           "paths": {cls: 0 for cls in CHANGED_CLASSES}}
        group = groups[key]
        group["commits_total"] += 1
        paths = touched.get(item["short"])
        if paths:
            group["commits"].append({
                "commit": item["short"], "subject": item["subject"],
                "merge": len(item["parents"]) > 1,
                "paths": {cls: sorted(set(found))
                          for cls, found in sorted(paths.items())}})
    for group in groups.values():
        seen: dict[str, set[str]] = {cls: set() for cls in CHANGED_CLASSES}
        for entry in group["commits"]:
            for cls, found in entry["paths"].items():
                seen[cls].update(found)
        group["paths"] = {cls: len(found) for cls, found in seen.items()}
    return [groups[key] for key in order]


def _reproduce(repo: Path, tree: Path, commit: str) -> str:
    """A path-free command that regenerates this report's findings."""
    command = "python3 tools/reconcile_inventory.py"
    if tree != repo:
        command += " --tree <extracted project directory>"
    return command + f" --revision {commit[:12]}"


def _statement(release: dict, commit: str) -> str:
    name = release.get("release") or "the last release"
    return (
        f"The inventory is the {name} seal. The tree is a development"
        f" revision ({commit[:12]}), not a release: its drift from the"
        " inventory is expected and is not repaired by rehashing. The seal"
        " must be"
        " regenerated by the owner's signed release process.")


# -- Rendering -----------------------------------------------------------


def _yes(value) -> str:
    return {True: "yes", False: "no", None: "unknown"}[value]


def _some(paths: list[str], limit: int = 6) -> str:
    """The first ``limit`` paths; the full list is under "Paths"."""
    shown = ", ".join(f"`{path}`" for path in paths[:limit])
    return shown + (f" and {len(paths) - limit} more"
                    if len(paths) > limit else "")


def render_markdown(report: dict) -> str:
    inv, tree, rev = report["inventory"], report["tree"], report["revision"]
    hist, counts = report["history"], report["counts"]
    lines = [
        "# Inventory reconciliation against the sealed release inventory",
        "",
        "Generated by `tools/reconcile_inventory.py` at"
        f" {report['generated_at']}.",
        "",
        "## Statement",
        "",
        report["statement"],
        "",
        "## Inputs",
        "",
        f"- Inventory: `{inv['path']}`, {inv['files']} files, SHA-256"
        f" `{inv['sha256']}`.",
        f"- Seal commit: `{inv['seal_commit'][:12]}` \"{inv['seal_subject']}\"."
        f" Inventory identical to the file at the seal commit:"
        f" {_yes(inv['matches_seal_commit'])}. The seal commit's tree holds"
        f" exactly the inventoried files and hashes:"
        f" {_yes(inv['seal_tree_matches_inventory'])}.",
        f"- Sealed release: {inv['release'] or 'unknown'}; source commit"
        f" `{(inv['source_commit'] or 'unknown')[:12]}`;"
        f" `{SOURCE_INVENTORY}` agrees with the inventory:"
        f" {_yes(inv['source_inventory_agrees'])}.",
        f"- Seal signature status (from `{RELEASE_MANIFEST}` at the seal):"
        f" status {inv['status'] or 'unknown'}, provenance signed"
        f" {_yes(inv['provenance_signed'])}, test evidence signed"
        f" {_yes(inv['test_evidence_signed'])}.",
        f"- Tree: `{tree['name']}`"
        + (" (the repository checkout)" if tree["is_repository_root"]
           else "" if tree["inside_repository"]
           else " (outside the repository, e.g. an extracted archive)")
        + f", {tree['files']} inventoried files.",
        f"- Revision: `{rev['commit'][:12]}` \"{rev['subject']}\""
        f" (requested `{rev['requested']}`); the tree is compared with it"
        " byte for byte.",
        f"- Reproduce from the repository root: `{report['reproduce']}`.",
        f"- History: {hist['commits_since_seal']} commits in"
        f" `seal..revision`; {hist['lineage_commits']} descend from the seal"
        f" ({hist['lineage_merges']} merges) and carry every change;"
        f" {hist['outside_lineage']} are history the seal never saw, joined"
        " by a merge, and are attributed nothing.",
        "",
        "## Counts",
        "",
        "| Class | Paths |",
        "| --- | ---: |",
    ]
    for cls in CLASSES:
        lines.append(f"| `{cls}` | {counts[cls]} |")
    lines.append(f"| `unattributed` | {counts['unattributed']} |")
    lines += [
        "",
        f"Gate: **{'passed' if report['gate']['passed'] else 'failed'}**.",
    ]
    for problem in report["gate"]["problems"]:
        lines.append(f"- {problem}")
    if report["unattributed"]:
        lines += ["", "## Unattributed paths", "",
                  "| Path | Class | Reason |", "| --- | --- | --- |"]
        for item in report["unattributed"]:
            lines.append(f"| `{item['path']}` | {item['class'] or '-'} |"
                         f" {item['reason']} |")
    if report["renames"]:
        lines += ["", "## Renames", "",
                  f"{counts['renamed']} inventoried paths were moved; each"
                  " appears once as `missing_from_tree` and once as"
                  " `extra_in_tree`.", "",
                  "| From | To | Commit |", "| --- | --- | --- |"]
        for item in report["renames"]:
            lines.append(f"| `{item['from']}` | `{item['to']}` |"
                         f" `{item['commit']}` |")
    lines += ["", "## Attribution by pull request", ""]
    for group in report["groups"]:
        if group["pr"] is None:
            title = "Commits not merged through a pull request"
        else:
            title = (f"PR #{group['pr']}: merge `{group['merge']}`"
                     f" \"{group['merge_subject']}\"")
        paths = group["paths"]
        lines += [
            f"### {title}", "",
            f"{group['commits_total']} commits;"
            f" {len(group['commits'])} change reconciled paths"
            f" ({paths['modified']} modified,"
            f" {paths['missing_from_tree']} missing,"
            f" {paths['extra_in_tree']} extra).",
            "",
        ]
        if group["commits"]:
            lines += ["| Commit | Subject | Paths |", "| --- | --- | --- |"]
            for entry in group["commits"]:
                found = "; ".join(
                    f"{cls} {len(paths_)}: " + _some(paths_)
                    for cls, paths_ in entry["paths"].items())
                subject = entry["subject"].replace("|", "\\|")
                lines.append(f"| `{entry['commit']}` | {subject} | {found} |")
            lines.append("")
    lines += ["## Paths", ""]
    for cls in CHANGED_CLASSES:
        records = report["paths"][cls]
        lines += [f"### `{cls}` ({len(records)})", ""]
        if not records:
            lines += ["None.", ""]
            continue
        lines += ["| Path | Commits since the seal | Note |",
                  "| --- | --- | --- |"]
        for record in records:
            commits = ", ".join(
                f"`{event['commit']}`" + (event["status"]
                                         if event["status"] != "M" else "")
                for event in record["commits"]) or "-"
            note = []
            if "renamed_from" in record:
                note.append(f"renamed from `{record['renamed_from']}`")
            if "renamed_to" in record:
                note.append(f"renamed to `{record['renamed_to']}`")
            if "unattributed" in record:
                note.append(f"**unattributed**: {record['unattributed']}")
            lines.append(f"| `{record['path']}` | {commits} |"
                         f" {'; '.join(note) or '-'} |")
        lines.append("")
    lines += [
        "Commit suffixes: `A` added, `D` deleted, `R` renamed; no suffix"
        " is a modification.",
        "",
    ]
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inventory", type=Path, default=None,
                        help="sealed inventory (default: RELEASE_SHA256.json"
                             " in --repo)")
    parser.add_argument("--tree", type=Path, default=None,
                        help="tree to reconcile: a checkout or an extracted"
                             " archive's project directory (default: the"
                             " repository root)")
    parser.add_argument("--repo", type=Path, default=Path("."),
                        help="Git checkout holding the history (default: .)")
    parser.add_argument("--revision", default="HEAD",
                        help="revision the tree must equal (default: HEAD)")
    parser.add_argument("--seal-commit", default=None,
                        help="seal commit (default: the last commit that"
                             " touched the inventory)")
    parser.add_argument("--json", type=Path, default=None,
                        help="write the JSON report here")
    parser.add_argument("--markdown", type=Path, default=None,
                        help="write the Markdown report here")
    args = parser.parse_args(argv)
    try:
        report = reconcile(repo=args.repo, tree=args.tree,
                           inventory_path=args.inventory,
                           revision=args.revision,
                           seal_commit=args.seal_commit)
    except (ReconcileError, OSError) as exc:
        print(f"inventory reconciliation failed: {exc}", file=sys.stderr)
        return 2
    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
    if args.markdown is not None:
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(render_markdown(report), encoding="utf-8")
    counts = report["counts"]
    print(" ".join(f"{cls}={counts[cls]}" for cls in (*CLASSES, "unattributed")))
    print(f"seal {report['inventory']['seal_commit'][:12]};"
          f" revision {report['revision']['commit'][:12]}")
    for item in report["unattributed"][:20]:
        print(f"unattributed: {item['path']}: {item['reason']}",
              file=sys.stderr)
    if report["gate"]["passed"]:
        print("every difference from the inventory is attributed to a commit"
              " since the seal")
        return 0
    for problem in report["gate"]["problems"]:
        print(f"gate failed: {problem}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
