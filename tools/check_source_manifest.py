"""Verify the release source inventory or a pinned Git baseline manifest.

Default mode checks the current checkout exactly. ``--baseline-ref`` verifies
the manifest and blobs stored at that immutable Git revision, then reports the
development delta separately; it never implies that the baseline manifest
covers unmanifested development changes.

The authoritative manifest is ``RELEASE_SHA256.json``. The historical
``SOURCE_SHA256.json`` is still accepted, so a checkout that predates the
release inventory can be verified without rewriting it.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_NAMES = ("RELEASE_SHA256.json", "SOURCE_SHA256.json")
SKIP_DIRS = {"__pycache__", ".git", ".venv", "dist", "build",
             ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
             "htmlcov"}
SKIP_EXTS = {".pyc", ".pyo", ".sqlite3", ".db", ".log",
             ".sqlite3-wal", ".sqlite3-shm", ".sqlite3-journal",
             ".db-wal", ".db-shm", ".db-journal"}
# Coverage state is produced by test runs, not shipped source. It must never
# enter the release inventory, or a fresh checkout cannot reproduce the seal.
SKIP_NAMES = {".coverage"}
# `release/` holds out-of-band provenance: the archive, its checksums, and the
# manifest that describes the archive. It must never be inventoried *into* the
# archive, or every rebuild would embed the previous release (and its stale
# checksum) inside the next one.
OUT_OF_BAND_DIRS = {"release"}
# A top-level `.claude/` is local agent state: Claude Code keeps agent
# worktrees (full checkouts of other branches) and `settings.local.json`
# there. `.git/info/exclude` hides it from `git status`, so the clean-tree
# gate cannot catch it; without this a seal would hash and archive all of
# it. Matched on the first path component only, like OUT_OF_BAND_DIRS: a
# nested `.claude` (e.g. `docs/.claude/`) is ordinary source.
LOCAL_STATE_DIRS = {".claude"}
# The build record describes the build, not the source. It is rewritten by
# every packaging run, so it cannot be part of the archive it describes.
OUT_OF_BAND_FILES = {"evidence/release/build_record.json",
                       "evidence/release/release_verification.json"}


def _valid_manifest(document):
    if (not isinstance(document, dict) or set(document) != {"schema", "files"}
            or type(document["schema"]) is not int or document["schema"] != 1
            or not isinstance(document["files"], dict)):
        raise ValueError("invalid manifest schema")
    for relative, expected in document["files"].items():
        pure = PurePosixPath(relative) if isinstance(relative, str) else PurePosixPath(".")
        if (not isinstance(relative, str) or not relative or pure.is_absolute() or "\\" in relative
                or any(part in ("", ".", "..") for part in relative.split("/"))
                or not isinstance(expected, str) or len(expected) != 64
                or any(c not in "0123456789abcdef" for c in expected)):
            raise ValueError("unsafe manifest entry " + repr(relative))
    return document["files"]


def _included(relative):
    path = PurePosixPath(relative)
    return (path.name not in {"SOURCE_SHA256.json", "RELEASE_SHA256.json"}
            and path.name not in SKIP_NAMES
            and not path.name.startswith(".coverage.")
            and not (path.parts and path.parts[0] in OUT_OF_BAND_DIRS)
            and not (path.parts and path.parts[0] in LOCAL_STATE_DIRS)
            and relative not in OUT_OF_BAND_FILES
            and not any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts)
            and path.suffix not in SKIP_EXTS)


def _manifest_path(root=None):
    """Return the authoritative manifest name and path in ``root``."""
    root = ROOT if root is None else root
    for name in MANIFEST_NAMES:
        path = root / name
        if path.is_file():
            return name, path
    raise ValueError(
        "no source manifest found; expected one of " + ", ".join(MANIFEST_NAMES))


def _verify_worktree(manifest):
    actual = {}
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT).as_posix()
        if not _included(relative) or path.is_symlink() or not path.is_file():
            continue
        actual[relative] = path
    if set(actual) != set(manifest):
        omitted = sorted(set(actual) - set(manifest))
        missing = sorted(set(manifest) - set(actual))
        raise ValueError("working-tree inventory mismatch; omitted=" + repr(omitted[:8])
                         + " missing=" + repr(missing[:8]))
    for relative, expected in manifest.items():
        if hashlib.sha256(actual[relative].read_bytes()).hexdigest() != expected:
            raise ValueError("working-tree hash mismatch: " + relative)
    return len(manifest)


def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], stderr=subprocess.PIPE)


def _read_baseline(ref):
    document = None
    for name in MANIFEST_NAMES:
        try:
            raw = _git(ROOT, "show", f"{ref}:{name}")
        except subprocess.CalledProcessError:
            continue
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"cannot read manifest {name} at Git revision {ref!r}") from exc
        break
    if document is None:
        raise ValueError(
            f"cannot read manifest/tree at Git revision {ref!r}")
    manifest = _valid_manifest(document)
    try:
        entries = _git(ROOT, "ls-tree", "-rz", "--full-tree", ref)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"cannot read manifest/tree at Git revision {ref!r}") from exc

    blobs = {}
    try:
        for entry in entries.split(b"\0"):
            if not entry:
                continue
            metadata, path_bytes = entry.split(b"\t", 1)
            mode, object_type, _oid = metadata.decode("ascii").split(" ", 2)
            relative = path_bytes.decode("utf-8", errors="strict")
            # The release inventory intentionally excludes symlink targets.
            if object_type == "blob" and mode != "120000" and _included(relative):
                blobs[relative] = None
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"baseline tree at {ref!r} contains an unsupported path entry") from exc
    if set(blobs) != set(manifest):
        omitted = sorted(set(blobs) - set(manifest))
        missing = sorted(set(manifest) - set(blobs))
        raise ValueError(f"baseline inventory mismatch at {ref}; omitted={omitted[:8]!r} missing={missing[:8]!r}")
    for relative, expected in manifest.items():
        try:
            content = _git(ROOT, "show", f"{ref}:{relative}")
        except subprocess.CalledProcessError as exc:
            raise ValueError(f"cannot read baseline blob {relative!r} at {ref}") from exc
        if hashlib.sha256(content).hexdigest() != expected:
            raise ValueError(f"baseline hash mismatch at {ref}: {relative}")
    return document, manifest


def _development_delta(ref):
    changed = set()
    try:
        changed.update(path.decode("utf-8", errors="replace")
                       for path in _git(ROOT, "diff", "--name-only", "-z", ref, "--").split(b"\0") if path)
        changed.update(path.decode("utf-8", errors="replace")
                       for path in _git(ROOT, "ls-files", "--others", "--exclude-standard", "-z").split(b"\0") if path)
    except subprocess.CalledProcessError as exc:
        raise ValueError(f"cannot compare working tree with Git baseline {ref!r}") from exc
    return sorted(changed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-ref", help="verify the manifest in this Git revision; report development changes separately")
    args = parser.parse_args(argv)
    try:
        if not args.baseline_ref:
            name, path = _manifest_path()
            manifest = _valid_manifest(
                json.loads(path.read_text(encoding="utf-8")))
            count = _verify_worktree(manifest)
            print(f"{count} source files SHA-256 verified in the current"
                  f" working tree ({name})")
            return 0

        baseline_document, baseline_manifest = _read_baseline(args.baseline_ref)
        print(f"{len(baseline_manifest)} source files SHA-256 verified at baseline {args.baseline_ref}")
        try:
            _, current_path = _manifest_path()
            current_document = json.loads(
                current_path.read_text(encoding="utf-8"))
            current_manifest = _valid_manifest(current_document)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("current source manifest is malformed") from exc

        if current_document == baseline_document:
            delta = _development_delta(args.baseline_ref)
            print(f"development delta: {len(delta)} paths; baseline manifest does not cover these changes")
            return 0

        count = _verify_worktree(current_manifest)
        print(f"{count} source files SHA-256 verified in the current development manifest")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"integrity failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
