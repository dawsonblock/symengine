"""Verify the release source inventory or a pinned Git baseline manifest.

Default mode checks the current checkout exactly. ``--baseline-ref`` verifies
the manifest and blobs stored at that immutable Git revision, then reports the
development delta separately; it never implies that the baseline manifest
covers unmanifested development changes.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {"__pycache__", ".git", ".venv", "dist", "build",
             ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox",
             "htmlcov"}
SKIP_EXTS = {".pyc", ".pyo", ".sqlite3", ".db", ".log",
             ".sqlite3-wal", ".sqlite3-shm", ".sqlite3-journal",
             ".db-wal", ".db-shm", ".db-journal"}
# `release/` holds out-of-band provenance: the archive, its checksums, and the
# manifest that describes the archive. It must never be inventoried *into* the
# archive, or every rebuild would embed the previous release (and its stale
# checksum) inside the next one.
OUT_OF_BAND_DIRS = {"release"}
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
            and not (path.parts and path.parts[0] in OUT_OF_BAND_DIRS)
            and relative not in OUT_OF_BAND_FILES
            and not any(part in SKIP_DIRS or part.endswith(".egg-info") for part in path.parts)
            and path.suffix not in SKIP_EXTS)


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
    try:
        raw = _git(ROOT, "show", f"{ref}:SOURCE_SHA256.json")
        document = json.loads(raw.decode("utf-8"))
        manifest = _valid_manifest(document)
        entries = _git(ROOT, "ls-tree", "-rz", "--full-tree", ref)
    except (subprocess.CalledProcessError, UnicodeDecodeError, json.JSONDecodeError) as exc:
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
            manifest = _valid_manifest(json.loads((ROOT / "SOURCE_SHA256.json").read_text(encoding="utf-8")))
            count = _verify_worktree(manifest)
            print(f"{count} source files SHA-256 verified in the current working tree")
            return 0

        baseline_document, baseline_manifest = _read_baseline(args.baseline_ref)
        print(f"{len(baseline_manifest)} source files SHA-256 verified at baseline {args.baseline_ref}")
        try:
            current_document = json.loads((ROOT / "SOURCE_SHA256.json").read_text(encoding="utf-8"))
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
