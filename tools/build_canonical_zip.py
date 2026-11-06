"""Build a deterministic, final-artifact-verified release ZIP.

Historical SOURCE_SHA256.json is excluded intentionally. Distributed source
is inventoried by the single RELEASE_SHA256.json included in the archive.

`release/` is out-of-band provenance and is never inventoried into the
archive: it contains the archive itself, so including it would embed the
previous ZIP (and its stale checksum) inside every rebuild. The build is
bound to the source tree it came from: `verify_against_tree` re-hashes every
archived member against the working tree, and the source commit/dirty state
is recorded in the returned report.
"""
from __future__ import annotations
import argparse
import json
import subprocess
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_release import verify, verify_against_tree
from build_release import write_manifest

GENERATED_PATHS = {"RELEASE_SHA256.json",
                   "evidence/release/build_record.json",
                   "evidence/release/release_verification.json"}


def source_binding(root: Path) -> dict:
    """Record the Git commit and any uncommitted source changes."""
    try:
        commit = subprocess.check_output(
            ["git", "-C", str(root), "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        ).decode().strip()
        status = subprocess.check_output(
            ["git", "-C", str(root), "status", "--porcelain", "--untracked-files=all"],
            stderr=subprocess.DEVNULL,
        ).decode()
    except (OSError, subprocess.CalledProcessError):
        return {"commit": None, "dirty": None, "dirty_paths": [], "note": "not a git checkout"}
    dirty = []
    for line in status.splitlines():
        path = line[3:].strip()
        if not path or path.startswith("release/") or path in GENERATED_PATHS:
            continue
        dirty.append(path)
    return {"commit": commit, "dirty": bool(dirty), "dirty_paths": dirty[:20]}


def build(root: Path, target: Path, require_clean: bool = True,
          project: str | None = None):
    root = Path(root).resolve()
    target = Path(target).resolve()
    project = project or root.name
    if not project or "/" in project or "\\" in project or project in {".", ".."}:
        raise ValueError("project name must be a single safe path component")
    binding = source_binding(root)
    if require_clean and binding["dirty"]:
        raise ValueError(
            "source tree has uncommitted changes; commit them or pass --allow-dirty: "
            + ", ".join(binding["dirty_paths"][:5])
        )
    write_manifest(root)
    manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
    for relative in manifest["files"]:
        if relative.startswith("release/") or relative.endswith(".zip"):
            raise ValueError("manifest covers out-of-band provenance: " + relative)
    target.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for rel in sorted([*manifest["files"], "RELEASE_SHA256.json"]):
            p = root / rel
            if p.is_symlink() or not p.is_file():
                raise ValueError("missing_or_symlink_member:" + rel)
            info = zipfile.ZipInfo(project + "/" + rel, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100644 << 16)
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    report = verify(target)
    report["source_binding"] = verify_against_tree(target, root)
    report["source"] = binding
    return report


def main():
    p = argparse.ArgumentParser()
    p.add_argument("path", type=Path, help="output ZIP path")
    p.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    p.add_argument("--allow-dirty", action="store_true",
                   help="build from a dirty tree (recorded in the report; not for releases)")
    p.add_argument("--project", default=None,
                   help="archive-internal project directory; defaults to the"
                        " source directory name")
    args = p.parse_args()
    print(json.dumps(build(args.source.resolve(), args.path.resolve(),
                           require_clean=not args.allow_dirty,
                           project=args.project), indent=2))


if __name__ == "__main__":
    main()
