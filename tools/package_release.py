#!/usr/bin/env python3
"""Build the release ZIP plus its out-of-band provenance bundle.

One command produces every artifact under ``release/`` from the current
source tree:

    SIS-v<version>-<label>.zip       archive (single project dir)
    RELEASE_SHA256.json                archive-internal manifest (repo root)
    release/release_manifest.json      release identity + source commit
    release/source_inventory.json      per-file hash + size
    release/verification.json          zip + fresh-extraction verification
    release/SHA256SUMS                 checksums of the out-of-band files

The archive never contains ``release/``: it is provenance about the
archive, not payload. The build refuses a dirty source tree, re-hashes
every member against the tree it came from, and records the exact Git
commit, so a stale ZIP cannot be published under a current manifest.
"""
from __future__ import annotations

import argparse
import compileall
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def _package_version(root: Path) -> str:
    """Read the version without importing the package under test."""
    source = (root / "src" / "sis" / "__init__.py").read_text(encoding="utf8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', source)
    if match is None:
        raise SystemExit("cannot determine the package version")
    return match.group(1)


sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance
from build_canonical_zip import build, source_binding
from verify_release import verify_tree

SMOKE_TEST = "tests/v3/test_candidates.py"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode().strip()


def _docs(root: Path) -> list[str]:
    paths = sorted((root / "docs" / "v3").glob("*.md"))
    paths += sorted((root / "docs" / "audits").glob("*.md"))
    return [p.relative_to(root).as_posix() for p in paths]


def _evidence(root: Path) -> list[str]:
    base = root / "evidence"
    return [f"evidence/{p.name}/" for p in sorted(base.iterdir()) if p.is_dir()]


def fresh_extraction_checks(tree: Path) -> dict:
    """Gate the extracted archive: it must compile and its smoke test pass.

    Recording a result is not verification. A non-compiling or
    test-failing extraction fails the build, so a broken archive can
    never ship under a green manifest.
    """
    if not compileall.compile_dir(str(tree / "src"), quiet=1, force=True):
        raise ValueError("fresh-extraction compile check failed")
    smoke = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", SMOKE_TEST],
        cwd=tree, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin",
             "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
             "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"},
    )
    lines = (smoke.stdout or smoke.stderr).strip().splitlines()
    tail = lines[-1] if lines else ""
    if smoke.returncode != 0:
        raise ValueError(
            f"fresh-extraction smoke test failed"
            f" (rc={smoke.returncode}): {tail}")
    return {
        "compileall_src": True,
        "extracted_test_smoke": {
            "command": f"pytest -q {SMOKE_TEST}",
            "returncode": smoke.returncode,
            "tail": tail,
        },
    }


def package(root: Path, release: str, *, status: str, passed: int,
            skipped: int, failed: int, allow_dirty: bool = False,
            provenance_seed: bytes | None = None,
            provenance_key_id: str = "release-key-1",
            provenance_trust_root: str = "qualification-only") -> dict:
    root = Path(root).resolve()
    out = root / "release"
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{release}.zip"

    binding = source_binding(root)
    build_record = {
        "schema_version": 1,
        "kind": "release_build_record",
        "release": release,
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "base_commit": binding["commit"],
        "builder": "tools/package_release.py -> tools/build_canonical_zip.py",
        "commit_binding": (
            "every archive member is re-hashed against the working tree at "
            "build time (verify_against_tree); the source commit and dirty "
            "state are recorded in release/verification.json"
        ),
        "manifest_scope": (
            "all _included() source/evidence files; release/ and "
            "evidence/release/build_record.json are out-of-band and never "
            "inventoried into the archive"
        ),
        "post_build_verification": (
            "release/verification.json — outside the archive by construction"
        ),
        "generated_at": _utcnow(),
    }
    (root / "evidence" / "release").mkdir(parents=True, exist_ok=True)
    (root / "evidence" / "release" / "build_record.json").write_text(
        json.dumps(build_record, indent=2, sort_keys=True) + "\n")

    started = _utcnow()
    report = build(root, archive, require_clean=not allow_dirty,
                   project=release)
    statement = provenance.build_statement(
        archive_name=archive.name,
        archive_sha256=report["zip_sha256"],
        release=release,
        branch=build_record["branch"],
        source_commit=report["source"]["commit"],
        builder="tools/package_release.py",
        invocation_id=f"release-{report['zip_sha256'][:16]}",
        started_on=started,
        finished_on=_utcnow())
    statement_sha256 = hashlib.sha256(
        provenance.canonical_json(statement)).hexdigest()
    if provenance_seed is not None:
        envelope = provenance.sign_statement(
            statement, provenance_seed, provenance_key_id)
        public_hex = provenance.public_key_hex(provenance_seed)
        provenance.verify_envelope(
            envelope, public_hex, archive_path=archive)
        provenance_path = out / "provenance.dsse.json"
        provenance_path.write_text(
            json.dumps(envelope, indent=2, sort_keys=True) + "\n")
        public_path = out / "provenance_public_key.hex"
        public_path.write_text(public_hex + "\n")
        provenance_info = {
            "signed": True,
            "key_id": provenance_key_id,
            "trust_root": provenance_trust_root,
            "path": f"release/{provenance_path.name}",
            "public_key_path": f"release/{public_path.name}",
            "statement_sha256": statement_sha256,
            "subject_sha256": report["zip_sha256"],
        }
    else:
        provenance_path = out / "provenance.intoto.json"
        provenance_path.write_text(
            json.dumps(statement, indent=2, sort_keys=True) + "\n")
        provenance_info = {
            "signed": False,
            "trust_root": provenance_trust_root,
            "path": f"release/{provenance_path.name}",
            "statement_sha256": statement_sha256,
            "subject_sha256": report["zip_sha256"],
        }
    manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
    inventory = {
        "schema_version": 1,
        "release": release,
        "source_commit": report["source"]["commit"],
        "files": {
            relative: {
                "sha256": digest,
                "bytes": (root / relative).stat().st_size,
            }
            for relative, digest in sorted(manifest["files"].items())
        },
    }

    with tempfile.TemporaryDirectory(prefix="sis-release-") as temp:
        with zipfile.ZipFile(archive) as z:
            z.extractall(temp)
        tree = Path(temp) / report["project"]
        tree_report = verify_tree(tree)
        fresh = fresh_extraction_checks(tree)
        verification = {
            "schema_version": 1,
            "kind": "release_verification",
            "archive": archive.name,
            "zip_verify": {
                "valid": report["valid"],
                "source_files": report["source_files"],
                "project": report["project"],
                "manifest": report["manifest"],
                "zip_sha256": report["zip_sha256"],
            },
            "source_binding": report["source_binding"],
            "source": report["source"],
            "fresh_extraction": {"verify_tree": tree_report, **fresh},
        }

    release_manifest = {
        "schema_version": 1,
        "release": release,
        "branch": _git(root, "rev-parse", "--abbrev-ref", "HEAD"),
        "source_commit": report["source"]["commit"],
        "source_commit_note": (
            "archive members are byte-identical to this commit for every "
            "manifest-covered file; the release commit itself touches only "
            "out-of-band release/ provenance"
        ),
        "status": status,
        "test_result": {
            "command": "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 PYTHONPATH=src python3 -m pytest -q",
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
        },
        "archive": {
            "path": f"release/{archive.name}",
            "sha256": report["zip_sha256"],
            "source_files": report["source_files"],
            "inner_project_dir": report["project"],
        },
        "docs": _docs(root),
        "evidence": _evidence(root),
        "provenance": provenance_info,
        "notes": (
            "release/ artifacts are out-of-band provenance and are "
            "intentionally absent from the archive manifest"
        ),
    }

    (out / "release_manifest.json").write_text(
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n")
    (out / "source_inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    (out / "verification.json").write_text(
        json.dumps(verification, indent=2, sort_keys=True) + "\n")
    sums = []
    names = [archive.name, "release_manifest.json",
             "source_inventory.json", "verification.json",
             provenance_path.name]
    if provenance_info.get("public_key_path"):
        names.append(Path(provenance_info["public_key_path"]).name)
    for name in names:
        sums.append(f"{_sha256(out / name)}  {name}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    return {"release_manifest": release_manifest, "verification": verification}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release", default=None,
                        help="release archive name without .zip; defaults to"
                             " SIS-v<package version>")
    parser.add_argument("--status", required=True)
    parser.add_argument("--passed", type=int, required=True)
    parser.add_argument("--skipped", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--provenance-key", type=Path,
                        help="file containing a 32-byte hex signing seed")
    parser.add_argument("--provenance-key-id", default="release-key-1")
    parser.add_argument("--provenance-trust-root",
                        default="qualification-only",
                        help="qualification-only or production")
    args = parser.parse_args()
    release = args.release or f"SIS-v{_package_version(args.root)}"
    seed = None
    if args.provenance_key is not None:
        raw = args.provenance_key.read_text().strip()
        try:
            seed = bytes.fromhex(raw)
        except ValueError as exc:
            raise SystemExit("provenance key must be hex") from exc
        if len(seed) != 32:
            raise SystemExit("provenance key must be 32 bytes")
    result = package(
        args.root, release, status=args.status,
        passed=args.passed, skipped=args.skipped, failed=args.failed,
        allow_dirty=args.allow_dirty,
        provenance_seed=seed,
        provenance_key_id=args.provenance_key_id,
        provenance_trust_root=args.provenance_trust_root,
    )
    print(json.dumps({
        "release": result["release_manifest"]["release"],
        "status": result["release_manifest"]["status"],
        "source_commit": result["release_manifest"]["source_commit"],
        "archive_sha256": result["release_manifest"]["archive"]["sha256"],
        "source_files": result["release_manifest"]["archive"]["source_files"],
        "fresh_extraction": result["verification"]["fresh_extraction"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
