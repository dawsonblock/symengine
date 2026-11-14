"""Explicit release/development inventory and authenticity policy for CI.

Release mode verifies the inventory, evidence-backed test totals, a
signed production provenance envelope, and a verified external isolation
attestation. Development mode reports inventory drift without rewriting
anything. The relying party supplies the release and isolator public
keys; the tool never treats a key shipped beside the artifact as its own
trust anchor.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance  # noqa: E402
from build_release import manifest_document  # noqa: E402
from check_source_manifest import _valid_manifest  # noqa: E402
from verify_release import verify_tree  # noqa: E402


def _public_key(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="utf-8").strip()
    if (len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError(
            "public key must be 64 lowercase hex characters or a file")
    return value


def _check_provenance(root: Path, release_doc: dict,
                      release_public_key: str | None) -> None:
    info = release_doc.get("provenance") or {}
    if info.get("signed") is not True:
        raise ValueError("release provenance is unsigned")
    if info.get("trust_root") != "production":
        raise ValueError("release provenance trust root is not production")
    if not release_public_key:
        raise ValueError(
            "release public key is required"
            " (--release-public-key or SIS_RELEASE_PUBLIC_KEY)")
    key = _public_key(release_public_key)
    archive = release_doc.get("archive") or {}
    statement = provenance.verify_file(
        root / info["path"], key,
        archive_path=root / archive["path"])
    subject = statement["subject"][0]["digest"]["sha256"]
    if subject != archive.get("sha256"):
        raise ValueError(
            "provenance subject does not match the archive digest")


def _check_isolation(release_doc: dict,
                     isolator_public_key: str | None) -> None:
    record = ((release_doc.get("isolation") or {})
              .get("external_attestation") or {})
    if record.get("verified") is not True:
        raise ValueError(
            "release has no verified external isolation attestation")
    if isolator_public_key is not None:
        if record.get("public_key") != _public_key(isolator_public_key):
            raise ValueError(
                "external isolation key does not match the pinned key")


def check(root: Path, mode: str, *,
          release_public_key: str | None = None,
          isolator_public_key: str | None = None) -> int:
    if mode not in {"release", "development"}:
        raise ValueError("unknown CI mode")
    try:
        manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
        _valid_manifest(manifest)
        if manifest != manifest_document(root):
            if mode == "development":
                print("development tree: inventory drift allowed; not release verification")
                return 0
            raise ValueError("release manifest is stale")
        report = verify_tree(root)
        release_manifest = root / "release" / "release_manifest.json"
        if mode == "release" and release_manifest.is_file():
            release_doc = json.loads(release_manifest.read_text())
            test_result = release_doc.get("test_result") or {}
            if test_result.get("source") != "evidence":
                raise ValueError(
                    "release manifest test result is not evidence-backed")
            if test_result.get("failed") or test_result.get("errors"):
                raise ValueError(
                    "release manifest reports failed or errored tests")
            _check_provenance(root, release_doc, release_public_key)
            _check_isolation(release_doc, isolator_public_key)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"release inventory check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release inventory verified: {report['files']} files")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("release", "development"))
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release-public-key", default=None,
                        help="release Ed25519 public key (hex or file)")
    parser.add_argument("--isolator-public-key", default=None,
                        help="external isolator Ed25519 public key (hex or file)")
    args = parser.parse_args(argv)
    return check(
        args.source.resolve(), args.mode,
        release_public_key=args.release_public_key
        or os.environ.get("SIS_RELEASE_PUBLIC_KEY"),
        isolator_public_key=args.isolator_public_key
        or os.environ.get("SIS_ISOLATOR_PUBLIC_KEY"))


if __name__ == "__main__":
    raise SystemExit(main())
