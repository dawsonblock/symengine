"""Explicit release/development inventory and authenticity policy for CI.

Release mode requires the constant-time signing backend
(``pip install -e .[production]``), the release metadata, the claimed
archive, the source binding, a signed production provenance envelope,
authenticated test evidence and a cryptographically verified external
isolation attestation. Development mode reports inventory drift without
rewriting anything and never claims release qualification. The relying party
supplies every trust anchor; the tool never treats a key shipped beside
the artifact as its own root of trust.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance  # noqa: E402
import test_evidence as test_evidence_module  # noqa: E402
import verify_external_attestation  # noqa: E402
from build_release import manifest_document  # noqa: E402
from check_source_manifest import _valid_manifest  # noqa: E402
from sis.v3 import signatures  # noqa: E402
from sis.v3.contracts import ContractError, ExecutionReceiptV1  # noqa: E402
from sis.v3.docker_sandbox import PRODUCTION_PROPERTIES  # noqa: E402
from verify_release import verify, verify_against_tree, verify_tree  # noqa: E402

RELEASE_MANIFEST = Path("release") / "release_manifest.json"
RELEASE_GATE = "release qualification (tools/check_release_ci.py --mode release)"


def _public_key(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="utf-8").strip()
    if (len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError(
            "public key must be 64 lowercase hex characters or a file")
    return value


def _digest(value, description: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError(f"{description} must be a lowercase SHA-256 digest")
    return value


def _release_path(root: Path, value, description: str) -> Path:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{description} path is missing")
    if Path(value).is_absolute():
        raise ValueError(f"{description} path must be relative")
    # Inspect the declared path before resolving it. ``resolve()``
    # replaces a link with its target, so ``is_symlink()`` on the
    # resolved path is always False and would let an internal link
    # through.
    current = root
    for part in Path(value).parts:
        current = current.parent if part == ".." else current / part
        if current.is_symlink():
            raise ValueError(
                f"{description} must not be a symlink: {value}")
    candidate = (root / value).resolve()
    try:
        candidate.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{description} path escapes the release tree") from exc
    if not candidate.is_file():
        raise ValueError(f"{description} is missing: {value}")
    return candidate


def _load_release_manifest(root: Path) -> dict:
    path = root / RELEASE_MANIFEST
    if not path.is_file():
        raise ValueError("release/release_manifest.json is missing")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(
            "release/release_manifest.json is not valid JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("release/release_manifest.json is not an object")
    return document


def _check_archive(root: Path, release_doc: dict):
    archive = release_doc.get("archive")
    if not isinstance(archive, dict):
        raise ValueError("release manifest has no archive record")
    declared = _digest(archive.get("sha256"), "archive sha256")
    path = _release_path(root, archive.get("path"), "release archive")
    actual = provenance.sha256_file(path)
    if actual != declared:
        raise ValueError(
            "release archive digest does not match the release manifest")
    report = verify(path)
    if report["zip_sha256"] != declared:
        raise ValueError(
            "release archive digest changed during verification")
    if archive.get("source_files") != report["source_files"]:
        raise ValueError(
            "release archive file count does not match the release manifest")
    project = archive.get("inner_project_dir")
    if project is not None and project != report["project"]:
        raise ValueError(
            "release archive project directory does not match the release"
            " manifest")
    binding = verify_against_tree(path, root)
    if binding["files"] != report["source_files"]:
        raise ValueError(
            "source binding file count does not match the archive")
    return path, report, binding


def _check_provenance(root: Path, release_doc: dict, archive_path: Path,
                      release_public_key: str | None) -> dict:
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
    path = _release_path(root, info.get("path"), "release provenance")
    statement = provenance.verify_file(
        path, key, archive_path=archive_path)
    subject = statement["subject"][0]
    archive = release_doc["archive"]
    if subject["digest"]["sha256"] != archive["sha256"]:
        raise ValueError(
            "provenance subject does not match the archive digest")
    if subject["name"] != archive_path.name:
        raise ValueError(
            "provenance subject does not name the archive")
    parameters = (
        statement.get("predicate", {})
        .get("buildDefinition", {})
        .get("externalParameters", {}))
    if parameters.get("source_commit") != release_doc.get("source_commit"):
        raise ValueError(
            "signed provenance source commit does not match the release"
            " manifest")
    if info.get("subject_sha256") not in (None, archive["sha256"]):
        raise ValueError(
            "release manifest provenance subject is inconsistent")
    return statement


def _check_test_evidence(root: Path, release_doc: dict, *,
                         public_key: str | None,
                         key_id: str | None) -> dict:
    test = release_doc.get("test_result") or {}
    if test.get("source") != "evidence":
        raise ValueError(
            "release manifest test result is not evidence-backed")
    evidence_info = test.get("evidence")
    if not isinstance(evidence_info, dict):
        raise ValueError("release manifest has no test evidence record")
    path = _release_path(
        root, evidence_info.get("path"), "release test evidence")
    digest = provenance.sha256_file(path)
    if evidence_info.get("sha256") != digest:
        raise ValueError(
            "release test evidence digest does not match the release"
            " manifest")
    if public_key is not None:
        public_key = _public_key(public_key)
    try:
        evidence = test_evidence_module.load(path)
        test_evidence_module.validate_evidence(
            evidence, release_doc.get("source_commit"),
            public_key=public_key, key_id=key_id,
            require_signature=True)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc
    counts = evidence["counts"]
    for name in ("passed", "skipped", "failed", "errors"):
        if test.get(name) != counts.get(name):
            raise ValueError(
                f"release manifest test {name} count does not match the"
                " evidence")
    if test.get("command") != " ".join(evidence["command"]):
        raise ValueError(
            "release manifest test command does not match the evidence")
    declared = evidence_info.get("output_sha256")
    if declared is not None and declared != evidence.get("output_sha256"):
        raise ValueError(
            "release manifest test output digest does not match the"
            " evidence")
    return evidence


def _check_isolation(root: Path, release_doc: dict, *,
                     isolator_public_key: str | None,
                     receipt_path: str | None,
                     attestation_path: str | None,
                     image_digest: str | None,
                     policy_digest: str | None,
                     properties: list[str] | None,
                     key_id: str | None,
                     max_age_seconds: int):
    record = ((release_doc.get("isolation") or {})
              .get("external_attestation") or {})
    if not isinstance(record, dict) or record.get("verified") is not True:
        raise ValueError(
            "release has no verified external isolation attestation")
    if not isolator_public_key:
        raise ValueError(
            "isolator public key is required"
            " (--isolator-public-key or SIS_ISOLATOR_PUBLIC_KEY)")
    key = _public_key(isolator_public_key)
    if receipt_path is not None:
        receipt_file = Path(receipt_path)
    else:
        receipt_file = _release_path(
            root, (record.get("receipt") or {}).get("path"),
            "isolation receipt")
    if attestation_path is not None:
        attestation_file = Path(attestation_path)
    else:
        attestation_file = _release_path(
            root, (record.get("attestation") or {}).get("path"),
            "isolation attestation")
    for path, description in (
            (receipt_file, "isolation receipt"),
            (attestation_file, "isolation attestation")):
        if not path.is_file():
            raise ValueError(f"{description} is missing: {path}")
    try:
        receipt = ExecutionReceiptV1.from_json(receipt_file.read_bytes())
        attestation = json.loads(attestation_file.read_text())
    except (OSError, ValueError, ContractError,
            json.JSONDecodeError) as exc:
        raise ValueError(
            f"external isolation evidence is unreadable: {exc}") from exc
    attestation_key_id = key_id or attestation.get("signer_key_id")
    if not attestation_key_id:
        raise ValueError(
            "external isolation attestation names no signer key id")
    image = image_digest or record.get("image_digest")
    policy = policy_digest or record.get("policy_digest")
    required = list(properties or record.get("required_properties") or [])
    if not image or not policy or not required:
        raise ValueError(
            "external isolation policy pins are incomplete: supply"
            " --isolation-image-digest, --isolation-policy-digest and"
            " --isolation-property")
    # The Docker backend's production contract includes gVisor and the
    # allowlist seccomp profile. A release gate configured with a weaker
    # property set would accept an attestation for a runc launch.
    omitted = sorted(set(PRODUCTION_PROPERTIES) - set(required))
    if omitted:
        raise ValueError(
            "external isolation policy omits required production"
            " properties: " + ", ".join(omitted))
    try:
        result = verify_external_attestation.verify(
            receipt, attestation,
            public_key=key, key_id=attestation_key_id,
            image_digest=image, policy_digest=policy,
            properties=required, max_age_seconds=max_age_seconds)
    except (ValueError, TypeError, KeyError, ContractError) as exc:
        raise ValueError(
            f"external isolation verification failed: {exc}") from exc
    if not result.ok:
        raise ValueError(
            "external isolation attestation rejected: " + result.reason)
    for name, actual in (
            ("receipt_digest", result.receipt_digest),
            ("attestation_digest", result.attestation_digest),
            ("policy_digest", result.policy_digest),
            ("image_digest", image),
            ("signer_key_id", result.signer_key_id)):
        if record.get(name) not in (None, actual):
            raise ValueError(
                f"release isolation {name} does not match the verified"
                " attestation")
    return result


def check(root: Path, mode: str, *,
          release_public_key: str | None = None,
          test_evidence_public_key: str | None = None,
          test_evidence_key_id: str | None = None,
          isolator_public_key: str | None = None,
          isolation_receipt: str | None = None,
          isolation_attestation: str | None = None,
          isolation_image_digest: str | None = None,
          isolation_policy_digest: str | None = None,
          isolation_properties: list[str] | None = None,
          isolation_key_id: str | None = None,
          isolation_max_age_seconds: int = 3600) -> int:
    if mode not in {"release", "development"}:
        raise ValueError("unknown CI mode")
    try:
        if mode == "release":
            # The release gate runs where the release is signed; it
            # refuses an environment without the constant-time backend.
            signatures.require_constant_time(RELEASE_GATE)
        manifest = json.loads(
            (root / "RELEASE_SHA256.json").read_text(encoding="utf-8"))
        _valid_manifest(manifest)
        if manifest != manifest_document(root):
            if mode == "development":
                print(
                    "development tree: inventory drift allowed;"
                    " not release verification. Attribute the drift"
                    " with tools/reconcile_inventory.py; only the"
                    " signed release process regenerates the seal.")
                return 0
            raise ValueError("release manifest is stale")
        report = verify_tree(root)
        if mode == "development":
            print(
                f"development inventory verified: {report['files']} files;"
                " release qualification not performed")
            return 0
        release_doc = _load_release_manifest(root)
        archive_path, _archive_report, _binding = _check_archive(
            root, release_doc)
        _check_provenance(
            root, release_doc, archive_path, release_public_key)
        _check_test_evidence(
            root, release_doc,
            public_key=test_evidence_public_key,
            key_id=test_evidence_key_id)
        _check_isolation(
            root, release_doc,
            isolator_public_key=isolator_public_key,
            receipt_path=isolation_receipt,
            attestation_path=isolation_attestation,
            image_digest=isolation_image_digest,
            policy_digest=isolation_policy_digest,
            properties=isolation_properties,
            key_id=isolation_key_id,
            max_age_seconds=isolation_max_age_seconds)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"release inventory check failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"release qualification verified: {report['files']} files,"
        f" archive {archive_path.name}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True,
                        choices=("release", "development"))
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--release-public-key", default=None,
                        help="release Ed25519 public key (hex or file)")
    parser.add_argument("--test-evidence-public-key", default=None,
                        help="CI test-evidence Ed25519 public key (hex or file)")
    parser.add_argument("--test-evidence-key-id", default=None,
                        help="expected CI signer key identifier")
    parser.add_argument("--isolator-public-key", default=None,
                        help="external isolator Ed25519 public key (hex or file)")
    parser.add_argument("--isolation-key-id", default=None,
                        help="expected isolator signer key identifier")
    parser.add_argument("--isolation-receipt", default=None,
                        help="override path to the signed execution receipt")
    parser.add_argument("--isolation-attestation", default=None,
                        help="override path to the signed attestation")
    parser.add_argument("--isolation-image-digest", default=None,
                        help="pinned evaluator image digest")
    parser.add_argument("--isolation-policy-digest", default=None,
                        help="pinned sandbox policy digest")
    parser.add_argument("--isolation-property", action="append", default=None,
                        help="required containment property (repeatable)")
    parser.add_argument("--isolation-max-age-seconds", type=int, default=3600,
                        help="maximum attestation age in seconds")
    args = parser.parse_args(argv)
    properties = args.isolation_property
    if properties is None and os.environ.get("SIS_ISOLATION_PROPERTIES"):
        properties = [
            value.strip()
            for value in os.environ["SIS_ISOLATION_PROPERTIES"].split(",")
            if value.strip()]
    return check(
        args.source.resolve(), args.mode,
        release_public_key=args.release_public_key
        or os.environ.get("SIS_RELEASE_PUBLIC_KEY"),
        test_evidence_public_key=args.test_evidence_public_key
        or os.environ.get("SIS_TEST_EVIDENCE_PUBLIC_KEY"),
        test_evidence_key_id=args.test_evidence_key_id
        or os.environ.get("SIS_TEST_EVIDENCE_KEY_ID"),
        isolator_public_key=args.isolator_public_key
        or os.environ.get("SIS_ISOLATOR_PUBLIC_KEY"),
        isolation_receipt=args.isolation_receipt
        or os.environ.get("SIS_ISOLATION_RECEIPT"),
        isolation_attestation=args.isolation_attestation
        or os.environ.get("SIS_ISOLATION_ATTESTATION"),
        isolation_image_digest=args.isolation_image_digest
        or os.environ.get("SIS_ISOLATION_IMAGE_DIGEST"),
        isolation_policy_digest=args.isolation_policy_digest
        or os.environ.get("SIS_ISOLATION_POLICY_DIGEST"),
        isolation_properties=properties,
        isolation_key_id=args.isolation_key_id
        or os.environ.get("SIS_ISOLATION_KEY_ID"),
        isolation_max_age_seconds=args.isolation_max_age_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
