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
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import provenance
import test_evidence as test_evidence_module
import verify_external_attestation
from build_canonical_zip import build, source_binding
from sis.v3.contracts import ContractError, ExecutionReceiptV1
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


def _preserve_archive(archive: Path) -> Path | None:
    """Move an existing archive aside before a reseal overwrites it.

    The ZIP is gitignored, so a rebuild is the only copy. Keep the
    previous bytes under ``release/history/`` named by their digest; a
    repeated reseal of the same bytes gets a numeric suffix instead of
    clobbering the first copy.
    """
    if not archive.exists():
        return None
    history = archive.parent / "history"
    history.mkdir(parents=True, exist_ok=True)
    previous = _sha256(archive)[:12]
    target = history / f"{archive.stem}.{previous}.zip"
    counter = 1
    while target.exists():
        target = history / f"{archive.stem}.{previous}.{counter}.zip"
        counter += 1
    archive.replace(target)
    return target


def _git(root: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(root), *args], stderr=subprocess.DEVNULL
    ).decode().strip()


def load_test_evidence(path: Path) -> dict:
    """Read a test evidence document produced by ``tools/run_tests.py``."""
    try:
        return test_evidence_module.load(Path(path))
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def validate_test_evidence(evidence: dict, commit: str, *,
                           public_key: str | None = None,
                           key_id: str | None = None,
                           require_signature: bool = False) -> None:
    """Refuse evidence that does not describe an authentic green run."""
    try:
        test_evidence_module.validate_evidence(
            evidence, commit, public_key=public_key, key_id=key_id,
            require_signature=require_signature)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc


def _parse_ts(value: str) -> datetime:
    parsed = datetime.fromisoformat(
        value[:-1] + "+00:00" if value.endswith("Z") else value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _probe_image_digest(root: Path) -> str | None:
    try:
        probe = json.loads(
            (root / "evidence" / "sandbox" /
             "docker_sandbox_probe.json").read_text())
    except (OSError, ValueError):
        return None
    value = probe.get("image_id")
    return value if isinstance(value, str) and re.fullmatch(
        r"[0-9a-f]{64}", value) else None


def _receipt_digest(root: Path) -> str | None:
    try:
        receipt = ExecutionReceiptV1.from_json(
            (root / "evidence" / "sandbox" / "gate2_isolation" /
             "receipt.json").read_bytes())
    except (OSError, ValueError):
        return None
    return receipt.digest


def load_external_attestation(path: Path) -> dict:
    """Read a verification record from tools/verify_external_attestation.py."""
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"external attestation is unreadable: {exc}") from exc
    if (not isinstance(record, dict)
            or record.get("kind") != "external_isolation_verification"):
        raise SystemExit(
            "external attestation is not an"
            " external_isolation_verification document")
    return record


def validate_external_attestation(
    record: dict, *,
    expected_image_digest: str | None = None,
    expected_receipt_digest: str | None = None,
    max_age_seconds: int = 3600,
    at_time: datetime | None = None,
) -> None:
    """Refuse an external attestation that does not bind this seal."""
    problems = []
    if record.get("schema_version") != 1:
        problems.append("schema_version must be 1")
    if record.get("verified") is not True:
        problems.append("attestation is not verified")
    if record.get("reason") != "ok":
        problems.append("attestation reason is not ok")
    public_key = record.get("public_key")
    if not (isinstance(public_key, str)
            and re.fullmatch(r"[0-9a-f]{64}", public_key)):
        problems.append("public_key is not a lowercase hex Ed25519 key")
    if not record.get("required_properties"):
        problems.append("attestation names no required properties")
    if expected_image_digest is not None and (
            record.get("image_digest") != expected_image_digest):
        problems.append("image_digest does not match the sealed probe")
    if expected_receipt_digest is not None and (
            record.get("receipt_digest") != expected_receipt_digest):
        problems.append("receipt_digest does not match the stored receipt")
    generated = record.get("generated_at")
    try:
        generated_at = _parse_ts(generated)
    except (TypeError, ValueError):
        problems.append("generated_at is missing or unparseable")
    else:
        now = at_time or datetime.now(timezone.utc)
        age = (now - generated_at).total_seconds()
        if age < 0 or age > max_age_seconds:
            problems.append(
                f"attestation is outside the {max_age_seconds}s window")
    if problems:
        raise SystemExit(
            "external attestation rejected: " + "; ".join(problems))


def verify_external_isolation(
    *,
    receipt_path: Path,
    attestation_path: Path,
    public_key: str,
    key_id: str,
    image_digest: str,
    policy_digest: str,
    properties: list[str],
    max_age_seconds: int = 3600,
    at_time: str | None = None,
) -> dict:
    """Re-verify the raw receipt and signed attestation, not a claim about them."""
    try:
        receipt = ExecutionReceiptV1.from_json(
            Path(receipt_path).read_bytes())
        attestation = json.loads(Path(attestation_path).read_text())
        result = verify_external_attestation.verify(
            receipt, attestation,
            public_key=public_key, key_id=key_id,
            image_digest=image_digest, policy_digest=policy_digest,
            properties=list(properties),
            max_age_seconds=max_age_seconds, at_time=at_time)
    except (OSError, ValueError, TypeError, KeyError,
            ContractError, json.JSONDecodeError) as exc:
        raise SystemExit(
            f"external isolation evidence is unreadable: {exc}") from exc
    if not result.ok:
        raise SystemExit(
            "external isolation attestation rejected: " + result.reason)
    return {
        "result": result,
        "receipt": receipt,
        "attestation": attestation,
    }


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


def _release_readme(manifest: dict, out: Path) -> str:
    """Render release/README.md from the manifest so identifiers cannot drift."""
    archive = manifest["archive"]
    test = manifest["test_result"]
    provenance = manifest["provenance"]
    signed = bool(provenance.get("signed"))
    lines = [
        "# SIS release artifacts",
        "",
        f"Latest sealed release: `{Path(archive['path']).name}`",
        f"SHA-256: `{archive['sha256']}`",
        "",
        "`release/*.zip` is gitignored. The archive is distributed",
        "out-of-band with this bundle; the tracked `SHA256SUMS` verifies a",
        "copy supplied alongside the repository.",
        "",
        "`release_manifest.json` and `verification.json` are authoritative for the",
        "archive identity, source commit, test result and fresh-extraction checks.",
        "",
        "## Release identity",
        "",
        f"- Release: `{manifest['release']}`",
        f"- Status: `{manifest['status']}`",
        f"- Branch: `{manifest['branch']}`",
        f"- Source commit: `{manifest['source_commit']}`",
        f"- Source files: {archive['source_files']}",
        f"- Test result: {test['passed']} passed, {test['skipped']} skipped, "
        f"{test['failed']} failed",
        "",
        "## Provenance status",
        "",
    ]
    if signed:
        lines += [
            f"**Signed.** `{provenance['path']}` is signed by "
            f"`{provenance.get('key_id', 'unknown')}` (trust root "
            f"`{provenance.get('trust_root', 'unknown')}`).",
        ]
    else:
        lines += [
            f"**{manifest['release']} is unsigned.** `{provenance['path']}` is an",
            "in-toto statement with no `signatures` field. It binds the archive",
            "digest for local evidence but is not an authentic release seal. An",
            "externally trusted signing key was not available.",
        ]
    if not signed and (out / "provenance.dsse.json").exists():
        lines += [
            "",
            "`provenance.dsse.json` and `provenance_public_key.hex` are historical",
            "artifacts from an earlier signed release. They do not describe",
            f"{manifest['release']} and are not part of this bundle's `SHA256SUMS`.",
        ]
    lines += [
        "",
        "This README is generated by `tools/package_release.py` from",
        "`release_manifest.json`; do not edit it by hand.",
        "",
        "## Verify",
        "",
        "```bash",
        f"python3 tools/verify_release.py {archive['path']}",
        "python3 tools/verify_release.py --compile .",
        "python3 tools/check_release_ci.py --mode release",
        "cd release && shasum -a 256 -c SHA256SUMS",
        "```",
        "",
    ]
    return "\n".join(lines)


def package(root: Path, release: str, *, status: str,
            passed: int | None = None,
            skipped: int = 0, failed: int = 0, allow_dirty: bool = False,
            provenance_seed: bytes | None = None,
            provenance_key_id: str = "release-key-1",
            provenance_trust_root: str = "qualification-only",
            test_evidence: dict | None = None,
            test_evidence_public_key: str | None = None,
            test_evidence_key_id: str | None = None,
            require_signed_test_evidence: bool = False,
            external_attestation: dict | None = None,
            isolation_receipt: Path | None = None,
            isolation_attestation: Path | None = None,
            isolator_public_key: str | None = None,
            isolation_key_id: str | None = None,
            isolation_image_digest: str | None = None,
            isolation_policy_digest: str | None = None,
            isolation_properties: list[str] | None = None,
            isolation_max_age_seconds: int = 3600,
            require_external_attestation: bool = False) -> dict:
    root = Path(root).resolve()
    out = root / "release"
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"{release}.zip"

    binding = source_binding(root)
    evidence_path = out / "test_evidence.json"
    evidence_digest = None
    if test_evidence is not None:
        if require_signed_test_evidence and not test_evidence_public_key:
            raise SystemExit(
                "signed test evidence requires --test-evidence-public-key")
        validate_test_evidence(
            test_evidence, binding["commit"],
            public_key=test_evidence_public_key,
            key_id=test_evidence_key_id,
            require_signature=require_signed_test_evidence)
        evidence_digest = test_evidence_module.write(
            evidence_path, test_evidence)
        counts = test_evidence.get("counts") or {}
        passed = counts.get("passed", 0)
        skipped = counts.get("skipped", 0)
        failed = counts.get("failed", 0)
    elif passed is None:
        raise SystemExit(
            "package() requires passed counts or test evidence")

    raw_isolation = any(value is not None for value in (
        isolation_receipt, isolation_attestation, isolator_public_key,
        isolation_image_digest, isolation_policy_digest, isolation_properties))
    isolation_info = {"external_attestation": None}
    isolation_names: list[str] = []
    if raw_isolation:
        missing = [
            name for name, value in (
                ("--isolation-receipt", isolation_receipt),
                ("--isolation-attestation", isolation_attestation),
                ("--isolator-public-key", isolator_public_key),
                ("--isolation-image-digest", isolation_image_digest),
                ("--isolation-policy-digest", isolation_policy_digest),
                ("--isolation-property", isolation_properties),
            ) if value is None or value == []
        ]
        if missing:
            raise SystemExit(
                "external isolation evidence is incomplete: missing "
                + ", ".join(missing))
        key = test_evidence_module.public_key(isolator_public_key)
        try:
            attestation_doc = json.loads(
                Path(isolation_attestation).read_text())
        except (OSError, ValueError) as exc:
            raise SystemExit(
                f"external isolation attestation is unreadable: {exc}") from exc
        key_id = isolation_key_id or attestation_doc.get("signer_key_id")
        if not key_id:
            raise SystemExit(
                "external isolation attestation names no signer key id")
        verification = verify_external_isolation(
            receipt_path=Path(isolation_receipt),
            attestation_path=Path(isolation_attestation),
            public_key=key, key_id=key_id,
            image_digest=isolation_image_digest,
            policy_digest=isolation_policy_digest,
            properties=list(isolation_properties),
            max_age_seconds=isolation_max_age_seconds)
        result = verification["result"]
        receipt_bytes = Path(isolation_receipt).read_bytes()
        attestation_bytes = Path(isolation_attestation).read_bytes()
        (out / "isolation_receipt.json").write_bytes(receipt_bytes)
        (out / "isolation_attestation.json").write_bytes(attestation_bytes)
        record = {
            "schema_version": 1,
            "kind": "external_isolation_verification",
            "generated_at": _utcnow(),
            "receipt_digest": result.receipt_digest,
            "attestation_digest": result.attestation_digest,
            "policy_digest": result.policy_digest,
            "backend": result.backend,
            "worker_identity": result.worker_identity,
            "signer_key_id": result.signer_key_id,
            "public_key": key,
            "image_digest": isolation_image_digest,
            "required_properties": sorted(isolation_properties),
            "verified": result.ok,
            "reason": result.reason,
        }
        record_bytes = (
            provenance.canonical_json(record) + "\n").encode("utf-8")
        (out / "isolation_verification.json").write_bytes(record_bytes)
        isolation_names = [
            "isolation_verification.json",
            "isolation_receipt.json",
            "isolation_attestation.json",
        ]
        isolation_info = {"external_attestation": {
            "verified": True,
            "verification": {
                "path": "release/isolation_verification.json",
                "sha256": hashlib.sha256(record_bytes).hexdigest(),
            },
            "receipt": {
                "path": "release/isolation_receipt.json",
                "sha256": hashlib.sha256(receipt_bytes).hexdigest(),
            },
            "attestation": {
                "path": "release/isolation_attestation.json",
                "sha256": hashlib.sha256(attestation_bytes).hexdigest(),
            },
            "signer_key_id": result.signer_key_id,
            "public_key": key,
            "image_digest": isolation_image_digest,
            "policy_digest": result.policy_digest,
            "receipt_digest": result.receipt_digest,
            "attestation_digest": result.attestation_digest,
            "backend": result.backend,
            "worker_identity": result.worker_identity,
            "required_properties": sorted(isolation_properties),
            "generated_at": record["generated_at"],
            "verification_mode": "raw_receipt_and_attestation",
        }}
    elif external_attestation is not None:
        if require_external_attestation:
            raise SystemExit(
                "external attestation requires the raw receipt and signed"
                " attestation (--isolation-receipt and"
                " --isolation-attestation)")
        expected_image = _probe_image_digest(root)
        expected_receipt = _receipt_digest(root)
        validate_external_attestation(
            external_attestation,
            expected_image_digest=expected_image,
            expected_receipt_digest=expected_receipt)
        isolation_info = {"external_attestation": {
            "verified": True,
            "signer_key_id": external_attestation.get("signer_key_id"),
            "public_key": external_attestation.get("public_key"),
            "image_digest": external_attestation.get("image_digest"),
            "policy_digest": external_attestation.get("policy_digest"),
            "receipt_digest": external_attestation.get("receipt_digest"),
            "generated_at": external_attestation.get("generated_at"),
            "required_properties": external_attestation.get(
                "required_properties"),
            "sha256": hashlib.sha256(
                provenance.canonical_json(
                    external_attestation)).hexdigest(),
            "verification_mode": "record_only",
        }}
    elif require_external_attestation:
        raise SystemExit("external attestation is required")
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
    _preserve_archive(archive)
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

    if test_evidence is not None:
        test_result = {
            "command": " ".join(
                str(part) for part in test_evidence["command"]),
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
            "errors": (test_evidence.get("counts") or {}).get("errors", 0),
            "source": "evidence",
            "evidence": {
                "path": "release/test_evidence.json",
                "sha256": evidence_digest,
                "source_commit": test_evidence.get("source_commit"),
                "pytest_version": test_evidence.get("pytest_version"),
                "counts": test_evidence.get("counts"),
                "signed": "signature" in test_evidence,
                "signer_key_id": test_evidence.get("signer_key_id"),
                "output_sha256": test_evidence.get("output_sha256"),
                "exit_status": test_evidence.get("exit_status"),
            },
        }
    else:
        test_result = {
            "command": ("PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 "
                        "PYTHONNOUSERSITE=1 PYTHONPATH=src "
                        "python3 -m pytest -q"),
            "passed": passed,
            "skipped": skipped,
            "failed": failed,
            "source": "operator",
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
        "test_result": test_result,
        "isolation": isolation_info,
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
    (out / "README.md").write_text(
        _release_readme(release_manifest, out) + "\n")
    sums = []
    names = [archive.name, "release_manifest.json",
             "source_inventory.json", "verification.json",
             provenance_path.name]
    if provenance_info.get("public_key_path"):
        names.append(Path(provenance_info["public_key_path"]).name)
    if evidence_digest is not None:
        names.append("test_evidence.json")
    names.extend(isolation_names)
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
    parser.add_argument("--passed", type=int, default=None,
                        help="operator-supplied count; prefer --test-evidence")
    parser.add_argument("--skipped", type=int, default=0)
    parser.add_argument("--failed", type=int, default=0)
    parser.add_argument("--test-evidence", type=Path, default=None,
                        help="JSON from tools/run_tests.py --json")
    parser.add_argument("--test-evidence-public-key", default=None,
                        help="CI Ed25519 public key (hex or file)")
    parser.add_argument("--test-evidence-key-id", default=None,
                        help="expected CI signer key identifier")
    parser.add_argument("--require-test-evidence", action="store_true",
                        help="refuse to seal without machine-readable"
                             " test evidence")
    parser.add_argument("--require-signed-test-evidence", action="store_true",
                        help="refuse to seal unless the test evidence is"
                             " signed by the supplied CI key")
    parser.add_argument("--external-attestation", type=Path, default=None,
                        help="verification record from"
                             " tools/verify_external_attestation.py")
    parser.add_argument("--isolation-receipt", type=Path, default=None,
                        help="execution receipt the isolator signed")
    parser.add_argument("--isolation-attestation", type=Path, default=None,
                        help="signed IsolationAttestationV1 document")
    parser.add_argument("--isolator-public-key", default=None,
                        help="external isolator Ed25519 public key (hex or file)")
    parser.add_argument("--isolation-key-id", default=None,
                        help="expected isolator signer key identifier")
    parser.add_argument("--isolation-image-digest", default=None,
                        help="pinned evaluator image digest")
    parser.add_argument("--isolation-policy-digest", default=None,
                        help="pinned sandbox policy digest")
    parser.add_argument("--isolation-property", action="append", default=None,
                        help="required containment property (repeatable)")
    parser.add_argument("--isolation-max-age-seconds", type=int, default=3600,
                        help="maximum attestation age in seconds")
    parser.add_argument("--require-external-attestation", action="store_true",
                        help="refuse to seal without verified raw isolation"
                             " evidence")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--provenance-key", type=Path,
                        help="file containing a 32-byte hex signing seed")
    parser.add_argument("--provenance-key-id", default="release-key-1")
    parser.add_argument("--provenance-trust-root",
                        default="qualification-only",
                        help="qualification-only or production")
    args = parser.parse_args()
    if args.provenance_trust_root not in {"qualification-only", "production"}:
        raise SystemExit(
            "--provenance-trust-root must be qualification-only or production")
    if args.require_test_evidence and args.test_evidence is None:
        raise SystemExit("--require-test-evidence needs --test-evidence")
    if args.require_signed_test_evidence and not args.test_evidence_public_key:
        raise SystemExit(
            "--require-signed-test-evidence needs --test-evidence-public-key")
    evidence = None
    if args.test_evidence is not None:
        evidence = load_test_evidence(args.test_evidence)
    elif args.passed is None:
        raise SystemExit("pass --test-evidence or --passed")
    raw_isolation = any(value is not None for value in (
        args.isolation_receipt, args.isolation_attestation,
        args.isolator_public_key, args.isolation_image_digest,
        args.isolation_policy_digest, args.isolation_property))
    if args.require_external_attestation and not raw_isolation:
        raise SystemExit(
            "--require-external-attestation needs the raw receipt and signed"
            " attestation (--isolation-receipt, --isolation-attestation,"
            " --isolator-public-key, --isolation-image-digest,"
            " --isolation-policy-digest, --isolation-property)")
    attestation_path = args.external_attestation
    if attestation_path is None and not raw_isolation:
        candidate = (args.root / "evidence" / "sandbox" / "gate2_isolation" /
                     "external_verification.json")
        if candidate.is_file():
            attestation_path = candidate
    external = None
    if attestation_path is not None:
        external = load_external_attestation(attestation_path)
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
        test_evidence=evidence,
        test_evidence_public_key=args.test_evidence_public_key,
        test_evidence_key_id=args.test_evidence_key_id,
        require_signed_test_evidence=args.require_signed_test_evidence,
        external_attestation=external,
        isolation_receipt=args.isolation_receipt,
        isolation_attestation=args.isolation_attestation,
        isolator_public_key=args.isolator_public_key,
        isolation_key_id=args.isolation_key_id,
        isolation_image_digest=args.isolation_image_digest,
        isolation_policy_digest=args.isolation_policy_digest,
        isolation_properties=args.isolation_property,
        isolation_max_age_seconds=args.isolation_max_age_seconds,
        require_external_attestation=args.require_external_attestation,
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
