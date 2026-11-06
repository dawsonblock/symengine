"""SLSA-style provenance for the release archive.

The statement follows the in-toto Statement v1 shape with the SLSA
provenance v1 predicate type. Signing uses a DSSE envelope so the
subject digest, build definition and builder identity are covered by one
Ed25519 signature. Verification binds the provenance to the archive's
exact SHA-256; a statement for a different artifact fails closed.

This is intentionally a narrow, dependency-free implementation: it does
not claim SLSA level conformance, only a signed, digest-bound provenance
statement in the SLSA shape.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sis.v3 import signatures
from sis.v3.contracts import canonical_json

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://sis.local/release/v1"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def public_key_hex(seed: bytes) -> str:
    return signatures.public_key(seed).hex()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build_statement(
    *,
    archive_name: str,
    archive_sha256: str,
    release: str,
    branch: str,
    source_commit: str,
    builder: str = "tools/package_release.py",
    invocation_id: str | None = None,
    started_on: str | None = None,
    finished_on: str | None = None,
) -> dict:
    if not (isinstance(archive_sha256, str) and len(archive_sha256) == 64
            and all(char in "0123456789abcdef" for char in archive_sha256)):
        raise ValueError("archive_sha256 must be a lowercase SHA-256 digest")
    if not (isinstance(source_commit, str)
            and re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_commit)):
        raise ValueError(
            "source_commit must be a lowercase 40- or 64-character digest")
    commit_algorithm = "sha1" if len(source_commit) == 40 else "sha256"
    if not (isinstance(archive_name, str) and archive_name):
        raise ValueError("archive_name is required")
    started = started_on or _utcnow()
    finished = finished_on or started
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": archive_name,
            "digest": {"sha256": archive_sha256},
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "release": release,
                    "branch": branch,
                    "source_commit": source_commit,
                },
                "internalParameters": {
                    "builder": builder,
                },
                "resolvedDependencies": [{
                    "uri": f"git+https://sis.local/{branch}",
                    "digest": {commit_algorithm: source_commit},
                }],
            },
            "runDetails": {
                "builder": {"id": builder},
                "metadata": {
                    "invocationId": invocation_id or
                    f"release-{source_commit[:12]}",
                    "startedOn": started,
                    "finishedOn": finished,
                },
            },
        },
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    return (b"DSSEv1 " + str(len(payload_type)).encode("utf8") + b" "
            + payload_type.encode("utf8") + b" "
            + str(len(payload)).encode("utf8") + b" " + payload)


def sign_statement(statement: dict, seed: bytes, key_id: str) -> dict:
    if len(seed) != 32:
        raise ValueError("provenance signing seed must be 32 bytes")
    payload = canonical_json(statement)
    signature = signatures.sign(seed, pae(PAYLOAD_TYPE, payload))
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{
            "keyid": key_id,
            "sig": base64.b64encode(signature).decode("ascii"),
        }],
    }


def verify_envelope(envelope: dict, public_hex: str,
                    *, archive_path: str | Path | None = None) -> dict:
    if not isinstance(envelope, dict):
        raise TypeError("provenance envelope must be an object")
    if envelope.get("payloadType") != PAYLOAD_TYPE:
        raise ValueError("unexpected provenance payload type")
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signature = base64.b64decode(
            envelope["signatures"][0]["sig"], validate=True)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise ValueError("provenance envelope is malformed") from exc
    if not signatures.verify(signature, pae(PAYLOAD_TYPE, payload),
                             bytes.fromhex(public_hex)):
        raise ValueError("provenance signature is invalid")
    statement = json.loads(payload)
    if statement.get("_type") != STATEMENT_TYPE:
        raise ValueError("unexpected in-toto statement type")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise ValueError("unexpected SLSA predicate type")
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or len(subjects) != 1:
        raise ValueError("provenance must name exactly one subject")
    subject = subjects[0]
    digest = subject.get("digest", {}).get("sha256")
    if archive_path is not None:
        actual = sha256_file(archive_path)
        if digest != actual:
            raise ValueError(
                "provenance subject digest does not match the archive")
        if subject.get("name") != Path(archive_path).name:
            raise ValueError(
                "provenance subject name does not match the archive")
    return statement


def verify_file(envelope_path: str | Path, public_hex: str,
                *, archive_path: str | Path | None = None) -> dict:
    envelope = json.loads(Path(envelope_path).read_text())
    return verify_envelope(envelope, public_hex, archive_path=archive_path)


__all__ = [
    "BUILD_TYPE",
    "PAYLOAD_TYPE",
    "PREDICATE_TYPE",
    "STATEMENT_TYPE",
    "build_statement",
    "pae",
    "public_key_hex",
    "sha256_file",
    "sign_statement",
    "verify_envelope",
    "verify_file",
]
