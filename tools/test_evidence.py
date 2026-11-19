"""Authenticated test-run evidence shared by the runner, packager and CI gate.

A test report is evidence only when it names the exact source commit, the
exact command that ran, the exit status and the digest of the output it
claims to summarise. ``validate_evidence`` re-parses the recorded output
instead of trusting the typed counts, and refuses a command that could
narrow or bypass the suite. A release gate additionally requires the
report to carry an Ed25519 signature from a CI key supplied by the
relying party, never from a key stored beside the artifact.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sis.v3 import signatures  # noqa: E402

DOMAIN = b"sis-v3:test_evidence:1\0"
SUITE = "tests/"
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
COUNT_KEYS = ("passed", "failed", "skipped", "errors")

_FORBIDDEN_ARGS = {
    "-k", "--deselect", "--ignore", "--ignore-glob", "--maxfail", "-x",
    "--exitfirst", "--lf", "--last-failed", "--co", "--collect-only",
    "-p", "--pyargs", "--rootdir", "--confcutdir", "-c",
    "--continue-on-collection-errors",
}


def _canonical(value) -> bytes:
    """Canonical JSON without the 64 KiB contract-record bound."""
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False,
        separators=(",", ":")).encode("utf-8")


def counts_from_output(output: str) -> dict[str, int]:
    """Parse pytest's summary line; the last match is the summary."""
    counts = {name: 0 for name in COUNT_KEYS}
    patterns = {
        "passed": r"(\d+) passed",
        "failed": r"(\d+) failed",
        "skipped": r"(\d+) skipped",
        "errors": r"(\d+) error(?:s)?",
    }
    for name, pattern in patterns.items():
        matches = re.findall(pattern, output)
        if matches:
            counts[name] = int(matches[-1])
    return counts


def _command_problems(command, suite: str) -> list[str]:
    problems = []
    if not isinstance(command, list) or len(command) < 5:
        return ["evidence command is not a complete pytest invocation"]
    if not all(isinstance(part, str) and part for part in command):
        return ["evidence command contains a non-string or empty argument"]
    if command[1] != "-m" or command[2] != "pytest":
        problems.append("evidence command does not run pytest as a module")
    if command[3] != suite:
        problems.append(
            "evidence command does not run the declared suite")
    if suite != SUITE:
        problems.append("release evidence must run the full tests/ suite")
    if command[4] != "-q":
        problems.append("evidence command is not the quiet pytest form")
    extras = command[5:]
    if extras:
        problems.append(
            "release evidence must not pass extra pytest arguments")
    for argument in extras:
        name = argument.split("=", 1)[0]
        if name in _FORBIDDEN_ARGS:
            problems.append(
                "evidence command can narrow the suite: " + argument)
    return problems


def validate_evidence(evidence: dict, commit: str, *,
                      public_key: str | None = None,
                      key_id: str | None = None,
                      require_signature: bool = False) -> None:
    """Fail closed unless the report is internally consistent and authentic."""
    problems: list[str] = []
    if not isinstance(evidence, dict):
        raise ValueError("test evidence rejected: evidence is not an object")
    if evidence.get("kind") != "test_evidence":
        problems.append("evidence is not a test_evidence document")
    if evidence.get("schema_version") != 1:
        problems.append("evidence schema_version must be 1")
    if evidence.get("source_commit") != commit:
        problems.append(
            "source_commit does not match the packaged tree")
    if evidence.get("dirty") is not False:
        problems.append("evidence was produced from a dirty tree")

    counts = evidence.get("counts")
    if (not isinstance(counts, dict) or set(counts) != set(COUNT_KEYS)
            or any(type(value) is not int or value < 0
                   for value in counts.values())):
        problems.append("evidence counts are not four non-negative integers")
        counts = None
    elif counts["failed"]:
        problems.append("evidence reports failed tests")
    elif counts["errors"]:
        problems.append("evidence reports errored tests")

    if evidence.get("exit_status") != 0:
        problems.append("evidence exit_status is not 0")
    if evidence.get("pytest_version") != evidence.get("pytest_pin"):
        problems.append(
            "evidence pytest version is not the pinned runner")
    if evidence.get("suite") != SUITE:
        problems.append("evidence suite is not the full tests/ suite")

    command = evidence.get("command")
    suite = evidence.get("suite")
    problems.extend(_command_problems(command, suite))
    if (isinstance(command, list) and command
            and evidence.get("python_executable") != command[0]):
        problems.append(
            "evidence python_executable does not match the command")

    output = evidence.get("output")
    if not isinstance(output, str):
        problems.append("evidence output is missing")
    else:
        digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
        if evidence.get("output_sha256") != digest:
            problems.append("evidence output digest does not match the output")
        if evidence.get("output_truncated") is not False:
            problems.append("evidence output was truncated")
        if counts is not None and counts_from_output(output) != counts:
            problems.append(
                "evidence counts do not match the recorded output")

    if require_signature or public_key is not None:
        if not public_key:
            problems.append(
                "test evidence public key is required for authentication")
        elif not verify_signature(evidence, public_key, key_id=key_id):
            problems.append("test evidence signature is invalid")

    if problems:
        raise ValueError("test evidence rejected: " + "; ".join(problems))


def sign_evidence(evidence: dict, seed: bytes, key_id: str) -> dict:
    """Return a copy of ``evidence`` signed over every field but the signature."""
    if len(seed) != 32:
        raise ValueError("test evidence signing seed must be 32 bytes")
    document = dict(evidence)
    document["signer_key_id"] = key_id
    signature = signatures.sign(
        seed, DOMAIN + _canonical(_unsigned(document)))
    document["signature"] = signature.hex()
    return document


def verify_signature(evidence: dict, public_hex: str,
                     *, key_id: str | None = None) -> bool:
    if key_id is not None and evidence.get("signer_key_id") != key_id:
        return False
    signature = evidence.get("signature")
    if not isinstance(signature, str) or not re.fullmatch(
            r"[0-9a-f]{128}", signature):
        return False
    try:
        public = bytes.fromhex(public_hex)
        signature_bytes = bytes.fromhex(signature)
    except ValueError:
        return False
    return signatures.verify(
        signature_bytes, DOMAIN + _canonical(_unsigned(evidence)), public)


def _unsigned(evidence: dict) -> dict:
    return {key: value for key, value in evidence.items()
            if key != "signature"}


def load(path: Path) -> dict:
    try:
        evidence = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"test evidence is unreadable: {exc}") from exc
    if not isinstance(evidence, dict) or evidence.get("kind") != "test_evidence":
        raise ValueError("test evidence is not a test_evidence document")
    if evidence.get("schema_version") != 1:
        raise ValueError("test evidence schema_version must be 1")
    return evidence


def write(path: Path, evidence: dict) -> str:
    """Write canonical evidence bytes and return their SHA-256."""
    payload = _canonical(evidence) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def public_key(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="utf-8").strip()
    if (len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ValueError(
            "public key must be 64 lowercase hex characters or a file")
    return value


__all__ = [
    "MAX_OUTPUT_BYTES",
    "SUITE",
    "counts_from_output",
    "load",
    "public_key",
    "sign_evidence",
    "validate_evidence",
    "verify_signature",
    "write",
]
