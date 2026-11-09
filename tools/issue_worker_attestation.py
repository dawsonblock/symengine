"""Issue a signed isolation attestation for one execution receipt (Phase 2.4).

Runs on the isolator host, never inside the evaluated workspace. It
reads the receipt the qualified worker actually produced, refuses
receipts that self-report unverified local execution, signs only the
containment properties the worker enforced, and writes the attestation
JSON the evaluator passes to ``OutcomeVerifier.evaluate``.

The seed file must be private to the isolator account (mode 0600 on
POSIX). This tool issues evidence; it does not implement containment.
The worker backend must independently enforce the properties supplied
here, or the attestation is a lie.

Usage:
    python3 tools/issue_worker_attestation.py \
      --receipt execution.json --seed-file isolator.seed \
      --backend linux-rootless-worker \
      --policy-digest <sha256> --image-digest <sha256> \
      --property fs:workspace_confined --property net:denied \
      --property proc:namespaced --output attestation.json
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.errors import InvalidInput
from sis.v3.contracts import ContractError, ExecutionReceiptV1
from sis.v3.isolation import issue_attestation_for_receipt
from sis.vault_storage import assert_private_acl, ensure_private_directory

_DIGEST = re.compile(r"[0-9a-f]{64}")


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _read_seed(path: Path) -> bytes:
    ensure_private_directory(path.parent, "isolator seed directory")
    assert_private_acl(path, "isolator seed")
    raw = path.read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(raw)
    except ValueError as exc:
        raise InvalidInput("isolator seed must be hexadecimal") from exc
    if len(seed) != 32:
        raise InvalidInput("isolator seed must be 32 bytes")
    return seed


def _write_atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".attestation-")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True,
                        help="execution receipt JSON produced by the worker")
    parser.add_argument("--seed-file", type=Path, required=True,
                        help="32-byte hex Ed25519 seed, private to the isolator")
    parser.add_argument("--key-id", default="isolator-1")
    parser.add_argument("--backend", required=True,
                        help="backend identifier the policy allowlists")
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--property", dest="properties", action="append",
                        required=True,
                        help="containment property the worker enforced")
    parser.add_argument("--issued-at", default=None,
                        help="ISO-8601 issuance time (default: now)")
    parser.add_argument("--expires-in", type=int, default=300,
                        help="attestation lifetime in seconds")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing attestation file")
    args = parser.parse_args(argv)

    for name, value in (("policy-digest", args.policy_digest),
                        ("image-digest", args.image_digest)):
        if not _DIGEST.fullmatch(value):
            parser.error(f"--{name} must be a lowercase SHA-256 digest")
    if not 1 <= args.expires_in <= 86_400:
        parser.error("--expires-in must be in [1,86400]")
    if args.output.exists() and not args.force:
        parser.error(f"refusing to overwrite {args.output} without --force")

    try:
        seed = _read_seed(args.seed_file)
        receipt = ExecutionReceiptV1.from_json(args.receipt.read_bytes())
        issued_at = args.issued_at or _utcnow()
        issued = datetime.fromisoformat(
            issued_at[:-1] + "+00:00" if issued_at.endswith("Z") else issued_at)
        expires_at = (issued + timedelta(seconds=args.expires_in)).isoformat(
            timespec="seconds").replace("+00:00", "Z")
        attestation = issue_attestation_for_receipt(
            receipt, seed, args.key_id,
            backend=args.backend,
            policy_digest=args.policy_digest,
            image_digest=args.image_digest,
            properties=tuple(args.properties),
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except (OSError, InvalidInput, ContractError, ValueError) as exc:
        print(f"attestation issuance failed: {exc}", file=sys.stderr)
        return 1

    _write_atomic(args.output, attestation.canonical_bytes() + b"\n")
    print(json.dumps({
        "attestation": str(args.output),
        "attestation_digest": attestation.digest,
        "backend": attestation.backend,
        "expires_at": attestation.expires_at,
        "policy_digest": attestation.policy_digest,
        "receipt_digest": attestation.execution_receipt_digest,
        "worker_identity": attestation.worker_identity,
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
