#!/usr/bin/env python3
"""Verify an isolation attestation signed by an external isolator.

``tools/qualify_docker_isolation.py`` signs with a key generated on the
evaluated machine (trust root ``qualification-only``). Production custody
requires the receipt to leave the machine, be signed by a separately held
key, and be verified here against that key's public half.

The receipt must come from the executor that actually ran the workload;
this tool does not produce one. Run the executor (or
``qualify_docker_isolation.py``) first, hand ``receipt.json`` to the
isolator, then verify the returned attestation:

    python3 tools/verify_external_attestation.py \
      --receipt evidence/sandbox/gate2_isolation/receipt.json \
      --attestation external/attestation.json \
      --public-key <64 hex> --key-id external-isolator \
      --image-digest <64 hex> --policy-digest <64 hex> \
      --property net:denied --property fs:root_read_only \
      --output evidence/sandbox/external_verification.json

A verification record is evidence about the attestation, not a new
signature. The external public key must be compared against the key the
relying party holds out of band.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sis.v3.contracts import ContractError, ExecutionReceiptV1
from sis.v3.isolation import (
    ProductionIsolationPolicy,
    verify_production_isolation,
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def verify(
    receipt: ExecutionReceiptV1,
    attestation: dict,
    *,
    public_key: str,
    key_id: str,
    image_digest: str,
    policy_digest: str,
    properties: list[str],
    backend: str = "docker_sandbox",
    max_age_seconds: int | None = 3600,
    at_time: str | None = None,
):
    """Verify one external attestation against its receipt and policy."""
    if not properties:
        raise ValueError("at least one required property is needed")
    policy = ProductionIsolationPolicy(
        allowed_backends=frozenset({backend}),
        trusted_keys={key_id: public_key},
        required_policy_digest=policy_digest,
        required_image_digest=image_digest,
        required_properties=frozenset(properties),
        max_attestation_age_seconds=max_age_seconds,
    )
    return verify_production_isolation(
        attestation, receipt, policy, at_time=at_time)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--attestation", type=Path, required=True)
    parser.add_argument("--public-key", required=True,
                        help="external isolator Ed25519 public key (hex)")
    parser.add_argument("--key-id", default="external-isolator")
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--policy-digest", required=True)
    parser.add_argument("--backend", default="docker_sandbox")
    parser.add_argument("--property", action="append", default=[])
    parser.add_argument("--max-age-seconds", type=int, default=3600)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        receipt = ExecutionReceiptV1.from_json(args.receipt.read_bytes())
        attestation = json.loads(args.attestation.read_text())
        result = verify(
            receipt, attestation,
            public_key=args.public_key, key_id=args.key_id,
            image_digest=args.image_digest,
            policy_digest=args.policy_digest,
            properties=args.property, backend=args.backend,
            max_age_seconds=args.max_age_seconds)
    except (OSError, json.JSONDecodeError, ContractError,
            ValueError, TypeError, KeyError) as exc:
        print(f"invalid attestation or receipt input: {exc}", file=sys.stderr)
        return 2
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
        "public_key": args.public_key,
        "image_digest": args.image_digest,
        "required_properties": sorted(args.property),
        "verified": result.ok,
        "reason": result.reason,
        "note": (
            "Verification record for an externally signed attestation."
            " Compare the public key with the key held by the relying"
            " party; this tool does not establish that custody."),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps(record, indent=2, sort_keys=True))
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
