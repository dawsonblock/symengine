#!/usr/bin/env python3
"""Qualify the Docker sandbox with a signed isolation attestation (Gate 2).

Runs one command through ``DockerSandboxExecutor``, writes the execution
receipt the worker produced, issues an ``IsolationAttestationV1`` from an
isolator seed that never enters the evaluated workspace, and verifies the
attestation against a ``ProductionIsolationPolicy``.

This tool issues evidence; it does not implement containment. The image
must be digest-pinned, the receipt must not self-report unverified local
execution, and the policy digest names the exact launch controls that
were enforced. The trust root is local: an externally trusted isolator
key is still required before the attestation can qualify a production
release.

Usage:
    python3 tools/qualify_docker_isolation.py \
      --image sis-evaluator:3.3.8@sha256:<64 hex> \
      --output evidence/sandbox/gate2_isolation
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3.contracts import canonical_digest
from sis.v3.docker_sandbox import DockerSandboxExecutor
from sis.v3.isolation import (ProductionIsolationPolicy,
                              issue_attestation_for_receipt,
                              verify_production_isolation)
from sis.v3.runner import CommandSpec, ResourceLimits
from sis.v3.signatures import public_key

KEY_ID = "gate2-local-isolator"
BACKEND = "docker_sandbox"
PROPERTIES = (
    "net:denied",
    "fs:root_read_only",
    "fs:workspace_confined",
    "user:non_root",
    "caps:dropped",
    "proc:no_new_privileges",
    "limits:memory",
    "limits:pids",
    "limits:disk",
    "limits:cpu_time",
    "output:capped",
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def policy_digest(image_digest: str) -> str:
    """Name the exact launch controls the executor enforces."""
    return canonical_digest("docker_sandbox_policy", 1, {
        "backend": BACKEND,
        "capabilities": "all_dropped",
        "cpu_time": "rlimit_cpu",
        "image_digest": image_digest,
        "ipc": "none",
        "memory_swap": "equal_to_memory",
        "network": "none",
        "no_new_privileges": True,
        "output_cap": True,
        "pids_limit": 128,
        "root_filesystem": "read_only",
        "tmp": "tmpfs:rw,noexec,nosuid",
        "user": "non_root",
        "workspace": "tmpfs:rw,nosuid,nodev,quota",
    })


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _image_hex(image: str) -> str:
    return image.rsplit("@sha256:", 1)[1]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True,
                        help="digest-pinned evaluator image")
    parser.add_argument("--output", type=Path, required=True,
                        help="evidence directory (created, mode 0700)")
    parser.add_argument("--seed-file", type=Path, default=None,
                        help="isolator seed; generated when absent")
    parser.add_argument("--trust-root", choices=("qualification-only", "production"),
                        default="qualification-only",
                        help="production requires --seed-file from an"
                             " independently held key")
    args = parser.parse_args(argv)

    image_digest = _image_hex(args.image)
    output = args.output
    _private_dir(output)
    # The isolator seed is never written into the evidence directory: the
    # attestation carries only the public key. Pass --seed-file to reuse a
    # key held outside the workspace.
    if args.seed_file:
        seed = bytes.fromhex(args.seed_file.read_text(encoding="ascii").strip())
    elif args.trust_root == "production":
        parser.error(
            "production trust root requires --seed-file; the tool must not"
            " generate an isolator key on the evaluated machine")
    else:
        seed = secrets.token_bytes(32)

    work = Path(tempfile.mkdtemp(prefix="sis-gate2-"))
    try:
        base = work / "base"
        base.mkdir()
        (base / "seed.txt").write_text("qualification")
        executor = DockerSandboxExecutor(
            work / "exec", image=args.image, production=True)
        workspace = executor.prepare(base, label="attestation")
        try:
            receipt = executor.run(workspace, CommandSpec(
                argv=("python3", "-c", "print('qualified')"),
                limits=ResourceLimits(wall_seconds=60)))
            stdout, stderr = executor.output(receipt.execution_id)
        finally:
            executor.destroy(workspace)

        (output / "receipt.json").write_bytes(receipt.canonical_bytes() + b"\n")
        issued_at = _utcnow()
        expires_at = (datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                      + timedelta(minutes=5)).isoformat(
                          timespec="seconds").replace("+00:00", "Z")
        digest = policy_digest(image_digest)
        attestation = issue_attestation_for_receipt(
            receipt, seed, KEY_ID,
            backend=BACKEND,
            policy_digest=digest,
            image_digest=image_digest,
            properties=PROPERTIES,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        (output / "attestation.json").write_bytes(
            attestation.canonical_bytes() + b"\n")

        policy = ProductionIsolationPolicy(
            allowed_backends=frozenset({BACKEND}),
            trusted_keys={KEY_ID: public_key(seed).hex()},
            required_policy_digest=digest,
            required_image_digest=image_digest,
            required_properties=frozenset(PROPERTIES),
        )
        verified = verify_production_isolation(attestation, receipt, policy)
        mismatch = verify_production_isolation(
            attestation, receipt,
            ProductionIsolationPolicy(
                allowed_backends=frozenset({BACKEND}),
                trusted_keys={KEY_ID: public_key(seed).hex()},
                required_policy_digest=digest,
                required_image_digest="0" * 64,
                required_properties=frozenset(PROPERTIES)))

        record = {
            "schema_version": 1,
            "kind": "docker_isolation_qualification",
            "generated_at": _utcnow(),
            "backend": BACKEND,
            "image": args.image,
            "image_digest": image_digest,
            "policy_digest": digest,
            "properties": list(PROPERTIES),
            "worker_identity": receipt.worker_identity,
            "receipt_digest": receipt.digest,
            "attestation_digest": attestation.digest,
            "signer_key_id": KEY_ID,
            "signer_public_key": public_key(seed).hex(),
            "trust_root": args.trust_root,
            "receipt_security_errors": list(receipt.security_errors),
            "verified": verified.ok,
            "verification_reason": verified.reason,
            "negative_image_mismatch_ok": not mismatch.ok,
            "negative_image_mismatch_reason": mismatch.reason,
            "stdout": stdout.decode("utf-8", "replace")[:200],
            "note": (
                "Signed with a key supplied via --seed-file. Verify the"
                " signer public key against the independent trust root"
                " before accepting a production claim."
                if args.trust_root == "production" else
                "Locally signed containment evidence, not an externally "
                "trusted attestation. Production qualification still "
                "requires an isolator key held independently of this "
                "machine."),
        }
        (output / "qualification.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n")
        print(json.dumps(record, indent=2, sort_keys=True))
        return 0 if (verified.ok and not mismatch.ok) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
