#!/usr/bin/env python3
"""Qualify the Docker sandbox with a signed isolation attestation (Gate 2).

Runs one command through ``DockerSandboxExecutor``, writes the execution
receipt the worker produced, issues an ``IsolationAttestationV1`` from an
isolator seed that never enters the evaluated workspace, and verifies the
attestation against the production isolation policy for this backend.

This tool issues evidence; it does not implement containment. The image
must be digest-pinned, the executor runs under gVisor (``--runtime
runsc``) with the allowlist seccomp profile, and the signed policy digest
is computed from the same method that builds the ``docker run`` flags
(``DockerSandboxExecutor.launch_policy``), so the policy cannot describe
controls the launch did not use. The policy document itself is written to
``policy.json`` beside the receipt.

``--probe-report`` and ``--redteam-report`` bind the containment probe
and red-team reports into the qualification record by digest; a report
that is not ``ok`` fails qualification.

The trust root is local unless ``--seed-file`` names an independently
held key: an externally trusted isolator key is still required before the
attestation can qualify a production release.

Usage:
    PYTHONPATH=src python3 tools/qualify_docker_isolation.py \
      --image sis-evaluator:3.3.9@sha256:<64 hex> \
      --probe-report evidence/sandbox/docker_sandbox_probe.json \
      --redteam-report evidence/sandbox/redteam_report.json \
      --output evidence/sandbox/gate2_isolation
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sis.v3.docker_sandbox import (BACKEND, PRODUCTION_PROPERTIES,
                                   PRODUCTION_RUNTIME, DockerSandboxExecutor,
                                   production_isolation_policy)
from sis.v3.isolation import (issue_attestation_for_receipt,
                              verify_production_isolation)
from sis.v3.runner import CommandSpec, ResourceLimits
from sis.v3.signatures import public_key

ROOT = Path(__file__).resolve().parents[1]
KEY_ID = "gate2-local-isolator"
PROPERTIES = PRODUCTION_PROPERTIES
DEFAULT_SECCOMP = ROOT / "docker" / "sandbox" / "seccomp.json"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def claimable_properties(receipt, executor) -> tuple[str, ...]:
    """The required properties this receipt's launch actually provided.

    ``kernel:gvisor`` needs a runsc launch and
    ``syscalls:seccomp_allowlist`` needs the allowlist profile; the base
    container controls need the Docker sandbox markers. A property the
    receipt cannot back is left out, so verification fails rather than
    signing a claim the run did not earn.
    """
    errors = set(receipt.security_errors)
    claims = []
    base = {"isolation:docker_sandbox", "docker:network_none",
            "docker:read_only_root", "docker:cap_drop_all",
            "docker:no_new_privileges", "docker:tmpfs_workspace"}
    for prop in PROPERTIES:
        if prop == "kernel:gvisor":
            if f"docker:runtime:{PRODUCTION_RUNTIME}" in errors:
                claims.append(prop)
        elif prop == "syscalls:seccomp_allowlist":
            digest = executor.seccomp_profile_sha256
            if digest and f"docker:seccomp_profile:{digest}" in errors:
                claims.append(prop)
        elif base <= errors:
            claims.append(prop)
    return tuple(claims)


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _image_hex(image: str) -> str:
    return image.rsplit("@sha256:", 1)[1]


def _bind_report(path: Path | None, kind: str) -> dict | None:
    if path is None:
        return None
    raw = path.read_bytes()
    document = json.loads(raw)
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "kind": document.get("kind", kind),
        "ok": document.get("ok") is True,
        "generated_at": document.get("generated_at"),
        "policy_digest": document.get("policy_digest"),
    }


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
    parser.add_argument("--valid-minutes", type=int, default=5,
                        help="attestation lifetime in minutes (1-1440)")
    parser.add_argument("--seccomp-profile", type=Path, default=DEFAULT_SECCOMP,
                        help="allowlist seccomp profile")
    parser.add_argument("--probe-report", type=Path, default=None,
                        help="tools/probe_docker_sandbox.py output to bind")
    parser.add_argument("--redteam-report", type=Path, default=None,
                        help="tools/redteam_sandbox.py output to bind")
    args = parser.parse_args(argv)
    if not 1 <= args.valid_minutes <= 1440:
        parser.error("--valid-minutes must be in [1,1440]")

    image_digest = _image_hex(args.image)
    output = args.output
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
    reports = {
        "probe": _bind_report(args.probe_report, "docker_sandbox_probe"),
        "redteam": _bind_report(args.redteam_report, "docker_sandbox_redteam"),
    }
    _private_dir(output)

    work = Path(tempfile.mkdtemp(prefix="sis-gate2-"))
    try:
        base = work / "base"
        base.mkdir()
        (base / "seed.txt").write_text("qualification")
        executor = DockerSandboxExecutor(
            work / "exec", image=args.image, production=True,
            runtime=PRODUCTION_RUNTIME, seccomp_profile=args.seccomp_profile)
        workspace = executor.prepare(base, label="attestation")
        try:
            receipt = executor.run(workspace, CommandSpec(
                argv=("python3", "-c", "print('qualified')"),
                limits=ResourceLimits(wall_seconds=60)))
            stdout, stderr = executor.output(receipt.execution_id)
        finally:
            executor.destroy(workspace)

        policy_document = executor.launch_policy()
        digest = executor.policy_digest()
        # The receipt names the policy its launch used; signing another
        # digest would attest controls this run did not have.
        policy_bound = f"docker:policy:{digest}" in receipt.security_errors
        (output / "policy.json").write_text(
            json.dumps(policy_document, indent=2, sort_keys=True) + "\n")
        (output / "receipt.json").write_bytes(receipt.canonical_bytes() + b"\n")
        issued_at = _utcnow()
        expires_at = (datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                      + timedelta(minutes=args.valid_minutes)).isoformat(
                          timespec="seconds").replace("+00:00", "Z")
        claims = claimable_properties(receipt, executor)
        attestation = issue_attestation_for_receipt(
            receipt, seed, KEY_ID,
            backend=BACKEND,
            policy_digest=digest,
            image_digest=image_digest,
            properties=claims,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        (output / "attestation.json").write_bytes(
            attestation.canonical_bytes() + b"\n")

        trusted = {KEY_ID: public_key(seed).hex()}
        verified = verify_production_isolation(
            attestation, receipt, production_isolation_policy(
                trusted_keys=trusted, image_digest=image_digest,
                policy_digest=digest))
        mismatch = verify_production_isolation(
            attestation, receipt, production_isolation_policy(
                trusted_keys=trusted, image_digest="0" * 64,
                policy_digest=digest))
        reports_ok = all(report is None or report["ok"]
                         for report in reports.values())

        record = {
            "schema_version": 2,
            "kind": "docker_isolation_qualification",
            "generated_at": _utcnow(),
            "backend": BACKEND,
            "image": args.image,
            "image_digest": image_digest,
            "runtime": executor.runtime,
            "seccomp_profile_sha256": executor.seccomp_profile_sha256,
            "policy_digest": digest,
            "policy_bound_to_receipt": policy_bound,
            "properties": list(PROPERTIES),
            "claimed_properties": list(claims),
            "worker_identity": receipt.worker_identity,
            "receipt_digest": receipt.digest,
            "attestation_digest": attestation.digest,
            "attestation_expires_at": expires_at,
            "signer_key_id": KEY_ID,
            "signer_public_key": public_key(seed).hex(),
            "trust_root": args.trust_root,
            "receipt_security_errors": list(receipt.security_errors),
            "reports": reports,
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
        return 0 if (verified.ok and not mismatch.ok and policy_bound
                     and reports_ok) else 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
