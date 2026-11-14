#!/usr/bin/env python3
"""Regenerate the Docker containment probe evidence.

Runs ``DockerSandboxExecutor.probe()`` against a digest-pinned evaluator
image and writes the factual containment observations. This is launch
evidence, not a signed attestation; ``tools/qualify_docker_isolation.py``
issues the receipt-bound ``IsolationAttestationV1``.

Usage:
    PYTHONPATH=src python3 tools/probe_docker_sandbox.py \
      --image sis-evaluator:3.3.8@sha256:<64 hex>
"""
from __future__ import annotations

import argparse
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sis.v3.docker_sandbox import DockerSandboxExecutor

NOTE = (
    "Factual containment probe, not a signed isolation attestation. "
    "Production qualification still requires an IsolationAttestationV1 "
    "from a separately trusted isolator."
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True,
                        help="digest-pinned evaluator image")
    parser.add_argument("--output", type=Path,
                        default=Path("evidence/sandbox/docker_sandbox_probe.json"))
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="sis-probe-root-") as root:
        executor = DockerSandboxExecutor(
            root, image=args.image, production=True)
        try:
            report = executor.probe()
        finally:
            executor.terminate_all()

    document = {
        "schema_version": 1,
        "kind": "docker_sandbox_probe",
        "backend": "docker_sandbox",
        "generated_at": _utcnow(),
        "note": NOTE,
        **report,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "ok": document["ok"],
        "checks": len(document["checks"]),
        "image": document["image"],
        "image_id": document["image_id"],
    }, indent=2))
    return 0 if document["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
