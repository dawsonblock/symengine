#!/usr/bin/env python3
"""Register gVisor's ``runsc`` as a Docker runtime in ``daemon.json``.

Used by the ``sandbox-qualification`` CI job; it merges into an existing
configuration instead of replacing it. ``--oci-seccomp`` makes runsc apply
the container's seccomp profile inside the sandbox (without it the
profile passed with ``--security-opt seccomp=...`` is ignored), and the
containerd image store lets a locally built image be referenced as
``name:tag@sha256:<id>``. Restart the Docker daemon afterwards.

Usage:
    sudo python3 tools/configure_docker_runsc.py \\
      --runsc /opt/gvisor/runsc --config /etc/docker/daemon.json
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

RUNTIME_ARGS = ("--oci-seccomp",)


def merged(config: dict, runsc: str) -> dict:
    """Return ``config`` with the runsc runtime and containerd store set."""
    if not isinstance(config, dict):
        raise ValueError("daemon.json must hold a JSON object")
    result = dict(config)
    runtimes = dict(result.get("runtimes") or {})
    runtimes["runsc"] = {"path": runsc, "runtimeArgs": list(RUNTIME_ARGS)}
    result["runtimes"] = runtimes
    features = dict(result.get("features") or {})
    features["containerd-snapshotter"] = True
    result["features"] = features
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runsc", required=True,
                        help="absolute path of the runsc binary")
    parser.add_argument("--config", type=Path,
                        default=Path("/etc/docker/daemon.json"))
    args = parser.parse_args(argv)
    if not os.path.isabs(args.runsc):
        parser.error("--runsc must be an absolute path")
    current = (json.loads(args.config.read_text())
               if args.config.exists() and args.config.read_text().strip()
               else {})
    document = json.dumps(merged(current, args.runsc), indent=2,
                          sort_keys=True) + "\n"
    args.config.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(dir=args.config.parent, prefix=".daemon-")
    with os.fdopen(fd, "w") as handle:
        handle.write(document)
    os.chmod(temp, 0o644)
    os.replace(temp, args.config)
    print(document, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
