#!/usr/bin/env python3
"""Run the supported suite and write machine-readable evidence.

``pytest`` is the supported runner; unittest discovery is not. The tool
refuses a runner version other than the pin in ``requirements-lock.txt``,
records the exact commit, command, environment and parsed counts, and
writes JSON that ``tools/package_release.py --test-evidence`` accepts.

Usage:
    python3 tools/run_tests.py --json /tmp/sis-test-report.json
    python3 tools/run_tests.py -- -k split_custody
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "requirements-lock.txt"
DEFAULT_PIN = "8.4.2"
SUITE = "tests/"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_evidence  # noqa: E402


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def _pinned_version() -> str:
    try:
        text = LOCK.read_text(encoding="utf-8")
    except OSError:
        return DEFAULT_PIN
    match = re.search(r"^pytest==([0-9][^\s#]*)", text, re.MULTILINE)
    return match.group(1) if match else DEFAULT_PIN


def _pytest_version(python: str) -> str:
    result = subprocess.run(
        [python, "-c", "import pytest; print(pytest.__version__)"],
        capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(
            "pytest is not importable by " + python + ": "
            + (result.stderr or result.stdout).strip()[:200])
    return result.stdout.strip()


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        return "unknown"
    return result.stdout.strip()


def _counts(output: str) -> dict:
    return test_evidence.counts_from_output(output)


def _duration(output: str) -> float | None:
    matches = re.findall(r" in ([0-9.]+)s", output)
    return float(matches[-1]) if matches else None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--suite", default=SUITE,
                        help="path passed to pytest (default tests/)")
    parser.add_argument("--json", type=Path, default=None,
                        help="write test evidence to this path")
    parser.add_argument("--allow-version-mismatch", action="store_true",
                        help="development only: run despite a different"
                             " pytest version")
    parser.add_argument("--signing-key", type=Path, default=None,
                        help="file containing a 32-byte hex CI signing seed")
    parser.add_argument("--key-id", default="ci-test-runner",
                        help="signer key identifier recorded in the evidence")
    parser.add_argument("extra", nargs=argparse.REMAINDER,
                        help="arguments after -- are passed to pytest")
    args = parser.parse_args(argv)

    pinned = _pinned_version()
    actual = _pytest_version(args.python)
    if actual != pinned and not args.allow_version_mismatch:
        print(
            f"pytest {actual} is not the supported runner {pinned}; "
            "install requirements-lock.txt or pass"
            " --allow-version-mismatch for a development run",
            file=sys.stderr)
        return 2

    extra = list(args.extra)
    if extra and extra[0] == "--":
        extra = extra[1:]
    command = [args.python, "-m", "pytest", args.suite, "-q", *extra]
    started_at = _utcnow()
    started = time.monotonic()
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True)
    elapsed = time.monotonic() - started
    output = result.stdout + result.stderr
    output_bytes = output.encode("utf-8")
    truncated = len(output_bytes) > test_evidence.MAX_OUTPUT_BYTES
    recorded_output = output_bytes[:test_evidence.MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace") if truncated else output
    counts = _counts(output)
    evidence = {
        "schema_version": 1,
        "kind": "test_evidence",
        "source_commit": _git("rev-parse", "HEAD"),
        "branch": _git("rev-parse", "--abbrev-ref", "HEAD"),
        "dirty": bool(_git("status", "--porcelain")),
        "command": command,
        "suite": args.suite,
        "python_executable": args.python,
        "pytest_version": actual,
        "pytest_pin": pinned,
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "started_at": started_at,
        "finished_at": _utcnow(),
        "duration_seconds": round(elapsed, 3),
        "reported_duration_seconds": _duration(output),
        "counts": counts,
        "exit_status": result.returncode,
        "output": recorded_output,
        "output_truncated": truncated,
        "output_sha256": hashlib.sha256(output_bytes).hexdigest(),
        "environment": {
            name: os.environ.get(name, "")
            for name in ("PYTEST_DISABLE_PLUGIN_AUTOLOAD",
                         "PYTHONNOUSERSITE", "DOCKER_HOST")
        },
    }
    if args.signing_key is not None:
        try:
            seed = bytes.fromhex(args.signing_key.read_text().strip())
        except (OSError, ValueError) as exc:
            print(f"test evidence signing key is unreadable: {exc}",
                  file=sys.stderr)
            return 2
        if len(seed) != 32:
            print("test evidence signing key must be 32 bytes",
                  file=sys.stderr)
            return 2
        evidence = test_evidence.sign_evidence(evidence, seed, args.key_id)
    if args.json is not None:
        test_evidence.write(args.json, evidence)
    print(output.strip()[-2000:])
    print(json.dumps({
        "counts": counts,
        "exit_status": result.returncode,
        "evidence": str(args.json) if args.json is not None else None,
        "signed": "signature" in evidence,
    }, indent=2))
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
