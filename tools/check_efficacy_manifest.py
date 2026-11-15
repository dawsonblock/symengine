#!/usr/bin/env python3
"""Validate a five-arm efficacy manifest without running the study.

Strict mode requires a powered preregistered protocol, at least ten
repositories (at least five of them holdout repositories), at least
``sample_size`` paired tasks, repository-disjoint partitions, hidden
tests outside the public repository, and no placeholder values.
``--allow-placeholders`` validates the shipped template instead.

Usage:
    python3 tools/check_efficacy_manifest.py \
      docs/v3/efficacy_manifest_template.json --allow-placeholders
    python3 tools/check_efficacy_manifest.py /secure/study/manifest.json \
      --check-paths
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sis.v3.efficacy_manifest import validate_manifest  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--allow-placeholders", action="store_true",
                        help="validate the template, not a runnable study")
    parser.add_argument("--check-paths", action="store_true",
                        help="require repository and hidden-test paths to exist")
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"efficacy manifest is unreadable: {exc}", file=sys.stderr)
        return 1
    report = validate_manifest(
        document, allow_placeholders=args.allow_placeholders,
        check_paths=args.check_paths)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["valid"]:
        return 1
    if args.allow_placeholders:
        return 0
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
