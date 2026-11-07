"""Explicit release/development inventory policy for CI (never rewrites files)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_release import manifest_document  # noqa: E402
from check_source_manifest import _valid_manifest  # noqa: E402
from verify_release import verify_tree  # noqa: E402


def check(root: Path, mode: str) -> int:
    if mode not in {"release", "development"}:
        raise ValueError("unknown CI mode")
    try:
        manifest = json.loads((root / "RELEASE_SHA256.json").read_text())
        _valid_manifest(manifest)
        if manifest != manifest_document(root):
            if mode == "development":
                print("development tree: inventory drift allowed; not release verification")
                return 0
            raise ValueError("release manifest is stale")
        report = verify_tree(root)
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f"release inventory check failed: {exc}", file=sys.stderr)
        return 1
    print(f"release inventory verified: {report['files']} files")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("release", "development"))
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    return check(args.source.resolve(), args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
