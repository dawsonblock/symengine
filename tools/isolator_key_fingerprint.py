#!/usr/bin/env python3
"""Print a stable fingerprint of an Ed25519 isolator public key.

The out-of-band check for independent sign-off compares this fingerprint,
read aloud or over a second channel, between the isolator host and the
relying party (the repository's ``SIS_ISOLATOR_PUBLIC_KEY`` secret). It
uses the same encoding as the evaluator key ids (``key-`` followed by the
first 24 hex digits of SHA-256 over the 32 raw public-key bytes), plus the
full SHA-256 grouped for reading aloud.

The key may be given as 64 hex characters or as a file holding them (the
format ``check_release_ci.py`` reads). ``--seed-file`` derives the public
key from an isolator seed and is meant to run only on the isolator host;
the seed is never printed. ``--expect`` exits non-zero unless the
fingerprint matches, so a scripted comparison cannot pass by accident.

Usage:
    python3 tools/isolator_key_fingerprint.py --public-key isolator-public.hex
    python3 tools/isolator_key_fingerprint.py --public-key <64 hex> \\
      --expect key-0123456789abcdef01234567
    python3 tools/isolator_key_fingerprint.py --seed-file isolator.seed --json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from sis.v3 import signatures

_HEX = set("0123456789abcdef")


def _read_hex(value: str, *, length: int, description: str) -> bytes:
    candidate = Path(value)
    if candidate.is_file():
        value = candidate.read_text(encoding="ascii").strip()
    value = value.strip().lower()
    if len(value) != length * 2 or not set(value) <= _HEX:
        raise ValueError(
            f"{description} must be {length * 2} hex characters or a file"
            " holding them")
    return bytes.fromhex(value)


def key_id(public: bytes) -> str:
    """The evaluator-style key id for a raw 32-byte public key."""
    return "key-" + hashlib.sha256(public).hexdigest()[:24]


def fingerprint(public: bytes) -> dict:
    """Every encoding of one public key's fingerprint."""
    if len(public) != 32 or not signatures.is_valid_public_key(public):
        raise ValueError("not a valid Ed25519 public key")
    digest = hashlib.sha256(public).hexdigest()
    return {
        "algorithm": "ed25519",
        "public_key": public.hex(),
        "key_id": key_id(public),
        "sha256": digest,
        "sha256_grouped": " ".join(
            digest[index:index + 4] for index in range(0, 64, 4)),
    }


def matches(record: dict, expected: str) -> bool:
    """Accept the key id, the full digest, or the grouped digest."""
    wanted = " ".join(expected.lower().split())
    return wanted in {record["key_id"], record["sha256"],
                      record["sha256_grouped"],
                      record["sha256_grouped"].replace(" ", "")}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--public-key",
                        help="64 hex characters, or a file holding them")
    source.add_argument("--seed-file", type=Path,
                        help="isolator seed (isolator host only)")
    parser.add_argument("--expect", default=None,
                        help="fingerprint to compare against (key id,"
                             " sha256 or grouped sha256)")
    parser.add_argument("--json", action="store_true",
                        help="print the full record as JSON")
    args = parser.parse_args(argv)
    try:
        if args.seed_file is not None:
            seed = _read_hex(str(args.seed_file), length=32,
                             description="isolator seed")
            public = signatures.public_key(seed)
        else:
            public = _read_hex(args.public_key, length=32,
                               description="public key")
        record = fingerprint(public)
    except (OSError, ValueError) as exc:
        print(f"invalid key input: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(record, indent=2, sort_keys=True))
    else:
        print(f"key id:  {record['key_id']}")
        print(f"sha256:  {record['sha256_grouped']}")
        print(f"public:  {record['public_key']}")
    if args.expect is not None and not matches(record, args.expect):
        print("fingerprint MISMATCH: do not trust this key", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
