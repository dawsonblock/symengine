"""Isolator public-key fingerprints for the out-of-band check (C5)."""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import isolator_key_fingerprint as fp  # noqa: E402
from sis.v3 import signatures  # noqa: E402


def _run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fp.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class FingerprintTests(unittest.TestCase):
    def setUp(self):
        self.seed, self.public = signatures.generate_keypair()

    def test_key_id_uses_the_evaluator_encoding(self):
        record = fp.fingerprint(self.public)
        self.assertEqual(
            record["key_id"],
            "key-" + hashlib.sha256(self.public).hexdigest()[:24])
        self.assertEqual(record["sha256_grouped"].replace(" ", ""),
                         record["sha256"])
        self.assertEqual(len(record["sha256_grouped"].split()), 16)

    def test_fingerprint_is_stable_across_input_forms(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "isolator.pub"
            path.write_text(self.public.hex().upper() + "\n")
            seed_path = Path(temp) / "isolator.seed"
            seed_path.write_text(self.seed.hex())
            outputs = {
                _run("--public-key", self.public.hex(), "--json")[1],
                _run("--public-key", str(path), "--json")[1],
                _run("--seed-file", str(seed_path), "--json")[1],
            }
        self.assertEqual(len(outputs), 1)
        record = json.loads(outputs.pop())
        self.assertEqual(record["public_key"], self.public.hex())
        self.assertNotIn(self.seed.hex(), json.dumps(record))

    def test_expect_accepts_every_encoding_and_rejects_others(self):
        record = fp.fingerprint(self.public)
        for expected in (record["key_id"], record["sha256"],
                         record["sha256_grouped"],
                         record["sha256_grouped"].upper()):
            with self.subTest(expected=expected):
                code, _out, _err = _run("--public-key", self.public.hex(),
                                        "--expect", expected)
                self.assertEqual(code, 0)
        _other_seed, other = signatures.generate_keypair()
        code, _out, err = _run("--public-key", self.public.hex(),
                               "--expect", fp.key_id(other))
        self.assertEqual(code, 1)
        self.assertIn("MISMATCH", err)

    def test_invalid_input_is_refused(self):
        for value in ("00" * 31, "zz" * 32, "ff" * 32):
            with self.subTest(value=value):
                code, _out, err = _run("--public-key", value)
                self.assertEqual(code, 2, err)


if __name__ == "__main__":
    unittest.main()
