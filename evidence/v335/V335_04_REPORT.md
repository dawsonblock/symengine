# V335-04 — Pinned suite and release seal

Status: implemented on `repair/v335-resource-security`. Scope limited to
the version bump, `RELEASE_SHA256.json`, `docs/v3/QUALIFICATION_REPORT_V3_3_5.md`,
`CHANGELOG.md`, and the out-of-band `release/` bundle. No source module
changed after V335-03.

## Version and manifest

- `src/sis/__init__.py` and `pyproject.toml` move to `3.3.5`.
- `RELEASE_SHA256.json` is regenerated over the repaired tree, so the
  archive can verify itself without Git history.
- The v3.3.4 archive, its manifest and its provenance are left in place
  as immutable historical evidence.

## Pinned suite

A fresh virtual environment containing only `pytest==8.4.2`:

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
```

- Pre-seal: 1271 passed, 14 skipped, 2 failed. Both are release seal
  checks — the stale `release/` inventory and the manifest commit
  binding — and both are resolved by the seal.
- Post-seal: 1273 passed, 14 skipped, 0 failed. Recorded in
  `release/release_manifest.json`.

The system interpreter with `psycopg` present runs 1272 passed, 13
skipped, 2 pre-seal failures; the clean environment additionally skips
the PostgreSQL control-plane test.

## Seal

- `tools/package_release.py` builds `release/SIS-v3.3.5.zip`, the
  archive-internal manifest, the source inventory, the verification
  record, and DSSE provenance signed under the release key supplied at
  packaging time.
- The archive hash, file count, fresh-extraction compile and smoke
  result, and the source commit are recorded in `release/verification.json`
  and `release/release_manifest.json` rather than repeated here, so this
  report stays valid across the two-pass seal (pre-seal result, then
  post-seal result).
- The seal commit touches only out-of-band `release/` provenance and
  `evidence/release/build_record.json`. No manifest-covered file changes,
  so the post-seal suite result applies to the archived tree.

## What this does not establish

- No qualified production sandbox. The archive still contains no
  independently qualified isolator, and production execution stays
  closed without one.
- No real-agent efficacy evidence. The release is
  `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
- Symbolic-search scaling remains the known limitation documented in
  `docs/v3/V33_LIMITATIONS.md`; it is out of scope for this repair line.
