# SIS release artifacts

Latest sealed release (predates the Gate 1 repair): `SIS-v3.3.8.zip`
SHA-256: `c5b1d27c4d60a24c184efc08d417a4ea8be555bf9d3bd6bb77622da1fd0a6ea6`

`release_manifest.json` and `verification.json` are authoritative for the
archive identity, source commit, test result and fresh-extraction checks.

## Provenance status

**v3.3.8 is unsigned.** `provenance.intoto.json` is an in-toto statement
with no `signatures` field. It binds the archive digest for local evidence
but is not an authentic release seal. An externally trusted signing key was
not available.

`provenance.dsse.json` and `provenance_public_key.hex` are historical
v3.3.5 artifacts signed under `release-v334-key-1`. They do not describe
v3.3.8 and are not part of this bundle's `SHA256SUMS`.

The sealed `SIS-v3.3.8.zip` predates the Gate 1 patch-verification repair.
The repaired source tree therefore no longer matches that archive; re-run
`tools/package_release.py` and re-sign before publishing a new seal.

## Verify

```bash
python3 tools/verify_release.py release/SIS-v3.3.8.zip
python3 tools/verify_release.py --compile .
python3 tools/check_release_ci.py --mode release
cd release && shasum -a 256 -c SHA256SUMS
```
