# SIS release artifacts

Current release: `SIS-v3.3.6.zip`
SHA-256: `2549c92fee28fbab017b1a7bb8a9433b1e70aa54c8b373857216d1aa6b3b92cc`

`release_manifest.json` and `verification.json` are authoritative for the
archive identity, source commit, test result and fresh-extraction checks.

## Provenance status

**v3.3.6 is unsigned.** `provenance.intoto.json` is an in-toto statement
with no signature (`signed: false`, `trust_root: qualification-only`). It
binds the archive digest for local evidence but is not an authentic
release seal. An externally trusted signing key was not available.

`provenance.dsse.json` and `provenance_public_key.hex` are historical
v3.3.5 artifacts signed under `release-v334-key-1`. They do not describe
v3.3.6 and are not part of this bundle's `SHA256SUMS`.

## Verify

```bash
python3 tools/verify_release.py release/SIS-v3.3.6.zip
python3 tools/verify_release.py --compile .
python3 tools/check_release_ci.py --mode release
cd release && shasum -a 256 -c SHA256SUMS
```
