# SIS release artifacts

Latest sealed release: `SIS-v3.3.8.zip`
SHA-256: `3e924b509b62d67e5076c90a3bf0aaf13e0826b1dcba611ccf054fcef947bca4`

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

The archive was re-sealed over the Gate 1 patch-verification repair, the
Gate 2 sandbox hardening and qualification, the efficacy `E_vs_A` contrast
fix and the historical evidence correction, at source commit `8466e97`
over 447 source files. The Docker containment probe ran live (13/13) and a
signed `IsolationAttestationV1` verifies against its policy; the signing
key is local, so the trust root is qualification-only. It is still
unsigned: re-sign with an externally held key before publishing.

## Verify

```bash
python3 tools/verify_release.py release/SIS-v3.3.8.zip
python3 tools/verify_release.py --compile .
python3 tools/check_release_ci.py --mode release
cd release && shasum -a 256 -c SHA256SUMS
```
