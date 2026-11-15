# Gate 2 — Docker sandbox qualification

Status date: 2026-11-14. Branch: `repair/v335-resource-security`.

This records live containment evidence for the Docker evaluator sandbox.
It is engineering evidence, not a production security certification: the
attestation is signed by a locally held qualification key, not by an
isolator trusted independently of this machine.

## What ran

| Check | Result |
| --- | --- |
| Base image | `python:3.12-slim@sha256:5e2bdb1b…` (index digest pinned in the Dockerfile) |
| Evaluator image | `sis-evaluator:3.3.9@sha256:5af4f6ce…` |
| Docker server | 29.9.3, linux/aarch64 |
| Containment probe, `production=True` | 13/13 checks pass |
| Execution receipt | `isolation:docker_sandbox`; no `docker:image_tag_only` |
| `IsolationAttestationV1` | verified (`reason: ok`) |
| Negative control (wrong image digest) | rejected (`image_mismatch`) |
| Full suite with Docker available | see `docs/v3/QUALIFICATION_REPORT_V3_3_9.md` |
| Real-container split custody | submission denied read of the private tests; worker reload keeps `custody="split"` |

The probe checks network denial, read-only root, workspace write, non-root
user, Docker-socket absence, `no-new-privileges`, dropped capabilities,
`setuid` denial, memory, pids, disk, CPU-time and output limits.

## Evidence

`evidence/sandbox/docker_sandbox_probe.json` — the 13-check probe result,
regenerated on 2026-11-14 by `tools/probe_docker_sandbox.py` against the
digest-pinned image.
`evidence/sandbox/gate2_isolation/` — the execution receipt, the signed
attestation and the qualification record (policy digest, public key,
verification result), regenerated on 2026-11-14 by
`tools/qualify_docker_isolation.py`. The isolator seed is never written
into the evidence directory.

The policy digest binds the launch controls the executor enforces; the
attestation binds the receipt, worker identity, policy and image. Both
tools reproduce the stored evidence.

## External isolator path

The stored bundle is qualification-only. Production custody uses a
receipt produced here and an attestation signed by a key held elsewhere:

1. Produce the receipt (`tools/qualify_docker_isolation.py` writes it,
   or run the executor directly).
2. Hand `receipt.json` to the isolator, who signs it with its own key.
3. Verify with `tools/verify_external_attestation.py`, passing the
   isolator's public key, key id, image digest, policy digest and
   required properties.

The verifier writes an `external_isolation_verification.json` record and
exits non-zero on any mismatch (wrong key, image, policy, missing
property, receipt binding, freshness). It proves the attestation is
bound to that receipt and policy; comparing the public key with the
relying party's copy remains an out-of-band step.

## What this does not claim

- The signing key is local (`gate2-local-isolator`, trust root
  `qualification-only`). A production seal needs an isolator key held
  independently of the evaluated machine.
- `--trust-root production` requires `--seed-file` and refuses to
  generate a key on the evaluated machine. Supplying a seed is not the
  same as independent custody: the signer public key must still be
  verified against a key held by the relying party.
- `release/provenance.intoto.json` remains unsigned.
- The probe is factual launch evidence; it does not prove kernel
  enforcement against a privileged attacker.
- Windows and the desktop GUI are still unqualified.

## Post-qualification repairs and evidence refresh (2026-11-14)

The Gate 2 audit reproduced five containment/evaluation defects after the
original evidence was recorded. They are repaired in the working tree,
and the stored probe, receipt and attestation were regenerated on
2026-11-14 over the repaired tree, so the evidence now describes the
current executor and image rather than the pre-repair snapshot.

- Copy-out extraction now enforces the declared disk budget and file
  count while reading, with a reason-specific `fs:` marker.
- A failed swap preserves the prepared workspace and restores the
  original if the staged rename fails.
- Private acceptance material is staged outside the graded tree and
  bound read-only at `/private` (Docker, Linux worker). The graded
  workspace is no longer placed on `PYTHONPATH`: a staged bootstrap
  imports the test runner before exposing the workspace, so a submission
  cannot shadow `pytest` or inject `sitecustomize`; a missing `-m` runner
  exits 70 before the workspace is importable, and direct scripts refuse
  a workspace `pytest` module. A local-backend rewrite is detected after
  the run
  (`sandbox:private_material_modified`). The residual same-process read
  risk is documented in
  [SECURITY_BOUNDARIES_V3_3.md](SECURITY_BOUNDARIES_V3_3.md).
- The evaluator worker, the demonstration cycle and the live-episode
  script default to Docker or require explicit authorization; local
  execution requires the flag.
- `verify_proposal()` rejects a target that resolves outside its base
  directory.

The same refresh also covers the later post-seal repairs: process-split
custody (`custody="split"`), the worker's `--split-user` /
`--require-split-custody` configuration, and durable custody in
`tasks.json`. Real-container split tests now run when the image is
present; they skip when it is not.

See the 2026-11-13 and 2026-11-14 CHANGELOG entries,
`tests/v3/test_gate2_containment_repairs.py` and
`tests/v3/test_split_custody.py`.

## v3.3.9 refresh (2026-11-14)

The probe, receipt and attestation were regenerated against
`sis-evaluator:3.3.9@sha256:5af4f6ceed7041f1665fdb077708c9b8fdd71cedf451e0adbfb0490e5e914466`
after the release-authenticity and hard-limit repairs:

- containment probe: 13/13;
- policy digest: `2cce5dcb68cedcc27f7f5b95b2d85d227d13455281a5a1dfb1312fc94168a050`;
- receipt digest: `f89dd405ad83ae571a4fab74d42e510a1c0103df58022ee0180186de542567a7`;
- attestation verification: `ok`, trust root `qualification-only`;
- real-container split custody: worker denied the private tests and a
  reloaded task kept `custody="split"`.

The production custody requirement is unchanged: the attestation must be
signed by a key held independently of the evaluated machine, and the
release gate must re-verify it with that key.
