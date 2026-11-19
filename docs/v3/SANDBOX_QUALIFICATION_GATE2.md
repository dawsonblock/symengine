# Gate 2 — Docker sandbox qualification

Status date: 2026-11-19 (SIS-FEAT-16). Branch: `claude/sis-sandbox-gvisor`.

This records containment evidence for the Docker evaluator sandbox and
the path to an independently signed qualification. It is engineering
evidence, not a production security certification: every attestation in
this repository is signed by a locally held qualification key, not by an
isolator trusted independently of the evaluated machine.

## Current status: the stored evidence is stale

The files in `evidence/sandbox/gate2_isolation/` and
`evidence/sandbox/docker_sandbox_probe.json` were generated on
2026-11-16 (commit `9daf61f`). They are kept as a historical record and
are **not** current qualification evidence:

- the attestation expired at `2026-11-16T08:41:42Z` (one-hour lifetime);
  it verifies only with an explicit `at_time` inside that window;
- they predate commit `22b2f37` (2026-11-18), which changed how sandbox
  containers are launched and cleaned up;
- the signed policy digest is the schema-1, hand-written policy, which
  stated `pids_limit: 128` while the receipt shows `docker:pids_limit:64`;
  it is not the digest of the policy the executor now derives from its
  launch flags;
- the run used the default runtime (runc) and Docker's default seccomp
  profile, so `kernel:gvisor` and `syscalls:seccomp_allowlist` were never
  attested.

`evidence/sandbox/gate2_isolation/freshness.json` records the same
verdict with the SHA-256 of each stored file, and
`tests/v3/test_gate2_qualification.py` fails if the stored policy digest
stops matching the current launch policy without a `stale` record.
No new evidence was generated for SIS-FEAT-16: the session that built it
had no Docker daemon or gVisor. Fresh evidence comes from the
`sandbox-qualification` CI job (below) or from the commands in
"Regenerating the evidence".

Stored digests (2026-11-16):

| Item | Digest |
| --- | --- |
| Evaluator image | `sis-evaluator:3.3.9@sha256:2c10724de03d141f69f3cf8ad41e5cecb3cd4ed443c141a73b2278dfb142f30c` |
| Policy digest (schema 1, hand-written) | `f244ee64210fd9fe911c3fb8480443cf86d23641f785248d4c886194f24d0b25` |
| Receipt digest | `db04044efb31ec9964f2fbf69ed641175f5fcac4fa98a5d99f0a29b28c31a3be` |
| Attestation digest | `70828824d445100b3a80a84e0e0e0ab86c85c1be048770c46be4654084fc85ee` |
| Signer | `gate2-local-isolator`, public key `858508bd…1f14` (`key-9e450240da77f8dd10272d81`), trust root `qualification-only` |
| Probe | 13/13, Docker server 29.9.3, generated `2026-11-16T07:41:41Z` |

## The qualification path (SIS-FEAT-16)

**Policy derived from the launch.** `DockerSandboxExecutor.launch_flags()`
builds the security-relevant `docker run` flags. The same method, called
with placeholders, builds the policy document
(`launch_policy()`, digest `policy_digest()`), so the signed policy and
the real launch cannot drift. The policy names the flag template, the
ceilings the per-run values never exceed, the runtime and the seccomp
profile by SHA-256; host-specific values (paths, numeric principals) are
placeholders, so one image and configuration has one digest on every
host. Each receipt carries `docker:policy:<digest>`,
`docker:runtime:<runtime>` and `docker:seccomp_profile:<sha256>`, and
`qualify_docker_isolation.py` writes `policy.json` beside the receipt and
refuses to sign a digest the receipt does not name.
`tests/v3/test_sandbox_launch_policy.py` checks that the rendered policy
equals the argv a recording fake Docker CLI received.

**gVisor and an allowlist seccomp profile.** A production executor
(`production=True`) requires `runtime="runsc"` (`--runtime runsc`) and a
seccomp profile, passed as `--security-opt seccomp=<executor-owned copy>`.
`docker/sandbox/seccomp.json` denies by default (EPERM). It is derived
by `tools/derive_sandbox_seccomp.py` from Moby's v27.3.1 default profile
(pinned by SHA-256): the unconditional allowlist minus kernel AIO,
handle-based opens, POSIX/SysV message queues, `vmsplice`, clock
adjustment, the 32-bit `socketcall`/`ipc` multiplexers and identity
changes (`setuid` family); no capability-gated rule (mount, ptrace,
bpf, namespaces, keyrings, module loading) is carried over; `socket` is
limited to `AF_UNIX`/`AF_INET`/`AF_INET6`, `clone` may not create
namespaces and `clone3` returns ENOSYS. The kept protections are
unchanged: `--cap-drop ALL`, `no-new-privileges`, read-only root,
`--network none`, a non-root user and the pids, memory, CPU-time,
descriptor, disk and output limits. The probe adds `kernel_gvisor`
(`/proc/version` carries gVisor's fixed build string
`#1 SMP Sun Jan 10 15:06:54 PST 2016`) and `seccomp_filter_active`
(`Seccomp: 2`). The required production properties
(`sis.v3.docker_sandbox.PRODUCTION_PROPERTIES`) add `kernel:gvisor` and
`syscalls:seccomp_allowlist`; the qualification tool claims each only
when the receipt shows the matching launch, and `check_release_ci.py`
refuses a release property set that omits any of them.

**Red team.** `tools/redteam_sandbox.py` runs seventeen hostile payloads
and a health check, each with one expected outcome: fork, memory and
disk bombs and oversized output must be stopped by a limit; sleeping
forever by the wall clock; TCP, UDP and DNS egress, runtime sockets,
setuid, ptrace, mount/unshare, signalling foreign processes, `/proc` and
`/sys` writes and host environment/credential reads (with a host-side
canary) must fail; symlink and hard-link escapes must be refused by the
copy-out. The JSON report becomes part of the qualification record
(`--redteam-report`, bound by SHA-256) and the tool exits non-zero on any
unexpected outcome.

**CI.** The `sandbox-qualification` job in `.github/workflows/ci.yml`
installs gVisor from a pinned release (`20261026.0`, SHA-512 verified),
registers it with `--oci-seccomp` (without it runsc ignores the profile),
builds and digest-pins the image, then runs the probe, the red-team
suite and the qualification with a generated `qualification-only` key,
uploads the evidence and fails on any regression. This keeps self-signed
evidence current; it is not independent sign-off.

## Regenerating the evidence

On a Linux host with Docker and runsc registered as a runtime
(`tools/configure_docker_runsc.py`):

```bash
IMAGE=sis-evaluator:3.3.9@sha256:<digest>
PYTHONPATH=src python3 tools/probe_docker_sandbox.py --image "$IMAGE"
PYTHONPATH=src python3 tools/redteam_sandbox.py --image "$IMAGE" \
  --output evidence/sandbox/redteam_report.json
PYTHONPATH=src python3 tools/qualify_docker_isolation.py --image "$IMAGE" \
  --probe-report evidence/sandbox/docker_sandbox_probe.json \
  --redteam-report evidence/sandbox/redteam_report.json \
  --output evidence/sandbox/gate2_isolation
```

Remove `freshness.json` only when the regenerated files replace the
stale ones.

## History

"What ran", "Evidence" and the dated sections at the end record earlier
qualification runs (2026-11-14 to 2026-11-18). Their digests are
historical; the stored files are the 2026-11-16 run listed above.

## What ran (2026-11-14 qualification)

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
relying party's copy remains an out-of-band step; the ritual is below.

## Isolator key custody and fingerprint check

Independent sign-off needs an isolator key that never touches the
evaluated machine or this repository.

**Who holds what.**

- The **isolator operator** (a person other than the release engineer,
  or at minimum a separate cloud account) holds the 32-byte isolator
  seed on a dedicated isolator host. The seed never leaves that host: it
  is not copied to CI, to a developer machine or into `evidence/`.
  `tools/issue_worker_attestation.py` runs there, on receipts handed to
  it, and refuses a seed file readable by anyone else.
- The **relying party** (the repository maintainers) holds only the
  public key, stored as the `SIS_ISOLATOR_PUBLIC_KEY` secret together
  with the pinned `SIS_ISOLATION_IMAGE_DIGEST`,
  `SIS_ISOLATION_POLICY_DIGEST` and `SIS_ISOLATION_PROPERTIES` variables.

**Fingerprint ritual** (on enrolment and on every key rotation):

1. On the isolator host, the operator prints the fingerprint from the
   seed: `python3 tools/isolator_key_fingerprint.py --seed-file
   /secure/isolator.seed`. The output is the key id
   (`key-` + the first 24 hex digits of SHA-256 over the raw public key,
   the encoding the evaluator key ids use), the full SHA-256 in sixteen
   groups, and the public key hex. The seed is never printed.
2. The operator sends the public key hex to the maintainers over one
   channel (for example the pull request or an e-mail).
3. A maintainer computes the fingerprint of the key they received:
   `python3 tools/isolator_key_fingerprint.py --public-key <hex>`.
4. Over a second, independent channel (a call or an in-person check, not
   the channel used in step 2), the operator reads the sixteen groups
   aloud and the maintainer compares them group by group. Scripted
   checks use `--expect <key id or sha256>`, which exits non-zero on a
   mismatch.
5. Only after a match does the maintainer store the key as
   `SIS_ISOLATOR_PUBLIC_KEY`. Both record the date, the key id and the
   two channels in the release notes of the next release.

A mismatch, or any doubt about the channel, means the key is not
trusted: generate a new seed on the isolator host and repeat. Expiry and
re-attestation rules are in
[RELEASE_PROCESS.md](RELEASE_PROCESS.md#isolation-re-attestation-policy).

## What this does not claim

- The signing key is local (`gate2-local-isolator`, trust root
  `qualification-only`). A production seal needs an isolator key held
  independently of the evaluated machine.
- `--trust-root production` requires `--seed-file` and refuses to
  generate a key on the evaluated machine. Supplying a seed is not the
  same as independent custody: the signer public key must still be
  verified against a key held by the relying party.
- `release/provenance.intoto.json` remains unsigned.
- The probe and red-team suite are factual launch evidence; they do not
  prove the absence of a host-kernel or gVisor vulnerability.
- No gVisor run has been recorded in this repository yet; the first
  evidence will come from the `sandbox-qualification` CI job.
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

## Rebuild at the canonical fingerprint seal (2026-11-16)

The image was rebuilt from the pinned Dockerfile after the canonical
fingerprint and study-kit repairs. The current image and policy digests
are recorded in `release/release_manifest.json`; the digest in the
sections above describes the 2026-11-14 qualification. The probe again
passed 13/13 checks, the fresh attestation verified, and the real
container denied the private tests.

## Executor changes after the stored evidence (2026-11-18)

These change how containers are started and cleaned up, not the
launch controls the probe checks; the stored probe, receipt and
attestation predate them and have not been regenerated.

- Sandbox containers start with `--rm` and the label
  `sis.v3.sandbox=<worker identity>`, so a container leaked by a crashed
  evaluator can be listed and removed
  (`docker ps -aq --filter label=sis.v3.sandbox`).
- A workspace path containing a comma is refused
  (`workspace_path_unrepresentable`) instead of being passed to
  `--mount`, which has no escaping.
- Background processes left by the command are killed (`kill -9 -1` as
  each run principal) before the workspace is copied out.
- The split-custody worker runs as `python3 -I`, so a workspace module
  cannot shadow the worker's own imports.
- Shared-custody (`/private` mount) receipts carry
  `custody:shared_unqualified`; only split custody is qualification-grade.
