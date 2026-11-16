# SIS v3.3.9 qualification report

Status date: 2026-11-14. Branch: `repair/v335-resource-security`.

## Status

`ENGINEERING_VERIFIED`, qualification-only. The release gate, test
evidence and isolation evidence are cryptographically bound, but the
stored trust roots are local. A production seal still requires three keys
held independently of the evaluated machine:

- a release provenance key;
- a CI test-evidence key; and
- an isolator key.

Until that key ceremony is completed, `tools/check_release_ci.py --mode
release` must reject this bundle. The learning workflow is unchanged; its
general effectiveness remains unproven.

## Re-seal: canonical fingerprint repair (2026-11-16)

The archive was re-sealed over the canonical repository fingerprint and
lineage repair. Repository identity now uses the working tree and
excludes VCS metadata, so clones of one revision share a snapshot
digest. `release/release_manifest.json` records the source commit and
archive digest.

Test evidence is the executed suite at that commit, recorded in
`release/test_evidence.json`; `release/release_manifest.json` records
the counts, source commit and archive digest. The Docker containment
probe passed 13/13 checks; the fresh isolation attestation verifies
against the image and policy digests recorded in the manifest and a
locally generated qualification-only isolator key. Every out-of-band
file matches `release/SHA256SUMS`; `verify_release.py` accepts the ZIP.

The trust roots remain local. `check_release_ci.py --mode release`
rejects the bundle with `release provenance trust root is not
production`. A production seal still requires independently held
release, CI-evidence and isolator keys.

### Re-seal test matrix

Snapshot at the first re-seal (2026-11-16). Later test additions change
these counts; `release/test_evidence.json` is authoritative for the
shipped seal.

| Environment | Command | Result |
| --- | --- | --- |
| macOS 3.12, Docker + PostgreSQL | `tools/run_tests.py --json ...` | 1703 passed, 7 skipped |
| macOS 3.12, Docker enabled, no PostgreSQL | `pytest tests/ -q` | 1695 passed, 15 skipped |
| macOS 3.10, Docker disabled | `DOCKER_HOST=unix:///nonexistent/docker.sock pytest tests/ -q` | 1672 passed, 38 skipped |
| macOS 3.13, Docker disabled | same | 1672 passed, 38 skipped |
| Linux 3.12 (`sis-evaluator:3.3.9`), no git/Docker/PostgreSQL | same | 1654 passed, 56 skipped |
| Linux 3.12 with git, no Docker/PostgreSQL | same | 1657 passed, 53 skipped |
| Docker containment | `pytest tests/v3/test_docker_sandbox.py tests/v3/test_split_custody.py -q` | 72 passed |
| PostgreSQL 14 concurrency | `pytest tests/v3/test_control_plane_postgres.py -q` | 8 passed |

The remaining skips are platform-specific and enumerated in each run
(Windows ACL, seatbelt, cgroup v2, missing vskill corpus, absent pinned
Git baseline, optional z3/cryptography dependencies, and non-UTF-8
filename support). No failure was left unexplained.

## What changed

v3.3.9 closes the release-authenticity, evidence-authentication and
hard-limit findings from the build-11 review. It does not add a learning
feature.

- Release mode requires the release manifest, the claimed ZIP, a
  byte-exact source-tree binding, signed production provenance,
  authenticated test evidence and a re-verified raw isolation
  attestation.
- Test evidence records the exact command, exit status, output digest and
  parsed counts; a fabricated count, a narrowed command, a truncated
  output or an unsigned report is rejected.
- The release manifest carries the raw receipt, signed attestation and a
  fresh verification record under `release/`; the gate re-runs
  `verify_production_isolation()` against the relying party's key and
  pinned image/policy digests.
- `induce(..., hard_limits=...)` routes through the enforced subprocess
  runner, with a parent monotonic deadline, `RLIMIT_AS`, optional
  `RLIMIT_CPU`/`RLIMIT_NPROC`, a signed resource receipt and a
  `resource_exhausted` result that can never be a pass.
- The local runner and Docker sandbox bound process-group termination and
  mark an execution that exits after the parent deadline as a timeout.

## Test matrix (original seal, 2026-11-14)

| Environment | Command | Result |
| --- | --- | --- |
| macOS 3.12, Docker enabled | `pytest tests/ -q` | 1587 passed, 14 skipped |
| macOS 3.10, Docker disabled | `DOCKER_HOST=unix:///nonexistent/docker.sock pytest tests/ -q` | 1552 passed, 37 skipped |
| macOS 3.13, Docker disabled | same | 1552 passed, 37 skipped |
| Linux 3.12 (`python:3.12-slim`), Docker disabled | same | 1536 passed, 53 skipped |
| Linux 3.12 with Docker | `pytest tests/v3/test_docker_sandbox.py tests/v3/test_split_custody.py -q` | 62 passed, 10 skipped |
| PostgreSQL 16 | `SIS_POSTGRES_DSN=... pytest tests/v3/test_control_plane_postgres.py tests/v3/test_control_plane_sqlite.py -q` | 14 passed |
| SQLite persistence/replay/recovery | `pytest tests/v3/test_authority_db.py tests/v3/test_authority_recovery.py tests/v3/test_authority_checkpoints.py tests/v3/test_episode_replay.py tests/v3/test_control_plane_sqlite.py -q` | 65 passed |
| Z3-enabled profile | `pytest tests/v3/test_v336_benchmark_semantics.py tests/test_system.py -q` | 39 passed |
| Windows 11 | not run | explicitly experimental |
| Clean extracted ZIP | `verify_release.py --compile`, `--source`, smoke test | recorded in `release/verification.json` |

The Linux-with-Docker run used a Linux Python 3.12 container with the
host Docker socket and a shared `TMPDIR`, so bind-mount source paths were
valid on both sides. It exercised the real evaluator image, not a Docker
CLI double.

## Sandbox evidence

| Check | Result |
| --- | --- |
| Evaluator image | `sis-evaluator:3.3.9@sha256:5af4f6ceed7041f1665fdb077708c9b8fdd71cedf451e0adbfb0490e5e914466` |
| Containment probe | 13/13 |
| Policy digest | `2cce5dcb68cedcc27f7f5b95b2d85d227d13455281a5a1dfb1312fc94168a050` |
| Receipt digest | `f89dd405ad83ae571a4fab74d42e510a1c0103df58022ee0180186de542567a7` |
| Attestation verification | `ok` |
| Trust root | `qualification-only` |
| Real-container split custody | worker denied the private tests; reload keeps `custody="split"` |

The probe covers network denial, read-only root, workspace write,
non-root execution, Docker-socket absence, `no-new-privileges`, dropped
capabilities, `setuid` denial, and memory, pids, disk, CPU-time and output
limits. It is factual launch evidence, not a proof against a privileged
kernel attacker.

## Adversarial regression matrix

The following scenarios are covered by executable tests:

| Scenario | Result |
| --- | --- |
| Delete release metadata | release mode rejects |
| Supply a valid signature for the wrong archive | rejects |
| Change one archive member | rejects |
| Forge `"verified": true` | rejects (raw attestation is re-verified) |
| Supply an invalid external public key | rejects |
| Replay an expired attestation | rejects |
| Supply a fabricated test count | rejects |
| Rename a fake command to include pytest | rejects (strict command shape) |
| Use a receipt from another execution/image | rejects |
| Read hidden acceptance files from the worker | denied (split custody) |
| Exceed a hard wall-clock deadline | terminates, records timeout |
| Exceed the disk-copy-out budget | rejects, preserves workspace |
| Attempt workspace path substitution | rejects |
| Reuse a consumed evaluation nonce | rejects (control-plane tests) |
| Revoke previously qualified evidence | stops serving affected guidance (revocation cascade tests) |

## Known gaps

- Windows remains experimental; the evaluator runtime relies on POSIX
  process semantics.
- The stored isolation attestation is signed by a local qualification key.
  It is not a production security certification.
- The learning workflow functions, but the efficacy study described in
  the repair plan has not been completed. Do not claim a general coding
  improvement until it is. Phase 6 is scaffolded in
  [EFFICACY_STUDY_PROTOCOL.md](EFFICACY_STUDY_PROTOCOL.md) with a
  manifest template and validator; the real-agent gate executes a
  validated manifest, but no preregistered manifest exists on the
  development host, so no confirmatory run has been executed.
- The Linux-with-Docker run used the host Docker daemon through a mounted
  socket; the CI workflow remains the canonical native-Linux run.
