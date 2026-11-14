# SIS v3.3.8 Qualification Report

Status: `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
This release moves evaluator execution of untrusted submitted code into a
Docker sandbox and records factual containment probes. The evaluator image
is digest-pinned and a signed `IsolationAttestationV1` verifies against
its policy, but the signing key is local (trust root `qualification-only`):
production still requires an isolator key held independently of the
evaluated machine. See
[docs/v3/SANDBOX_QUALIFICATION_GATE2.md](SANDBOX_QUALIFICATION_GATE2.md).

## What changed

| Item | Scope | Evidence |
| --- | --- | --- |
| V338-01 | New `sis.v3.docker_sandbox.DockerSandboxExecutor` implements the `WorkspaceExecutor` protocol: no network, read-only root, quota-limited tmpfs workspace fed from a read-only `/submission` bind, tmpfs `/tmp`, non-root uid, `cap-drop ALL`, `no-new-privileges`, memory/pids/CPU-time/disk bounds, capped output, wall-clock kill. | `src/sis/v3/docker_sandbox.py`, `tests/v3/test_docker_sandbox.py` |
| V338-02 | `tools/learn_recommend_cycle.py --sandbox docker` runs every evaluator acceptance test inside the sandbox and aborts if the containment probe fails. | `tools/learn_recommend_cycle.py`, `evidence/qualification/learn_cycle_live_docker.json` |
| V338-03 | `docker/sandbox/Dockerfile` builds the evaluator image with the pinned test runner and an unprivileged user. | `docker/sandbox/Dockerfile` |
| V338-04 | Containment probe evidence: network denied, root write denied, workspace write allowed, non-root user, Docker socket absent, no-new-privileges, capabilities dropped, setuid denied, memory limit enforced (exit 137), pids limit enforced, disk quota enforced, CPU-time budget enforced, combined output cap enforced. | `evidence/sandbox/docker_sandbox_probe.json` |

## Docker-backed cycle

The live cycle was repeated with `--sandbox docker`:

- dev `task-money` and `task-money2`: pass;
- procedure `exp-exp-money`: qualified, cites both receipts;
- holdout `task-money3`: `recommend`;
- control `task-slug2`: `abstain`, `precondition_failed`;
- holdout without guidance: `fail`, `no_action: true`;
- holdout with guidance: `pass`, `no_action: false`.

Every evaluator run was executed in `sis-evaluator:3.3.7` (image id
`76873b68…`, the same image content later tagged `3.3.8`) under
`--network none`, a read-only root, a quota-limited tmpfs workspace, a
tmpfs `/tmp`, the host non-root uid, `--cap-drop ALL`,
`no-new-privileges`, and memory/pids/CPU-time bounds. Receipts carry
`isolation:docker_sandbox` and the individual control markers.

The image is tag-only in this development run; receipts carry
`docker:image_tag_only`. Production requires a digest-pinned image and a
signed isolation attestation; the Docker receipt markers are factual
launch controls, not a containment proof.

## Test result at the original seal

Environment: Python 3.12.0 on macOS arm64, pinned `pytest==8.4.2`,
`z3-solver==4.16.0`, Docker Desktop 4.99.0 / engine 29.9.3,
`PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONNOUSERSITE=1`,
`PYTHONPATH=src`.

- **1396 passed, 13 skipped, 0 failed.**
- The Docker integration tests skip when the daemon or
  `sis-evaluator:3.3.8` is unavailable; the construction tests always
  run.
- Skips: 8 PostgreSQL (`SIS_POSTGRES_DSN` not configured), 2 Windows ACL,
  1 missing `cryptography`, 1 cgroup v2, 1 pinned Git baseline, 1 missing
  vskill corpus.

## What remains unqualified

- **Production sandbox.** The Docker controls are enforced by the Docker
  daemon, but the receipt is self-reported. Production requires an
  independent isolator's signed attestation, a digest-pinned image, and
  key custody outside the evaluated workload.
- **Efficacy.** The cycle remains n = 1 per condition; a powered,
  repository-disjoint, preregistered study is still required.
- The lesson is supervised capture, and the failure class is declared by
  the fixture at task registration.
- Provenance is unsigned unless an externally trusted release key is
  supplied.

## Post-seal repair (2026-11-11)

The workspace-ownership and sandbox-limit repair changed the
implementation this report describes. A `Workspace` handle is now
resolved through a backend registry, and the Docker workspace is a
quota-limited tmpfs with a read-only `/submission` bind, a copy-in before
the command and a filtered copy-out afterwards. The probe now observes
thirteen checks, records a digest-pinned image, `environment_digest` is
domain version 2, and the copy-out has a drained stderr and a watchdog.
The archive was re-sealed after that repair; see `release/README.md` for
the current digest and `evidence/sandbox/docker_sandbox_probe.json` for
the refreshed probe.

The repair was re-sealed twice. The first re-seal ran with a working
Docker daemon and recorded the same 1396 passed / 13 skipped. The second
re-seal ran after the daemon's metadata store went read-only (an
environment failure, not a code change), so `_docker_ready()` skipped the
15 Docker integration tests instead of failing them and the run recorded
**1381 passed, 28 skipped, 0 failed**. The skip is the documented
contract; the Docker-backed cycle evidence above still comes from the
working run.

## Post-seal evidence refresh (2026-11-14)

The post-seal repairs (Gate 2 containment, process-split custody, worker
split configuration, custody durability) changed the executor and the
verifier. The Docker probe and attestation were regenerated over the
current tree:

- image `sis-evaluator:3.3.8@sha256:27415edf…`, Docker 29.9.3,
  `production=True`;
- probe 13/13 checks pass; no `docker:image_tag_only`;
- `IsolationAttestationV1` verified (`reason: ok`); the negative control
  is rejected (`image_mismatch`);
- real-container split custody: the worker UID is denied the private
  tests, and a task reloaded in the worker child keeps `custody="split"`;
- suite: **1490 passed, 13 skipped, 0 failed.**

The trust root remains `qualification-only`. This refresh binds the
evidence to the current source and image; it does not replace an
isolator key held independently of the evaluated machine. See
[SANDBOX_QUALIFICATION_GATE2.md](SANDBOX_QUALIFICATION_GATE2.md).
