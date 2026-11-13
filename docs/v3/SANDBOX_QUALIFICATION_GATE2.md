# Gate 2 — Docker sandbox qualification

Status date: 2026-11-13. Branch: `integration/gate2`.

This records live containment evidence for the Docker evaluator sandbox.
It is engineering evidence, not a production security certification: the
attestation is signed by a locally held qualification key, not by an
isolator trusted independently of this machine.

## What ran

| Check | Result |
| --- | --- |
| Base image | `python:3.12-slim@sha256:5e2bdb1b…` (index digest pinned in the Dockerfile) |
| Evaluator image | `sis-evaluator:3.3.8@sha256:71dddad6…` |
| Docker server | 29.9.3, linux/aarch64 |
| Containment probe, `production=True` | 13/13 checks pass |
| Execution receipt | `isolation:docker_sandbox`; no `docker:image_tag_only` |
| `IsolationAttestationV1` | verified (`reason: ok`) |
| Negative control (wrong image digest) | rejected (`image_mismatch`) |
| Full suite with Docker available | 1413 passed, 13 skipped, 0 failed |

The probe checks network denial, read-only root, workspace write, non-root
user, Docker-socket absence, `no-new-privileges`, dropped capabilities,
`setuid` denial, memory, pids, disk, CPU-time and output limits.

## Evidence

`evidence/sandbox/docker_sandbox_probe.json` — the 13-check probe result.
`evidence/sandbox/gate2_isolation/` — the execution receipt, the signed
attestation and the qualification record (policy digest, public key,
verification result). The isolator seed is never written into the
evidence directory.

The policy digest binds the launch controls the executor enforces; the
attestation binds the receipt, worker identity, policy and image. See
`tools/qualify_docker_isolation.py` to reproduce.

## What this does not claim

- The signing key is local (`gate2-local-isolator`, trust root
  `qualification-only`). A production seal needs an isolator key held
  independently of the evaluated machine.
- `release/provenance.intoto.json` remains unsigned.
- The probe is factual launch evidence; it does not prove kernel
  enforcement against a privileged attacker.
- Windows and the desktop GUI are still unqualified.
