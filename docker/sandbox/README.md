# Docker evaluator sandbox

The Dockerfile pins its base image by index digest
(`python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`,
resolved 2026-11-12), so a rebuild cannot silently pick up different base
bytes. Build the evaluator image (the tag is for development; production
must also pin the resulting image by digest and record it in the isolation
policy):

```bash
docker build --platform linux/arm64 -t sis-evaluator:3.3.9 docker/sandbox
```

Run the containment probe:

```bash
PYTHONPATH=src python3 - <<'PY'
import json, tempfile
from pathlib import Path
from sis.v3.docker_sandbox import DockerSandboxExecutor

root = Path(tempfile.mkdtemp(prefix="sis-docker-probe-"))
executor = DockerSandboxExecutor(
    root / "exec", image="sis-evaluator:3.3.9",
    require_image_digest=False)
print(json.dumps(executor.probe(), indent=2))
PY
```

Run the full cycle with the sandboxed evaluator:

```bash
PYTHONPATH=src:. python3 tools/learn_recommend_cycle.py \
  --agent codex --sandbox docker --wall 150 -o /tmp/cycle.json
```

The probe checks network denial, read-only root, workspace write,
non-root execution, Docker-socket absence, `no-new-privileges`,
dropped capabilities, `setuid` denial, memory limit, pids limit, disk
quota, CPU-time budget and combined output cap. The tool aborts before
evaluating if any check fails.

The workspace is a quota-limited tmpfs inside the container. The host
process archives the prepared workspace and streams it into the tmpfs
before the command runs (the host tree is never bind-mounted, so the
copy-in works whatever its host ownership, also when the evaluator runs
as root and the container user is 65534), and it is copied back through
a filtered tar stream afterwards. The copy-out archive is extracted with `filter="data"`, so
absolute paths, `..` escapes, device nodes and links that leave the
workspace are rejected. A run that is stopped by the wall clock, the
output cap or pids exhaustion reports `fs:workspace_state_unavailable`
rather than presenting the pre-run tree as final; a successful run whose
tree cannot be collected fails with `workspace_copy_out_failed`.

The probe also pins the descriptor budget as
`docker:ulimit_nofile:<n>`; `nofile_limit` is a constructor parameter
(default 1024), not a fixed cap.

## Production runtime: gVisor and the allowlist seccomp profile

A production executor (`production=True`) requires `runtime="runsc"`
and `seccomp_profile=docker/sandbox/seccomp.json`; it launches with
`--runtime runsc` and `--security-opt seccomp=<executor-owned copy>`.
Register runsc with Docker with `--oci-seccomp`, or gVisor ignores the
profile:

```bash
sudo python3 tools/configure_docker_runsc.py --runsc /opt/gvisor/runsc
sudo systemctl restart docker
```

`seccomp.json` is derived, not hand-edited: `tools/derive_sandbox_seccomp.py`
starts from Moby's v27.3.1 default profile (pinned by SHA-256), removes
the syscalls a Python test workload never needs (each listed with its
reason in the tool's `REMOVED` table), keeps no capability-gated rule,
and restricts `socket`, `personality` and `clone` by argument. Regenerate
or check it with the pinned upstream file:

```bash
curl -sSfL -o /tmp/moby-default.json \
  https://raw.githubusercontent.com/moby/moby/v27.3.1/profiles/seccomp/default.json
python3 tools/derive_sandbox_seccomp.py --upstream /tmp/moby-default.json --check
```

Without `--upstream`, the tool only checks the committed profile's
invariants (deny by default; no `ptrace`, `mount`, `unshare`, `bpf`,
keyring or module syscalls). Any change to the profile changes the
policy digest, so earlier attestations stop verifying.

## What this is not

The receipt markers (`isolation:docker_sandbox`, `docker:*`) are factual
launch controls. They are not a signed containment proof. Production
qualification still requires a digest-pinned image and an
`IsolationAttestationV1` from a separately trusted isolator.
