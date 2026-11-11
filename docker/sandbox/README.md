# Docker evaluator sandbox

Build the evaluator image (the tag is for development; production must
pin the base image and the resulting image by digest):

```bash
docker build --platform linux/arm64 -t sis-evaluator:3.3.8 docker/sandbox
```

Run the containment probe:

```bash
PYTHONPATH=src python3 - <<'PY'
import json, tempfile
from pathlib import Path
from sis.v3.docker_sandbox import DockerSandboxExecutor

root = Path(tempfile.mkdtemp(prefix="sis-docker-probe-"))
executor = DockerSandboxExecutor(
    root / "exec", image="sis-evaluator:3.3.8",
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
non-root execution, memory limit and pids limit. The tool aborts before
evaluating if any check fails.

## What this is not

The receipt markers (`isolation:docker_sandbox`, `docker:*`) are factual
launch controls. They are not a signed containment proof. Production
qualification still requires a digest-pinned image and an
`IsolationAttestationV1` from a separately trusted isolator.
