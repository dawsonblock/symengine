# Exploratory pilot runbook (Track B7)

The pilot is an **exploratory** A-vs-E study with Claude Code: 6–8
holdout repositories, about 10 induction repositories, about 100 tasks,
Docker split custody, and per-arm budgets of 900 s, 150k tokens and 100
tool calls. It estimates the effect, its interval, the intra-repository
correlation, the cost per task and the negative-transfer rate, then sizes
a confirmatory study. An exploratory manifest can never be labelled
confirmatory. The protocol is in `EFFICACY_STUDY_PROTOCOL.md`.

Everything below runs from the repository root on a Linux host. Each
step is a command to run as written once the `<placeholders>` are filled.

## 0. Host

```bash
claude --version                       # pin this in both spec files
docker build -t sis-evaluator:3.3.9 docker/sandbox
docker image inspect sis-evaluator:3.3.9 --format '{{json .RepoDigests}}'
export PYTHONPATH=$PWD/src
mkdir -p /study/{repos,private,imports,state,keys,prereg,reports} && chmod 700 /study
cp docs/v3/pilot_study_spec_template.json /study/spec.json
cp docs/v3/pilot_learning_spec_template.json /study/learning.json
```

- The runner defaults to the pinned
  `sis-evaluator:3.3.9@sha256:5af4f6ce…` image. If your build has a
  different digest, pass `--docker-image <name>@sha256:<digest>`
  everywhere below (a registry-pushed reference). A local tag without a
  digest needs `--allow-unpinned-image` and is development-only.
- Once Track C lands the gVisor runtime, add `--docker-runtime runsc`.
- The evaluator image carries pytest only. Pick repositories whose tests
  run with the standard library and pytest, or use the test-dependency
  variant below; importer verification under Docker rejects the rest.
- The evaluator may run as root or as a dedicated user. On a root host
  the container user defaults to 65534:65534; the workspace is streamed
  into the container, so host ownership does not matter.

### Test-dependency image variant

`docker/sandbox/Dockerfile.testdeps` builds `sis-evaluator:3.3.9-testdeps`:
the same pinned base, user (65534), `HOME=/tmp` and `/workspace` layout,
the same pytest lock, plus `docker/sandbox/requirements-testdeps.lock`
(hypothesis, pytest-mock, pytest-timeout, freezegun, pyyaml, toml and
their dependencies, installed with `--require-hashes --only-binary=:all:`;
no nose, which does not import on Python 3.12). Use it only for a study
whose repositories need those libraries, and use one image for every arm.

```bash
docker build -f docker/sandbox/Dockerfile.testdeps \
  -t sis-evaluator:3.3.9-testdeps docker/sandbox
id="$(docker image inspect --format '{{.Id}}' sis-evaluator:3.3.9-testdeps)"
echo "sis-evaluator@${id}"          # image-ID pin, works without a registry
docker tag sis-evaluator:3.3.9-testdeps localhost:5000/sis-evaluator:3.3.9-testdeps
docker push localhost:5000/sis-evaluator:3.3.9-testdeps
docker image inspect sis-evaluator:3.3.9-testdeps --format '{{json .RepoDigests}}'
```

Pass either pin as `--docker-image` everywhere below, for example
`localhost:5000/sis-evaluator:3.3.9-testdeps@sha256:<digest>` (a registry
host with a port is accepted). Then probe it once as the user that will
run the pilot, and keep the JSON with the pilot notes:

```bash
python3 tools/probe_docker_sandbox.py --image <pinned ref> \
  --runtime runc --output /study/reports/probe-testdeps.json
```

Drop `--runtime runc` once gVisor is installed (runsc is the tool's
default). The probe must report `"ok": true` with the same checks as the
base image. On a host whose egress goes through a TLS-intercepting proxy, build
from a scratch copy of `docker/sandbox` whose Dockerfile copies the
proxy CA to `/tmp/proxy-ca.crt` and runs the `pip install` with
`PIP_CERT=/tmp/proxy-ca.crt` (`docker build --network host
--build-arg HTTPS_PROXY=$HTTPS_PROXY`); the `rm -rf /tmp/*` step removes
it from the final filesystem. Never commit the CA or that Dockerfile.
To change a pin, resolve the wheels for CPython 3.12 on x86_64 and
aarch64 with `pip download --only-binary=:all: --python-version 3.12
--platform manylinux2014_<arch>`, check each `sha256` against PyPI, and
keep every line hashed.
- The agent runs as your user and can read files outside its workspace.
  Run the pilot as a user that cannot read `/study/private` and
  `/study/repos` other than through SIS, or on a host where those paths
  are not discoverable, and say which in the pilot notes.

## 1. Repositories

Clone each candidate with its full history and leave the checkout at the
commit the study is frozen at (`HEAD` becomes the repository's
`base_commit`; every task commit must be an ancestor of it):

```bash
git clone <url> /study/repos/<id>
git -C /study/repos/<id> checkout --detach <frozen commit>
```

Holdout and induction repositories must be different codebases: no
shared Git history (the validator compares root commits) and no copies.

Screen the candidates before importing them. Docker grading is slow,
and many correct upstream fixes are rejected for reasons a static scan
predicts:

```bash
python3 tools/screen_study_repos.py --repo /study/repos/<id> \
  --repo /study/repos/<id2> -o /study/diag/screen.json
# add an empirical rate on the first N fix candidates (Docker, slow):
#   --sample 6 --docker-image <pinned ref>
```

Run it as the user that owns the clones (Git refuses a checkout another
user owns). For each repository it reports the layout and package
names, the third-party test imports that the base image and the
`-testdeps` variant lack, and patterns split custody cannot grade: a
test-defined function, lambda, class or instance passed into the
package (`key=`, callbacks), a package decorator on a test function, a
test class subclassing a package class, `pickle`/`copy` of a package
object, `monkeypatch.setattr`/`mock.patch` on the package, data files
read beside the tests, and APIs Python 3.12 or pytest 8 removed
(`assertEquals`, `assertRaisesRegexp`, nose `setup`, `yield` tests).
The verdict (`likely`, `partial`, `unlikely`, for each image) rests on
the share of the first ten fix candidates (`--candidates`) whose test
file, at its fix commit, shows none of these, or on the test modules at
HEAD when there are fewer than three candidates. It is a heuristic, not
a verdict on any task: only `import_study_tasks.py --verify docker`
decides. Prefer `likely` repositories, check `partial` ones with
`--sample`, and record the screen with the pilot notes.

On the pilot clones (2026-11-20) the screen gave inflection `likely`
(6/6 candidates clean; Docker accepted 4/6), cachetools `unlikely` (0/10
clean: package decorators on test functions, subclassing, callbacks;
Docker 0/8) and jmespath `unlikely` (1/10 clean: hypothesis, nose-era
APIs, subclassing, data files; Docker 0/8).

## 2. Tasks

Holdout tasks (about 12–15 per holdout repository, into the study spec):

```bash
python3 tools/import_study_tasks.py --repo /study/repos/<id> \
  --repository-id <id> --partition holdout \
  --hidden-dir /study/private/<id> --max-tasks 15 \
  --verify docker --merge-into /study/spec.json -o /study/imports/<id>.json
```

Induction tasks (into the learning spec; about 6 training and 4
qualification repositories):

```bash
python3 tools/import_study_tasks.py --repo /study/repos/<id> \
  --repository-id <id> --partition induction \
  --learning-split training \
  --hidden-dir /study/private/<id> --max-tasks 10 \
  --verify docker --merge-into /study/learning.json -o /study/imports/<id>.json
# the same with --learning-split qualification for the qualification repositories
```

Each fragment lists the accepted tasks (base fails, fix passes) and the
rejected commits with reasons. `--prompt-file issues.json` replaces
commit messages with issue text. Then fill the ten induction entries of
`/study/spec.json` with the same paths as the learning spec, set
`protocol.sample_size` to the imported task count (at least 100 for the
template's power plan), and fill `agent` and `preregistration`.

## 3. Trust anchors and keys

```bash
python3 tools/build_guidance_bundle.py --print-public-keys \
  --evaluator-key-dir /study/keys/evaluator \
  --operator-key-dir /study/keys/operator > /study/keys/public.json
python3 - <<'PY'
import json
from sis.v3.governed_eval import preregister
keys = json.load(open("/study/keys/public.json"))
protocol = preregister(
    primary_metric="qualification paired wins", method="select_improvement",
    alpha=0.05, min_effect=1.0, sample_size=1, powered=False,
    budget={"wall_seconds": 900, "token_budget": 150000, "tool_budget": 100},
    arms=("A", "E"), notes="pilot guidance qualification")
json.dump({**keys, "evaluation_protocol": protocol},
          open("/study/trust.json", "w"), indent=2)
PY
chmod 600 /study/trust.json
```

Keep the key directories off the study host's shared storage; only the
public keys go into `trust.json`.

## 4. Guidance bundle

```bash
python3 tools/build_guidance_bundle.py \
  --learning-spec /study/learning.json --exclude-spec /study/spec.json \
  --trust-config /study/trust.json --candidate-registry /study/candidates.db \
  --evaluator-key-dir /study/keys/evaluator \
  --operator-key-dir /study/keys/operator \
  --executor docker --state-dir /study/state/bundle \
  -o /study/guidance_bundle.json
```

Exit 1 with `missing_arms` in `/study/guidance_bundle.json.report.json`
means no candidate of that arm qualified; that is a pilot finding (record
it), not something to tune away against the holdout. Set
`"guidance_bundle": "/study/guidance_bundle.json"` in `/study/spec.json`.

## 5. Preregister

```bash
python3 tools/build_efficacy_manifest.py --spec /study/spec.json \
  --output /study/prereg/manifest.json
git -C /study/prereg init -q
git -C /study/prereg add manifest.json
git -C /study/prereg commit -qm "Preregister the SIS efficacy pilot"
```

The builder checks the installed `claude --version` against the spec,
fingerprints every repository and task tree, and binds the bundle digest.
Do not edit the manifest after this commit; a dirty or uncommitted
manifest is recorded as not preregistered.

## 6. Smoke test (2–3 tasks, real Claude Code)

```bash
python3 - <<'PY'
import json, tempfile
from pathlib import Path
from types import SimpleNamespace
from sis.v3.benchmark import BudgetCaps, UsageMeter
from sis.v3.learning_qualification import ClaudeCodeAgent
from sis.v3.study_runtime import materialize_commit
doc = json.load(open("/study/prereg/manifest.json"))
repos = {r["repository_id"]: r for r in doc["repositories"]}
for task in doc["tasks"][:3]:
    tree = Path(tempfile.mkdtemp()) / "ws"
    materialize_commit(repos[task["repository_id"]]["path"],
                       task["base_commit"], tree)
    agent = ClaudeCodeAgent(prompts={task["task_id"]: task["prompt"]},
                            model=doc["agent"]["model"], wall_seconds=900)
    ctx = SimpleNamespace(task=SimpleNamespace(task_id=task["task_id"]),
                          workspace=tree, guidance=None,
                          usage_meter=UsageMeter(), supervisor=None,
                          budget=BudgetCaps(wall_seconds=900,
                                            token_budget=150000,
                                            tool_budget=100))
    try:
        print(task["task_id"], agent(ctx), ctx.usage_meter.detail)
    except RuntimeError as exc:
        print(task["task_id"], "failed:", exc, ctx.usage_meter.tokens)
    agent.close()
PY
```

Check that tokens, tool calls and cache counters are plausible and that
the workspace changed. This does not touch the study state.

## 7. Pilot run

```bash
python3 tools/five_arm_campaign.py --real-agent --executor docker \
  --manifest /study/prereg/manifest.json \
  --guidance-bundle /study/guidance_bundle.json \
  --candidate-registry /study/candidates.db --trust-config /study/trust.json \
  --state-dir /study/state/pilot --workers 2 \
  -o /study/reports/pilot.json
```

If the run stops (quota, reboot, kill), first stop leftovers, then rerun
the identical command; it resumes from `/study/state/pilot/journal.jsonl`:

```bash
pkill -f 'claude -p' || true
docker rm -f $(docker ps -aq --filter label=sis.v3.sandbox) 2>/dev/null || true
```

`BLOCKED_RESUME` means the journal does not match this study or its
receipts; keep the state directory as evidence and start a new one only
with a note in the pilot record.

## 8. Analysis and sizing

```bash
python3 - <<'PY'
import json
from sis.v3.governed_eval import pilot_planning_inputs, required_repositories
report = json.load(open("/study/reports/pilot.json"))
q = report["learning_qualification"]
print(json.dumps({
    "evidence_class": q["evidence_class"],
    "decisive_contrast": q["decisive_contrast"],
    "repository_test": q["primary_analysis"]["repository_test"],
    "repository_interval": q["primary_analysis"]["repository_interval"],
    "negative_transfer": q["negative_transfer"],
    "resource_overhead": q["resource_overhead"],
    "failure_categories": q["failure_categories"],
}, indent=2))
inputs = pilot_planning_inputs(report)
print(json.dumps(inputs, indent=2))
plan = required_repositories(
    baseline_rate=inputs["baseline_rate"],
    treatment_rate=max(inputs["treatment_rate"], inputs["baseline_rate"] + 0.1),
    tasks_per_repository=round(inputs["tasks_per_repository"]),
    difference_icc=inputs["difference_icc"] or 0.0,
    simulations=2000, seed=0)
print(json.dumps({k: v for k, v in plan.items() if k != "curve"}, indent=2))
PY
```

Use a conservative effect (the lower end of the pilot interval, or the
smallest effect worth acting on) rather than the point estimate: the
`treatment_rate` above is a placeholder rule, not a recommendation.
Per-row `usage_detail` holds cache tokens and the reported cost in
micro-USD for the cost-per-task estimate.

## 9. Decision

Go to a confirmatory study only with a non-negative pilot effect, no
material negative transfer, a qualified bundle for every arm, and a
`required_repositories` result you can staff (never fewer than 20
holdout repositories). Record the decision and the numbers above with
the pilot report and its `<report>.evidence/` bundle.
