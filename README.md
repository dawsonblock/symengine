# SIS — Symbolic Induction Engine

**Learn small, checkable rules from examples. Reuse them only with signed evidence.**

[![Tests](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml/badge.svg)](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-3.3.9-informational)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Dependencies](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SIS induces bounded, human-readable rules and procedures from examples and
verified execution traces. It persists them in a hash-linked registry, and
it serves them to coding agents only through an authority layer built on
signed receipts, revocation history and checkpoints. The core runtime is
pure Python 3.10+ with **no third-party dependencies**.

> [!IMPORTANT]
> SIS is `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`. The governed learning workflow
> is implemented and reproducible. **It has not been shown to improve
> real coding-agent performance**, and the evaluator sandbox has not been
> independently qualified. See [Status](#status).

---

## Contents

- [Quickstart](#quickstart)
- [Status](#status)
- [How it works](#how-it-works)
- [The rule learner](#the-rule-learner)
- [Evaluator sandbox](#evaluator-sandbox)
- [Efficacy studies](#efficacy-studies)
- [Serving guidance](#serving-guidance)
- [Installation options](#installation-options)
- [Development](#development)
- [Documentation](#documentation)
- [Security](#security)

## Quickstart

```bash
git clone https://github.com/dawsonblock/symengine.git
cd symengine
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e '.[dev]'
```

Learn a rule from a study file, apply it, and verify the registry:

```bash
sis --db knowledge.sqlite3 train   examples/arithmetic_study.json   # induce + validate + promote
sis --db knowledge.sqlite3 predict examples/predict.json            # {"status": "predicted", "output": 11, ...}
sis --db knowledge.sqlite3 rules   --namespace arithmetic_demo      # inspect the stored rule
sis --db knowledge.sqlite3 audit                                    # verify the hash-linked history
```

Promotion is evidence-gated: a rule that fails validation is rejected, not
stored. `sis --help` lists all commands, including skills, workflows, code
learning and sealed evaluation.

Check the checkout:

```bash
pytest -q                              # full suite (SQLite profile)
python tools/smoke_integration.py      # CLI + HTTP end-to-end
```

## Status

| Area | State |
| --- | --- |
| **Rule learner** (Learner v2) | Implemented. Recovers 58% of a 62-target benchmark corpus (up from 23%) with **zero false positives** |
| **Authority layer** (M0–M5) | Implemented. Covered by adversarial tests, on SQLite and PostgreSQL |
| **Evaluator sandbox** (M6) | Docker + gVisor path implemented, probed and red-teamed in CI on every push. **Not independently qualified** |
| **Real-agent efficacy** (M9) | **Not demonstrated.** Pilot tooling for Claude Code and Codex is ready, but no study has been run |
| **Release seal** | v3.3.9 source on `main`. The seal must be rebuilt ([release process](docs/v3/RELEASE_PROCESS.md)) |

## How it works

```mermaid
flowchart LR
    A[Examples and traces] --> B[Induce<br/>typed enumeration]
    B --> C{Validate<br/>dev and holdout}
    C -- fails --> X[Rejected]
    C -- passes --> D[(Hash-linked<br/>registry)]
    D --> E[Candidates]
    F[Agent runs in<br/>sandboxed evaluator] --> G[Signed receipts]
    G --> E
    E --> H[Qualification<br/>certificates]
    H --> I[Custody, revocations<br/>and checkpoints]
    I --> J[Serving gateway<br/>scoped and authenticated]
```

| Layer | Module | Responsibility |
| --- | --- | --- |
| Rule induction | `sis.induction`, `sis.synthesis`, `sis.expression` | Typed bottom-up search over a versioned op registry |
| Structural code learning | `sis.code_learning` | Constrained operator substitutions from verified changes |
| Experience and skills | `sis.v3.memory`, `sis.v3.episode_store`, `sis.v3.learning` | Episodes, strategies and instruction variants |
| Candidate registry | `sis.v3.candidates` | Candidate states and qualification evidence |
| Evidence custody | `sis.v3.evidence_custody`, `sis.v3.checkpoints` | Certificates, revocations and rollback detection |
| Control plane | `sis.v3.control_plane` | Transactional nonces and receipts (SQLite or PostgreSQL) |
| Evaluation | `sis.v3.runner`, `sis.v3.docker_sandbox`, `sis.v3.verifier` | Isolated grading and signed outcome receipts |
| Serving | `sis.v3.serving`, `sis.v3.serving_service` | Scoped, authenticated guidance delivery |

Most of the system is the authority chain: every served decision traces
back to a signed checkpoint over the candidate journal and custody heads.

## The rule learner

Learner v2 searches a small typed expression grammar. It does not do
general program synthesis.

| Kind | Ops |
| --- | --- |
| Integer | `add`, `sub`, `mul`, `neg`, `abs`, `absdiff`, `min`, `max`, `floordiv`, `mod` (a zero divisor is an error, never a fit) |
| Comparison | `lt`, `le`, `gt`, `eq` |
| String | `concat`, `slice_prefix`, `slice_suffix`, `len`, `contains`, `str_of_int`, `lower`, `upper`, `reverse` |
| Conditional | `if_lt`, `if_eq` (one level, each branch learned separately) |

- **Search.** It uses typed bottom-up enumeration with
  observational-equivalence pruning, exact integer affine fitting over up to
  three features, and a hard 31-node / 6-level limit. Budgets and truncation
  are reported.
- **Honest statuses.** A rule is reported as `locally_validated` only when its
  holdout carries at least 4 bits of evidence and, for conditionals, exercises
  both branches. Otherwise it is `provisional`. A rival scan over the whole
  search space reports `ambiguous` instead of guessing.
- **Versioned.** Results carry `grammar_version` and `engine_version`. Stored
  rules keep their IDs and still pass `sis audit`.

Results on the committed corpus (`examples/induction_corpus/`, 62 seeded targets):

| Category | Previous engine | Learner v2 |
| --- | --- | --- |
| Linear | 4 / 10 | 8 / 10 |
| Nonlinear | 8 / 10 | 8 / 10 |
| Div / mod | 0 / 10 | 5 / 10 |
| Piecewise | 0 / 10 | 7 / 10 |
| String | 2 / 12 | 8 / 12 |
| Distractors (no rule exists) | 10 / 10 rejected | 10 / 10 rejected |
| **False positives** | **0** | **0** |

Reproduce the results with `python tools/benchmark_induction.py --corpus examples/induction_corpus`.
The stored results are in [`evidence/benchmark/`](evidence/benchmark/).

## Evaluator sandbox

Untrusted submissions are graded by `DockerSandboxExecutor`. A production executor requires:

- **Isolation.** gVisor (`--runtime runsc`), a deny-by-default seccomp
  allowlist ([`docker/sandbox/seccomp.json`](docker/sandbox/seccomp.json)), no
  network, a read-only root, a non-root user and `cap-drop ALL`.
- **Limits.** Memory, PID, CPU-time, disk and output limits.
- **Split custody.** Submitted code runs as a second container identity, so it
  never sees the hidden tests.
- **Signed launch policy.** The policy is derived from the exact `docker run`
  flags, and its digest is signed into every receipt.

The `sandbox-qualification` CI job installs a pinned gVisor, runs the
containment probe, then runs the red team
([`tools/redteam_sandbox.py`](tools/redteam_sandbox.py): 17 hostile payloads
including fork and memory bombs, egress, ptrace, mount escapes and link
escapes), and fails on any regression. These attestations are still signed by
a locally held key. Independent sign-off needs an isolator host you control:
see [Gate 2](docs/v3/SANDBOX_QUALIFICATION_GATE2.md).

> [!WARNING]
> Do not evaluate hostile code on the local subprocess backend. macOS is
> development-only: memory is enforced by a watchdog, not a kernel limit.
> Windows support is experimental.

## Efficacy studies

SIS includes the full apparatus for testing whether learned guidance helps a
real coding agent:

- **Agent adapters.** Claude Code (`sis.v3.adapters.claude_code`) and Codex
  CLI (`sis.v3.adapters.codex_cli`), with budgets enforced while the agent
  runs.
- **Task import.**
  [`tools/import_study_tasks.py`](tools/import_study_tasks.py) builds tasks
  from real bug-fix commits.
- **Guidance bundles.**
  [`tools/build_guidance_bundle.py`](tools/build_guidance_bundle.py) learns
  guidance on training repositories and qualifies it on separate ones,
  counting agent failures as losses.
- **Study runner.** [`tools/five_arm_campaign.py`](tools/five_arm_campaign.py)
  runs the study with Docker split custody, a resumable journal and parallel
  workers.
- **Statistics.** A repository-level sign-flip test with Holm correction, plus
  power planning (`sis.v3.governed_eval.required_repositories`).

Start with the exploratory pilot in [docs/v3/PILOT_RUNBOOK.md](docs/v3/PILOT_RUNBOOK.md).
A confirmatory study needs at least 20 held-out repositories.

## Serving guidance

The v3 boundary is built in application code. The `sis serve` CLI exposes
only the legacy `/v1` surface.

```python
from sis.server import create_server

server = create_server(..., v3_service=service)   # /v3/guidance, /v3/outcome
```

Production mode requires a qualification policy, an evidence custody store,
a verified authority checkpoint and a control plane. See
[docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) for wiring, key rotation
and recovery.

## Installation options

| Extra | Adds |
| --- | --- |
| `dev` | `pytest` 8.4.2 (pinned and enforced at runtime) |
| `evaluator` | Pinned test runner for the isolated evaluator |
| `postgres` | `psycopg` for the multi-replica control plane |
| `z3` | SMT-backed equivalence checks and tie-breaking |
| `codex` | The `openai-codex` SDK adapter |
| `training` | `torch` / `transformers` / `peft` for the neural experiments |

```bash
pip install -e '.[dev,postgres]'
```

The Claude Code adapter needs the `claude` CLI on `PATH`; it has no extra.
The sandbox image is built from [`docker/sandbox/`](docker/sandbox/).

## Development

```bash
pytest -q                                                    # SQLite profile
SIS_POSTGRES_DSN='postgresql://user:pass@127.0.0.1:5432/sis' pytest -q   # PostgreSQL profile
ruff check src tests tools                                   # lint (ruff 0.16.0 in CI)
```

`pytest` is pinned to 8.4.2, and a mismatch raises `RuntimePinError` because
receipt generation depends on the exact runner.

CI covers:

- Linux on Python 3.10, 3.12 and 3.13, and macOS on Python 3.12;
- PostgreSQL 16;
- a Docker-absent profile;
- lint;
- gVisor sandbox qualification;
- an experimental Windows job.

```text
src/sis/          core engine (induction, registry, CLI, HTTP server)
src/sis/v3/       authority layer, evaluator, adapters, study runtime
tools/            benchmarks, campaigns, sandbox probes, release tooling
examples/         study files and the induction corpus
docker/sandbox/   pinned evaluator image and seccomp profile
evidence/         stored benchmark and sandbox evidence
docs/             design, operations, security and qualification reports
```

## Documentation

| Document | Contents |
| --- | --- |
| [docs/INDEX.md](docs/INDEX.md) | Full documentation map |
| [docs/v3/ARCHITECTURE_V3_3.md](docs/v3/ARCHITECTURE_V3_3.md) | v3 subsystem design |
| [docs/v3/SECURITY_BOUNDARIES_V3_3.md](docs/v3/SECURITY_BOUNDARIES_V3_3.md) | What each boundary does and does not guarantee |
| [docs/v3/SANDBOX_QUALIFICATION_GATE2.md](docs/v3/SANDBOX_QUALIFICATION_GATE2.md) | Sandbox evidence and the independent sign-off procedure |
| [docs/v3/EFFICACY_STUDY_PROTOCOL.md](docs/v3/EFFICACY_STUDY_PROTOCOL.md) | Study design and analysis |
| [docs/v3/PILOT_RUNBOOK.md](docs/v3/PILOT_RUNBOOK.md) | Running the exploratory pilot |
| [docs/v3/RELEASE_PROCESS.md](docs/v3/RELEASE_PROCESS.md) | Branches, tags, seal and verification |
| [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) | Deployment, recovery and key rotation |
| [docs/V332_EFFICACY_STATUS.md](docs/V332_EFFICACY_STATUS.md) | What is and is not demonstrated |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/LEGACY_README.md](docs/LEGACY_README.md) | Pre-3.3.3 README and v2.x CLI reference |

## Security

The threat model, adversary capabilities and residual risk are documented in
[docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md). Two points
matter most:

- **Isolation is engineering evidence, not certification.** Until an
  independent isolator signs, treat the sandbox as unqualified.
- **Serving is only as strong as its evidence store.** Production requires
  custody, signed dependency links and a witnessed authority checkpoint.
  A deployment that weakens these loses revocation propagation.

## License

MIT. See [LICENSE](LICENSE).
