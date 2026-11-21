# SIS — Symbolic Induction Engine

**Learn small, checkable rules from examples. Reuse them only with signed evidence.**

[![CI](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml/badge.svg)](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml)
![Version](https://img.shields.io/badge/version-3.3.9-informational)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)
![Runtime deps](https://img.shields.io/badge/runtime%20deps-none-brightgreen)
![Engine](https://img.shields.io/badge/engine-sis--induce--3-purple)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SIS learns bounded, human-readable rules and procedures from examples and
verified execution traces. It stores them in a hash-linked registry. It serves
them to coding agents only through an authority layer of signed receipts,
revocation history and checkpoints. The core runtime is pure Python 3.10+ with
**no third-party dependencies**.

> [!IMPORTANT]
> SIS is `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`. The governed learning workflow
> is implemented and reproducible. **It has not been shown to improve
> real coding-agent performance**, and the evaluator sandbox has not been
> independently qualified. See [Status](#status).

## At a glance

- **Honest induction.** Rules are reported as `locally_validated` only with enough holdout evidence. Otherwise the
  result is `provisional` or `ambiguous`, never a guess. There are 0 false positives on the
  [62-target corpus](#the-rule-learner).
- **Evidence-gated reuse.** Every served decision traces back to a signed checkpoint over the candidate journal and
  custody heads.
- **Isolated grading.** Submissions run in Docker under gVisor with split custody, and the coding agent can run as a
  separate OS user. CI probes and red-teams the sandbox on every push.
- **Reproducible from a download.** CI builds the canonical source archive, extracts it and runs the whole suite from
  the copy. Every file that differs from the sealed inventory is
  [attributed to a commit](evidence/v339/inventory_reconciliation.md).

---

## Contents

- [At a glance](#at-a-glance)
- [Quickstart](#quickstart)
- [Status](#status)
- [How it works](#how-it-works)
- [The rule learner](#the-rule-learner)
- [Evaluator sandbox](#evaluator-sandbox)
- [Efficacy studies](#efficacy-studies)
- [Serving guidance](#serving-guidance)
- [Releases and provenance](#releases-and-provenance)
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
stored. `sis --help` lists every command, including skills, workflows, code
learning and sealed evaluation.

Check the checkout:

```bash
pytest -q                              # full suite (SQLite profile); needs the pinned pytest 8.4.2
python tools/smoke_integration.py      # CLI + HTTP end-to-end
```

## Status

| Area | State |
| --- | --- |
| **Rule learner** (Learner v2, engine `sis-induce-3`) | Implemented. Recovers 36 of 62 corpus targets (58%) with **zero false positives**, and recovers the benchmark rule at every width from 2 to 64 fields |
| **Authority layer** (M0–M5) | Implemented. Covered by adversarial tests, on SQLite and PostgreSQL |
| **Evaluator sandbox** (M6) | Docker + gVisor with split custody, and an optional separate OS user for the agent. Probed and red-teamed in CI on every push. **Not independently qualified** |
| **Real-agent efficacy** (M9) | **Not demonstrated.** Pilot tooling for Claude Code and Codex is ready, but no study has been run. A confirmatory study requires a separate agent OS user |
| **Release seal** | Sealed at v3.3.9 (`d81f7bf`). `main` is a development tree whose differences from the seal are fully attributed. Resealing is the owner's signed step ([release process](docs/v3/RELEASE_PROCESS.md)) |
| **v3.4 roadmap** | Gate G1 (reproducible source and test evidence) is in: [reconciliation](evidence/v339/inventory_reconciliation.md) and [test evidence](evidence/v339/TEST_EVIDENCE.md). Next: the signed seal, then an exploratory A/E pilot |

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
| Agent principal | `sis.v3.agent_principal` | Runs the agent as a separate OS user that cannot read evaluator material |
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

- **Search.** The learner uses:
  - typed bottom-up enumeration by cost, pruning programs that behave identically;
  - exact integer affine fitting over up to three features;
  - goal-directed completions. Cheap inverse lookups run first, and the per-terminal forward checks run at the end of
    each stage.

  Expressions are limited to 31 nodes and 6 levels. Budgets and truncation are always reported.
- **Honest statuses.** A rule is `locally_validated` only when its holdout carries at least 4 bits of evidence and,
  for conditionals, exercises both branches. Otherwise it is `provisional`. A rival scan over the whole search space
  reports `ambiguous` instead of guessing.
- **Versioned.** Results carry `grammar_version` (`sis-grammar-2`) and `engine_version` (`sis-induce-3`).
  Promotion refuses a result from another engine, so re-induce it. Stored rules keep their IDs and still pass
  `sis audit`.

**Corpus** (`examples/induction_corpus/`, 62 seeded targets):

| Category | Previous engine | Learner v2 |
| --- | --- | --- |
| Linear | 4 / 10 | 8 / 10 |
| Nonlinear | 8 / 10 | 8 / 10 |
| Div / mod | 0 / 10 | 5 / 10 |
| Piecewise | 0 / 10 | 7 / 10 |
| String | 2 / 12 | 8 / 12 |
| Distractors (no rule exists) | 10 / 10 rejected | 10 / 10 rejected |
| **False positives** | **0** | **0** |

**Scaling** (target `x[n-2] * x[n-1] + 2`; 6 training, 3 development and 3 holdout rows; 500,000 signature checks):

| Fields | Candidates | Verdict | Holdout |
| ---: | ---: | --- | ---: |
| 2 | 9 | ambiguous (an equivalent rival exists on 0..9) | 1.0 |
| 8 | 29 | ambiguous | 1.0 |
| 32 | 101 | ambiguous | 1.0 |
| 64 | 22,110 | intended rule found; budget ends the search (`search_incomplete`) | 1.0 |

On the negative domain with z3 equivalence checks, every width from 2 to 32 is an exact, verified recovery. The
records are in [`evidence/v339/`](evidence/v339/README.md).

Reproduce them with `python tools/benchmark_induction.py --corpus examples/induction_corpus` (corpus) or the
commands in the evidence README (scaling).

## Evaluator sandbox

Untrusted submissions are graded by `DockerSandboxExecutor`. A production executor requires:

- **Isolation.**
  - gVisor (`--runtime runsc`) with a deny-by-default seccomp allowlist
    ([`docker/sandbox/seccomp.json`](docker/sandbox/seccomp.json)).
  - No network, a read-only root, a non-root user and `cap-drop ALL`.
- **Limits.** Memory, PID, CPU-time, disk and output limits.
- **Split custody.** Submitted code runs as a second container identity, so it never sees the hidden tests.
- **Signed launch policy.** The policy is derived from the exact `docker run` flags, and its digest is signed into
  every receipt.

The coding agent itself can run as a **separate OS user** (`--agent-user NAME`):

- Its workspace is streamed in and out through a helper, and returned files cannot lock the evaluator out.
- A preflight confirms that user cannot read the hidden tests, keys, registry or state before any turn.

The `sandbox-qualification` CI job does three things:

1. installs a pinned gVisor;
2. runs the containment probe and the red team
   ([`tools/redteam_sandbox.py`](tools/redteam_sandbox.py): 18 hostile payloads, including fork and memory bombs,
   egress, ptrace, mount escapes and link escapes);
3. fails on any regression.

These attestations are still signed by a locally held key. Independent sign-off needs an isolator host you control;
see [Gate 2](docs/v3/SANDBOX_QUALIFICATION_GATE2.md).

> [!WARNING]
> Do not evaluate hostile code on the local subprocess backend. macOS is
> development-only: memory is enforced by a watchdog, not a kernel limit.
> On Windows only the core learner and CLI are supported; the evaluator,
> sandbox and study layer is POSIX-only.

## Efficacy studies

SIS includes the full apparatus for testing whether learned guidance helps a real coding agent:

| Step | Tool |
| --- | --- |
| Agent adapters, with budgets enforced while the agent runs | Claude Code (`sis.v3.adapters.claude_code`), Codex CLI (`sis.v3.adapters.codex_cli`) |
| Screen candidate repositories for gradability | [`tools/screen_study_repos.py`](tools/screen_study_repos.py) |
| Build tasks from real bug-fix commits | [`tools/import_study_tasks.py`](tools/import_study_tasks.py) |
| Learn guidance on training repositories and qualify it on separate ones (agent failures count as losses) | [`tools/build_guidance_bundle.py`](tools/build_guidance_bundle.py) |
| Run the study with Docker split custody, a resumable journal and parallel workers | [`tools/five_arm_campaign.py`](tools/five_arm_campaign.py) |
| Repository-level sign-flip test with Holm correction, and power planning | `sis.v3.governed_eval` |

Start with the exploratory pilot in [docs/v3/PILOT_RUNBOOK.md](docs/v3/PILOT_RUNBOOK.md).

A confirmatory study:

- needs at least 20 held-out repositories;
- needs a separate agent user. Without `--agent-user`, the run stops before the first turn with
  `BLOCKED_AGENT_PRINCIPAL_REQUIRED`.

## Serving guidance

The v3 boundary is built in application code. The `sis serve` CLI exposes only the legacy `/v1` surface.

```python
from sis.server import create_server

server = create_server(..., v3_service=service)   # /v3/guidance, /v3/outcome
```

Production mode requires a qualification policy, an evidence custody store, a verified authority checkpoint and a
control plane. See [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) for wiring, key rotation and recovery.

## Releases and provenance

`RELEASE_SHA256.json` and `release/` hold the sealed inventory and the provenance of the last release.

| Concern | How it is handled |
| --- | --- |
| **Development drift** | `tools/reconcile_inventory.py` compares the tree, or an extracted download (`--tree DIR`), with the seal. It attributes every difference to the commits and PR merges since then, and exits non-zero if anything is unattributed. Local agent state under `.claude/` is never inventoried |
| **Signing** | Release and production signing require the constant-time Ed25519 backend (`pip install -e '.[production]'`). Packaging and `tools/check_release_ci.py --mode release` refuse the pure-Python fallback |
| **Self-contained source** | The `archive` CI job builds the canonical source zip, extracts it into an empty directory, installs from it and runs the suite there |
| **Verification** | `tools/verify_release.py` checks an archive against its inventory, source binding and signed provenance |

The seal ritual is in [docs/v3/RELEASE_PROCESS.md](docs/v3/RELEASE_PROCESS.md).

## Installation options

| Extra | Adds |
| --- | --- |
| `dev` | `pytest` 8.4.2 (pinned and enforced at runtime) |
| `evaluator` | Pinned test runner for the isolated evaluator |
| `production` | `cryptography` 50.0.2, the constant-time signing backend for production and release signing |
| `postgres` | `psycopg` for the multi-replica control plane |
| `z3` | SMT-backed equivalence checks and tie-breaking |
| `codex` | The `openai-codex` SDK adapter |
| `training` | `torch` / `transformers` / `peft` for the neural experiments |

```bash
pip install -e '.[dev,postgres]'
```

The Claude Code adapter needs the `claude` CLI on `PATH`; it has no extra. The sandbox image is built from
[`docker/sandbox/`](docker/sandbox/).

## Development

```bash
pytest -q                                                                  # SQLite profile
SIS_POSTGRES_DSN='postgresql://user:pass@127.0.0.1:5432/sis' pytest -q     # PostgreSQL profile
SIS_TEST_AGENT_USER=sisagent pytest -q tests/v3/test_agent_principal.py    # real second OS user
ruff check src tests tools                                                 # lint (ruff 0.16.0 in CI)
```

- **Pinned runner.**
  - The evaluator refuses any pytest except 8.4.2, because receipt generation depends on the exact runner.
  - Under another version the suite stops before collection with one message and exit code 4.
    `SIS_ALLOW_UNPINNED_PYTEST=1` runs it anyway, for compatibility work.
- **Agent-user tests.**
  - These run only when `SIS_TEST_AGENT_USER` names a second user that `sudo -n -u USER /usr/bin/python3` can
    become.
  - A host-wide lock keeps concurrent suites from killing each other's helpers.
- **CI covers:**
  - Linux on Python 3.10, 3.12 and 3.13, and macOS on Python 3.12;
  - PostgreSQL 16;
  - a Docker-absent profile;
  - the source archive, built, extracted and tested;
  - lint;
  - gVisor sandbox qualification;
  - Windows on Python 3.12 for the core suite (`tests/v3` is POSIX-only and is not collected there).

| Path | Contents |
| --- | --- |
| `src/sis/` | Core engine: induction, registry, CLI, HTTP server |
| `src/sis/v3/` | Authority layer, evaluator, agent principal, adapters, study runtime |
| `tools/` | Benchmarks, campaigns, sandbox probes, release and reconciliation tooling |
| `examples/` | Study files and the induction corpus |
| `docker/sandbox/` | Pinned evaluator image and seccomp profile |
| `evidence/` | Dated benchmark, sandbox, reconciliation and test evidence |
| `docs/` | Design, operations, security and qualification reports |

## Documentation

| Document | Contents |
| --- | --- |
| [docs/INDEX.md](docs/INDEX.md) | Full documentation map |
| [docs/v3/ARCHITECTURE_V3_3.md](docs/v3/ARCHITECTURE_V3_3.md) | v3 subsystem design |
| [docs/v3/SECURITY_BOUNDARIES_V3_3.md](docs/v3/SECURITY_BOUNDARIES_V3_3.md) | What each boundary does and does not guarantee |
| [docs/v3/SANDBOX_QUALIFICATION_GATE2.md](docs/v3/SANDBOX_QUALIFICATION_GATE2.md) | Sandbox evidence and the independent sign-off procedure |
| [docs/v3/QUALIFICATION_REPORT_V3_3_9.md](docs/v3/QUALIFICATION_REPORT_V3_3_9.md) | v3.3.9 qualification report |
| [docs/v3/EFFICACY_STUDY_PROTOCOL.md](docs/v3/EFFICACY_STUDY_PROTOCOL.md) | Study design and analysis |
| [docs/v3/PILOT_RUNBOOK.md](docs/v3/PILOT_RUNBOOK.md) | Running the exploratory pilot |
| [docs/v3/RELEASE_PROCESS.md](docs/v3/RELEASE_PROCESS.md) | Branches, tags, seal and verification |
| [evidence/v339/TEST_EVIDENCE.md](evidence/v339/TEST_EVIDENCE.md) | Preserved test run and the typed skip inventory (unsigned development evidence) |
| [evidence/v339/inventory_reconciliation.md](evidence/v339/inventory_reconciliation.md) | Every difference from the v3.3.9 seal, attributed to its commits |
| [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) | Deployment, recovery and key rotation |
| [docs/V332_EFFICACY_STATUS.md](docs/V332_EFFICACY_STATUS.md) | What is and is not demonstrated |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [docs/history/](docs/history/README.md) | Historical record: milestone and test reports, the pre-3.3.3 README and v2.x CLI reference |

## Security

The threat model, adversary capabilities and residual risk are documented in
[docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md). Three points matter most:

- **Isolation is engineering evidence, not certification.** Until an independent isolator signs, treat the sandbox as
  unqualified.
- **Serving is only as strong as its evidence store.** Production requires custody, signed dependency links and a
  witnessed authority checkpoint. A deployment that weakens these loses revocation propagation.
- **Release keys need the constant-time backend.** The vendored Ed25519 fallback is for development and tests only.

## License

MIT. See [LICENSE](LICENSE).
