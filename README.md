# SIS — Symbolic Induction Engine

**Bounded, evidence-gated symbolic induction with a governed authority layer.**

[![Tests](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml/badge.svg)](https://github.com/dawsonblock/symengine/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

SIS learns small, checkable rules and procedural skills from examples, then
gates their reuse behind signed evidence, revocation history and an auditable
authority chain. The core runtime has **no dependencies** — Python 3.10+ and the
standard library.

---

## Project status

| Area | State |
|---|---|
| Authority controls (M0–M5) | Implemented, covered by adversarial tests |
| Evaluator isolation (M6) | **Not qualified** |
| Real-agent efficacy (M9) | **Not demonstrated** |

SIS is `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`. No improvement in real coding-agent
performance is claimed, and the confirmatory study is incomplete. What *is*
demonstrated is a governed learning workflow with reproducible evidence — see
[docs/V332_EFFICACY_STATUS.md](docs/V332_EFFICACY_STATUS.md).

## What it does

- **Induces bounded rules** from labelled examples over a small expression
  grammar — arithmetic, comparisons and simple transformations, not general
  program synthesis.
- **Learns procedural skills** from verified execution traces, then versions and
  evaluates them.
- **Remembers episodes** with provenance, so a past success can be retrieved and
  reused.
- **Qualifies candidates** through signed evaluation certificates rather than
  self-reported metrics.
- **Serves guidance** through an authenticated, scoped boundary that refuses
  revoked or uncheckpointed evidence.

## Quickstart

```bash
git clone https://github.com/dawsonblock/symengine.git
cd symengine

python3 -m venv .venv
source .venv/bin/activate        # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e '.[dev]'
```

Verify the checkout:

```bash
pytest -q                        # full suite, SQLite profile
python tools/smoke_integration.py   # CLI + HTTP end-to-end
```

Then learn and apply a rule:

```bash
sis --db ./knowledge.sqlite3 train examples/arithmetic_study.json
sis --db ./knowledge.sqlite3 predict examples/predict.json
sis --db ./knowledge.sqlite3 rules
sis --db ./knowledge.sqlite3 audit
```

`sis audit` verifies the hash-linked history in the database. Promotion is
evidence-gated: a rule that cannot be validated against the study is rejected
rather than stored.

## Architecture

| Layer | Module | Responsibility |
|---|---|---|
| Symbolic induction | `sis.induction`, `sis.v3.learning.symbolic` | Discover bounded rules from examples |
| Structural code learning | `sis.code_learning` | Extract constrained operator substitutions from verified changes |
| Experience memory | `sis.v3.memory`, `sis.v3.episode_store` | Store and retrieve verified episodes |
| Skill optimization | `sis.v3.learning.optimization` | Generate and rank instruction variants |
| Candidate registry | `sis.v3.candidates` | Track candidate states and qualification evidence |
| Authority checkpoints | `sis.v3.checkpoints` | Detect candidate and custody rollback |
| Evidence custody | `sis.v3.evidence_custody` | Certificates, dependencies, revocations, supersessions |
| Control plane | `sis.v3.control_plane` | Transactional nonce and receipt commit, SQLite or PostgreSQL |
| Serving gateway | `sis.v3.serving`, `sis.v3.serving_service` | Scoped, authenticated guidance delivery |

The authority chain is the substantial part of the system: every served
decision can be traced back to a signed checkpoint over the candidate journal
and the custody heads.

## Serving

The v3 boundary is constructed in application code, not the `sis serve` CLI
(which exposes only the legacy `/v1` surface):

```python
from sis.server import create_server

server = create_server(..., v3_service=service)   # /v3/guidance, /v3/outcome
```

Production mode requires a qualification policy, an evidence custody store, a
verified authority checkpoint and a control plane. Wiring, key rotation and
recovery are covered in [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md).

## Optional extras

| Extra | Adds |
|---|---|
| `dev` | `pytest` 8.4.2 (pinned and runtime-enforced) |
| `evaluator` | Pinned test runner for the isolated evaluator |
| `postgres` | `psycopg` for the multi-replica control plane |
| `z3` | SMT-backed constraint solving |
| `training` | `torch`/`transformers`/`peft` for the neural experiments |
| `codex` | `openai-codex` adapter |

```bash
pip install -e '.[dev,postgres]'
```

## Testing

The default suite runs entirely on SQLite. The PostgreSQL profile is opt-in and
qualifies cross-replica behaviour:

```bash
SIS_POSTGRES_DSN='postgresql://user:pass@127.0.0.1:5432/sis' pytest -q
```

`pytest` is pinned to `8.4.2`; a mismatch raises `RuntimePinError` because
receipt generation depends on the exact runner. CI runs Linux 3.10/3.12/3.13,
an experimental Windows job, and a dedicated PostgreSQL 16 job.

## Security

The threat model, adversary capabilities and residual risk are documented in
[docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md). Two boundaries
deserve emphasis:

- **Evaluator isolation is not qualified.** Hostile-code evaluation must not be
  run on the local subprocess backend.
- **Serving is only as strong as its evidence store.** Production requires
  custody, signed dependency links and a witnessed authority checkpoint;
  deployments that weaken those settings forfeit revocation propagation.

Known defects and their fixes are recorded in
[docs/V332_AUTHORITY_CONSISTENCY.md](docs/V332_AUTHORITY_CONSISTENCY.md).

## Documentation

| Document | Contents |
|---|---|
| [docs/v3/ARCHITECTURE_V3_3.md](docs/v3/ARCHITECTURE_V3_3.md) | v3 subsystem design |
| [docs/V332_OPERATIONS.md](docs/V332_OPERATIONS.md) | Deployment, recovery, key rotation |
| [docs/V332_AUTHORITY_CONSISTENCY.md](docs/V332_AUTHORITY_CONSISTENCY.md) | Authority-consistency defects and fixes |
| [docs/V332_ACCEPTANCE_MATRIX.md](docs/V332_ACCEPTANCE_MATRIX.md) | Executed acceptance scenarios |
| [docs/V332_EFFICACY_STATUS.md](docs/V332_EFFICACY_STATUS.md) | What is and is not demonstrated |
| [docs/SECURITY_THREAT_MODEL.md](docs/SECURITY_THREAT_MODEL.md) | Adversaries, mitigations, residual risk |
| [docs/EVALUATION_CERTIFICATES.md](docs/EVALUATION_CERTIFICATES.md) | Signed qualification evidence |
| [docs/EVIDENCE_CUSTODY.md](docs/EVIDENCE_CUSTODY.md) | Revocation and dependency tracking |
| [CHANGELOG.md](CHANGELOG.md) | Release-by-release history |
| [docs/LEGACY_README.md](docs/LEGACY_README.md) | Pre-3.3.3 README, v2.x CLI reference |

## License

MIT — see [LICENSE](LICENSE).
