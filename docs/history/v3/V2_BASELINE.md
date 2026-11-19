# V2 Authority Recovery — baseline record (PR-00 / gate G0)

This document freezes the source baseline for the V2 → V4 qualification
train and records the executed regression matrix. It is evidence, not a
qualification certificate.

## Provenance

| item | value |
| --- | --- |
| source archive | `SIS-2026-10-24-FULL-UPGRADED-V2-Authority-Recovery.zip` |
| archive SHA-256 | `f62ef2a500fe487cf17fb1b7d19862ab0eb686c411663b89d02011f310a7d077` |
| verification | `shasum -a 256` matched the plan-stated digest byte-for-byte |
| extraction | unpacked in a clean directory; `diff -r` against a second extraction produced zero differences |
| baseline commit | `d79a813` on branch `codex/sis-authority-transfer-qualification` |
| baseline tag | `v2-authority-recovery-baseline` |
| per-file hashes | `RELEASE_SHA256.json` (schema 1 manifest, SHA-256 per file) |

## Test environment

| item | value |
| --- | --- |
| platform | macOS 26.2 (arm64), Darwin 25.2.0 |
| interpreter | CPython 3.12.0 (Clang 21.0.0 build) |
| pytest | 8.4.2 |
| sqlite | 3.51.0 |
| cryptography | 48.0.1 (constant-time Ed25519 backend active) |
| optional deps | `z3-solver`, `torch`/`transformers`/`peft`/`accelerate`, `openai-codex==0.163.0` — none imported by the v3 authority path |

Command for every row below:

```
PYTHONPATH=src:. python3 -m pytest -q <file>
```

## Executed baseline matrix (2026-10-24)

Full suite: `PYTHONPATH=src:. python3 -m pytest -q` → **562 passed, 2 skipped in ~19s**.

| suite | result |
| --- | --- |
| tests/test_system.py | 29 PASS |
| tests/test_upgrade.py | 27 PASS |
| tests/test_v120.py | 16 PASS |
| tests/test_v130.py | 9 PASS |
| tests/test_v140.py | 29 PASS |
| tests/test_v150.py | 30 PASS |
| tests/test_v160.py | 15 PASS |
| tests/test_v170.py | 21 PASS |
| tests/test_v180.py | 23 PASS |
| tests/test_v190.py | 19 PASS |
| tests/test_v200.py | 21 PASS |
| tests/test_v210.py | 18 PASS |
| tests/test_v22_experience_abstraction.py | 32 PASS |
| tests/test_v230_http.py | 1 PASS |
| tests/test_v230_workflows.py | 15 PASS |
| tests/test_v240_code_learning.py | 25 PASS |
| tests/test_v240_http.py | 1 PASS |
| tests/test_v240_review.py | 6 PASS, 1 SKIP (Windows ACL integration test — platform) |
| tests/v3/test_audit.py | 6 PASS |
| tests/v3/test_authority_recovery.py | 6 PASS |
| tests/v3/test_benchmark.py | 5 PASS |
| tests/v3/test_codex_adapter.py | 8 PASS |
| tests/v3/test_codex_cli_adapter.py | 6 PASS |
| tests/v3/test_contracts.py | 11 PASS |
| tests/v3/test_episode_replay.py | 12 PASS |
| tests/v3/test_evaluator_worker.py | 3 PASS |
| tests/v3/test_guidance.py | 5 PASS |
| tests/v3/test_http_permissions.py | 4 PASS |
| tests/v3/test_patcher.py | 9 PASS |
| tests/v3/test_policy.py | 4 PASS |
| tests/v3/test_procedures.py | 14 PASS |
| tests/v3/test_promotion.py | 26 PASS |
| tests/v3/test_receipt_signatures.py | 16 PASS |
| tests/v3/test_release_artifact.py | 12 PASS |
| tests/v3/test_retrieval.py | 16 PASS |
| tests/v3/test_roadmap_modules.py | 29 PASS |
| tests/v3/test_runner_isolation.py | 18 PASS |
| tests/v3/test_schemas.py | 3 PASS |
| tests/v3/test_source_manifest.py | 1 PASS, 1 SKIP (pinned Git baseline `daf0ccce...` objects absent from source distribution) |
| tests/v3/test_upgrade_integrity_learning.py | 7 PASS |
| tests/v3/test_verified_episode.py | 4 PASS |

Independent plan-check reproduced:

```
PYTHONPATH=src:. python3 -m pytest -q \
  tests/v3/test_authority_recovery.py tests/v3/test_upgrade_integrity_learning.py \
  tests/v3/test_benchmark.py tests/v3/test_codex_adapter.py tests/v3/test_retrieval.py
# → 42 passed
```

## Known-unsafe surfaces carried by the baseline (fixed by PR-01/PR-02)

- `ProcedureStore.add(record, allow_qualified=True)` mints qualified catalog
  state without any signed decision. Any holder of the store object can do it.
- Promotion writes are two independently fsynced JSONL files
  (`decisions.jsonl` then `procedures.jsonl`); crash-gap recovery exists but
  is replay-based, not transactional.
- `Catalog.set_scope` gates on a role string and persists an unsigned sidecar;
  cross-repository scope has no signed-grant requirement at this layer
  (`StrictGuidanceGateway.namespace_authorizer` is the only hook).
- Legacy `GuidanceGateway` serves recommendations from any `ProcedureStore`
  without consulting the promotion journal at all.
- `Catalog.cascade_suspend` and helpers in `rollback.py` delegate to the
  controller; in the baseline both coexist with the writable store.

## Reproduction notes for PR-01/02 regression tests

| unsafe path | baseline behavior |
| --- | --- |
| `store.add(qualified_record, allow_qualified=True)` | record persisted and servable by legacy `GuidanceGateway` |
| qualified record seeded with no decision | `StrictGuidanceGateway` abstains globally (`authority_verification_failed` → `catalog_unavailable`) |
| crash between decision append and record append | journal ahead of catalog; `verify()` reports `decision_materialization_drift`; recovery replays on next open |
| second `PromotionController` on same log after external commit | `stale_controller` via `_check_fresh_authority` |
| `store.add(record, allow_qualified=True)` after restart in a fresh process | qualified state is durable and readable — the capability is ambient |

## Scope of this record

No code was modified before this baseline was captured. The two skips are
environmental (Windows ACL test on macOS; pinned Git baseline objects absent
from the source distribution). No counts were invented; every row was
executed on this machine on 2026-10-24.
