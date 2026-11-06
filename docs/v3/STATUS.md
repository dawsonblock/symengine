# SIS v3 implementation status

> **Historical build ledger.** This file records the M0/M1 implementation
> sequence and is retained for provenance. It does not describe the
> current release. For the current status see
> `docs/v3/QUALIFICATION_REPORT.md` and `docs/v3/RELEASE_NOTES_V3_3.md`.

Current classification: **M0 contracts/policy plus SIS3-003 executor,
SIS3-005 episode store, SIS3-006 signed receipts, SIS3-004 CLI adapter (real
backend contact, quota-limited), SIS3-007–012 (procedure store + miner,
source-preserving patcher, hard-gated retrieval, recommend/abstain guidance,
signed promotion controller + rollback, external anchor chain, four-arm
benchmark harness) are implemented and locally tested.** A *passing* live
Codex episode is blocked by account quota (reset ~8:36 PM on run date);
OS-validated isolation, evaluator process separation, and any efficacy claim
remain unestablished. No v3.0.0-alpha label is claimed.

## SIS3-001 and SIS3-002 report

```yaml
phase_id: SIS3-001+SIS3-002
status: blocked
base_revision: daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08
source_files_changed:
  - .github/workflows/ci.yml
  - pyproject.toml
  - src/sis/server.py
  - tools/check_source_manifest.py
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/MIGRATION.md
  - docs/v3/STATUS.md
  - docs/v3/TEST_MATRIX.md
  - docs/v3/THREAT_MODEL.md
  - docs/v3/TRUST_BOUNDARIES.md
  - examples/v3/contracts_v1.json
  - examples/v3/negative_transfer/remaining_balance.json
  - src/sis/v3/__init__.py
  - src/sis/v3/contracts.py
  - src/sis/v3/guidance.py
  - src/sis/v3/policy.py
  - tests/v3/__init__.py
  - tests/v3/test_contracts.py
  - tests/v3/test_guidance.py
  - tests/v3/test_http_permissions.py
  - tests/v3/test_policy.py
  - tests/v3/test_source_manifest.py
tests_added: 25
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0cccea495f4e62f1e3ddde3f9a3a68e2e1b08"
  - "python3 -m compileall -q src/sis tests/v3"
  - "Isolated temporary venv: pip install -e .; import sis, sis.v3"
  - "Extracted Git baseline: unittest, smoke integration, and source manifest checks"
observed_outcomes:
  - "Baseline at base_revision: 338 tests, 1 skipped; smoke passed; 138 manifest files verified"
  - "Development tree: 363 tests, 1 skipped; smoke passed; compileall passed"
  - "Pinned baseline integrity: 138 files verified; development delta reported separately"
  - "Editable install passed; imported SIS 2.4.0 and v3 schema version 1"
  - "The plan's exact ZIP SHA-256 was not verified because that ZIP is absent"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "setuptools 82.0.1 (pinned build backend)"
security_tests:
  - "All 12 operator POST routes denied a keyed reader token and forged JSON role"
  - "Unknown route aliases returned 404; query alias remained subject to operator authentication"
  - "Unkeyed loopback code-study compatibility passed in a disposable temporary database"
  - "Contract unknown fields, duplicate keys, non-finite numbers, oversized JSON, invalid paths, and executable preconditions rejected"
  - "Legacy Sub-to-Add preview reproduced the remaining_balance false transfer; v3 guidance abstained with unverified_task_intent and no procedure IDs"
remaining_unknowns:
  - "Exact planned archive symbolic-induction-engine-v2.4.0-codex-sis-v3-m0.zip and SHA-256 5ef4a01f63f3d9b95619f89f06769c955e9d1816ea97b0c90d12ecffca00244c remain unverified"
  - "GitHub CI was configured but not observed running; Windows and Python 3.10/3.13 were not tested locally"
  - "No real Codex SDK integration/run, isolated hostile-code execution, evaluator custody, signed receipt verification, external anchor, or efficacy experiment"
  - "The existing v2 sis_code_preview remains experimental and can still propose the known false transfer"
next_gate: "Verify the exact source archive identity and review M0 evidence before starting M1"
```

## Gate interpretation

The implementation and local tests are complete for the first two tickets, but
the overall M0 gate remains blocked on the planned archive identity. The pinned
Git source manifest and extracted Git baseline were independently checked in
this workspace; this does not substitute for verifying the absent ZIP hash.
No claim is made about live Codex capture, hostile-code containment, qualified
procedures, or improved coding-agent outcomes.

## SIS3-004 Codex adapter implementation slice

```yaml
phase_id: SIS3-004-adapter-slice
status: tested
base_revision: f001ade3110f6e5954488b72af228469569087c6
source_files_changed:
  - pyproject.toml
  - src/sis/v3/contracts.py
  - src/sis/v3/adapters/__init__.py
  - src/sis/v3/adapters/base.py
  - src/sis/v3/adapters/codex.py
  - tests/v3/test_codex_adapter.py
  - docs/v3/CODEX_ADAPTER.md
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/STATUS.md
tests_added: 8
commands_run:
  - "PYTHONPATH=src python3 -m unittest tests.v3.test_codex_adapter -v"
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 tools/check_source_manifest.py --baseline-ref daf0ccc"
  - "python3 -m compileall -q src/sis/v3/adapters tests/v3/test_codex_adapter.py"
  - "python3 -m pip install --dry-run '.[codex]'"
  - "python3 -m pip wheel --no-deps --no-build-isolation -w /tmp/sis-codex-adapter-wheel ."
  - "python3 -c 'import glob, zipfile; wheels=glob.glob(\"/tmp/sis-codex-adapter-wheel/*.whl\"); assert len(wheels)==1; names=set(zipfile.ZipFile(wheels[0]).namelist()); expected={\"sis/v3/adapters/__init__.py\", \"sis/v3/adapters/base.py\", \"sis/v3/adapters/codex.py\"}; assert expected <= names'"
  - >-
    PYTHONPATH=/Users/dawsonblock/Downloads/codex-main/sdk/python/src:src python3 -c 'import inspect, openai_codex; from sis.v3.adapters import AgentTurn, CodexAdapter; from openai_codex import Codex, ExternalMessage, Sandbox; assert "thread_start" in dir(Codex) and "thread_resume" in dir(Codex); assert "turn" in dir(openai_codex.Thread); assert "stream" in dir(openai_codex.TurnHandle) and "interrupt" in dir(openai_codex.TurnHandle); assert Sandbox.__members__["workspace_write"]; assert ExternalMessage.__init__; print("source_sdk_version=" + openai_codex.__version__); print(inspect.signature(openai_codex.Thread.turn)); print("public API surface check passed")'
observed_outcomes:
  - "Adapter tests passed: 8 tests; the full SIS suite passed: 371 tests, 1 skipped"
  - "CLI/HTTP smoke passed; this is local integration evidence only"
  - "Pinned pristine baseline: 138 source files verified; development delta reported separately"
  - "Optional dependency resolved to openai-codex 0.163.0 and openai-codex-cli-bin 0.163.0"
  - "Built wheel contains all three sis.v3.adapters package files"
  - "Built wheel SHA-256: 602b05952f70f7ed694c80510433f59d453728cd8035e0cff387d4ad5416a191"
  - "Provided SDK source imports as 0.0.0-dev and exposes typed thread, turn, interrupt, sandbox, and ExternalMessage APIs"
environment_and_dependency_versions:
  - "macOS 26.2"
  - "Python 3.12.0"
  - "Provided SDK checkout: openai-codex 0.0.0-dev; CLI binary requirement 0.153.4"
  - "Build extra: published openai-codex==0.163.0; dependency resolution dry-run only"
security_tests:
  - "SDK event summaries omit prompt/assistant text, command/output content, terminal input, diffs, and paths"
  - "Default Codex sandbox is read-only; adapter rejects full_access"
  - "External SIS content is passed through SDK ExternalMessage with tool-level provenance"
  - "The adapter has no direct command runner, evaluator-state writer, or signing API; Codex handles tool execution under its configured permissions"
remaining_unknowns:
  - "No authenticated live Codex task was run; wheel install and SDK runtime behavior remain unverified"
  - "The supplied Codex source directory has no Git revision; adapter targets its public API and pins the published SDK separately"
  - "Workspace-write is a Codex permission preset, not a validated OS isolation boundary"
  - "Commands are observed by event type and exit state; the adapter does not classify whether command text invoked tests"
  - "No durable event store, replay/recovery, source snapshot collector, independent verifier, or signed outcome receipt exists yet"
  - "M0's exact source archive and SHA-256 remain unavailable and unverified"
next_gate: "Run one controlled authenticated task in a disposable workspace, then implement durable event capture and exact workspace snapshot collection before claiming M1 complete"
```

## SIS3-003 / SIS3-005 / SIS3-006 report

```yaml
phase_id: SIS3-003+SIS3-005+SIS3-006
status: tested
base_revision: extracted archive tree (no .git; see manifest test skip note)
source_files_changed:
  - src/sis/v3/runner.py
  - src/sis/v3/episode_store.py
  - src/sis/v3/signatures.py
  - src/sis/v3/verifier.py
  - tests/v3/test_runner_isolation.py
  - tests/v3/test_episode_replay.py
  - tests/v3/test_receipt_signatures.py
  - tests/v3/test_verified_episode.py
  - tests/v3/test_source_manifest.py
  - docs/v3/STATUS.md
  - docs/v3/EVIDENCE_PROTOCOL.md
  - docs/v3/THREAT_MODEL.md
  - docs/v3/TRUST_BOUNDARIES.md
  - docs/v3/TEST_MATRIX.md
  - docs/v3/MIGRATION.md
tests_added: 48
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests/v3 -t . -q"
  - "PYTHONPATH=src python3 tools/smoke_integration.py"
  - "python3 -m compileall -q src/sis/v3 tests/v3"
observed_outcomes:
  - "Full suite: 419 tests, 0 failures, 2 skips (pre-existing skip + pinned-baseline probe absent .git)"
  - "v3 slice: 81 tests, 0 failures, 1 skip; no ResourceWarnings under -W error"
  - "CLI/HTTP smoke passed; local integration evidence only"
  - "RFC 8032 known-answer tests pass; vendored Ed25519 cross-verifies with cryptography 48.0.1 when installed"
  - "Executor: infinite loop wall-clock killed; 4 MiB stdout capped at 1 MiB with flag; 64 MiB write stopped at RLIMIT_FSIZE; aggregate disk budget audited; fork attempt bounded; host env not leaked; symlink escape flagged; terminate_all leaves no live workers"
  - "sandbox-exec seatbelt verified on this host: network connect denied (EPERM), writes outside workspace denied; executor reports network:seatbelt_denied vs network:not_enforced honestly"
  - "Episode store: chained replay, idempotent retry, conflict rejection, missing-artifact rejection, partial-tail crash recovery, mid-file tamper detection, head anchoring"
  - "Verifier: signed pass/fail receipts verify online and offline with public key only; tampered body, wrong key, unknown signer rejected; replayed nonce and duplicate evaluation rejected across restart; corrupt journal fails closed; agent/runner/learner/operator/forged roles denied evaluate"
  - "End-to-end vertical passed with a deterministic scripted agent on a real disposable workspace; NOT a live Codex run"
environment_and_dependency_versions:
  - "macOS 26.x (Darwin 25.2.0)"
  - "Python 3.12.0"
  - "cryptography 48.0.1 present in dev env (interop check only; not required at runtime)"
  - "sandbox-exec present at /usr/bin/sandbox-exec (deprecated Apple API; treated as experimental)"
security_tests:
  - "CommandSpec rejects argv traversal, oversize args/stdin/env, invalid cwd and env names"
  - "Receipts always carry isolation:unverified_local; network enforcement status is reported, not implied"
  - "OutcomeReceiptV1 signature is Ed25519 over canonical payload with domain sis-v3:outcome_receipt:1"
  - "Evaluation rejected for: unregistered_task, source_mismatch (incl. missing base_commit), replayed_nonce, duplicate_evaluation, missing submission, task_registration_conflict"
  - "Evaluator seed stored 0600 in a 0700 directory; public verification path needs only the exported public key"
remaining_unknowns:
  - "No live Codex/agent episode; M1 gate item 'actual coding task end-to-end' is demonstrated only with a scripted fixture agent"
  - "local-subprocess executor is not a validated sandbox even with seatbelt; no Linux rootless or microVM backend exists"
  - "RLIMIT_NPROC counts the real UID's processes on POSIX; low values can make forking commands fail early"
  - "ru_maxrss is a cumulative high-water mark, not a per-exec delta"
  - "Vendored pure-Python Ed25519 is not constant-time; production should substitute a vetted provider behind the same API"
  - "Append-only store is code discipline over a writable filesystem, not WORM; anchor_head exports heads but no external attestation service exists"
  - "Verifier shares the caller's OS process in tests; separate evaluator service/process custody is specified but not deployed"
  - "No promotion controller, qualified catalog, or benchmark harness; no efficacy claim"
next_gate: "Run one authenticated Codex task in a disposable workspace through this pipeline, then gate M1 on real adapter capture + independent receipt"
```

## SIS3-004 (CLI) + SIS3-007–012 report

```yaml
phase_id: SIS3-004-cli+007-012
status: tested (live contact achieved; passing live episode blocked by quota)
source_files_changed:
  - src/sis/v3/adapters/codex_cli.py
  - src/sis/v3/procedures.py
  - src/sis/v3/patcher.py
  - src/sis/v3/retrieval.py
  - src/sis/v3/guidance.py
  - src/sis/v3/promotion.py
  - src/sis/v3/rollback.py
  - src/sis/v3/audit.py
  - src/sis/v3/benchmark.py
  - src/sis/v3/verifier.py  # persists full receipts; load_receipt accessor
  - src/sis/v3/schemas/*.json  # 9 golden canonical examples
  - scripts/v3/run_codex_episode.py
  - examples/v3/fixtures/buggy_calc/*
  - docs/v3/episodes/live-001/*
  - tests/v3/test_codex_cli_adapter.py
  - tests/v3/test_procedures.py
  - tests/v3/test_patcher.py
  - tests/v3/test_retrieval.py
  - tests/v3/test_promotion.py
  - tests/v3/test_audit.py
  - tests/v3/test_benchmark.py
  - tests/v3/test_schemas.py
tests_added: 60
commands_run:
  - "PYTHONPATH=src python3 -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 -W error::ResourceWarning -m unittest discover -s tests -q"
  - "PYTHONPATH=src python3 scripts/v3/run_codex_episode.py --work-root /tmp/sis-live-ws --evidence-root /tmp/sis-live-evidence"
  - "codex exec --json --ephemeral -s workspace-write -C /tmp/codex-dbg (direct capability probe)"
observed_outcomes:
  - "Full suite: 479 tests, 0 failures, 2 skips; no ResourceWarnings under -W error"
  - "LIVE CODEX CONTACT: codex-cli 0.156.1 (ChatGPT auth) reached the backend inside a disposable fixture workspace; turn failed with account usage-limit error; episode.jsonl (5 chained events), anchor, journal, and public key preserved in docs/v3/episodes/live-001/"
  - "Evaluator correctly signed outcome=fail on the still-buggy tree; offline public-key signature verification passed at run time"
  - "A passing live episode remains blocked: ChatGPT Codex quota exhausted, resets ~8:36 PM; codex-mini-latest not supported on this account"
  - "ProcedureStore: digest-keyed append-only catalog, revision conflicts, chain/tamper detection, persistence across reopen"
  - "Miner: deterministic candidates from verified episodes only; learner role required; pass→candidate, fail→counterexample-bearing candidate"
  - "Patcher: unique-span byte replacement preserves CRLF/Unicode/comments; nonunique/missing/identity/path-escape rejected; proposals are artifacts, not writes"
  - "Retrieval: every precondition kind gated; contraindication→prior_negative_transfer; only qualified records surface; deterministic ranking"
  - "Guidance: recommend path returns procedures+evidence+matched gates; abstains on unverified intent, empty catalog, or all-gates-failed incl. the remaining_balance fixture (prior_negative_transfer)"
  - "Promotion: full lifecycle draft→…→qualified; illegal edges, wrong token, agent role, missing receipts, missing/invalid evaluator signature all rejected; decision log hash-chained, restart-safe, tamper-detecting; checkpoint/restore suspends post-checkpoint qualifications"
  - "Audit: AnchorChain records verified heads; reports grew_after_anchor vs corrupt vs missing"
  - "Benchmark: paired A/B/C/D arms in fresh workspaces, identical-tree receipt reuse, independent scoring, paired wins/losses/ties report"
environment_and_dependency_versions:
  - "macOS 26.x; Python 3.12.0; codex-cli 0.156.1; ChatGPT plan (no API key)"
security_tests:
  - "CLI adapter emits bounded summaries only (no command/output text); scrubbed env; wall-clock process-group kill; cancel; danger-full-access not offered"
  - "Promotion decisions require operator role+token AND evaluator Ed25519 signature for evidence-bearing transitions"
  - "Replayed operator token alone cannot qualify: evaluator signature is independently verified"
remaining_unknowns:
  - "No PASSING live Codex episode — quota-limited; the M1 gate item 'one actual coding task completes end-to-end' is demonstrated for failure capture, not task success"
  - "Promotion operator token is a shared-secret digest gate (research build), not per-principal auth"
  - "Benchmark token/tool budgets are declared caps enforced by the agent runtime; the harness enforces wall-clock only"
  - "Miner is deterministic and records observed evidence; no LLM candidate generation yet"
next_gate: "When quota resets, run scripts/v3/run_codex_episode.py for a passing live episode; then pilot qualification + the four-arm benchmark on scripted tasks before any efficacy language"
```

## Repair pass (post-012)

```yaml
phase_id: repairs-1
status: tested
source_files_changed:
  - src/sis/v3/signatures.py  # cryptography preferred, vendored fallback
  - src/sis/v3/promotion.py   # per-principal operator Ed25519 auth
  - src/sis/v3/evaluator_worker.py  # evaluator signing in a child process
  - src/sis/v3/benchmark.py   # wall-clock budget violation flags
  - tests/v3/test_receipt_signatures.py
  - tests/v3/test_promotion.py
  - tests/v3/test_benchmark.py
  - tests/v3/test_evaluator_worker.py
tests_added: 9
observed_outcomes:
  - "Full suite: 488 tests, 0 failures, 2 skips"
  - "signatures.backend() == 'cryptography' here (constant-time); vendored path byte-identical and still tested"
  - "Promotion accepts operator Ed25519 signatures; wrong key / missing credentials rejected; shared token remains as fallback"
  - "evaluate_via_subprocess: seed loads only inside the child process; signed receipt verifies offline; unregistered task rejected with exit 2"
  - "Benchmark arms now flag wall_seconds > budget.wall_seconds as budget_exceeded and count them in the report"
remaining_unknowns:
  - "Subprocess custody shares one OS principal — a true split needs a separate service account/host"
  - "Passing live Codex episode still pending quota reset"
```

## Live episode 002 — passing Codex task (M1 gate item met)

```yaml
phase_id: live-episode-002
status: verified
observed_outcomes:
  - "codex exec --json (codex-cli 0.156.1) ran the buggy_calc fixture after the 8:36 PM quota reset: 16 chained events including a failed command (exit 128), one file_change edit (percentage fix), a verification command (exit 0), turn.completed with real token usage"
  - "Independent evaluator injected hidden acceptance tests into a fresh workspace and signed outcome=pass; offline public-key verification passed"
  - "Evidence preserved under docs/v3/episodes/live-002/ including the full signed OutcomeReceiptV1"
remaining_unknowns:
  - "One solved task is pipeline proof, not lift; no cross-task retrieval or efficacy evidence exists"
next_gate: "Mine a candidate from this episode, qualify it via promotion on disjoint fixtures, then a scripted four-arm pilot"
```

## v3.1 roadmap slice — release integrity, projection, envelopes, semantic gates, catalog scopes, guidance phases, benchmark stats

```yaml
phase_id: v31-roadmap-slice-1
tickets: [SIS3-101, SIS3-102, SIS3-122, SIS3-131, SIS3-141, SIS3-150(partial), SIS3-161, SIS3-170/171(partial)]
status: implemented_and_tested
changed_files:
  - tools/build_release.py           # NEW: RELEASE_SHA256.json generation + drift check
  - tools/verify_release.py          # ZIP-native verify() restored + RELEASE manifest + verify_tree + build_zip + compile
  - tools/check_source_manifest.py   # both manifest names excluded from source inventory
  - src/sis/registry.py              # close() + context manager
  - src/sis/family_eval.py           # close() + context manager
  - src/sis/skill_holdout.py         # close() + context manager
  - src/sis/v3/episode_projection.py # NEW: deterministic projection + agent_view redaction
  - src/sis/v3/outcome_v2.py         # NEW: OutcomeEnvelopeV2 issue/verify, key registry, revocation, nonce replay, expiry
  - src/sis/v3/semantic_checks.py    # NEW: AST operator-class diff + metamorphic violation flags
  - src/sis/v3/counterexamples.py    # NEW: cross-catalog negative-evidence index
  - src/sis/v3/catalog.py            # NEW: namespace scopes + cascade_suspend
  - src/sis/v3/guidance_gateway.py   # NEW: shadow/diagnostic/conditional phases + kill switch + acceptance log
  - src/sis/v3/retrieval.py          # AblationFlags (benchmark-only gate removal)
  - src/sis/v3/benchmark.py          # wilson_ci + mcnemar_p + per-arm solve-rate CIs in report
  - src/sis/v3/contracts.py          # OutcomeEnvelopeV2 record (V1 serialization untouched)
  - tests/v3/test_release_artifact.py
  - tests/v3/test_roadmap_modules.py
tests_added: 40
observed_outcomes:
  - "Full suite: 526 tests, 0 failures, 2 skips, run under -W error with zero warnings"
  - "RELEASE_SHA256.json covers 220 files; build_zip + ZIP-native verify() round-trips; verify_tree on fresh extraction + --compile passes"
  - "ZIP verifier rejects: missing manifest, extra/missing/tampered member, duplicate paths, symlinks, unsafe paths, oversized members — streaming, never extracts"
  - "OutcomeEnvelopeV2 verifies offline; forgery, tampered payload, unknown/revoked/wrong-purpose keys, nonce replay, expiry, and validity windows all fail closed"
  - "semantic_checks flags Sub->Add noncommutative->commutative swaps (remaining_balance class); commutative->commutative passes"
  - "GuidanceGateway: shadow abstains but logs would_recommend; diagnostic reports reasons without procedure IDs; conditional serves; kill switch via file and SIS3_DISABLE env"
  - "Cascade suspension converts a revoked evidence digest into governed suspension decisions on dependent qualified records"
remaining_unknowns:
  - "Cross-repository scope promotion has no repository-disjoint evidence requirement enforced in code yet — scope is metadata, gate is procedural"
  - "OutcomeEnvelopeV2 is defined and tested but not yet wired into the benchmark/evaluator issuance path"
  - "mcnemar/wilson are correct statistics but zero real held-out tasks have been run; M5 efficacy gate untouched"
  - "SQLite close() exists everywhere; WAL databases still leave -wal/-shm files by design until final checkpoint"
next_gate: "Wire envelope issuance into verifier path; enforce cross-repo evidence count in promotion; pre-register held-out suite"
```

## SIS-311/312/313 — receipt authority, transactional ledger, fail-closed retrieval

```yaml
phase_id: v31-integrity-closure-1
tickets: [SIS-311, SIS-312, SIS-313]
status: implemented_and_tested
changed_files:
  - src/sis/v3/verifier.py      # verify_and_resolve_receipt + ExpectedProtocol protocol binding
  - src/sis/v3/promotion.py     # PromotionDecisionV2 (post-state inside signed body), stale-head
                              # optimistic concurrency, crash-tail recovery, full V2 replay verify,
                              # projected_statuses, qualified_projection_drift
  - src/sis/v3/procedures.py    # add() rejects status=qualified without allow_qualified
  - src/sis/v3/contracts.py     # PromotionDecisionV2 record; expired/revoked/stale_evidence/
                              # unsupported_context reason codes
  - src/sis/v3/retrieval.py     # expires_at enforcement (malformed -> expired), revoked digest
                              # denylist, now injection
  - src/sis/v3/guidance.py      # revoked/now pass-through, policy reasons updated
  - tests/v3/test_promotion.py  # +8 receipt-authority + 6 ledger/projection tests
  - tests/v3/test_retrieval.py  # +5 expiry/revocation tests
tests_added: 14
observed_outcomes:
  - "Full suite: 546 tests, 0 failures, 2 skips under -W error"
  - "signed-FAIL->tampered-PASS -> receipt_digest_mismatch, head unchanged; substituted receipt, forged signature, untrusted/revoked signer, protocol mismatch, malformed/unresolvable receipts all rejected with stable reason codes"
  - "suspended->qualified requalification requires fresh verified receipts + evaluator signature"
  - "direct store.add(status=qualified) rejected; only allow_qualified fixtures/controller mint qualified state"
  - "V2 decisions sign the complete post-state (new_record_digest + new_qualified_head) BEFORE either signature; verify() replays chain + evaluator/operator signatures + transition legality + head continuity; torn trailing writes truncated on restart"
  - "expected_old_head optimistic-concurrency guard rejects stale views"
  - "expired/malformed-expiry/revoked-digest procedures abstain with stable reason codes; malformed expires_at rejected at contract parse"
remaining_unknowns:
  - "V1 decisions verify for chain/digest only (pre-state not inside their signed body) — flagged legacy_v1 in verify()"
  - "Qualified-catalog materialized projection exists (projected_statuses) but retrieval still reads record.status directly — full projection-only retrieval is the next hardening step"
  - "min_pass_receipts/min_distinct_repos are policy knobs; recommended pilot defaults (>=3 tasks, >=2 repos) are documented, not yet enforced as defaults"
next_gate: "SIS-314 release attestation; then v3.2 governed artifact channel + typed AST repair procedures"
```

## v3.1-alpha — authority transfer: transactional decision+revision store (PR-01/PR-02)

```yaml
phase_id: v31-authority-transfer
tickets: [PR-01, PR-02]
status: implemented_and_tested
baseline: SIS-2026-10-24-FULL-UPGRADED-V2-Authority-Recovery.zip (sha256 f62ef2a500fe487cf17fb1b7d19862ab0eb686c411663b89d02011f310a7d077)
changed_files:
  - src/sis/v3/authority_db.py        # NEW: single SQLite WAL store — decision+revision commit in one transaction
  - src/sis/v3/promotion.py           # PromotionController now persists via AuthorityDB.commit_transition; no JSONL journal
  - src/sis/v3/procedures.py          # allow_qualified removed; intake accepts rev-1 draft/candidate only
  - src/sis/v3/secure_guidance.py     # StrictGuidanceGateway typed over AuthorityDB
  - src/sis/v3/authority.py           # AuthorizedCatalogView docstring updated (same strict projection contract)
  - src/sis/v3/compat/guidance_gateway.py  # NEW: legacy GuidanceGateway moved to compat namespace (never production)
  - src/sis/v3/guidance_gateway.py    # deprecation shim -> compat import
  - tools/migrate_authority.py        # NEW: dry-run reconcile + quarantine + signed report + reversible cutover
  - tests/v3/authority_testkit.py     # NEW: authenticated test factories (real signed receipts + real decisions)
  - tests/v3/test_authority_db.py     # NEW: fault injection x8 steps, concurrency, restart, torn write, double promotion
  - tests/v3/test_promotion.py        # migrated: SQL-level tamper tests replace JSONL journal tamper tests
  - tests/v3/test_authority_recovery.py  # rewritten: atomic-commit semantics (zero partial state on fault)
  - tests/v3/test_retrieval.py        # _store fixture now produces real promoted state via AuthorityDB
  - tests/v3/test_roadmap_modules.py  # CatalogTests over AuthorityDB; gateway tests use compat namespace
  - tests/v3/test_procedures.py       # add() contract updated; replace_record test removed
  - tests/v3/test_upgrade_integrity_learning.py  # 3-layer I-1 test: write reject + verify + serve abstain
tests_added: 16 (authority_db) + migrated suites
observed_outcomes:
  - "Full suite: 563 passed, 2 skipped"
  - "allow_qualified bypass removed: no caller can mint qualified state; direct add(status!=draft/candidate) raises"
  - "decision+revision visible atomically: fault injected at each of 8 commit steps leaves zero partial state"
  - "4-process concurrent writers serialize; exactly one commits each edge; verify() stays clean"
  - "stale controller (same or second handle) rejected via in-transaction head re-check"
  - "restart preserves chain head + qualified head; corrupt page/decision row fails closed (no silent truncation)"
  - "migration tool: dry-run reconcile quarantines unauthorized rev-1 fixture seeds; execute produces signed report"
remaining_unknowns:
  - "receipt_binding stores digest+task+repo only; full receipt custody stays in evaluator store"
  - "backup/restore tested; power-fail mid-fsync relies on SQLite WAL semantics (platform dependent)"
  - "scope_grant/revocation tables exist but policy integration is PR-03/PR-04"
next_gate: "PR-03 verified scope grants + repository registry (G2)"
```

## v3.1-alpha — verified scope grants + repository registry (PR-03, G2)

```yaml
phase_id: v31-verified-scope-grants
tickets: [PR-03]
status: implemented_and_tested
baseline: codex/sis-authority-transfer-qualification (PR-01/PR-02 commits)
changed_files:
  - src/sis/v3/contracts.py           # RepositoryIdentityV1 + ScopeGrantV1 records + validation
  - src/sis/v3/repository_registry.py # NEW: trusted registry — signed identities, alias rejection, signed JSONL load/dump
  - src/sis/v3/scope_grants.py        # NEW: ScopeGrantAuthority — issue/verify/permits, distinct-registry evidence rule
  - src/sis/v3/authority_db.py        # commit_scope_grant (in-tx verify + nonce consume + receipt bindings), scope_grants(), receipts_for_grant(), commit_revocation()/revocations(), grant integrity in verify()
  - src/sis/v3/catalog.py             # set_scope + sidecar retired; scope_of projects committed grants on the current revision
  - src/sis/v3/secure_guidance.py     # registry-resolved requester identity; per-request grant re-verification; namespace_authorizer removed
  - tests/v3/authority_testkit.py     # registry/grant authenticated factories
  - tests/v3/test_scope_grants.py     # NEW: 26 adversarial + lifecycle tests
  - tests/v3/test_roadmap_modules.py  # CatalogTests rewritten onto grant projection
observed_outcomes:
  - "Full suite: 610 passed, 2 skipped"
  - "repository-local default serves with no grant; unresolved/empty repository_id abstains"
  - "cross-repo grant serves target repo only; family grant covers family members, does not leak across families"
  - "forged signature, untrusted signer, unbound authority, missing verifier, nonce replay: all rejected"
  - "post-commit tamper of grant_json -> abstain + verify() reports mismatch; grant row deletion -> abstain, not corruption"
  - "expired grants abstain per-request via injected now; expired grants cannot be issued"
  - "grant binds exact revision digest: re-qualification invalidates old grants; repo-local unaffected"
  - "registry rejects duplicate registry_id/tree/commit aliases and wrong-key identities; load fails closed on tampered lines"
  - "transfer evidence must resolve to >=2 distinct registry identities including source (and target for cross-repo)"
remaining_unknowns:
  - "registry store is in-memory/JSONL here; production custody (HSM/KMS + quorum) is a deployment concern"
  - "grant revocations() write path exists; cascade_suspend for revoked grant digests is PR-04"
  - "receipts_for_grant replays stored receipt JSON; custody of evaluator receipt originals remains external"
next_gate: "PR-04: artifact channel + revocations wiring; then independently evaluated paired study"
```

## v3.1-alpha — signed revocations + evidence cascade (PR-04, G3)

```yaml
phase_id: v31-signed-revocations
tickets: [PR-04]
status: implemented_and_tested
baseline: codex/sis-authority-transfer-qualification (through 8a1c6ea)
changed_files:
  - src/sis/v3/contracts.py           # RevocationV1 record (record|receipt|grant|signer kinds)
  - src/sis/v3/revocation.py          # NEW: RevocationAuthority — signed issuance + verification
  - src/sis/v3/authority_db.py        # commit_revocation: signed record + in-tx verifier; revocation_json column; revocations() decode-verified reads; verify() checks revocation rows
  - src/sis/v3/promotion.py           # PromotionController.revoke(): commit + cascade_suspend for receipts, eval-key revocation for signers
  - src/sis/v3/scope_grants.py        # verify/permits honor committed revocation sets (grant digests, signer ids, receipt digests)
  - src/sis/v3/secure_guidance.py     # per-request committed-revocation resolution: record denylist, evidence-citing records denied, grant/signer revocation into permits
  - tests/v3/test_revocation.py       # NEW: 15 adversarial + enforcement tests
observed_outcomes:
  - "Full suite: 625 passed, 2 skipped"
  - "forged/untrusted-signer/unbound-authority/unsigned-verifier revocations rejected in-tx"
  - "record revocation denies on next request and survives restart"
  - "receipt revocation cascades: citing qualified records suspended via signed decisions; status change is decision-backed"
  - "receipt revocation denies citing records pre-cascade and invalidates grants citing the receipt"
  - "grant revocation stops cross-repo serving; owner-local unaffected"
  - "signer revocation stops its grants at serving and blocks new evaluator decisions"
  - "tampered revocation row -> undecodable_revocation in verify() + catalog_unavailable abstain"
  - "duplicate revocation is a conflict, not silent state"
remaining_unknowns:
  - "revocation signer custody is test-scope; production custody is a deployment concern"
  - "no revocation expiry/appeal semantics yet (kind=revocation-of-revocation not modeled)"
next_gate: "PR-05+: authenticated Codex runtime + execution qualification (Stage 2)"
```

## v3.1-alpha — execution qualification: hard budgets + auth gate (PR-05, Stage 2 start)

```yaml
phase_id: v31-execution-qualification
tickets: [PR-05]
status: implemented_and_tested
changed_files:
  - src/sis/v3/benchmark.py           # watchdog-thread arm execution (agent_timeout at wall_seconds), UsageMeter on ArmContext, verified|reported|unverified accounting in report
  - src/sis/v3/adapters/codex.py      # require_authentication fail-closed probe; usage(thread_id) — stream-derived token/tool counters
  - tests/v3/test_execution_qualification.py  # NEW: 10 tests
observed_outcomes:
  - "Full suite: 635 passed, 2 skipped"
  - "runaway arm abandoned at wall_seconds → error=agent_timeout + budget_exceeded; suite does not wait"
  - "meter-recorded usage reports accounting=verified; agent-dict usage=reported; absent=unverified"
  - "metered token overrun flags budget_exceeded and excludes the arm from solved counts"
  - "require_authentication: unauthenticated/missing-probe clients fail closed (authentication_failed | authentication_unverifiable)"
  - "adapter.usage(thread_id) returns stream-derived total_tokens and tool_request count; never agent self-report"
remaining_unknowns:
  - "live SDK authentication is probed not exercised — no real Codex credentials were used; no live-integration claim"
  - "thread-based preemption cannot kill arbitrary in-process code; subprocess agents should run via WorkspaceExecutor"
  - "token accounting depends on SDK token_usage events; SDKs that do not report remain unverified"
next_gate: "PR-06+: trustworthy source-change capture + learning loop"
```

## v3.1-alpha — trustworthy source-change capture (PR-06)

```yaml
phase_id: v31-source-change-capture
tickets: [PR-06]
status: implemented_and_tested
changed_files:
  - src/sis/v3/contracts.py           # SourceChangeV1 record + validation
  - src/sis/v3/source_change.py       # NEW: capture_change + verify_capture
  - tests/v3/test_source_change.py    # NEW: 7 tests
observed_outcomes:
  - "Full suite: 642 passed, 2 skipped"
  - "all digests are computed by the capture path (scan_tree + per-file sha256 + self-generated unified diff); agent-reported digests can never enter the record"
  - "expected_before_digest anchors capture to the attested workspace base; mismatch refuses"
  - "added/removed/modified classification; binary files marked, text files unified-diffed"
  - "identical trees refuse; tampered diff bytes detected by verify_capture; captures are deterministic under fixed now"
remaining_unknowns:
  - "capture binds filesystem trees only — mapping a change to a specific agent turn requires the episode/attempt correlation (adapter side)"
  - "no semantic judgment: a captured change is evidence, not correctness"
next_gate: "PR-07+: observe-learn-verify-reuse wiring + strategic/structural induction"
```

## v3.1-alpha — trustworthy source-change capture (PR-06)

```yaml
phase_id: v31-source-change-capture
tickets: [PR-06]
status: implemented_and_tested
changed_files:
  - src/sis/v3/contracts.py           # SourceChangeV1 record + validation
  - src/sis/v3/source_change.py       # NEW: capture_change + verify_capture
  - tests/v3/test_source_change.py    # NEW: 7 tests
observed_outcomes:
  - "Full suite: 642 passed, 2 skipped"
  - "all digests are computed by the capture path (scan_tree + per-file sha256 + self-generated unified diff); agent-reported digests can never enter the record"
  - "expected_before_digest anchors capture to the attested workspace base; mismatch refuses"
  - "added/removed/modified classification; binary files marked, text files unified-diffed"
  - "identical trees refuse; tampered diff bytes detected by verify_capture; captures are deterministic under fixed now"
remaining_unknowns:
  - "capture binds filesystem trees only — mapping a change to a specific agent turn requires the episode/attempt correlation (adapter side)"
  - "no semantic judgment: a captured change is evidence, not correctness"
next_gate: "PR-07+: observe-learn-verify-reuse wiring + strategic/structural induction"
```

## v3.1-alpha — evidence-bound induction (PR-07)

```yaml
phase_id: v31-learning-evidence-binding
tickets: [PR-07]
status: implemented_and_tested
changed_files:
  - src/sis/v3/learning/symbolic.py    # induce_from_source_change + source_change_digest lineage
  - src/sis/v3/learning/strategies.py  # receipt_resolver independent verification
  - tests/v3/test_learning_evidence.py # NEW: 8 tests
observed_outcomes:
  - "Full suite: 650 passed, 2 skipped"
  - "induce_from_source_change requires a captured SourceChangeV1 + byte-exact file contents verified against file_changes digests; wrong bytes, multi-file changes, and non-operator edits are rejected"
  - "induced candidates carry source_change_digest lineage to the capture artifact"
  - "induce_strategies accepts an optional receipt_resolver; every episode receipt must resolve to committed evidence — unresolved/forged digests rejected"
  - "all learned outputs remain status=candidate; no qualification, persistence, or serving path added"
remaining_unknowns:
  - "evidence binding is not causality: transfer requires repository-disjoint holdout + independent promotion (still pending, M6)"
  - "structural induction remains single-operator-AST-only; multi-node and cross-language transforms unsupported by design"
next_gate: "observe-learn-verify-reuse wiring; M5 independent candidate optimization"
```

## v3.1-alpha — loop composition + repo-disjoint evaluation (PR-08, M6 harness)

```yaml
phase_id: v31-loop-and-evaluation
tickets: [PR-08, M6-harness]
status: implemented_and_tested
changed_files:
  - src/sis/v3/learning/pipeline.py    # NEW: observe-* orchestration
  - src/sis/v3/evaluation.py           # NEW: disjointness + paired summary
  - tests/v3/test_learning_loop.py     # NEW: 9 tests
  - docs/v3/G4_GATE_REPORT.md          # NEW
observed_outcomes:
  - "Full suite: 659 passed, 2 skipped"
  - "single audited entry point composes capture→induction→candidate→intake; all outputs land as candidate rev-1, promotion stays external"
  - "assert_repository_disjoint fails any eval task whose repo digest supplied learning evidence; paired_summary extracts the preregistered D-vs-A contrast"
remaining_unknowns:
  - "the decisive repository-disjoint live study has NOT been run — harness is qualified, efficacy is not"
next_gate: "run the preregistered paired study; M7 operational hardening"
```

## v3.1-alpha — M7 operational hardening

```yaml
phase_id: v31-operational-hardening
tickets: [M7]
status: documented
changed_files:
  - docs/v3/OPERATIONS.md  # NEW: key custody, DB backup, revocation drill, execution boundary, release procedure
observed_outcomes:
  - "deployment trust boundaries documented; all enforcement-side behaviors (fail-closed verify, per-request revocation, hard budgets) already implemented and tested"
remaining_unknowns:
  - "efficacy gate remains OPEN until the preregistered repo-disjoint study runs"
```

## v3.1-alpha — executable study runner + end-to-end loop validation

```yaml
phase_id: v31-study-runner-e2e
tickets: [M6-runner, e2e]
status: implemented_and_tested
changed_files:
  - tools/run_paired_study.py    # NEW: preregistered study entry point
  - tests/v3/test_e2e_loop.py    # NEW: 2 tests — capture→induce→promote→grant→serve
observed_outcomes:
  - "Full suite: 661 passed, 2 skipped"
  - "e2e test drives a learned strategy candidate through real signed promotion, a committed cross-repo grant, and StrictGuidanceGateway serving — decision=recommend"
  - "run_paired_study.py enforces repo disjointness, hard budgets, and the preregistered D-vs-A decision rule; exits 0 only on PASS"
remaining_unknowns:
  - "the study has still not been executed against live Codex — efficacy gate OPEN"
```

## v3.1-alpha — live study attempt #1 (authenticated Codex, M6)

```yaml
phase_id: v31-live-study-1
tickets: [M6-live]
status: executed_gate_not_met
changed_files:
  - tools/live_study.py  # NEW: self-contained live paired study
observed_outcomes:
  - "authenticated codex exec (ChatGPT login) ran all 8 arm executions (2 tasks x 4 arms), 16-35s each, zero errors, zero budget violations"
  - "arm D received real gateway-served guidance (signed promotion + committed cross-repo grant); grading was evaluator-private pytest injected at evaluation time"
  - "result: A=2/2, B=2/2, C=2/2, D=2/2 -> solved_delta=0, mcnemar_p=1.0 -> efficacy gate NOT MET"
  - "corpus had a ceiling effect: trivial one-line bugs are solved by baseline Codex unaided; n=2 is also far below McNemar power (need >=6 all-discordant pairs for p<=0.05)"
  - "debugging found the runner PATH resolves python3 to the Xcode stub without pytest; verifier argv must use sys.executable"
remaining_unknowns:
  - "efficacy gate remains OPEN: needs a harder held-out corpus where baseline Codex actually fails, and >=8 tasks for statistical power"
  - "run_paired_study.py spec runner lacks verifier wiring (superseded by live_study.py for now)"
```

## v3.1-alpha — live study #2: real signal, gate still open (M6)

```yaml
phase_id: v31-live-study-2
status: executed_signal_positive_gate_not_met
observed_outcomes:
  - "run 1 (ceiling corpus): all arms 2/2 -> delta=0"
  - "run 2 (convention corpus, pre-steps-fix): A=4,D=4 -> delta=0; exposed that served guidance never transmitted procedure steps"
  - "FIX: helpful_next_checks now serves the winning procedure's steps"
  - "run 3 (post-fix): A=3, B=4, C=3, D=5 -> delta=+2, mcnemar_p=0.5, zero losses; D won money+clamp where all unguided arms failed"
  - "slug failed in every arm incl. D -> hint underdetermined (apostrophe rule)"
remaining_unknowns:
  - "efficacy gate remains OPEN: direction is positive but n=6 is underpowered; needs >=6 all-discordant pairs -> more convention-hard tasks and sharper hints"
```
