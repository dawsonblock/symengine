# Changelog

## 2026-11-10 — SIS v3.3.6 trust, memory-enforcement and benchmark repair (V336-01…V336-04)

V336-01 — memory trust profiles are a closed enumeration:

- `MemoryTrustProfile` validates at construction. Only `development` and
  `production` modes exist; a production profile must enable every
  control (signed records, evaluator evidence, chain signature, witness,
  registered-task verification), and a development profile must enable
  none. The v3.3.5 bypass — `name="production"` with every flag false —
  now raises `production_profile_requires_every_trust_control`.
- `trust_status()` derives trust from `production_trust` plus the
  controls the store actually holds (signer keys, chain key, witness,
  verifier), not from the profile-name string. Renaming or flag-forging
  a profile object cannot manufacture trust.
- A production store refuses construction when the verifier lacks
  `registered_task`, so missing registered-task verification fails
  before any record is accepted.
- 18 regressions in `tests/v3/test_v336_trust_profile.py`, including the
  exact audit bypass, unsigned legacy records, partial custom profiles,
  forged profile objects and removed controls.

V336-02 — process-level hard-memory enforcement:

- `sis.enforced_induction.run_induction_enforced` runs `induce` in a
  separate Python process capped by `RLIMIT_AS` before the interpreter
  starts. The in-process `tracemalloc` budget remains explicitly soft
  and diagnostic; it is not the hard claim.
- `MemoryEnforcementReceipt` is valid only when the child observed the
  exact requested soft and hard limit. `EnforcedInduction.hard_memory_verified`
  requires a valid receipt, a completed child and no memory kill; a
  timeout, forged report, mismatched limit or signal death never reports
  hard success.
- 18 regressions in `tests/v3/test_v336_memory_enforcement.py`. macOS
  cannot lower `RLIMIT_AS` below the interpreter's current address
  space, so the meaningful-cap qualification remains a Linux-worker
  gate; the protocol and refusal paths are tested on both.

V336-03 — benchmark semantics:

- `tools/benchmark_induction.py` no longer reports
  `rule_recovered = rule is not None`. Candidate existence, intended
  structure, bounded equivalence, holdout accuracy and search completion
  are separate metrics; `exact_recovery_verified` is the only exact
  recovery claim and requires a non-ambiguous result.
- On the default non-negative domain the search returns
  `absdiff(x[n-2] * x[n-1], -2)`, which matches every example but is a
  different function; the tool now reports it as a candidate with the
  wrong structure, not as recovery. `--input-min` adds negative values,
  and `--equivalence z3` proves equivalence over the declared box.
- 9 regressions in `tests/v3/test_v336_benchmark_semantics.py`.

V336-04 — release seal:

- Package version 3.3.6. The system interpreter (psycopg, cryptography
  and z3 4.15.4) runs 1319 passed / 13 skipped; a fresh venv with pytest
  8.4.2 and optional z3-solver 4.16.0, no PostgreSQL driver and no
  `cryptography`, runs 1318 passed / 14 skipped (the extra skip is the
  Ed25519 cross-check). Without z3 the same venv skips the three
  z3-gated tests (1315 passed / 17 skipped). No failures in any
  configuration. Release
  packaging and independent artifact verification are recorded in
  `docs/v3/QUALIFICATION_REPORT_V3_3_6.md` and `release/`.
- Provenance signing still requires an externally trusted key; without
  one the bundle is explicitly unsigned qualification evidence, not an
  authentic release seal.

## 2026-11-10 — SIS v3.3.5 resource-security repair (V335-01…V335-04)

V335-01 — memory-budget lifecycle:

- `SearchState.start()` enables `max_memory_bytes` whenever a cap is set,
  whether or not the caller already owns a tracer. A caller-owned tracer
  is measured from its current baseline and is never stopped; `close()`
  stops only a tracer the search started.
- The cap is an incremental soft budget over Python allocations
  (`current - baseline`), sampled at resource-check points and reported
  as `observed_peak_bytes` and `memory_limit_source`. It is not an OS RSS
  limit and cannot see native-extension allocations.
- The budget now fails closed when its measurement disappears. If the
  tracer stops mid-search the check records `memory_tracer_lost`; if it
  is stopped and restarted (or its peak is reset) it records
  `memory_tracer_restarted`. Either way the search reports
  `resource_exhausted` instead of returning success with a zero-growth
  reading.
- `spend_signature()` checks the cap before incrementing, so the reported
  count never exceeds `max_signature_checks`.

V335-02 — production verdict trust boundary:

- `classify_execution(production=True)` is fail-closed and always returns
  SANDBOX_FAILURE; the forgeable `isolation_verification` argument is
  removed. Only `classify_production_execution(receipt, attestation,
  policy, ...)` can return TASK_PASS, and only after parsing a real
  `IsolationAttestationV1` and checking signer, backend allowlist,
  policy/image digests, required properties, expiry, and the exact
  receipt/command/workspace/worker binding.
- `ProductionIsolationPolicy` gains `revoked_keys`; a revoked signer is
  rejected as `signer_revoked`. The policy digest commits to the new
  field, so every policy digest changes on upgrade, including a policy
  with no revocations; a deployment that pins a digest must recompute it.

V335-03 — explicit memory chain membership:

- Trusted memory reads require the exact record being returned to own a
  `memory_chain` entry. Membership is one statement joining `experience`
  to `memory_chain`, so the row and its chain entry are read from the
  same snapshot rather than inferred from a store-wide invariant
  evaluated earlier.
- A record that was never ingested, whose row was removed, or that
  appears between the chain check and the row read raises
  `experience_unchained` instead of being reported as trusted.
  Membership is not provenance: signature and lineage checks still
  decide trust.
- Development stores keep reading legacy rows without chain enforcement.

V335-04 — release seal:

- Package version 3.3.5; `RELEASE_SHA256.json` and the release bundle are
  regenerated for the repaired tree and resealed under the release
  provenance key.
- The full suite runs in a clean environment with pinned pytest 8.4.2;
  results are recorded in `docs/v3/QUALIFICATION_REPORT_V3_3_5.md` and
  `release/release_manifest.json`.

## 2026-11-09 — SIS v3.3.4 G1/G3 hardening (development line)

Gate G1 — receipt identity:

- `OutcomeVerifier.load_receipt` recomputes the canonical digest and
  fails as `receipt_digest_mismatch` when the stored artifact does not
  hash to the address it was read from; unparseable artifacts fail as
  `receipt_malformed`. A valid signature over a different evaluation is
  no longer evidence for this one.
- `verify_experience_evidence` independently requires the resolved
  artifact to hash to `record.outcome_receipt_digest`, so a storage
  resolver cannot substitute another valid receipt.
- Journal load validates entry shape, rejects duplicate receipt lines
  and replayed nonces, and binds each entry to its persisted receipt on
  digest, receipt ID, task, repository, criterion, outcome, signer and
  attempt/execution where the artifact carries them. Only entries
  re-authenticated under a trusted key corroborate an execution digest;
  missing artifacts and rotated-out signers are unverified. Journal
  entries now record `signer_key_id`; legacy journals still load.
- 13 adversarial regressions cover substitution, cross-signer replay,
  protocol swap, missing/altered/replayed receipts, and a corrupted
  journal.

Gate G3 — memory trust:

- `MemoryTrustProfile.development()` / `.production()` make the trust
  configuration explicit. Production refuses to construct without
  signed-record keys, a custodian chain key, an external witness, and
  an evaluator verifier; development reports every record as
  `untrusted:development_profile`.
- `sis.v3.memory_witness.MemoryWitness` is an append-only, separately
  signed witness of `(sequence, memory_head_digest)` stored outside the
  database directory. Production reads require the store to match the
  newest witness; a restored snapshot is `memory_rollback_detected` and
  `reconcile_witness()` cannot re-anchor it. A rebuild over an existing
  witness requires a fresh epoch.
- Production ingest and reads run the full
  experience → outcome → execution → registered-task lineage,
  including the exact suite commitment; `repair_chain` refuses to
  chain legacy rows.
- `retrieve_memories` separates trust, applicability and usefulness,
  with `trust_check` as a hard gate before scoring and `on_reject`
  reporting each stage.
- 34 regressions cover profile enforcement, rollback, stale and
  tampered witnesses, database rewrites, lineage, and retrieval gates.

Gate G4 — bounded symbolic induction:

- Early stopping now consults development data. A shallow rule that fits
  only the training rows no longer stops deepening; `dev` decides
  selection and a sealed `holdout` decides the final status. The result
  reports `holdout_sealed` and never presents selection data as
  independent generalization evidence.
- `SearchBudget` makes five limits explicit: `max_candidates`,
  `max_signature_checks`, `max_wall_seconds`, `max_memory_bytes`, and
  `max_expression_depth`. Results report `search_outcome`
  (completed/truncated/resource_exhausted) and `limits_hit`; the memory
  limit is opt-in because tracing costs about 5x on wide searches.
- Enumeration uses a cheap train+development signature and computes the
  full probe signature only for fitting candidates, preserving ambiguity
  rivals while cutting the 16-field regression from 12.5s to 2.0s.
- Candidate ordering ranks development fit, ambiguity, complexity, and
  fingerprint; stage-2 mids rank residual variance then complexity.
- Counterexample-guided refinement uses an optional labelled oracle,
  bounded rounds, and never treats generated probes as ground truth.
- `validation.check_inputs` accepts up to 64 fields (was 16) so the
  scalability matrix can run; 65 fields still fail closed.
- `tools/benchmark_induction.py` records the 2/4/8/16/32/64-field matrix:
  2-16 recover with a sealed holdout pass, 32 recovers at the
  signature-check limit, 64 truncates at the candidate cap. Evidence:
  `evidence/benchmark/v334_induction_scalability.json`.
- 19 regressions cover budget validation, each limit, development-guided
  deepening, sealed-holdout status, oracle refinement, and wide fields.

Gate G2 — production isolation boundary:

- `ProductionIsolationPolicy` makes every containment requirement
  mandatory: backend allowlist, trusted isolator keys, pinned policy and
  image digests, required properties, expiry and freshness, and the
  exact receipt/command/workspace/worker binding. A policy with any
  omitted requirement refuses to construct.
- `verify_production_isolation` returns a typed
  `IsolationVerification` naming the receipt, attestation, policy,
  backend, worker, signer and verified properties.
  `classify_execution` accepts only that object for production; the
  caller-supplied `isolation_attested` boolean is gone.
- `OutcomeVerifier` accepts an `isolation_policy` and, for production,
  requires a signed attestation for the exact execution — passed
  directly or fetched by a post-execution resolver. Missing, expired,
  reused, or property-incomplete evidence rejects the evaluation
  instead of issuing a pass/fail receipt.
- `OutcomeReceiptV2` binds `attempt_id`, `execution_receipt_digest`,
  `isolation_attestation_digest`, `evaluator_runtime_digest`,
  `evaluation_protocol_digest`, `worker_identity` and
  `sandbox_policy_digest` under a separate signature domain. Production
  evaluation requires an attempt identity, so memory lineage can check
  it against the signed outcome instead of skipping it. V1 remains
  readable for historical verification; production evaluations issue V2.
- `issue_attestation_for_receipt` and
  `tools/issue_worker_attestation.py` give an independent isolator a real
  issuance path; both refuse a receipt that self-reports
  `isolation:unverified_local`.
- 44 regressions cover policy validation, every rejection reason, typed
  classification, V2 issuance/reload/restart, V1/V2 coexistence,
  attestation reuse, and the local backend's permanent disqualification.
  Executor red-team cases (symlink, network, environment, fork, resource
  exhaustion) remain in `test_runner_isolation.py`.

- `sis.v3.linux_worker` is a rootless bubblewrap scaffold: user/PID/
  network/IPC/UTS/cgroup namespaces, read-only system binds, one
  writable workspace, address-space/CPU/file-size/descriptor/process
  limits, wall-clock kill of the whole process group, bounded output,
  and a factual receipt. It fails closed off Linux or without bwrap and
  never holds evaluator keys.
- `tools/linux_worker_probe.py` tests the target host for namespace
  availability, network denial, filesystem confinement, fork/memory
  limits, wall-clock and process-group kill, and environment scrubbing.
  It exits 2 off Linux; a passing run is platform evidence, not a
  qualification claim.
- 21 scaffold tests cover argv confinement, the hardened /etc mount,
  cgroup leaf behavior, the seccomp filter and wrapper, config
  validation, fail-closed behavior, and the absence of evaluator key
  access (one real-cgroup test skips off Linux).
- The worker now applies its own seccomp filter inside the sandbox
  after bwrap setup: the command reports `Seccomp: 2`, and `unshare`
  and `mount` return `EPERM`. The wrapper is bound read-only at
  `/opt/sis-seccomp`; `seccomp:inner_filter` is the receipt marker the
  isolation policy can require.
- The probe was run on Debian 12 (bubblewrap 0.8.0, Python 3.11.2,
  LinuxKit 7.0.14) with a host-mounted cgroup v2 hierarchy: 13/13
  probes passed. cgroup v2 `pids.max`/`memory.max` enforce the fork and
  memory bounds, and `/etc` is a read-only tmpfs of individual files (a
  plain `--dir /etc` was writable and failed the write-escape probe).
  In the full probe sequence the fork bomb was stopped by the wall
  clock; an isolated direct test stopped it in 0.84s with
  `BlockingIOError`, so the bound is enforced either way. The container
  was privileged because that kernel denied unprivileged user
  namespaces; the result validates the bubblewrap configuration, not
  the container's containment. Evidence:
  `evidence/sandbox/v334_linux_worker_probe.json` and `_env.json`.

Suite: 1253 passed, 13 skipped. Two release-seal checks
(`ReleaseIdentityTests` commit binding and inventory)
remains red until `release/` is re-signed with the release key in
Phase 5; the source change itself is covered by the baseline record in
`evidence/baseline/v334_baseline.json`.

## 2026-11-08 — SIS v3.3.3 trust-boundary repair

Closes the five externally audited defects reproduced in
`tests/v3/test_v333_trust_boundary.py`:

- Isolation self-attestation removed. `LocalSubprocessExecutor` can no
  longer mint `isolation:verified` (the `verified_isolation` flag is
  rejected for this backend) and production runs always refuse. New
  `IsolationAttestationV1` plus `sis.v3.isolation`: an independently
  trusted isolator signs the backend, worker identity, policy/image
  digests, command spec, workspace input tree and the exact execution
  receipt; `classify_execution(production=True)` requires that verified
  verdict, never a self-reported marker.
- Experience evidence binds the full evaluation lineage.
  `ExperienceRecordV2` is evaluator-signed and binds task, attempt,
  repository snapshot and execution receipt; `verify_experience_evidence`
  re-checks every binding against the authenticated artifact plus the
  evaluator journal (`execution_digest_for`). V1 records are
  legacy/untrusted reads only.
- Memory-store tamper resistance. With `trusted_signer_keys` the store
  accepts and serves only signed V2 records, re-verifying on every
  access; the append-only `memory_chain` (custodian-signed via
  `chain_key`) commits every record digest in order so deletion,
  rewrites and forged entries fail closed. `repair_chain` migrates
  pre-chain databases (`rebuild=True` for a corrupt chain or mid-stream
  key adoption), `last_chain_failure` reports the cause, and
  `head_digest` is the external rewind witness — now pinned into the
  governed campaign evidence.
- Paraphrase-tolerant suppression. `suppression_match` adds
  content-token containment over function-word filtering, so negated or
  rephrased counterexamples still suppress unsafe memory transfer —
  heuristic text matching that deliberately over-fires toward
  suppression; `retrieve_memories(on_suppress=...)` audits each firing.
- Signature-directed symbolic search. Stage-2 induction compares
  evaluation signatures over train+validation+probe inputs and emits
  only combinations guaranteed to fit, closing the enumeration-order
  starvation that hid representable rules inside the candidate budget.
- Release provenance bound to source. Inventory, manifest and DSSE
  envelope regenerated for the 384-file tree; a suite test now fails
  when release metadata predates covered source.
- Hardening fixes in this line: malformed `memory_chain` signatures and
  caller-supplied `schema_version` in record issuance fail closed;
  chain custody without record trust still verifies chain integrity on
  reads; the production-refusal error is named
  `local_backend_not_production_qualified`.

The previously unreleased review corrections below are included in this
archive.

## Unreleased — review corrections

- Evaluator key custody: the Ed25519 seed is published with an exclusive
  create (`O_EXCL` on POSIX, `CREATE_NEW` plus a protected DACL on
  Windows) and the payload is written through that same validated
  handle, so a losing creator can never replace or delete another
  creator's material. A concurrent start waits out the winner's payload
  write instead of failing on a half-created seed; a seed that never
  reaches 32 bytes still fails closed. A missing `ed25519.pub` left by
  an interrupted publish is rebuilt from the seed, while an existing
  full record is never rewritten.
- The evaluator key directory is created private and a pre-existing
  directory is verified, never re-permissioned — POSIX now matches the
  Windows behaviour instead of silently `chmod`-ing a location the
  process did not create. Concurrent creation of that directory
  converges on the verified winner instead of raising
  `FileExistsError` out of the constructor. The Win32 layer caches its
  `advapi32`/`kernel32` bindings, derives the ACE trustee allow-list
  from the caller SID directly instead of re-parsing rendered SDDL, and
  requests `FILE_READ_ATTRIBUTES` alongside `READ_CONTROL` on the
  handles it queries with `GetFileInformationByHandleEx`.
- `preregister` refuses a powered plan whose declared `sample_size` is
  below the recomputed power floor. `allow_underpowered=True` is the
  explicit, digest-visible opt-out (`power_analysis.underpowered_declared`)
  for a deliberately exploratory run; `powered=False` registers a
  diagnostic screen. Diagnostic plans, and forgeries that mix the
  diagnostic label with a power block, can never satisfy production
  qualification.
- `QualificationValidator` recomputes the power floor and adds
  `protocol_power_analysis_valid` and `sample_count_meets_power_analysis`;
  `_protocol_conformance` flags a forged `required_n`
  (`power_analysis_required_n_mismatch`), an underpowered run, and a
  non-positive declared sample size.
- `ProtocolRegistry` stores and returns deep snapshots, so a caller
  cannot mutate a registered protocol after the digest was computed.
- New `sis.vault_storage` helpers — `private_directory`,
  `ensure_private_directory`, `assert_private_acl`, `create_private_file`
  — replace the ad-hoc POSIX/Windows permission handling in the
  evaluator key store.
- `AuthorityDB.backup` and `SqliteControlPlane.__init__` close their
  SQLite connections on every path, so a failed open no longer leaks a
  handle (which keeps the file locked on Windows); a close that fails
  cannot mask the original error, and `close()` is a no-op after a
  failed open.
- `.gitattributes` pins LF for the v3 contract schemas and signed test
  fixtures; CI adds a macOS leg and the Codex CLI adapter test now has a
  platform-native fake executable.
- `docs/v3/QUALIFICATION_REPORT.md` refreshed: the SQLite control-plane
  tests are tracked in Git, the earlier sandbox deselections no longer
  apply to the current run, and the recorded suite/inventory results
  match this tree. The historical v3.3.0 report moved verbatim to
  `docs/v3/QUALIFICATION_REPORT_V3_3_0.md`, so the development report
  carries a single top-level heading.
- Evidence-qualification gates hardened: `QualificationPolicy` requires
  paired baseline outcomes by default (`require_paired_outcomes=True`;
  `False` remains the explicit, digest-visible legacy opt-out), a
  certificate that pairs only some receipts never qualifies, claimed
  intervals must cover the Newcombe interval reconstructed at the
  claimed confidence level, and `primary_metric` must agree across
  policy, certificate and protocol.
- The CLI/HTTP smoke test now reads `sis.__version__` instead of asserting
  the stale `3.3.1` string.
- SQLite `-wal`, `-shm` and `-journal` sidecars are excluded from the
  release inventory and `.gitignore`, so running the CLI in the repository
  root no longer makes `verify_release.py` fail.
- `sis --version` reports the package version.
- Release packaging derives its default archive name from the package
  version instead of a hardcoded v3.3.1 label.
- Provenance verification accepts either a 64-hex key or the shipped
  `provenance_public_key.hex` file.
- The v3 contract schemas are included in the wheel and sdist.
- Release archives use a stable archive-internal project directory
  (`SIS-v<version>-...`) instead of the local checkout directory name.
- CI selects the release-inventory gate by event identity: tag pushes
  and published releases run `tools/check_release_ci.py --mode release`,
  where stale, missing, malformed or incomplete inventories fail;
  branch and PR runs use explicit development mode, which permits drift
  but reports it as not release verification.
- Documentation: README, release notes, threat model, operations wiring,
  architecture and the top-level doc cross-references now describe v3.3.2.
- Current suite status and remaining qualification limits are tracked in
  `docs/v3/QUALIFICATION_REPORT.md`.

## 2026-10-27 — SIS v3.3.2 authority consistency (M0–M5)

- Enforced execution identity in production: a gateway constructed with
  `require_execution_identity=False` is rejected, the signed session
  carries an explicit maximum lifetime (default 3600 s), and the
  authenticated caller's requester identity is checked against it.
- Added a shared control plane (`sis.v3.control_plane`) with SQLite and
  PostgreSQL profiles. `commit_authorization` consumes the signed
  session nonce and writes the decision receipt in one transaction, so
  two replicas racing with the same identity produce exactly one
  successful authorization. Production cannot construct a gateway
  without it.
- Witnessed custody in authority checkpoints: `revocation_head`,
  `supersession_head` and `custody_entry_count` are signed, compared on
  every production serve, and advanced monotonically. Restoring a
  pre-revocation custody directory or deleting the revocation log now
  fails closed. Checkpoints without custody history remain
  byte-compatible with v3.3.1, preserving old signatures and the
  previous-digest chain.
- Serving captures a witnessed snapshot, composes against it, then
  revalidates and commits. A revocation committed while guidance is
  being prepared aborts the decision instead of delivering revoked
  evidence.
- Replaced the shared visited set in `EvidenceCustodyStore.status` with
  active-path cycle detection plus memoization and depth/node bounds.
  Diamond-shaped evidence graphs are accepted; cycles are rejected.
- Added the authenticated v3 serving boundary
  (`sis.v3.serving_service`): bearer-authenticated `/v3/guidance` and
  `/v3/outcome`, default isolation of legacy `/v1` routes (also forced by `SIS_V3_ONLY=1`),
  custody freshness enforced in `serve()`, an explicit `advisory`
  decision distinct from abstention, and durable guidance-to-outcome
  records. `create_server` exposes the configured server for deployment
  and tests.
- Added 50 permanent security regression tests and executed baseline evidence:
  five target defects open on v3.3.1, zero open on this tree. Suite:
  **981 passed, 8 skipped**. See `docs/V332_AUTHORITY_CONSISTENCY.md`.
- Added opt-in PostgreSQL qualification tests (duplicate nonce, four
  concurrent replicas -> one commit, two-replica serving, outcome
  binding, monotonic head). With a disposable PostgreSQL 14.20 cluster
  the suite is **986 passed, 3 skipped**; see
  `evidence/v332/qualification.json`.
- Custody revocations/supersessions can publish the new witnessed head
  automatically via `EvidenceCustodyStore.bind_on_change`.
- Signed dependency links: `require_signed_links=True` and
  `bind_link_signer` make certificate dependency manifests tamper-evident;
  unsigned legacy links are cross-checked against the certificate's
  declared receipt and delivery digests.
- Exact outcome binding: `/v3/outcome` accepts `authorization_id` and
  rejects a decision that does not name the committed receipt.
- Production isolation gate: `LocalSubprocessExecutor(production=True)`
  refuses to run unless `verified_isolation=True`, and
  `classify_execution(production=True)` requires `isolation:verified`.
- Readiness: `GET /health` reports authority, custody and control-plane
  checks and returns 503 when degraded.
- Key rotation: a checkpoint signer change requires a strictly higher
  `authority_epoch`; v3 API keys support `expires_at`.
- Upgrade recovery: a fresh control plane seeds `authority_head` from the
  latest verified checkpoint on first serve.
- Release provenance: signed DSSE envelope in the in-toto/SLSA shape,
  verified against the archive's exact SHA-256; `requirements-lock.txt`
  and a PostgreSQL CI job.
- Added `docs/V332_OPERATIONS.md`, `docs/V332_ACCEPTANCE_MATRIX.md` and
  `docs/V332_EFFICACY_STATUS.md`.
- Regenerated `RELEASE_SHA256.json` (375 files) and built
  `release/SIS-v3.3.2-AUTHORITY-CONSISTENCY.zip`; the ZIP and its signed
  DSSE provenance verify. The provenance key is labelled
  `qualification-only`, not a production trust root.
- Not qualified: evaluator isolation (M6), full SLSA level conformance,
  real-agent efficacy (M9), and a real multi-host PostgreSQL deployment.

## 2026-10-26 — SIS v3.3.1 authority closure

- Added external signed authority checkpoints (`sis.v3.checkpoints`):
  monotonic sequence, authority epoch, previous-digest chain, journal
  head/sequence, candidate-revision digest, compare-and-append, atomic
  file store, crash recovery, and fail-closed serving. A deleted final
  revocation, stale database restoration or journal-head substitution is
  detected against independent custody; a local-only database is not
  treated as rollback resistant.
- Added candidate-specific evaluation certificates
  (`sis.v3.evaluation_certificate`): evidence classes, qualification
  policy, harness-signed delivery attestations, protocol registry and a
  validator that re-derives sample size, conformance, statistics,
  negative transfer, revocation and scope. Two-task runs cannot satisfy
  a 29-task protocol; demonstration runs cannot serve production.
- Added authenticated execution identity (`sis.v3.execution_identity`)
  and durable evidence custody (`sis.v3.evidence_custody`): immutable
  objects, dependency links, signed revocation/supersession logs,
  offline policy, and fail-closed status checks on every qualified read.
- Hardened skill ingestion: scope-aware candidate ids, structured
  Markdown parsing (code/quotes/example commands never become steps),
  high-severity findings block automatic qualification, explicit
  discovery completeness/pagination, bounded large documents, and
  frontmatter variants.
- Added pinned evaluator runtime and outcome taxonomy
  (`sis.v3.evaluation_runtime`): 2 GiB default envelope, bootstrap probe,
  plugin policy, protected-path/network denial, and infrastructure
  failures that never count as task pass/fail.
- Added five-arm learning qualification (`sis.v3.learning_qualification`)
  with exact McNemar, Wilson/Newcombe intervals, negative transfer,
  resource overhead and a real-agent gate. The scripted demo is labelled
  demonstration. An eight-task real five-arm Codex attempt was executed
  until the Codex quota blocked four tasks; the gate is recorded as
  `BLOCKED_EXTERNAL_AGENT_QUOTA`, not as a task failure.
- Added docs/V331_ARCHITECTURE.md and the v3.3.1 authority, certificate,
  identity, custody, ingestion, evaluation, threat-model, migration and
  release documents. Suite: **926 passed, 3 skipped**.

## 2026-10-25 — Skill ingestion (M10)

- Added `sis.v3.skill_ingest` + `tools/ingest_skills.py`: real skill
  directories (`SKILL.md` frontmatter + body, optional
  `references/`/`scripts/`/`assets/`) and skill trees are parsed into
  bounded `CandidateV1` records of type `skill_bundle` and submitted by
  the `learner` role at PROPOSED. vskill-style bundles are accepted
  through the existing verified import path.
- Bounded, dependency-free parsing: frontmatter ≤ 8 KiB, body ≤ 24 KiB
  (split into contract-sized instruction chunks), ≤ 64 resources hashed
  (contents never inlined), symlinks/traversal/hidden files refused,
  UTF-8 only, control characters refused.
- Ingestion is packaging only: a claimed `qualified` status is ignored,
  no signing keys are held, and qualification still requires signed
  holdout evidence plus an operator decision. Scan findings (shell
  execution tokens in served steps, prompt-injection phrasing in the
  body) are advisory and reported, never a refusal or a qualification.
- Candidate ids are derived from name + content digest, so re-ingesting
  identical content is a no-op and changed content is a new candidate.
- Added `tools/skill_holdout.py` and the `tools/skill_holdouts.py`
  registry: worked examples (`write-skills` artifact check,
  `php2shell-check` pinned-runtime check, `write-tests` mutation-checked
  suite) that run the full ingest → holdout probe (with and without
  guidance) → evaluator evidence + operator decision → serve path. The
  registry records planned tiers and every excluded skill with a reason,
  and the tool gains `--list`, `--tier` and `--only`.
- `OutcomeVerifier` accepts an explicit `limits` envelope (default
  unchanged) so a meta-test that runs the submitted suite in a nested
  process can opt out of `RLIMIT_NPROC=64`, which blocks the nested fork
  on platforms that count every process of the user.
- Suite: **804 passed, 2 skipped**.

## 2026-10-25 — Authority/evidence binding and serving integrity hardening

- Candidate qualification no longer accepts an unrelated pass receipt.
  Added `CandidateEvidenceV1` + `CandidateEvidenceAuthority`: an
  evaluator-signed binding of receipt digests to one exact candidate
  record/content digest on the sealed holdout partition under the
  expected protocol. `CandidateRegistry.qualify` requires every cited
  receipt to be covered by an authenticated binding that names the
  candidate; a pass receipt for another task, repository or candidate
  is refused.
- Serving state is no longer a mutable column gated by a role string.
  Added `CandidateDecisionV1` + `CandidateDecisionAuthority`:
  operator-signed exact-edge decisions for `evaluating→qualified` and
  `qualified→revoked`, binding the candidate digest, edge, evidence
  handles and actor identity. Decision nonces are consumed atomically
  with the transition; replay is a conflict.
- Every registry read now folds the hash-chained transition log,
  requires the committed state column to match the projection, and
  re-authenticates the signed decision/evidence behind each qualified
  candidate. A direct SQL state flip raises `state_projection_drift`;
  the serving gateway abstains `catalog_unavailable` with an audited
  `integrity_error`. Legacy unbacked qualifications are excluded and
  revocable only under a signed decision.
- `GovernedServingGateway.record_outcome` now requires an
  authenticated receipt with the same task and outcome; a bare digest
  cannot write a `serving_outcome` row. A revocation naming the
  candidate's receipt, evidence binding **or decision** suppresses it
  (`evidence_revoked`).
- Both governed campaigns now evaluate each candidate individually on
  the holdout and issue candidate-specific evidence + decisions instead
  of reusing a collective arm receipt. The probe runs through
  `run_candidate_probe`, which enforces repository disjointness and
  records budget/sample-size conformance against the preregistered
  protocol; a candidate that composes no guidance is reported as
  `no_guidance` rather than bound to a pass.
- Qualification requires a pinned evaluation protocol
  (`expected_evaluation_protocol_digest`); without it qualification is
  refused and a serving replica cannot read the qualified catalog.
- Upgrading a v3.3 database reseals the audit chain only after the old
  chain verifies against the old digest domain; a broken pre-migration
  chain refuses to open. The reseal is recorded in
  `registry_migration` and reported by `verify()["migrations"]`.
- A serving transition whose cited decision or evidence row is missing
  is `unbacked` (`decision_missing`/`evidence_missing`): it cannot
  serve, but intake and signed takedown stay possible instead of the
  whole catalog freezing.
- Evidence/decision expiry is compared as parsed UTC instants, not
  strings, and `expires_at <= issued_at` is refused at issuance.
- Suite: **777 passed, 2 skipped**. Deterministic campaign still
  reproduces A=0/B=2/C=2/D=0/E=2 and qualifies 5 candidates.

## v3.3.0 — Governed learning (2026-10-25)

- Added a typed candidate registry (`CandidateV1`, six artifact types) with
  role-gated transitions, hash-chained audit, and receipt-authenticated
  qualification.
- Added ReasoningBank-style experience memory with JSON-only ingest,
  episode-replay rejection, evidence-bound verification, and gated retrieval
  with abstention.
- Added EvoSkill-style bounded skill evolution: pure-payload mutators,
  injected dev evaluator, hard budgets, ranked frontier, intake-only output.
- Added the five-arm governed evaluation plane (A–E) with sealed holdout
  partitions, preregistered protocol digests, sample sizing, and honest
  abstention/negative-transfer metrics.
- Added strict governed serving with registry-resolved repository identity,
  scope/revocation/applicability/counterexample gates, and audited delivery.
- Added vskill-style skill bundle export/verify/import; imports land at
  PROPOSED regardless of claimed status.
- Added deterministic and authenticated live campaigns exercising the full
  lifecycle, plus 13 failure-injection scenarios.
- Hardening: qualification requires a signature-authenticated pass receipt;
  the release archive is source-bound and cannot embed itself; the release
  build fails closed when the extracted tree does not compile or fails its
  smoke test; regression rate is relative to baseline solves; memory ingest
  and serving outcomes are evidence-bound.
- Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED** — security/correctness gates
  pass; learning efficacy on unseen repositories is not established. See
  `docs/v3/QUALIFICATION_REPORT.md` and `docs/v3/V33_LIMITATIONS.md`.

## 2026-10-24 — Signed decision recovery and authority hardening (development release)

- Write-ahead, signed promotion decisions and deterministic catalog materialization recovery.
- Fail-closed checks for unmaterialized intermediate status decisions.
- POSIX promotion writer lock and stale-controller rejection.
- Tightened torn-journal-tail handling and fault-injection recovery regressions.
- See `AUTHORITY_RECOVERY_RELEASE_NOTES.md` for limitations and validation results.

## v2.4.0 — Bounded coding-agent repair recipes (2026-10-21)

- Added pure Python AST operator-swap capture, with no arbitrary Python source execution.
- Replays every labeled input through a restricted bounded expression interpreter before promotion.
- Generalizes successful repair operators across independently supplied Python function names.
- Adds separated source-program holdouts, duplicate/overlap checks, independent promotion recomputation.
- Adds SQLite code recipe catalog, local hash-linked audit, retirement and conflict protection.
- Exposes read-only code previews through model ToolBridge; operator-only study and retirement through CLI/HTTP.
- Ships functional demo, adversarial tests, detailed security/limitations guide; v1.0–v2.3 retained.
- Does not implement sandboxed Python unit-test execution, generalized code synthesis, or real LLM qualification.

## v2.3.0 — Controlled tabular workflow learning (2026-10-21)

- Added observed-tool `WorkflowSession` with deterministic filter/aggregation operations over bounded typed records.
- Added replay and SHA-256-linked execution events. Full capture control remains an untrusted authority boundary.
- Added exact semantic canonicalization for reordered and duplicate independent filters. Does not claim unrestricted equivalence of algorithms.
- Added independent SQLite `WorkflowCatalog`, operator-gated promotions, local audit verification, retirement, and fail-closed inference.
- Added read-only LLM tool definition, CLI commands, and local HTTP routes with separated operator authorization.
- Added adversarial tests and demonstration. Existing symbolic skill, LoRA, and holdout workflows remain included unchanged.
- No independent external-task evaluation, unrestricted agent execution, or real-model training claim.

## 2.2.0 — Instrumented Experience Abstraction

- Capture actual allowlisted deterministic tool executions through `InstrumentedSession`, preserving explicit input, previous-result, and literal provenance; reject ambiguous value-only binding.
- Replay captures through the unchanged bounded SIS interpreter; verify each resolved operand, step result, strict JSON type, local event hash link, and final answer.
- Cluster verified successful training captures by their generalized data-flow AST, reject incompatible programs and duplicate/overlapping train-validation inputs; convert erroneous executions into corrected training examples only with independent correction labels.
- Submit reconstructed candidates to the existing v2.1 governed `trace_study` and `SkillCatalog` promotion sequence; model tool bridge remains read-only.
- Add CLI `experience-capture` and `experience-induce`, documented Python instrumentation API, complete runnable synthetic example fixtures, and 32 focused tests.
- Explicit non-goals: no arbitrary tool execution, raw-chat understanding, privileged external attestation, automatic LoRA execution, or independent intelligence improvements.

## v2.1.0 — Typed execution-trace induction (2026-10-21)

- Added `sis.trace_learning`: bounded declarative step programs, typed intermediate replay, and train-only proposal extraction.
- Added operator-side `Service.trace_study` and `sis trace-study` CLI, preserving the existing verification and promotion gate.
- Rejected forged intermediate values, future-variable references, invalid ASTs, type confusion, validation-derived traces and injected proposals.
- Added integration tests, sample multi-step traces, documentation, and clean source manifest packaging.
- Real task-family generalization, independent evaluator custody, and GPU finetuning are **not** established.

## v2.0.0 — Evaluator-controlled task-family comparison

- Added `sis.family_eval`: signed evaluation precommitments, explicit family
  and input collision checks, a one-use SQLite experiment vault, 3/4-arm
  paired live comparison, Holm-corrected item and family-level sign-test p-values, within-family accuracy,
  and frozen qualification-policy scoring. No mutating tool exposure.
- Added `sis family-eval-seal` and `sis family-eval-run` with opt-in networking,
  protected evaluator secret, pinned claimed model IDs and non-overwriting
  results; added `sis family-eval-verify` for signed report authenticity.
- Added synthetic, offline four-arm demonstration, adversarial tests, and
  detailed data-custody / inference limitations.
- Retained all v1.9 neural training, procedural skill, induction, and audit
  subsystems. **No real LLM fine-tuning or benchmark lift measured in this release.**

## v1.9.0 — Opt-in LoRA training and three/four-arm evaluation

- Implemented training export authenticity checks and a dependency-optional, actual PEFT/Transformers LoRA training runner with completion-only LM labels.
- Added strict config/data checks, opt-in execution, offline loading default, never-overwrite adapters and source-bound training receipt.
- Added frozen-bundle neural comparison: base LLM, base LLM with skill result, adapted LLM, optional placebo prompt, paired aggregate metrics.
- Added v1.9 fixtures, new security and experimental-design guide, and regression tests.
- Does not claim trained neural weights or independent real-LLM results; this source release tests validation, masking and orchestration using mocks.

## v1.8.0 — Frozen procedural evaluation and controlled pseudo-labels

- Hash-bound `skill-freeze` artifacts include independently checked active skill dependency closure and audit head.
- Precommitted two-split procedural-skill holdouts under evaluator-owned SQLite vault/HMAC, one-use scoring, signed aggregate receipts, strict replay and crash-safe receipt recovery.
- Sample-size, coverage, accuracy and 95% Wilson lower-bound qualification policy per split, declared exclusion records and duplicate prevention.
- Qualified skill-to-LLM JSONL *pseudo-label* export with custodian-side private-overlap rejection and signed output hash manifest; **no neural weight training**.
- Regression tests for forgery, modification, reuse, concurrent claims, distribution shift, archive/CLI integration, and failure paths.
- Honest evidence boundaries: local software verification only; independent holdout ownership is required for credible generalization claims.

## v1.7.0 — Governed bounded procedural skills

- Added strict interpreted JSON program AST: conditionals, lexical bindings, bounded list reductions and skill composition with active dependency checks.
- Added deterministic skill discovery and operator proposals, requiring disjoint caller-provided validation, ambiguity checks, and independent recomputation before promotion.
- Added separate hash-linked skill catalog with semantic transition replay, fail-closed prediction, negative-feedback suspension, and retirement.
- Added conservative episode-to-study adapter that requires external corrected outputs for failed episodes; trace strings are metadata only.
- Added skill CLI, HTTP endpoints, read-only LLM tool bridge and basic caller-controlled benchmarking.
- Preserved v1.6 rule engine, evaluator, paired LLM tests, and existing database schema; skill chain has no external anchor and is not independently qualified.

## v1.6.0 — Paired LLM evaluation (2026-10-20)

- Same-model, read-only baseline vs SIS-augmented benchmark with counterbalanced arm order.
- No reference labels included in LLM request content; fail-closed registry audit and drift checks.
- Strict typed JSON answer/abstention decoding; provider failures invalidate runs.
- Exact McNemar comparison, paired contingency table, Wilson descriptive intervals, coverage, latency, and optional provider-reported token usage.
- Two-step network opt-in CLI; refuses overwriting benchmark result artifacts.
- Added local tests, synthetic fixtures, and explicit limitations of local experiment evidence.
- No changes to prior SQLite storage schema, evidence claims, or promotion authority.

## 1.5.0 — October 20, 2026

- Add explicit, one-to-one schema-map transfer of active source rules with strict type/list constraints; no automatic assertion of cross-domain validity.
- Extend read-only Service, CLI, HTTP, and agent tool-bridge entrypoints for one-record and bounded batch transfer.
- Precommit a typed evaluation qualification policy into the authenticated public study at sealing time.
- Add post-score evaluator-signed qualification and replay verification, separate from source rule promotion.
- Require meaningful holdout sample counts, overall accuracy/coverage, shifted-test performance, descriptive baseline margin, and 95% Wilson lower-bound screening.
- Preserve v1.4 sealed evaluation compatibility but refuse retroactive qualification of uncommitted legacy test policies.
- Add dedicated local integration and adversarial tests; explicitly deny that synthetic datasets or signed local policy passes establish independent effectiveness.

## 1.4.0 — October 20, 2026

- Introduce a separate evaluator-side, HMAC-authenticated one-use holdout vault, isolated from model-facing public train/validation data.
- Bind submissions to a signed public task and evaluate only locally admissible AST candidates.
- Provide test and shifted-regime aggregate metrics without revealing holdout examples or labels to the candidate process.
- Reject repeated or overlapping samples across all tasks in a single vault, including concurrent duplicate scoring attempts.
- Add signed scoring receipts and evaluator-side replay verification against private test data.
- Add 27 unit/integration checks, CLI subcommands, documentation and a synthetic example generator.
- Clarify that single-vault anti-reuse and HMAC receipts do not establish independent test custody or prevent whole-vault rollback.

## 1.3.0 — October 20, 2026

- Harden event replay with semantic transition validation, immutable field checks,
  typed/counter validation, and rule-ID integrity checks.
- Add an admission firewall rejecting bounded witnesses of disagreement against
  existing active rules in the same namespace and schema.
- Add separate HTTP operator secret for mutating/trusted routes. Prediction-only
  keys cannot promote rules, send feedback, or invoke operator LLM chat.
- Fail closed when listing rules with invalid audit; reject output-type mismatches
  before feedback can suspend a rule.
- Enforce strict type equivalence for candidate fitting and benchmark scoring
  (Python `True == 1` must never count as a valid typed match).
- Add adversarial regression tests and authenticated operator integration tests.

## 1.2.0 — October 20, 2026

- Require a full independent registry re-induction from supplied examples and search options before promotion (fixes the forged-result Python boundary).
- Add opt-in, operator-held audit checkpoints with SHA-256 or HMAC-SHA256 integrity for validating a DB audit prefix across appends.
- Add bounded batch prediction to CLI, Python service, and HTTP API.
- Refuse LLM HTTP redirects to reduce bearer-token and training-data exfiltration risk.
- Add new regression suite and release documentation.

## v1.1.0 — 2026-10-20

- Implemented deterministic, bounded active query selection from multiple training-consistent rules. Questions are explicitly **unlabeled** and never automatically promoted.
- Added disjoint train/validation/test benchmark with coverage, selective accuracy, overall accuracy, and a train-majority baseline. Caller's test set is not transmitted to induction.
- Added complete rule projections to the SQLite hash-linked events. The verifier now compares replayed latest projections against each stored rule and predictions fail closed if inconsistent.
- Added rule retirement with an append-only event and explicit no-reactivation policy.
- Added portable LLM tool definitions and a narrowly allowlisted Python `ToolBridge` that exposes only prediction and query proposal.
- Extended local HTTP API, CLI, example fixtures, verification instructions and tests.
- Maintained the no-exec, bounded-AST, opt-in external-LLM baseline.
- Legacy v1.0 database events are detected as unverifiable rather than silently upgraded; see `docs/UPGRADE_V1_1.md`.

## v1.0.0 — 2026-10-20

- Initial installable Python symbolic-induction research prototype.
- Implemented bounded AST synthesis and hypothesis counterexample probing.
- Implemented optional Z3 disagreement search, opt-in LLM proposals, SQLite registry and local HTTP/CLI APIs.
- Provided local synthetic tests and a deterministic ZIP source manifest.
