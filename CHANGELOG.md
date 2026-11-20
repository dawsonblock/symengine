# Changelog

## 2026-11-20 — Root hosts, a test-dependency image and repository screening (SIS-FIX-21)

- **The Docker evaluator works on a root host.** The workspace was
  bind-mounted read-only at `/submission` and copied into the tmpfs by
  the container user. On a root host that user is 65534, and the
  prepared tree is root-owned (mode 0700 at its top when it came from a
  `mkdtemp`), so the copy-in failed with `cp: cannot stat
  '/submission/.': Permission denied` and split custody with
  `evaluator_bootstrap_error`. The host process now archives the
  prepared workspace from its registry path and streams it into the
  tmpfs (`docker exec -i ... tar -x`), children only, so the tmpfs keeps
  its own mode. Nothing on the host is chowned or widened, the workspace
  is no longer bind-mounted at all, and split custody is unchanged: the
  private material is still installed by the evaluator UID in a 0700
  directory the worker UID cannot read.

## 2026-11-20 — Split custody releases handles and stages test data (SIS-FIX-20)

The boundary is unchanged: nothing is unpickled or evaluated in the
evaluator, no class or callable crosses except as a handle, and the
evaluator never raises `BaseException`, `SystemExit`,
`KeyboardInterrupt` or `unittest.SkipTest` for the worker. Several
paths are now tighter.

- **Handles are released.** Every handle has one lease in the
  bootstrap, shared by the `Ref`s, exceptions and stand-in classes that
  refer to it and counting how often the worker handed it out. When the
  lease is collected its finalizer queues `[handle, count]` (no lock,
  no I/O); the next request carries the queue as `"release"`, and the
  worker drops a handle once every hand-out is released. Malformed,
  unknown, repeated and non-`#n` entries are ignored and never fail a
  request. `MAX_HANDLES` now bounds live handles, so a long or threaded
  test (jmespath's 32 x 4096 calls) no longer exhausts it.
- **Trusted names import from the trusted path.** A name the evaluator
  provides is imported from the spec found on `sys.path` without the
  workspace, by the finder itself; a path-entry hook makes every
  workspace entry on `sys.path` find nothing for any later finder; a
  standard-library name the evaluator lacks is missing, never the
  workspace's. A regression test plants workspace copies of
  not-yet-imported standard-library modules and checks that none runs
  and that no `sys.path` entry resolves into the workspace.
- **Exception names resolve only to builtin and stdlib classes.** A
  worker-reported class of an installed package or a test helper gets an
  inert stand-in instead of being built with worker-chosen arguments.
  Stand-ins are published once across threads, and a factory-made class
  first raised without a path gains the path when its alias is read.
- **Protocol fixes.** Namespace packages spanning the workspace root and
  `src/` keep every portion; a data result too large for a frame comes
  back as a handle instead of ending the run as `split_worker_lost`;
  `with x as y` binds the worker's own mutable `__enter__` result;
  three-argument `pow` is forwarded; the host client keeps a generator's
  typed return value.
- **Support files.** The importer captures the data files a hidden test
  (or a captured helper) names by a string-literal path, and the data
  files of a test subdirectory it names (jmespath's
  `tests/compliance/*.json`), all of a directory or, past
  `MAX_SUPPORT_FILES` or a size bound, none, with a `support_notes`
  reason. Support targets may be data files (never a loadable-code
  suffix or an evaluator-staged name), must be fully normalized, and may
  not take the primary test's staged name even without
  `hidden_tests_target`. Relative imports of a captured helper resolve
  against its own package, so `tests/sub/helper.py` brings `.data`.

## 2026-11-20 — Authority verification reads one snapshot (SIS-FIX-19)

`AuthorityDB.verify()` replayed the revision, decision and grant tables
in autocommit mode, one snapshot per statement, holding only the
in-process lock. A writer in another process could commit a transition
(decision and revision together) between two of those statements; the
replay then saw the decision without its revision, reported
`decision_without_revision`, and `PromotionController` refused to load a
valid store. This surfaced as an intermittent macOS failure of
`test_concurrent_process_writers`. The replay now runs in one read
transaction (`AuthorityDB._read`), and a deterministic test commits a
transition from a second connection in the middle of a verify.

## 2026-11-19 — Split custody grades ordinary pytest suites (SIS-FIX-18)

The pilot graded correct upstream fixes under Docker split custody and
saw them fail on the harness, not the code. The boundary is unchanged:
the worker still cannot run code in the evaluator, nothing is unpickled
or evaluated there, and no class or callable crosses except as a handle.
The release seal is still stale and must be rebuilt before the next
release.

- **Sets and non-text-key mappings cross as data.** `set`, `frozenset`
  and mappings whose keys are not text join the closed codec in all
  three encoders; call arguments may be slices. Elements and keys must
  decode to something hashable, within `MAX_ITEMS` and `MAX_DEPTH`;
  anything else stays a handle. inflection's
  `[(w,) for w in inflection.UNCOUNTABLES]` now works.
- **Protocols on worker objects.** `len`, `in`, indexing and item
  assignment, iteration, `reversed`, comparisons in both directions with
  plain data, arithmetic (plain, reflected, in-place), `bool`, `str`,
  `repr`, `hash`, `format`, `int`/`float`/`index`/`round`, `with`
  blocks, `isinstance`/`issubclass` against worker classes and attribute
  assignment are forwarded through one new worker op, `dunder`, whose
  names come from a fixed table; every other name is refused there.
  Iteration streams through a worker-held iterator, one round trip per
  item. `__name__`, `__qualname__`, `__version__` and `__all__` are the
  only dunder attributes a test can read.
- **Submission exception classes.** The worker reports an exception's
  class chain by name; the bootstrap raises a local stand-in class per
  (module, qualname), which is also what `pkg.CustomError` resolves to
  through the proxy. `pytest.raises(pkg.CustomError)`, `except
  pkg.Base`, `match=` on the worker's message and `excinfo.value.attr`
  (read through a handle) work. Stand-ins always derive from
  `Exception`; a forged report cannot raise `BaseException`,
  `SystemExit` or `KeyboardInterrupt` in the evaluator, and no name
  resolves to a class of the runner's own modules (`unittest`, `pytest`,
  `pluggy`, `doctest`): a `unittest.SkipTest` raised by the submission
  crosses as an ordinary error, not as a skip that would let a failing
  hidden test exit 0. Worker messages
  carry up to 8 KiB instead of 400 characters.
- **src/ layout.** A workspace with a `src/` directory that is not a
  package is searched at its root and then under `src/`, in the same
  order by the worker and the evaluator's finder (cachetools). Trusted
  modules still cannot be shadowed from either place.
- **Submission state stays in the worker.** A read of a mutable
  container (`list`, `dict`, `set`, `bytearray`, `deque`, and
  subclasses) is a handle to the worker's own object instead of a
  decoded copy: an attribute read of a module or object, an item read
  with a non-slice key, and an in-place operator that returns its
  operand. inflection's `inflection.UNCOUNTABLES.add("ors")` now
  reaches the submission. Method calls run in the worker; `len`, `in`,
  iteration, `==` both ways, indexing and item assignment go through
  the `dunder` op, which also forwards `copy.copy`/`copy.deepcopy`.
  Immutable values, call results, slices and iteration items still
  cross as data, so a function returning a fresh list still returns a
  `list`; one returning its module's internal list returns a copy.
  `isinstance(pkg.UNCOUNTABLES, set)` is now false (a test asserted it
  and was changed deliberately: mutation decides whether a correct fix
  passes, `isinstance` of a module-level container is rare in tests).
- **Test helper files are registered with the test.** The importer
  captures from the fix commit, never from a submission, the test's
  `conftest.py` files (its directory and every directory above), the
  `__init__.py` of each test package up to its test root, and the
  helper modules it imports from its own test package (`from . import
  CacheTestMixin`, `from tests import unittest`). Only paths in a
  `test`/`tests` directory count as packages or helpers, so a source
  package is never captured. They are registered as further private
  files at their repository paths (the verifier already took several)
  and recorded as an optional `acceptance.support_files` list of
  `{target, path, digest}` beside `hidden_tests_path`, stored inside the
  hidden-tests directory. The manifest builder, the manifest validator
  and the five-arm campaign (and so the guidance-bundle builder) check
  each file and digest wherever the primary test's are checked. In the
  bootstrap, "beside the tests" follows `sys.path` as pytest changes it
  (links resolved, nothing in the workspace trusted), so a helper is
  imported from the private directory and the workspace's file of the
  same name stays proxied.
- **Threads.** Requests from several test threads are serialized on the
  socket; they used to read each other's answers. The worker serves one
  request at a time, so a race a test provokes with threads does not
  happen in the submission.
- **Real repositories.** Re-grading the 22 correct upstream fix commits
  that were rejected before (6 inflection, 8 cachetools, 8 jmespath)
  under Docker split custody accepts 4 (inflection), up from 0; each
  accepted task's base still fails, and deliberately wrong fixes fail.
  The rest are rejected for reasons outside the harness or at the
  boundary: two inflection commits change no behaviour (import order,
  flake8) and their base passes; all 8 cachetools test files apply
  cachetools decorators to test-defined functions, pass test-defined
  callables (`getsizeof=`), subclass or pickle a worker class; 5
  jmespath tests need `nose`/`hypothesis`, absent from the evaluator
  image; 2 subclass a worker class with test-defined methods; and one
  (2020) fails on Python 3.12 itself (`assertRaisesRegexp`,
  `random.sample` of dict keys) and, with 32 threads × 4096 parses,
  exhausts the worker's 100,000 never-released handles.
- **Still out of scope**, each because it would need code, class or
  pickled objects to cross, or the worker to drive evaluator objects:
  test-defined callables or objects passed to the submission
  (decorators applied to test functions, `getsizeof=`/`key=`
  callbacks), subclassing a worker class, pickling a worker object,
  thread-level concurrency inside the submission, and data files a test
  reads from beside itself. The remaining proxy limits are listed in
  the `sis.v3.split_harness` module docstring.

## 2026-11-19 — Repository cleanup (SIS-CHORE-17)

No behaviour changes for users; every CLI command works as before.

- **Historical record moved to `docs/history/`.** The files
  `docs/INDEX.md` lists as historical (v1.5–v2.4 milestone reports,
  per-version test reports, early upgrade and release notes, the
  pre-3.3.3 README, the v3 gate and pre-3.3.8 qualification reports,
  the v3 status ledger and two root-level release notes) moved with
  `git mv`; every relative link was rewritten and none is broken.
  `docs/INDEX.md` names the v3.3.9 qualification report as current.
- **Grouped `sis --help`.** The 58 commands are listed once, under ten
  headings, instead of twice as a flat list. `COMMAND_GROUPS` in
  `sis.cli` is the single table, and `tests/test_cli_help.py` requires
  every command to be in exactly one group.
- **Windows: core only.** Windows is supported for the core learner and
  CLI; the v3 evaluator, sandbox and study layer is POSIX-only. The
  Windows CI job is no longer experimental: it runs the core suite
  (`--ignore=tests/v3`) and is required. `tests/conftest.py` leaves
  `tests/v3` out of collection on Windows and says so in the run header.
  The strict release-tag gate runs on the POSIX runners, since it
  re-hashes LF source bytes.

## 2026-11-19 — Sandbox qualification path (SIS-FEAT-16)

Track C of the efficacy plan: a Docker + gVisor qualification path with a
red team and the in-repo half of independent sign-off. No new sandbox
evidence was generated (no Docker daemon or gVisor was available); the
stored Gate 2 evidence is marked stale and the new CI job produces fresh
evidence. The release seal is still stale and must be rebuilt.

- **The signed policy is the launch.** `DockerSandboxExecutor.launch_flags()`
  builds both the security-relevant `docker run` flags and, with
  placeholders, the policy document whose digest is signed
  (`launch_policy()`, `policy_digest()`). The hand-written policy in
  `tools/qualify_docker_isolation.py` (which said `pids_limit: 128`
  while receipts showed 64) is gone. Receipts carry
  `docker:policy:<digest>`, `docker:runtime:*` and
  `docker:seccomp_profile:*`; the qualification tool writes `policy.json`
  and refuses to sign a digest the receipt does not name.
- **gVisor and an allowlist seccomp profile.** `runtime="runsc"`
  (`--runtime runsc`) and `seccomp_profile=` (`--security-opt
  seccomp=...`, from an executor-owned copy) are new executor options; a
  production executor requires both. `docker/sandbox/seccomp.json` denies
  by default and is derived reproducibly by
  `tools/derive_sandbox_seccomp.py` from Moby's v27.3.1 default profile.
  The probe adds `kernel_gvisor` and `seccomp_filter_active`;
  `PRODUCTION_PROPERTIES` adds `kernel:gvisor` and
  `syscalls:seccomp_allowlist`, and `check_release_ci.py` refuses a
  release property set that omits any production property.
- **Red team.** `tools/redteam_sandbox.py` runs seventeen hostile
  payloads and a health check with expected outcomes (resource bombs,
  egress, runtime sockets, setuid, ptrace, mount/unshare, foreign
  processes, copy-out link escapes, `/proc`/`/sys` writes, host
  credentials) and exits non-zero on any unexpected outcome.
- **CI.** A new `sandbox-qualification` job installs gVisor 20261026.0
  (SHA-512 pinned) with `--oci-seccomp`, builds the digest-pinned image
  and runs the probe, red team and qualification with a generated
  qualification-only key. Existing jobs are unchanged.
- **Independent sign-off, in-repo half.** `tools/isolator_key_fingerprint.py`
  prints a stable key fingerprint; `SANDBOX_QUALIFICATION_GATE2.md`
  documents key custody and the out-of-band fingerprint ritual, and
  `RELEASE_PROCESS.md` the re-attestation policy (per release and per
  launch change, at most one hour old). The isolator host and key are
  the operator's to provide.
- **macOS stays development-only.** The local runner's RSS watchdog
  kills a darwin run over `memory_bytes` (`memory:watchdog`,
  `rlimit:memory_watchdog_exceeded`; `memory:not_enforced` stays). Local
  hostile evaluation on darwin needs `--allow-unqualified` in the
  evaluator worker and the campaign tools other than
  `five_arm_campaign.py`.

## 2026-11-19 — Efficacy pilot tooling (SIS-FEAT-15)

Track B of the stronger-learner / real-pilot / qualified-sandbox plan:
everything an exploratory Claude Code pilot needs except the run itself,
which needs real repositories and agent quota
(`docs/v3/PILOT_RUNBOOK.md`). No efficacy claim changes.

- **Claude Code adapter.** `sis.v3.adapters.claude_code` runs
  `claude -p --output-format stream-json` headless in the task
  workspace (one documented argv builder, scrubbed environment,
  wall-clock watchdog, process-group cleanup). Tokens are metered as
  `input_tokens + output_tokens` de-duplicated per API message and
  reconciled with the final usage; cache tokens and cost are reported
  per row as `usage_detail`. `ClaudeCodeAgent` enforces the token and
  tool budgets while the run streams and fails an overrun as an attested
  budget failure. `agent.kind` is `codex-cli` or `claude-code` in the
  manifest validator, the builder and the analysis provenance check; the
  runner pins the version with `claude --version`.
- **Split custody on Linux.** `five_arm_campaign.py --executor docker`
  grades in `DockerSandboxExecutor` with a second container identity
  (`--docker-split-user`), the pinned image by default
  (`--docker-image`), and passes `--docker-runtime` through when the
  executor supports one.
- **Task corpus importer.** `tools/import_study_tasks.py` turns bug-fix
  commits into tasks (parent = base, the fix's test = hidden acceptance,
  commit or issue text = prompt) and keeps only tasks whose base fails
  and fix passes under the runner's own grading. A task may now carry
  its own `base_commit` within its repository, bound by its own snapshot
  and execution digests; trees are materialized blob by blob without
  running repository-configured programs. Hidden tests may be a
  directory of per-task files.
- **Guidance bundle producer.** `tools/build_guidance_bundle.py` learns
  B/C/D candidates on induction training repositories with
  `sis.v3.learning`, qualifies them on separate induction repositories,
  and signs evidence and decisions with the `--trust-config` keys. The
  runner now refuses a bundle whose qualification evidence comes from a
  study holdout repository, its own training repositories or a study
  task, or whose qualifying receipts are not the declared ones.
- **Runner robustness.** `--state-dir` journals every `(task, arm)` row
  (digest-chained, bound to the study identity; journaled receipts are
  re-verified) and an interrupted run resumes; `--workers N` runs tasks
  in parallel with seeded per-task arm order and results equal to a
  serial run. A tree graded just before an interruption reuses its
  receipt (`OutcomeVerifier.prior_receipt`).
- **Repository-level power planning.**
  `sis.v3.governed_eval.required_repositories` simulates the exact
  repository sign-flip decision with repository difficulty, task
  difficulty and a repository-specific effect, and
  `pilot_planning_inputs` reads the rates and intra-repository
  correlations from a pilot report.
- **Pilot preparation.** `docs/v3/pilot_study_spec_template.json`
  (exploratory, A/E, Claude Code, 900 s / 150k tokens / 100 tools),
  `docs/v3/pilot_learning_spec_template.json` and the runbook. An
  end-to-end dry run (imported temporary repositories, scripted agent,
  SIGKILL and resume) is in `tests/v3/test_efficacy_pilot_dry_run.py`.

## Learner v2 (SIS-FEAT-14)

Track A of the learner plan: a deeper, typed, conditional rule learner,
measured on a fixed corpus before and after. Induction results now carry
`grammar_version: sis-grammar-2` and `engine_version: sis-induce-2`.
Stored rules keep their ids and still pass `sis audit`; a result induced
by an earlier engine must be re-induced before promotion.

- **One op registry.** Every grammar op is an `OpSpec` in
  `sis.expression.OPS` (shape, operand/result types, total evaluation
  function, cost, commutativity, Z3 translation, structural tag).
  Evaluation, validation, cost, the enumerator, `smt.py`, schema
  transfer, the LLM proposal prompt and the benchmark's structural form
  all read it. `validate_ast` counts depth from 1 like `depth()`; the
  accepted set (31 nodes, 6 levels) is unchanged and the message now
  states it.
- **Version stamps.** `induce` stamps both versions. `Registry.promote`
  and sealed evaluation (`score` for submissions, `verify` for receipts)
  refuse another engine's output with "re-induce under the current
  engine" instead of an opaque mismatch.
- **Grammar 2 ops.** `floordiv` and `mod` (Python floor semantics; a
  zero divisor is an evaluation error on that record, never a fitted
  value), `lt`/`le`/`gt`, `concat` (bounded to 128 characters),
  `slice_prefix`/`slice_suffix` with a literal length, `len`, `contains`,
  `str_of_int` and the `if_lt` conditional. `if_eq` is now enumerated.
- **Typed bottom-up enumeration** (`sis.synthesis`) replaces the
  stage-1/stage-2 search: pools per type built by increasing cost with
  observational-equivalence pruning over training, development and a
  probe prefix; exact small-integer affine fitting over at most three
  features (plus one ranked depth-2 feature); goal-directed completions;
  one-level conditional synthesis that learns each branch separately.
  `SearchBudget` and `SearchState.outcome` keep their meaning, and
  truncation is still reported.
- **Ambiguity over the whole space.** A rival scan resumes the selection
  enumerator to the end of its declared space, including conditionals,
  and replaces the bounded depth-2 `_deep_rival_scan`. A rival counts
  when it fits every labelled row, costs at most 4 more than the selected
  rule and disagrees on a probe. Probes add values for the new ops and
  data-derived boundaries. `ambiguity_scope` is now `full_search_space`,
  `bounded_rival_scan` or `selection_pool_only`.
- **Stricter `locally_validated`.** A conditional rule is `provisional`
  unless the holdout exercises both branches (`branch_holdout_coverage`).
  A holdout carrying less than 4 bits of evidence under the label
  distribution (`holdout_evidence_bits`; three binary rows carry 3) is
  `provisional`. A rule that still fails development rows after
  refinement is `validation_failed`.
- **Induction corpus.** `examples/induction_corpus/` holds 62 seeded
  targets in six categories with a committed split;
  `tools/benchmark_induction.py --corpus` reports per-category recovery,
  false positives, `no_rule` rate and runtime percentiles.
  `evidence/benchmark/induction_corpus_baseline.json` (previous engine)
  and `induction_corpus_v2.json` hold the results: recovery rises from
  23% to 58% overall (linear 40%→80%, divmod 0%→50%, piecewise 0%→70%,
  string 17%→67%) with no false positives in any category.
  `tests/test_induction_corpus.py` runs a 15-target subset.
- **Pinned tests updated deliberately** where the stronger learner
  changes an outcome: see the commit that updates them for each reason.

## 2026-11-18 — Review follow-ups (SIS-FIX-13)

The follow-ups left open by SIS-FIX-12. The release seal is still stale
and must be rebuilt before the next release.

- **`sis.enforced_induction` no longer uses `preexec_fn`.** Its hard
  limits are applied through the evaluator's limit launcher, the change
  SIS-FIX-11 made for the local runner. A refused limit still raises
  `EnforcementUnavailable`.
- **Windows ACL checks compare principals, not SDDL spellings.** The
  check failed for the RID-500 Administrator (the GitHub Windows
  runner's account), which Windows writes back as `LA`. The allowed set
  of principals is unchanged.
- **The manifest tier binds the label.** A manifest declares
  `study_tier` (`confirmatory` by default for a powered protocol,
  `exploratory` or `diagnostic`). A confirmatory manifest needs at least
  20 holdout repositories, the same floor the analysis applies. A study
  declared exploratory or diagnostic is never labelled confirmatory.
- **The five-arm campaign accepts trust anchors.** `--trust-config` (the
  `sis.v3.bootstrap` config format) supplies the trusted keys, so a
  verified bundle can be served from the command line. A candidate
  registry without trust anchors is refused unless `--record-unverified`
  acknowledges recording-only mode.

## 2026-11-18 — Review fixes across authority, sandbox and study (SIS-FIX-12)

A whole-repository review found defects in three layers. Each fix has a
regression test in a `test_review_fix_*` file. The SIS-v3.3.9 release
seal (`release/`, `RELEASE_SHA256.json`) predates these changes and must
be rebuilt before the next release.

- **Authority and serving.** Signed custody revocations and supersessions
  of a candidate, decision or certificate now withdraw it at serve time.
  Previously only client-supplied `revoked_digests` were consulted. A
  withdrawn candidate is excluded individually instead of taking the
  catalog down. `AuthorityDB` reads are locked. Checkpoints verify
  append-only custody extension before signing. The control plane
  (schema v3) accepts one outcome per evaluator receipt. Token-mode
  operator authorizations are HMACs. `sis serve --v3-config` builds the
  production v3 stack via `sis.v3.bootstrap`.
- **Evaluator sandbox.** The rlimit launcher, split worker and seccomp
  wrapper run as `python -I` from a neutral directory, fail closed when a
  limit cannot be set, and reap descendants on Linux. Git queries on
  untrusted checkouts no longer run repository filters. A shared-custody
  pass requires a pytest report, so `os._exit(0)` fails, and receipts
  mark shared custody unqualified. The split import proxy cannot shadow
  libraries. Execution classification ignores submission-controlled
  stderr. The verifier rejects submissions that change during
  evaluation. The seccomp filter adds x32, `clone` namespace flags,
  `clone3`, the new mount API and io_uring. The Linux worker joins its
  cgroup before exec, and Docker containers are `--rm` and labelled.
- **Efficacy study and induction.** Contrasts use the preregistered
  alpha. Declared power effects cannot exceed `min_effect`. Timeouts and
  budget overruns are attested failures. Negative transfer is measured
  and gated. The confirmatory decision is a repository-level sign-flip
  test requiring at least 20 holdout repositories, and secondary
  contrasts are Holm-adjusted. The campaign serves guidance per task
  through `GovernedServingGateway`. Legacy induction splits validation
  into disjoint dev and holdout rows, and promotion requires a sealed
  holdout.

## 2026-11-16 — Resource limits no longer use preexec_fn (SIS-FIX-11)

`LocalSubprocessExecutor` applied `RLIMIT_CPU`, `RLIMIT_AS`,
`RLIMIT_FSIZE` and `RLIMIT_NPROC` through `subprocess`'s `preexec_fn`.
Python documents that parameter as unsafe when other threads exist: the
child between fork and exec can deadlock on a lock another thread holds.
The evaluator can run from worker threads, so the risk was real even
though the common path is single-threaded.

- The runner now wraps the command in a small `python -c` launcher that
  sets the same limits and `execvpe`s the target. The launcher is a
  separate process, so no Python code runs between fork and exec, and
  the limits apply to the target and to split-custody workers.
  `rlimits:launcher` is recorded in the receipt's security markers.
- The same `preexec_fn` pattern remains in `sis.enforced_induction` and
  `sis.v3.linux_worker`; those paths are unchanged here.
- Regression coverage includes the existing FSIZE, NPROC, wall-clock and
  threaded-termination tests, plus a new test that applies a file-size
  limit from a worker thread.

## 2026-11-16 — v3 authenticates before reading the body (SIS-FIX-10)

The `/v3` handler read and parsed the request body before
`V3ServingService` authenticated it, so an unauthenticated client could
force JSON parsing (including the `RecursionError` path) and the server
had no request socket timeout.

- `V3ServingService.authenticate()` authenticates headers on their own;
  `handle()` accepts the already-authenticated requester. The HTTP
  handler authenticates first, answers `401` without reading the body
  and closes the connection. Authenticated invalid JSON still answers
  `400`.
- The request handler sets a 30-second socket timeout, so a stalled
  client cannot hold a handler thread indefinitely.
- `docs/LEGACY_README.md` had 24 local links written relative to the
  repository root instead of the file; they now resolve.
- Regression coverage lives in
  `tests/v3/test_v332_security_regressions.py`.

## 2026-11-16 — Primary-contrast two-arm study path (SIS-FIX-08)

The five-arm design spends five agent runs per task, but only A vs E is
the confirmatory contrast; B–D are mechanism controls. At the 103-task
floor that is 515 runs instead of 206.

- `PRIMARY_CONTRAST_ARMS = ("A","E")`. A manifest with kind
  `primary_contrast_efficacy_manifest` declares those arms and validates
  through the same gate. The five-arm kind still requires A–E; a kind and
  arm mismatch is invalid, and a non-string kind is reported rather than
  raised.
- `FiveArmCampaign` accepts either arm set and requires the protocol
  arms to match the campaign.
- `tools/five_arm_campaign.py --real-agent --manifest` builds the
  declared arms, serves E from the same B/C/D guidance components, and
  writes a `primary_contrast_learning_qualification_real_run` report.
- `tools/build_efficacy_manifest.py` accepts a
  `primary_contrast_study_spec` and writes the matching manifest kind.
- Template: `docs/v3/efficacy_manifest_two_arm_template.json`. The
  study-protocol and build-plan docs describe the design and its cost.
- `tools/five_arm_campaign.py --demo --arms primary` runs the scripted
  two-arm demonstration; `evidence/evaluation/two_arm_demo.json` records
  the two-task run (A 0/2, E 2/2, exact p=0.5, `demonstration` class).
- Regression coverage lives in `tests/v3/test_efficacy_manifest.py`,
  `tests/v3/test_build_efficacy_manifest.py`,
  `tests/v3/test_five_arm_real_run.py` and
  `tests/v3/test_governed_eval.py`.
- This is machinery, not evidence. A powered run still requires the
  repositories, the pinned Codex CLI and the agent budget.

## 2026-11-16 — Git queries cannot execute repository configuration (SIS-FIX-06)

`validate_manifest(check_paths=True)` runs `git status` in every
repository a manifest names — a checkout that has not been trusted yet.
A checkout's own `.git/config` can name a program: `core.fsmonitor` is
executed by `git status`. An inherited `GIT_DIR` could also redirect
every query to another repository while `--show-toplevel` still named the
path under test, so a clean checkout could "prove" a commit it never
contained.

- `sis.v3.gitquery` runs every read-only Git query with
  `-c core.fsmonitor=false` and `-c core.hooksPath=<devnull>` (command
  line beats repository, global and included config), scrubs every
  inherited `GIT_*` variable, disables the system and global config
  files, and sets `GIT_OPTIONAL_LOCKS=0` so `status` cannot rewrite the
  index. The repository's own config is still read because the
  provenance check needs `remote.origin.url`.
- The manifest validator, the study-spec builder, the five-arm campaign
  manifest anchor and the canonical ZIP source binding use it.
  `gitquery.raw()` preserves porcelain output, whose first column can be
  a significant space.
- Regression coverage in `tests/v3/test_gitquery.py` proves a live
  fsmonitor hook does not run and that `GIT_DIR`/`GIT_WORK_TREE` cannot
  redirect the query; `tests/v3/test_release_artifact.py` covers the
  porcelain path.

## 2026-11-16 — A deeply nested JSON body is answered, not dropped (SIS-FIX-07)

`json.loads` raises `RecursionError` for a body such as 200 KB of `[`.
Both HTTP parse sites caught only `ValueError` and `UnicodeDecodeError`,
so the exception escaped `do_POST` and the connection closed without a
response. `RecursionError` is now treated as invalid JSON and answered
with `400`. Regression coverage lives in
`tests/v3/test_v332_security_regressions.py`.

The README quickstart now passes `--namespace arithmetic_demo` to
`sis rules`; the study trains that namespace, so the previous command
printed an empty list.

## 2026-11-16 — Powered-plan direction and release-path validation (SIS-FIX-05)

The powered planner could not register the study it exists to power. A
protocol is registered from `expected_baseline` and `expected_treatment`;
`required_sample_size()` required its second rate to be lower than its
first, and `preregister()` mapped the treatment onto that second rate.
Any plan that expected learned guidance to *raise* the solve rate was
refused, while a plan expecting it to lower the rate was accepted and
recorded as the study hypothesis.

- `required_sample_size()` now treats the two rates as an unordered pair
  and uses `q = |p1 - p2|`. The two-sided alternative needs the same
  number of pairs for an improvement and a regression of the same size;
  only equal rates (no effect to detect) and out-of-range or non-finite
  rates are refused. Existing protocols recompute to the same
  `required_n` because `d` and `|q|` are symmetric under the swap.
- `preregister()` defaults are now `expected_baseline=0.4`,
  `expected_treatment=0.6`, so the default plan declares the
  improvement hypothesis. The manifest fallbacks, the study-spec
  builder, the campaign harnesses, the manifest template and the study
  protocol all declare the same direction. The template's protocol
  digest changed to
  `c2f4fd36a07134a09333f1e35c5054c4dff17d328e7b1d5f27b7025a1e70e50d`.
- `_release_path()` in `tools/check_release_ci.py` checked
  `candidate.is_symlink()` *after* `Path.resolve()`, where the final
  component is never a link, so the rule never fired for an internal
  symlink. It now walks the declared path components before resolving
  and refuses a link anywhere in the path; a path that escapes the
  release tree is still refused after resolution.
- Regression coverage lives in `tests/v3/test_governed_eval.py` (both
  directions register, equal rates refused) and
  `tests/v3/test_release_ci.py` (symlinked file, symlinked directory
  component and escaping path).
- The seal is stale until `tools/package_release.py` runs again.

## 2026-11-16 — Verified origins and complete histories (SIS-FIX-04)

Lineage was derived from a checkout's Git root commits, but a shallow
clone reports its boundary as a root, so two shallow clones of one
repository could look independent. A manifest also had no way to say
which upstream a checkout came from, so a locally fabricated commit
that happened to be HEAD still passed.

- Every repository now declares an `origin`. The builder records the
  checkout's configured `origin` remote (or verifies a declared value)
  and refuses a checkout without one or with a shallow history.
- With `check_paths=True` the validator verifies that the checkout's
  `remote.origin.url` equals the declared origin, that the history is
  not shallow, and that the base commit is reachable from at least one
  remote-tracking ref. The report adds `repository_origins`.
- `tools/five_arm_campaign.py` repeats the provenance check before
  registering tasks. A locally fabricated commit reports
  `repository_commit_not_on_remote`; an origin mismatch reports
  `repository_origin_mismatch`; a shallow clone reports
  `repository_history_is_shallow`.
- This is local consistency, not proof that the upstream contains the
  commit. Independent verification still requires fetching from the
  declared origin or a signed attestation. A manifest built before this
  repair lacks `origin` and must be rebuilt.
- Regression coverage lives in
  `tests/v3/test_build_efficacy_manifest.py` and
  `tests/v3/test_five_arm_real_run.py`.

## 2026-11-16 — Repository execution fingerprint (SIS-FIX-03)

The repository-content digest binds file bytes and symlink targets but
deliberately ignores permissions, so two checkouts with identical
content can still execute differently: a script that is executable in
one and not the other, a directory that cannot be traversed, or a
setuid binary. The manifest had no way to pin that state.

- `runner.repository_execution_digest()` hashes each entry's type and
  permission bits (including setuid, setgid and sticky), the root
  directory mode, and symlink targets. It uses the same canonical
  ordering and VCS exclusion as the content digest. Ownership and
  hard-link identity are excluded: Git does not preserve them and the
  staged workspace is runner-owned.
- The content digest is unchanged. The execution fingerprint is a
  separate field, `repo_execution_digest`, so content identity stays
  shareable between clones while execution state is pinned per
  checkout.
- `validate_manifest(check_paths=True)` recomputes and verifies the
  fingerprint (`repository_execution_mismatch`); the report adds
  `repository_execution`. The study-kit builder records it,
  `tools/five_arm_campaign.py` re-verifies it before registering tasks,
  and `BenchmarkHarness` requires every staged workspace to match it
  before an arm runs.
- The manifest template carries the new field. A manifest built before
  this repair omits it and is refused; rebuild it with the study kit.
  Regression coverage lives in
  `tests/v3/test_build_efficacy_manifest.py` and
  `tests/v3/test_five_arm_real_run.py`.

## 2026-11-16 — Manifest commit binding (SIS-FIX-02)

`validate_manifest(check_paths=True)` re-fingerprinted each repository
but never checked its declared `base_commit`. A manifest assembled
outside the study kit could name a fabricated commit — for example,
replacing a repository's commit with `0000…` — as long as its task
records agreed, and the validator still reported `valid` and `ready`.
The builder checked the real HEAD; the validator did not.

- With `check_paths=True` the validator now binds every repository to
  its commit: the path must be the root of a Git checkout, HEAD must be
  the declared `base_commit`, and the working tree must have no staged,
  unstaged or untracked changes. A repository that cannot prove its
  commit reports `repository_head_unverifiable`; a mismatch reports
  `repository_base_commit_mismatch`; a dirty checkout reports
  `repository_is_dirty`. The report adds `repository_commits`.
- `tools/five_arm_campaign.py` repeats the binding immediately before
  it registers tasks, so a checkout that moves between validation and
  execution cannot run. The check covers every repository, not only
  those named by a task.
- `tools/build_efficacy_manifest.py` no longer accepts a non-Git
  directory with a declared commit: an unverifiable commit is refused
  when the manifest is built, not only when it is validated.
- Regression coverage lives in `tests/v3/test_build_efficacy_manifest.py`
  and `tests/v3/test_five_arm_real_run.py`; the latter's fixtures are
  now real Git checkouts.

Executable permissions remain outside the repository-content
fingerprint: a v3 digest binds file bytes and symlink targets, not
modes. SIS-FIX-03 adds a separate execution fingerprint rather than
changing the content identity.

This is a provenance repair, not an efficacy result.

## 2026-11-15 — Canonical repository fingerprint (SIS-FIX-01)

The v3 tree digest hashed entries in `os.walk` order, which is
filesystem-dependent. Two trees with identical contents could receive
different identities, and staging an unchanged repository could fail
with `repository_changed_during_staging`. The digest is now versioned.

- `scan_tree(..., version=2)` is the default and canonical format. It
  sorts directory names and entries by encoded name bytes at every
  level, so the digest depends only on contents, never on directory
  iteration order. Names use `os.fsencode`, so a name that is not valid
  UTF-8 round-trips instead of raising. Empty directories, special
  files and permissions are not part of the fingerprint.
- `version=1` reproduces the legacy traversal-order-dependent digest
  byte for byte. It exists only to re-verify historical records and
  must not mint a digest for a new record.
- `version=3` is the repository-content format: it hashes the working
  tree and excludes `.git`, `.hg` and `.svn`, so two clones of one
  revision share a snapshot digest. Manifests, task envelopes and the
  study kit use it. Workspace receipts and disk accounting stay on the
  full-tree v2 format. `verify_repository_digest()` accepts v3 first
  and replays full-tree v2 and legacy v1 records read-only.
- `verify_tree_digest(root, expected)` returns the version that
  matched (2, then 1 unless `allow_legacy=False`). `TreeScan` records
  its `version`. New execution receipts, task envelopes, registry
  identities and manifests therefore carry canonical digests.
- `BenchmarkHarness` still replays a task whose envelope carries a
  legacy digest; a digest that matches neither version is refused.
- Manifest validation with `check_paths=True` now recomputes each
  repository's canonical digest, verifies the declared digest (legacy
  v1 accepted read-only), and rejects two holdout entries — or an
  induction and a holdout entry — that resolve to the same codebase.
  Identical induction repositories remain permitted. The report adds
  `repository_trees`, `repository_tree_versions` and
  `distinct_repository_trees`.
- Repository lineage is checked separately from content. Every
  repository declares a stable `lineage_id`; a confirmatory manifest
  must supply one. With `check_paths=True`, a Git checkout's lineage is
  derived from its sorted root commits, so two revisions or clones of
  one repository are one lineage even when their files differ. Entries
  connected by a derived or declared lineage key may not both be
  holdout (or span induction and holdout). The report adds
  `repository_lineage` and `distinct_holdout_lineages`. Shallow clones
  report their shallow boundary as a root, so lineage is exact only for
  full clones.

Regression coverage lives in `tests/v3/test_canonical_tree_digest.py`,
`tests/v3/test_benchmark.py`, `tests/v3/test_efficacy_manifest.py` and
`tests/v3/test_five_arm_real_run.py`.

The archive was re-sealed over this repair; `release/test_evidence.json`
records the executed counts and `release/release_manifest.json` records
the source commit and archive digest. The release and isolator keys
remain local, so strict release mode still refuses the bundle. Linux
environments without git now skip the two release tests that require it
instead of failing.

Added `tools/build_efficacy_manifest.py`, a study-kit builder that
turns a declarative spec into a validated, ready-to-run manifest. It
computes canonical repository digests, Git base commits, lineage
metadata and hidden-test digests, and refuses to write unless the
manifest validator reports `valid` and `ready`. It does not invent
repositories, prompts, hidden tests or guidance bundles.

## 2026-11-15 — Revision 15 repairs: custody, power, coverage, execution and lineage

The Revision 14 verification found five defects in the efficacy path.
None of these repairs is an efficacy result; the sealed archive still
describes the pre-repair tree.

- **Workspace custody.** `BenchmarkHarness` staged repositories with
  `shutil.copytree`'s default symlink-following behaviour, so a link in
  a public repository could copy an evaluator-readable file into the
  agent's workspace. `stage_repository()` now rejects a symlinked
  source, rejects external symlinks and hard-linked files before and
  after the copy, copies links verbatim (`symlinks=True`) and requires
  the staged tree to hash identically to the source. Internal hard
  links are allowed; a file whose link count exceeds its in-repository
  paths is refused. A link swapped in during the copy is observed as a
  link, never dereferenced. Each staged digest is bound to the task
  envelope so post-manifest drift is refused.
- **Powered classification.** `analyze_report()` recomputes the power
  floor with `protocol_required_sample_size()` and requires an
  explicitly powered plan. A diagnostic (`powered=False`) protocol, a
  missing/inconsistent `power_analysis` block or a forged `required_n`
  is `exploratory` at best and can never reach `EFFICACY_SUPPORTED`.
  `run_governed_evaluation()` labels a diagnostic run `diagnostic`.
- **Readiness at execution.** The real-agent gate refuses a manifest
  whose validator result is not `ready`; a diagnostic manifest must use
  the demo path. A powered protocol that also declares
  `analysis_kind: diagnostic`, or a diagnostic protocol carrying a
  `power_analysis` block, is invalid, and every task must declare the
  holdout partition.
- **Holdout coverage and budgets.** Manifest validation counts the
  holdout repositories that actually contribute tasks (at least five)
  and the distinct snapshots among them (at least five independent
  codebases), rejects a declared holdout repository with no tasks, and
  reports `holdout_repositories_used`, `holdout_snapshots_used` and
  `tasks_per_holdout_repository`.
  Per-task budgets must equal the preregistered protocol budget. The
  analysis reports solved counts per repository and a deterministic
  repository-cluster bootstrap interval for the pooled `E - A` delta.
- **Execution control.** At the wall limit the harness aborts the arm
  through `ArmSupervisor`; `CodexCliAgent` registers a terminator that
  kills the CLI process group. The harness waits for the worker to
  exit; a worker that survives is `agent_timeout_unterminated` and its
  workspace is retained, never removed or reused. A failed, cancelled,
  timed-out or nonzero-exit CLI turn raises instead of returning a
  normal result. One completed command/edit counts as one tool call,
  cumulative `turn.completed` usage is taken once rather than summed,
  and oversized JSONL lines are drained in bounded chunks. Stderr is
  drained continuously; platforms without process groups fall back to
  terminating the process directly.
- **Learned guidance lineage.** `--guidance-bundle` accepts only a
  schema-2 bundle whose steps name immutable candidate records
  (`candidate_digest`, `content_digest`, `evidence_digest`), whose
  training snapshots are the manifest's induction repositories, and
  whose digest matches the manifest's precommitted
  `guidance_bundle_digest`. `--candidate-registry` additionally requires
  every candidate to resolve to a qualified record whose evidence
  covers the declared digest; without it the bundle is
  `learned_unverified` and cannot support a confirmatory label. A file
  that merely says `"source": "learned"` is rejected. The served
  guidance carries the candidate and evidence IDs, the exact bundle
  bytes are exported with the evidence, a precommitted bundle must be
  supplied, and duplicate JSON keys or oversized files are rejected. A
  bundle whose candidate IDs, step count or step text cannot satisfy
  the guidance contract is refused at load time instead of failing the
  campaign.

Regressions live in `tests/v3/test_benchmark.py`,
`tests/v3/test_codex_cli_adapter.py`,
`tests/v3/test_efficacy_manifest.py`,
`tests/v3/test_execution_qualification.py`,
`tests/v3/test_five_arm_real_run.py`,
`tests/v3/test_governed_eval.py` and
`tests/v3/test_learning_qualification.py`. Regenerate the archive and
its evidence with `tools/package_release.py` before making a release
claim.

## 2026-11-14 — Revision 14 repairs: sampler, provenance and evidence

The Revision 13 audit found a release-blocking sampler crash and four
integrity gaps in the new efficacy path. None of these repairs is an
efficacy result.

- **Arbitrary-size sampling.** `distinct_inputs()` used
  `random.sample(range(possible), count)`, which asks for a
  machine-sized length; a 32-field decimal domain (`10**32`) raised
  `OverflowError` and the default benchmark crashed. Floyd's algorithm
  now draws the indices in O(count) without materialising the domain.
  Regressions cover 32 and 64 fields and the CLI.
- **Metered usage.** `CodexCliAgent` reads `token_usage` from the CLI
  event stream and records tokens and tool calls through the harness
  meter. `UsageMeter` distinguishes fully `verified` accounting from a
  `partial` one where only one counter was metered; the audit's
  unenforced token budget now surfaces as missing accounting rather than
  a silent pass.
- **Provenance-gated classification.** `analyze_report()` accepts a
  `provenance` block. A confirmatory label now also requires the real
  `codex-cli` agent (an injected agent is `invalid`), a matching
  installed CLI version, split custody, learned guidance from
  `--guidance-bundle`, a committed manifest and fully verified usage.
  The built-in `Recall…`/`Workflow…`/`Procedure…` prompts are recorded
  as `fixed_control` and can never qualify.
- **Durable evidence.** A run writes `<report>.evidence/` containing
  every signed receipt, the evaluator public key, the exact manifest and
  a `bundle.json` binding the manifest, report and receipt digests. The
  verifier's temporary key store no longer takes the evidence with it.
- **Randomized arm order.** `BenchmarkHarness.run()` accepts an
  `arm_order_seed`, shuffles the arms per task and records the executed
  order, as the protocol requires.
- **CLI version pin.** The gate compares the installed `codex --version`
  with the manifest and fails closed on a mismatch or an unreadable
  version.
- **Holdout repository floor.** The manifest validator now requires at
  least five holdout repositories, so a task count cannot be met from
  one or two correlated codebases. Repository-clustered analysis is
  documented as a required companion metric.
- **Review follow-ups.** `campaign_digest()` now normalizes the float
  values in an analysis report, which `canonical_digest` rejects; the
  helper had been unusable since v3.3.2. The gate also refuses a
  manifest that still contains placeholder values.

Regressions live in `tests/v3/test_five_arm_real_run.py`,
`tests/v3/test_learning_qualification.py`,
`tests/v3/test_v336_benchmark_semantics.py`,
`tests/v3/test_execution_qualification.py` and
`tests/v3/test_efficacy_manifest.py`. The sealed archive and its
evidence predate these repairs; regenerate them with
`tools/package_release.py` before making a release claim.

## 2026-11-14 — Authority-closure repairs: paired inference, executable gate, bounded sampling

Three defects that stood between the Phase 6 scaffold and the Phase 6
question are repaired. None of them is an efficacy result.

- **Paired inference.** `paired_contrast()` reported a Newcombe interval
  built from the two marginal solve rates, which treats the paired arms
  as independent samples. It now uses Newcombe's method 10 for paired
  data (`newcombe_paired_difference_interval`), combining the marginal
  Wilson intervals with the observed pair correlation. With 100 paired
  tasks, 8 treatment-only solves and 0 baseline-only solves, the old
  interval was `[-5.76, +21.34]` percentage points and included zero
  while exact McNemar rejected the null (`p=0.0078125`); the paired
  interval is `[+2.35, +13.48]`. `evaluation_certificate` reconstructs
  the paired interval from the receipt matrix, so a certificate carrying
  the corrected interval still verifies.
- **Executable real-agent gate.** `tools/five_arm_campaign.py
  --real-agent --manifest` no longer returns
  `BLOCKED_REAL_RUN_NOT_EXECUTED` for every supplied manifest. It
  validates the manifest, verifies each repository snapshot digest,
  registers the evaluator-owned acceptance material, runs the five arms
  with `CodexCliAgent`, and writes the paired report with a receipt
  digest per `(task, arm)` and the frozen guidance bundles. An invalid
  manifest, repository drift, an unavailable agent and unavailable split
  custody still fail closed.
- **Bounded benchmark sampling.** `tools/benchmark_induction.py` drew
  distinct samples by rejection with no feasibility check, so a valid
  CLI request such as `--fields 2 --input-min 0 --input-max 1` (four
  possible inputs, twelve requested) looped forever. Sampling now draws
  from the domain's integer indices, and an impossible request exits 2
  with a message before induction starts.
- **Release CI archive delivery.** `release/*.zip` is git-ignored, so the
  strict gate on a tag had no archive to verify. The `tests` job now
  uses a supplied `release/SIS-*.zip` when present and otherwise fetches
  the asset attached to the release (`gh release download`), then
  re-hashes it against `release/release_manifest.json` and the signed
  provenance. A missing archive fails with an explicit error naming the
  tag. The job also checks the six repository secrets/variables before
  calling the gate and reports every missing trust anchor in one
  message. The release-only evidence job now fails with an explicit
  error when `SIS_TEST_EVIDENCE_SIGNING_KEY` is absent instead of
  uploading an unsigned report the seal rejects.
- **Release-identity test portability.** `ReleaseIdentityTests` skipped
  only when `release/release_manifest.json` was absent, so an extracted
  source tree (manifest present, ZIP and `.git` absent) failed instead
  of skipping. The guard now requires the archive the manifest names,
  and the commit test skips when the release commit is not in local Git
  history.

Regressions live in `tests/v3/test_learning_qualification.py`,
`tests/v3/test_five_arm_real_run.py` and
`tests/v3/test_v336_benchmark_semantics.py`. The sealed archive and its
evidence predate these repairs; regenerate them with
`tools/package_release.py` before making a release claim.

## 2026-11-14 — Phase 6 efficacy-study scaffold

Adds the preregistration and manifest validation needed before a real
five-arm efficacy study can run. This is not an efficacy result.

- `docs/v3/EFFICACY_STUDY_PROTOCOL.md` defines the A–E arms, the
  repository-disjoint hidden holdout, the 103-pair design target
  (0.60 → 0.40; 515 arm runs), equal budgets, metrics, evidence classes
  and the persistence requirement.
- `docs/v3/efficacy_manifest_template.json` is the manifest shape. It
  carries the preregistered protocol digest and placeholders for at
  least ten repositories and 103 paired tasks.
- `src/sis/v3/efficacy_manifest.py` and
  `tools/check_efficacy_manifest.py` validate the five arms, the
  recomputed power floor, repository disjointness, hidden tests outside
  the public repository, safe acceptance paths, pinned agent identity and
  equal task budgets. A valid manifest is a prerequisite, not evidence.
- `tests/v3/test_efficacy_manifest.py` covers the template, a complete
  ready manifest, partition overlap, hidden-test placement, digest
  mismatch, an explicitly underpowered plan and unsafe acceptance paths.

The real-agent gate remains `BLOCKED_MANIFEST`; no confirmatory run was
executed and the learning workflow's general effectiveness remains
unproven.

## 2026-11-14 — SIS v3.3.9 controlled repair release

v3.3.9 is a security, correctness and verification repair, not a feature
release. The learning workflow is unchanged; its general effectiveness
remains unproven. Production qualification still requires keys held
independently of the evaluated machine.

- `tools/check_release_ci.py --mode release` now requires
  `release/release_manifest.json`, the claimed archive, a byte-exact
  source-tree binding, a signed `production` provenance envelope,
  authenticated test evidence and a cryptographically re-verified raw
  isolation attestation. A development-mode inventory success never
  satisfies the release gate, and a valid signature over an unrelated or
  malformed ZIP is rejected.
- `tools/verify_release.py --source <tree>` binds a ZIP to the exact
  source tree; release mode also streams the archive, rejects duplicate,
  missing, unexpected or modified members, and compares every member with
  the current source digest.
- Test evidence is now authenticated. `tools/run_tests.py` records the
  full output and its digest, the exact command, exit status, commit and
  parsed counts, and can sign the report with an Ed25519 CI key. The
  packager and gate reject an unsigned report, a fabricated count, a
  truncated output, a narrowed pytest command or a report from another
  commit. Evidence is written to `release/test_evidence.json`.
- The release manifest records `release/isolation_receipt.json`,
  `release/isolation_attestation.json` and a fresh
  `release/isolation_verification.json`. The gate re-verifies the
  signature with the relying party's isolator key, pins the image and
  policy digests, checks freshness and rejects a receipt from another
  execution.
- Hard resource enforcement: `induce(..., hard_limits=...)` routes a
  search through `sis.enforced_induction.run_induction_enforced`. The
  receipt records the parent monotonic deadline, observed wall time,
  `RLIMIT_AS`, `RLIMIT_CPU` and `RLIMIT_NPROC`, distinguishes cooperative
  budget exhaustion from a hard-limit termination, and can be signed with
  `sign_receipt()`. A `resource_exhausted` result is never a successful
  evaluation.
- `LocalSubprocessExecutor` and `DockerSandboxExecutor` now stop their
  pump threads instead of closing a blocked pipe, so a grandchild holding
  a pipe cannot extend an 8-second deadline into a ~20-second
  termination. An execution that exits just after the parent deadline is
  recorded as a timeout, and a CPU-limit signal is marked
  `rlimit:cpu_exceeded` so it classifies as a resource limit, not a task
  failure.
- Docker evidence was regenerated against
  `sis-evaluator:3.3.9@sha256:5af4f6ce…`: the containment probe passes
  13/13 and the local `IsolationAttestationV1` verifies with reason `ok`.
  The stored trust root remains `qualification-only`.
- Qualification matrix: Python 3.10, 3.12 and 3.13; Linux without Docker;
  PostgreSQL 16; SQLite; Z3-enabled bounded equivalence; and a clean
  extracted archive. Windows remains explicitly experimental.

The checked-in v3.3.9 bundle is qualification-only. A production seal
still requires an independently held release key, CI evidence key and
isolator key.

## 2026-11-14 — Release authenticity gates

Closes the code side of the build-10 release-authenticity finding. The
key ceremony remains external.

- `tools/check_release_ci.py --mode release` now requires a signed
  `production` provenance envelope and verifies it against the relying
  party's release key, supplied with `--release-public-key` or
  `SIS_RELEASE_PUBLIC_KEY`. A key shipped beside the artifact is not
  accepted as its own trust anchor.
- Release mode also requires `release_manifest.isolation.
  external_attestation.verified` to be true. Passing
  `--isolator-public-key` (or `SIS_ISOLATOR_PUBLIC_KEY`) pins the
  recorded isolator key.
- `tools/package_release.py` accepts `--external-attestation` and
  `--require-external-attestation`. The record must be a fresh
  `external_isolation_verification`, verified with reason `ok`, name
  its required properties, and bind the probe image digest and stored
  receipt digest. The release manifest records the record's digest,
  signer, image, policy and receipt bindings.
- `tests/v3/test_release_ci.py` covers unsigned provenance, a
  qualification trust root, a missing or wrong release key, a missing
  isolation attestation and a mismatched isolator key. The evidence
  tests cover expired, failed, unbound and malformed external records.

The stored bundle remains qualification-only; a production seal still
needs an isolator key held independently of the evaluated machine.

## 2026-11-14 — Private evaluation defaults to split custody

Closes the remaining custody default identified by the build-10 review.
Private acceptance material no longer defaults to shared custody.

- `OutcomeVerifier.register_task(custody=None)` resolves private
  material to `split` when the backend has a second principal and fails
  closed with `split_custody_unavailable_for_private_material`
  otherwise. A registration without private files stays shared.
- `custody="shared"` requires a verifier built with
  `allow_shared_custody=True`; the flag conflicts with
  `require_split_custody` and with a production `isolation_policy`.
  Shared private material is refused at registration with
  `shared_custody_requires_explicit_opt_out`.
- Production is enforced in two places: `register_task()` refuses a
  shared private registration with `production_requires_split_custody`,
  and `evaluate()` rejects a legacy shared row with the same reason
  before running it.
- The worker accepts `--allow-shared-custody` (development only). It
  conflicts with `--require-split-custody` and `--split-user`. A worker
  without the opt-out rejects a shared private task as
  `shared_custody_not_permitted`, and refuses to start when the loaded
  registry needs split custody but the executor has no second principal.
- `tools/learn_recommend_cycle.py` defaults to `--split-user 2002:2002`
  for Docker, registers every private task with `custody="split"`, and
  aborts when the probe's split check fails. Its report records
  `private_test_custody`.
- `DockerSandboxExecutor.probe()` adds `split_identity_exec` when a
  split user is configured: a command runs as the second UID and the
  receipt must carry both `evaluation:process_split` and
  `split:custody:separate_uid`.
- The development harnesses (`five_arm_campaign.py`,
  `governed_campaign.py`, `governed_live_campaign.py`, `live_study.py`,
  `real_agent_campaign.py`, `skill_holdout.py`,
  `scripts/v3/run_codex_episode.py`) name `custody="shared"` and opt out
  explicitly. `tests/v3/test_private_evaluation_entrypoints.py` scans
  `tools/` and `scripts/` so an unmarked private registration or a
  shared registration without the verifier opt-out fails the suite.
- `tests/v3/isolation_testkit.ScriptedExecutor` models the split
  capability so production-path tests register private material without
  weakening the verifier.

New regressions live in `tests/v3/test_split_custody.py`,
`tests/v3/test_evaluator_worker.py` and
`tests/v3/test_private_evaluation_entrypoints.py`. The tree is
unsealed until build 11 reseals it.

## 2026-11-14 — Test-matrix portability and evidence-bound releases

Makes the suite honest where Docker is absent and binds release test
totals to an executed run.

- The two Docker construction tests in
  `tests/v3/test_split_custody.py` patch `_require_docker`, so they
  test configuration instead of contacting a daemon. The full suite now
  runs with `DOCKER_HOST` pointed at a nonexistent socket: 1509 passed,
  33 skipped, 0 failed locally.
- CI adds a `docker-absent` job with a dead `DOCKER_HOST` and requires
  zero failures or errors.
- `tools/run_tests.py` is the supported runner. It refuses a pytest
  version other than the pin in `requirements-lock.txt` and writes
  machine-readable evidence (commit, dirty flag, command, environment,
  parsed counts, output digest).
- `docker/sandbox/requirements.lock` pins pytest and every transitive
  dependency with SHA-256 hashes; the evaluator image installs it with
  `--require-hashes`. `tests/v3/test_evaluator_image_lock.py` keeps the
  lock complete.
- `tools/package_release.py` accepts `--test-evidence` and
  `--require-test-evidence`. Evidence from another commit, a dirty
  tree, a non-pinned pytest, or a run with failures or errors is
  refused; `--passed` remains only as an explicit operator override.
- `tools/check_release_ci.py --mode release` refuses a release manifest
  whose `test_result.source` is not `evidence`, or that reports failed
  or errored tests.
- `ReleaseIdentityTests.test_release_commit_covers_current_source`
  skips on a development tree whose `RELEASE_SHA256.json` is stale;
  release mode remains the enforcing gate.
- Windows remains experimental and non-blocking for build 11; the
  release does not claim Windows evaluator support.

New regressions live in `tests/v3/test_release_test_evidence.py`,
`tests/v3/test_evaluator_image_lock.py` and
`tests/v3/test_release_ci.py`.

## 2026-11-14 — Induction scaling, CI image build and archive retention

Closes the remaining scaling, CI and retention gaps identified by the
review. The induction change is an ordering strategy, not a relaxation of
the acceptance criteria.

- `candidates()` ranks depth-1 binary expressions by residual variance
  when more than twelve numeric features are present, and offers the
  constant-offset completion of a top-ranked mid before the raw
  enumeration. The completion must fit training and development to stop
  the search, the same criterion the engine already applies.
- Benchmark (`x[n-2] * x[n-1] + 2`, 6/3/3 partition, default budgets):
  - 64 fields: 129 candidates, 193 signature checks, no limits hit,
    intended structure recovered; with `--equivalence z3` the report is
    `exact_recovery_verified: true` over the declared 0..9 box.
  - 32 fields: 65 candidates, 97 signature checks (was 4,267 candidates
    and 500,000 signature checks, truncated).
  - 16 fields: 33 candidates, 49 signature checks with the intended
    structure (was 1,251 candidates and 160,707 checks, ambiguous).
  - 8 fields: on the default 0..9 domain the existing ambiguity is still
    reported (the rival is observationally equivalent there). With
    `--input-min -9 --equivalence z3` the search recovers the intended
    structure exactly in 474 candidates and 38,938 checks.
  - A target without a constant-offset completion still truncates
    honestly under the same budget.
- CI builds `sis-evaluator:3.3.8` on Linux before the suite, so the
  Docker integration tests run there instead of skipping.
- `tools/package_release.py` moves an existing archive to
  `release/history/` (named by its digest) before a reseal. The
  directory is gitignored; it is a local safeguard, not a published
  archive.
- `tools/qualify_docker_isolation.py --trust-root production` refuses to
  generate a key on the evaluated machine and requires `--seed-file`.
  The signer public key must still be verified against a key held by the
  relying party.
- Added `tools/verify_external_attestation.py`: the production custody
  path verifies an attestation signed by a key held elsewhere against the
  receipt, image digest, policy digest and required properties, and fails
  closed on any mismatch. The stored bundle remains qualification-only.
- The remaining campaign harnesses (`five_arm_campaign.py`,
  `governed_campaign.py`, `governed_live_campaign.py`, `live_study.py`,
  `real_agent_campaign.py`, `skill_holdout.py`) now refuse to execute
  without `--allow-local-executor`, matching the demonstration cycle and
  episode runner. `skill_holdout.py --list` is exempt because it runs
  nothing.
- Fixed a latent `NameError` in `tools/live_study.py`: the shared source
  receipt was minted before the per-task failure class existed, so the
  tool could never complete a grant. Each grant now mints source
  evidence carrying the matching class. CI lint now covers `tests/` and
  `tools/`, where the undefined name hid.

## 2026-11-14 — Docker evidence refresh and repository hygiene

Regenerates the Docker containment evidence over the post-seal tree and
closes the review findings that were still open. Not a feature release.

- Added `tools/probe_docker_sandbox.py`, the missing reproducible driver
  for `evidence/sandbox/docker_sandbox_probe.json`. It runs
  `DockerSandboxExecutor.probe()` against a digest-pinned image.
- Regenerated the probe (13/13) and
  `evidence/sandbox/gate2_isolation/` against
  `sis-evaluator:3.3.8@sha256:27415edf…` on Docker 29.9.3. The
  attestation verifies (`reason: ok`) and the wrong-digest control is
  rejected (`image_mismatch`). Trust root remains `qualification-only`.
- Added real-container split-custody tests. They verify that the worker
  UID cannot read the private tests and that a task reloaded in the
  worker child keeps `custody="split"`; they skip when Docker or the
  image is unavailable.
- `OutcomeVerifier` now implies `require_split_custody` when the executor
  has a configured `split_user`, matching the worker CLI instead of
  leaving the API path weaker. `DockerSandboxExecutor.split_user` is
  public.
- Cleared the 64 pre-existing pyflakes findings in `tests/` (`ruff check
  src tests` is now clean) and corrected stale documentation:
  `QUALIFICATION_REPORT.md` is marked superseded, `STATUS.md` points at
  the v3.3.8 report, the Gate 2 section no longer cites its historical
  suite count as current, and the generated release README states that
  the ZIP is distributed out-of-band.

Suite on the refreshed tree: 1490 passed, 13 skipped, 0 failed.

## 2026-11-14 — Split-custody worker configuration (post-seal)

Makes the process-split boundary reachable through the shipped evaluator
worker and lets a deployment refuse shared custody for hidden tests. Not a
feature release; the sealed v3.3.8 archive still describes the pre-repair
tree.

- `evaluator_worker` accepts `--split-user uid[:gid]` (API:
  `build_worker_executor(split_user=...)` and
  `evaluate_via_subprocess(split_user=...)`) and passes it to
  `DockerSandboxExecutor`, so `supports_split_custody` is true for a
  deployment that configured the second identity. The Docker executor
  validates the value: numeric, non-root and distinct from the evaluator
  UID. The local backend refuses a split user because its boundary is a
  seatbelt read denial, not a second UID.
- `OutcomeVerifier(require_split_custody=True)` (CLI
  `--require-split-custody`) fails closed in three places:
  construction rejects a backend without a second principal
  (`split_custody_required_but_unavailable`); `register_task()` refuses
  private acceptance files under shared custody
  (`split_custody_required_for_private_material`); `evaluate()` rejects a
  registration that predates the policy (`split_custody_required`, an
  evaluator bootstrap error).
- Configuring `--split-user` enables the policy implicitly, so a worker
  that was told which second UID to use does not keep grading hidden
  tests beside the submission.
- Custody is persisted in `tasks.json` and verified on load. A row
  written before the field existed is recovered from its suite
  commitment; a row whose declared mode disagrees with the commitment
  raises `JournalIntegrityError` instead of loading. Without this, every
  reload — and `evaluator_worker` builds a fresh verifier in each child
  process — reset a split task to shared custody, silently removing the
  boundary the registration was meant to hold.
- A worker started without `--split-user` still rejects split tasks as
  before; shared custody remains the development path.

Limits: the Docker split is still unit-tested against a Docker CLI double
and not live-qualified on every host. Re-run the Docker containment probe
on the exact image before claiming production isolation. Regressions:
`tests/v3/test_split_custody.py`.

## 2026-11-13 — Process-split acceptance custody (post-seal)

Closes the read path left by private-material separation: the acceptance
runner and the submitted code shared one process, so a submission could
read the tests it was graded against. Not a feature release; the sealed
v3.3.8 archive still describes the pre-repair tree.

- `register_task(custody="split")` runs the acceptance command in the
  evaluator's process and reaches submitted code only through an
  out-of-process proxy (`src/sis/v3/split_harness.py`). A meta-path
  finder replaces each workspace module — including a submission laid
  out as a package and its submodules — with a proxy whose attribute
  reads and calls are marshalled over a Unix socket.
- The worker runs under a separate principal that cannot read the
  private directory: a seatbelt profile with
  `(deny file-read* (subpath <private>))` on the local backend
  (`split:custody:seatbelt_read_denied`), or a second numeric UID
  through `docker exec --user` on the Docker backend
  (`split:custody:separate_uid`).
- The wire codec is JSON over a closed type set. Submission-produced
  bytes are never unpickled in the evaluator process; an unsupported
  argument or return type fails the call instead of widening the codec,
  and a worker can only raise ordinary exceptions there (never
  `SystemExit` or `KeyboardInterrupt`).
- Split custody pins pytest configuration to the private directory
  (`-c`, `--confcutdir`, `-p no:cacheprovider`). Without that, pytest
  would read `pytest.ini`, `pyproject.toml` and `conftest.py` from the
  graded workspace, and a submission could have its own plugin imported
  into the process that holds the tests.
- A harness failure is never a verdict about the submission. The
  bootstrap pings the worker before running the command and exits with a
  dedicated status if it is missing or dies; the executor maps that
  status to `sandbox:split_custody_unavailable` or
  `sandbox:split_worker_lost`, so the outcome is a sandbox failure
  rather than `TASK_FAIL`.
- Fail-closed: a split task on a backend without the capability is
  rejected (`split_custody_unavailable`, an evaluator bootstrap error);
  a receipt that does not carry `evaluation:process_split` is rejected
  (`split_custody_unverified`, a sandbox failure); a non-Python
  acceptance command is refused at registration instead of being handed
  the Python bootstrap. `LinuxRootlessWorker` declares the capability
  false because bwrap maps the caller's UID into the namespace.
- Docker verifies the container copy of the private material, not the
  host staging directory the worker never sees
  (`sandbox:private_material_modified`).
- `custody` is bound into the suite commitment only when declared, so
  existing shared-custody registrations keep their historical
  commitments.

Limits: only primitives, callables and composites of primitives cross
the socket, so a test that passes an arbitrary object or expects a
non-primitive return value fails the call rather than widening the
codec. The local backend shares a UID with the worker, so the seatbelt
read denial — not the UID — is the boundary. The Docker split is covered
by unit tests against a Docker CLI double; it is not live-qualified on
this host. Regressions: `tests/v3/test_split_custody.py`.

## 2026-11-13 — Gate 2 containment repairs (post-seal)

Security/correctness repair of the Docker evaluator boundary. This is not
a feature release and does not change any signed artifact; the sealed
v3.3.8 archive and its evidence still describe the pre-repair tree.

Containment:

- `DockerSandboxExecutor._copy_out` enforces the run's `disk_bytes` and
  the workspace file-count bound **while reading** the tar stream, not
  after the host has written the archive. A regular member over budget
  is rejected before extraction, sparse members are refused, and the
  stream carries a hard cap. Violations preserve the workspace and
  report a reason-specific marker (`fs:disk_budget_exceeded`,
  `fs:file_count_exceeded`, `fs:sparse_member_rejected`), plus
  `fs:workspace_state_unavailable` and `fs:copy_out_rejected:<reason>`.
- A failed copy-out swap restores the prepared workspace instead of
  deleting it (`shutil.rmtree` before `os.rename` removed).
- `OutcomeVerifier` stages registered acceptance files outside the graded
  workspace when the backend supports private material. Docker and the
  Linux worker bind them read-only at `/private`; the local backend uses
  an absolute sibling directory. Registered argv tokens are rewritten
  and the receipt carries `evaluation:private_material_separated`.
  Legacy backends keep the co-located staging.
- The graded workspace is **not** placed on `PYTHONPATH`. A Python
  acceptance command runs through a staged, read-only bootstrap that
  imports the test runner and only then adds the workspace to
  `sys.path`. This closes two forgeries: a submission `pytest.py` no
  longer shadows the runner, and a submission `sitecustomize.py` is no
  longer imported at interpreter startup. Both previously made a failing
  acceptance test report exit 0, which classifies as a pass.
- The bootstrap fails closed when the trusted runner cannot be imported:
  a `-m` runner missing from the trusted environment writes
  `evaluation_runner_unavailable: <module>` and exits 70 before the
  workspace is importable, and direct scripts install an import guard
  that refuses a workspace `pytest` module. `classify_execution` maps
  that marker to an evaluator bootstrap error, even if a receipt reports
  exit 0.
- A post-run check re-reads the staged private files. A local backend
  run that rewrote them carries `sandbox:private_material_modified` and
  classifies as a sandbox failure, never a pass. Docker and the Linux
  worker mounts are read-only; the check is defense in depth.
- `register_task()` enforces the same private-material bounds as
  staging (64 files, 1 MiB each, 8 MiB total, normalized relative
  names), so an over-bound task fails at registration rather than as an
  evaluation infrastructure error.

Evaluation defaults:

- `sis.v3.evaluator_worker` defaults to `DockerSandboxExecutor` and
  requires an image. Local execution requires explicit
  `allow_local_executor` authorization.
- `tools/learn_recommend_cycle.py` defaults to `--sandbox docker`;
  `--sandbox local` requires `--allow-local-executor`.
- `scripts/v3/run_codex_episode.py` requires `--allow-local-executor`
  before it will construct the local backend.
- `tools/package_release.py` regenerates `release/README.md` from
  `release_manifest.json`, so the archive hash, source commit, file
  count and test result cannot survive a new seal. The previous README
  still named the pre-repair hash, commit and 448-file inventory.

Correctness:

- `verify_proposal()` rejects a target path that resolves outside its
  base directory (`target_escapes_base`), matching `propose_edit()`.

Tests: `tests/v3/test_gate2_containment_repairs.py` covers the over-budget
archive, member-count and stream rejection, sparse members, swap-failure
and restore-failure preservation, private material separation (Docker
argv and local execution), the bootstrap (startup and runner shadowing),
tamper detection, staging/registration bounds, verifier staging, the
patch symlink escape and the worker defaults. Full suite: 1452 passed,
13 skipped after the repaired tree is re-sealed with
`tools/package_release.py`.

Limits: at the time of that repair, same-process, same-principal test
runners could still read a private path they deliberately enumerate.
That read path is closed by `custody="split"` in the entry above. The
local backend's material is mode-protected, not OS-read-only, so
tampering is detected after the fact rather than prevented. Regenerate
the sealed archive with `tools/package_release.py` before a release
claim.

## 2026-11-13 — Gate 2 sandbox qualification: live containment and signed attestation

Live qualification of the Docker evaluator sandbox, with evidence.

Containment:

- The evaluator Dockerfile pins `python:3.12-slim` by multi-architecture
  index digest (`sha256:5e2bdb1b…`), so a rebuild cannot resolve to
  different base bytes.
- The containment probe gains four hostile checks: Docker-socket absence,
  `no-new-privileges`, empty effective capabilities and `setuid(0)`
  denial. All 13 checks pass in production mode against
  `sis-evaluator:3.3.8@sha256:71dddad6…` on Docker 29.9.3.
- The Docker integration tests run instead of skipping in this
  environment: 1413 passed, 13 skipped, 0 failed.

Attestation:

- `tools/qualify_docker_isolation.py` runs one command, writes the
  execution receipt, issues an `IsolationAttestationV1` from an isolator
  seed that never enters the workspace, and verifies it against a
  `ProductionIsolationPolicy`. A wrong image digest is rejected.
- Evidence is recorded under `evidence/sandbox/`, and
  `tests/v3/test_gate2_qualification.py` re-verifies the stored
  attestation without a daemon.

Limits: the signing key is local (trust root `qualification-only`) and
release provenance remains unsigned. A production seal still needs an
isolator key held independently of the evaluated machine. See
`docs/v3/SANDBOX_QUALIFICATION_GATE2.md`.

## 2026-11-12 — Patch-verification binding and release-inventory repair (Gate 1)

Post-seal correctness repair. `verify_proposal()` had no production call
site, but its output was not bound to the reviewed change: substituted
patched bytes passed, an empty source skipped the source-digest check, and
two different binary replacements shared one diff and one proposal digest.

Patch binding:

- `PatchProposalV1` now commits to `source_span_offset`,
  `source_span_length` and `patched_content_digest`, so the proposal digest
  covers the exact replacement span and the complete resulting bytes.
- `verify_proposal()` checks the source digest unconditionally (including
  empty files), checks the patched-content digest and size, replays the one
  permitted span replacement against the source, and requires the supplied
  diff to be the canonical diff of that source-to-output transformation.
- New regressions in `tests/v3/test_patcher.py` cover substituted output,
  empty-source digest bypass, distinct binary replacements, path
  substitution, out-of-bounds spans and a diff that does not bind content.
  Golden schema and contract examples carry the new fields.

Benchmark semantics:

- `tools/benchmark_induction.py` now includes the `if_eq` right operand in
  `structural_form()`, so conditionals that differ only in the comparison
  target are no longer treated as the same structure. Pinned by
  `tests/v3/test_v336_benchmark_semantics.py`.

Efficacy analysis:

- `analyze_report()` built `contrasts["E_vs_A"]` with treatment `A` instead
  of `E`, so that entry compared the baseline with itself. The entry now
  uses the same A-vs-E contrast as `decisive_contrast`; pinned by
  `tests/v3/test_learning_qualification.py`. The two historical report
  files were corrected post hoc by replacing only that derived field with
  their existing `decisive_contrast`; raw outcomes were not changed. See
  `evidence/evaluation/CORRECTIONS.md`.

Sandbox evidence:

- Refreshed `evidence/sandbox/docker_sandbox_probe.json` from
  `DockerSandboxExecutor.probe()` against the digest-pinned
  `sis-evaluator:3.3.8@sha256:71dd…` image. The probe records thirteen
  checks, including Docker socket absence, no-new-privileges, dropped
  capabilities and setuid denial.

Release inventory:

- `.coverage` and `.coverage.*` are structurally excluded from the release
  inventory in `tools/check_source_manifest.py`; the manifest was
  regenerated over 440 files and verifies with `tools/verify_release.py`.
- `release/README.md` now identifies `SIS-v3.3.8.zip`, records its SHA-256,
  and states that the sealed archive predates this repair and remains
  unsigned.

## 2026-11-11 — SIS v3.3.8 workspace-ownership and sandbox-limit repair (V338-05…V338-09)

Post-seal repair of the v3.3.8 containment line. It changes evaluator
behavior, not any efficacy claim.

V338-05 — a workspace handle is a capability, not a path:

- `sis.v3.workspace_guard.ManagedWorkspaceRegistry` records every
  workspace a backend creates. `run()` and `destroy()` resolve the
  handle ID through that registry and accept a caller-supplied path only
  when it is exactly the registered canonical path. A forged handle, a
  handle from another executor, a mismatched executor identity, a
  symlinked workspace directory, or a workspace whose directory has been
  deleted is rejected before the backend mounts, executes within, or
  deletes anything (`workspace_not_registered`,
  `workspace_path_substituted`, `workspace_executor_identity_mismatch`,
  `workspace_path_symlink_escape`, `workspace_path_missing`).
- Destruction marks a workspace closing, refuses new runs, terminates
  the executions still in flight, and removes the directory only after
  every execution that already started has left its critical section.
  Repeated destruction of the same handle is a no-op, and a removal that
  cannot be verified raises `workspace_remove_failed` instead of being
  reported as success.
- 9 new ownership regressions in
  `tests/v3/test_v338_workspace_ownership.py` (43 total), including the
  concurrent execute/destroy race.

V338-06 — the Docker workspace is a quota-limited tmpfs:

- The host tree is mounted read-only at `/submission`, copied into the
  tmpfs before the command runs, and copied back through a filtered tar
  stream afterwards. `disk_bytes` is enforced by the filesystem during
  execution instead of being audited after it.
- The copy-out archive is extracted with `filter="data"`: absolute
  paths, `..` escapes, device nodes and links that leave the workspace
  are rejected. Four regressions in
  `tests/v3/test_v338_workspace_ownership.py` pin each rejection.
- A run stopped by the wall clock, the output cap or pids exhaustion
  reports `fs:workspace_state_unavailable` instead of presenting the
  pre-run tree as final.

V338-07 — resource bounds compose with the executor:

- `pids` and the output cap are the minimum of the executor limit and
  the spec request; previously a larger spec value overrode the executor
  cap. Output is now capped across both streams, not per stream.
- CPU time is a kernel `RLIMIT_CPU` inherited by the command, so it is a
  budget rather than only a scheduling share.
- `nofile` is a bounded constructor parameter (`nofile_limit`, default
  1024) instead of an undocumented 256 hard cap; the value is reported
  as `docker:ulimit_nofile:<n>` and folded into the environment digest.
- A root container identity is rejected at construction, and a host that
  runs as root falls back to `65534:65534`.

V338-08 — copy-out liveness:

- The copy-out reader drained stdout but never stderr. A workspace with
  thousands of unreadable entries makes GNU tar write far more than one
  pipe buffer to stderr; the child then blocked before finishing the
  archive and `run()` waited forever, leaking the container and the
  workspace. stderr now goes to a temporary file, and a watchdog bounds
  the copy-out. Regression:
  `test_copy_out_does_not_stall_on_a_stderr_flood`.

V338-09 — protected material and bootstrap staging:

- `protect()` refuses a protected path that contains the executor root,
  and the `protected_paths` constructor argument now runs the same check
  instead of bypassing it. `prepare()` refuses any source tree that
  overlaps protected key or registry material in either direction
  (`base_dir_overlaps_protected_material`).
- The runtime bootstrap check no longer stages its base tree under the
  evaluator registry directory.

Behavior changes for operators: `DockerSandboxExecutor(user=...)` must be
a numeric `uid[:gid]` and must not be root; `destroy()` can raise
`workspace_busy` or `workspace_remove_failed`; and a submission larger
than `disk_bytes` now fails at copy-in instead of producing a
`fs:disk_budget_exceeded` receipt. The sealed v3.3.8 archive and
qualification evidence describe the pre-repair tree and must be
regenerated with `tools/package_release.py` before any release claim.

Repository hygiene in the same repair:

- Ruff is pinned in `pyproject.toml` (`E9` and `F` over `src`); the CI
  `lint` job runs it plus `compileall`. The 27 unused imports and six
  unused variables it found are removed without changing behavior.
- `tests/v3/test_docker_sandbox.py` probes for the ability to create a
  container, so a daemon that is reachable but unusable skips the
  integration class instead of failing it.
- `docs/v3/RELEASE_PROCESS.md` records the branch, tag and seal ritual.
  The sealed releases are tagged `SIS-v3.3.5` through `SIS-v3.3.8` on
  their seal commits.

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
