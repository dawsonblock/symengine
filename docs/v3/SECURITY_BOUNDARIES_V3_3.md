# SIS v3.3 Security Boundaries

## Roles and permissions (policy.py)

| role | permissions relevant to learning plane |
| --- | --- |
| agent | guidance:read, qualified_catalog:read, observation:append |
| runner | workspace:execute, observation:append, artifact:read |
| learner | candidate:write, artifact:read |
| evaluator | outcome:evaluate, outcome:sign, evaluator_private:read, artifact:read |
| operator | promotion:approve, policy:write, qualified_catalog:read, artifact:read |

- `candidate:write` → learner only. Memory induction and the skill
  optimizer run under this role: they can submit at PROPOSED and move
  `proposed→validated`. Nothing else.
- `outcome:evaluate` → evaluator only. Owns `validated→evaluating`,
  `evaluating→rejected|inconclusive`, and every receipt signature.
- `promotion:approve` → operator only. Owns `evaluating→qualified` and
  `qualified→revoked`. Serving state is not conferred by a role string:
  qualification requires three independent signed artifacts — a
  signature-authenticated pass receipt (`receipt_authority`), an
  evaluator-signed `CandidateEvidenceV1` binding those receipts to the
  *exact* candidate record/content digest on the sealed holdout
  partition under the expected protocol (`evidence_authority`), and an
  operator-signed `CandidateDecisionV1` for the exact edge
  (`decision_authority`). Revocation requires its own decision. Without
  the corresponding authority the transition is refused; a bare 64-hex
  string is never treated as evidence.

## Fail-closed boundaries (all tested)

- **Registry reads re-verify digests** — a tampered `candidate` row raises
  `candidate_tampered`; a tampered `experience` row raises
  `experience_tampered`. Corrupt JSON never deserializes into a record.
- **Workspace handles are capabilities, not paths** — each executor keeps
  a private registry of the workspaces it created, and `run()`/`destroy()`
  accept a caller-supplied path only when it is exactly the registered
  canonical path. A forged handle, a handle from another executor, a
  mismatched executor identity, a symlinked workspace directory or a
  deleted workspace raises before any mount, execution or delete
  (`workspace_not_registered`, `workspace_path_substituted`,
  `workspace_executor_identity_mismatch`, `workspace_path_symlink_escape`,
  `workspace_path_missing`). Destruction marks the workspace closing,
  refuses new runs, terminates in-flight executions and removes the
  directory only after every started execution has left its critical
  section; a removal that cannot be verified raises
  `workspace_remove_failed`. Repeated destruction is a no-op.
- **Docker workspaces are collected through a filtered, budgeted archive**
  — the host process streams the prepared tree as an archive into a
  quota-limited tmpfs (no host bind of the workspace, so the copy-in
  does not depend on host ownership, including on a root host). The copy-out tar is extracted with
  `filter="data"`, so absolute paths, `..` escapes, device nodes and
  links that leave the workspace are rejected instead of materializing
  on the host. The declared `disk_bytes` and file-count bound are
  enforced **while the archive is read**: a regular member is rejected
  before its bytes are written, sparse members are refused, and the tar
  stream itself is capped. A violation stops extraction and reports a
  reason-specific marker (`fs:disk_budget_exceeded`,
  `fs:file_count_exceeded`, `fs:sparse_member_rejected`) plus
  `fs:workspace_state_unavailable` (never a pass). The prepared
  workspace is replaced only after a complete, in-budget extraction; a
  failed swap restores the original tree instead of deleting it.
- **Private acceptance material lives outside the graded tree** — a
  backend that supports private material stages registered acceptance
  files in a directory beside its managed workspaces and exposes it
  read-only at `/private` (Docker, Linux worker) or as an absolute host
  path (local). The material is never written into the submission
  workspace, never included in its tree digest or copy-out archive, and
  a submission's `conftest.py` is not loaded from the test root. The
  graded workspace is **not** placed on `PYTHONPATH`: a Python
  acceptance command runs through a staged, read-only bootstrap that
  imports the test runner and only then adds the workspace to
  `sys.path`, so a submission cannot shadow `pytest` or supply a
  `sitecustomize` that runs at interpreter startup. A `-m` runner that
  cannot be imported from the trusted environment fails closed
  (`evaluation_runner_unavailable`, exit 70) before the workspace is
  importable, direct scripts install an import guard that refuses a
  workspace `pytest` module. Classification never reads submission-
  controlled stderr: under shared custody exit 70 is an ordinary
  failure (the bootstrap probe already verified the runner), and only a
  split-custody receipt's exit 70 is an evaluator bootstrap error.
  Staging is bounded
  (64 files, 1 MiB each, 8 MiB total) and registration enforces the
  same bounds. The execution receipt carries
  `evaluation:private_material_separated`. Backends without that
  capability keep the legacy co-located staging.
- **Submitted code runs in Docker by default** — the evaluator worker
  constructs a `DockerSandboxExecutor` and refuses to start without an
  image; `LocalSubprocessExecutor` requires an explicit
  `allow_local_executor` authorization (or `--allow-local-executor` on
  the CLI, the demonstration cycle, and the live-episode script). Local
  execution remains `isolation:unverified_local` and is never a
  containment claim.
- **Replayed episodes are rejected** — `MemoryStore.ingest` keys on
  `(episode_id, task_fingerprint)`; a mutated copy of an episode is a
  `DuplicateEpisode`, never a second vote.
- **Idempotent submit, conflicting ids rejected** — re-submitting an
  identical candidate is a no-op; the same id with different content is a
  conflict.
- **Transition audit is hash-chained** — every `candidate_transition`
  row is sealed inside the same transaction as the state change with a
  `prev_digest`/`entry_digest` link that also covers the cited evidence
  and decision digests; `audit()` re-verifies the whole chain on every
  read, so rewritten, reordered, deleted or truncated history raises
  `audit_chain_tampered`. Databases without a chain are backfilled at
  open (sealed over current content — backfill makes rows verifiable, it
  cannot prove they were not already altered). A database already
  chained under the previous digest domain is resealed **only after the
  old chain verifies end-to-end against that old domain**; a broken
  pre-migration chain refuses to open with
  `audit_chain_tampered:pre_migration_*` instead of sealing over it. The
  reseal is recorded in `registry_migration` and reported by
  `verify()["migrations"]`, so the rewrite is attributable rather than
  silent.
- **Serving state is decision-backed, not a column** — the registry
  folds the transition log and requires the committed `state` column to
  match that projection. A direct SQL flip to `qualified` raises
  `state_projection_drift`; it cannot serve. Every serving-state
  transition must cite an operator-signed decision (and, for
  qualification, evaluator-signed evidence) that is re-authenticated on
  every read. Decision nonces are consumed atomically with the
  transition, so replay is a conflict. A serving transition whose cited
  decision or evidence row is absent is `unbacked`
  (`decision_missing`/`evidence_missing`): the candidate cannot serve,
  but the catalog stays writable so it can still be revoked under a
  signed decision.
- **Qualification evidence names the candidate** — an
  `OutcomeReceiptV1` only proves an outcome for a task. Qualification
  additionally requires a signed `CandidateEvidenceV1` whose
  `candidate_digest`/`content_digest` match the candidate being
  qualified, whose `partition` is `holdout`, whose protocol digest
  matches the registry's pinned evaluation protocol, and whose
  `receipt_refs` cover every cited receipt. Pinning is mandatory:
  qualification is refused with
  `qualification_requires_expected_protocol` when the registry has no
  expected protocol, and a serving replica without the pin cannot read
  the qualified catalog (`serving_protocol_unpinned`). A pass receipt
  from an unrelated task, repository or candidate is rejected with
  `evidence_receipt_not_bound` / `evidence_candidate_digest_mismatch`.
- **Serving re-derives catalog integrity** — `qualified()` re-folds the
  chain, re-checks the state projection, and re-authenticates the
  decision and evidence behind every candidate on every request. Any
  integrity failure abstains with `catalog_unavailable` and records an
  `integrity_error` in the serving audit; it never serves a partial
  catalog.
- **Outcomes require an authenticated receipt** — `record_outcome`
  resolves the cited digest through the trusted evaluator boundary,
  requires the receipt's task and outcome to match the served task and
  claimed outcome, and refuses without a configured authority. An
  unauthenticated digest cannot write a `serving_outcome` row.
- **Basis revocation suppresses** — when a caller supplies a revocation
  set, a revocation naming a candidate's receipt, evidence binding or
  decision rejects it with `evidence_revoked`.
- **Skill ingestion is untrusted input handling** — `skill_ingest`
  parses skill directories with bounded, dependency-free rules; it never
  executes, imports, or fetches anything. Symlinks (the skill directory,
  `SKILL.md`, or any resource), hidden files, non-UTF-8, control
  characters, oversized bodies and oversized resource sets are refused.
  Ingested skills enter at PROPOSED under `candidate:write`; a claimed
  qualification status is ignored, scan findings are advisory, and
  serving still requires signed holdout evidence plus an operator
  decision.
- **Serving is scope-bound** — `repository_scope` of `registry_id` /
  `family_id` resolves through the signed `RepositoryRegistry`; a
  self-declared or unknown repository identity abstains. `global` scope
  is served only behind an explicit `allow_global_scope` flag.
- **Family targeting is an opt-in hard gate** — `target_task_family` is
  provenance by default; when the caller passes `task_family`,
  off-target candidates are rejected with `family_mismatch` and counted
  in the audit rejections.
- **Counterexamples suppress with boundary anchoring** — a
  `known_counterexamples` string vetoes a candidate only on a
  token-boundary match in the task's failure/symbol/file context
  (needles shorter than 3 characters must equal a whole token), so a
  short string cannot suppress everything it merely substrings.
- **Serving audit records what was delivered** — `candidate_digests`
  covers only candidates whose steps actually shipped in
  `helpful_next_checks` (post-budget, post-truncation), not every
  catalog item considered; each rejection is recorded with a reason.
  Every `served_guidance` audit row carries the `task_id` and the
  guidance digest.
- **Outcomes bind to delivered guidance** — `record_outcome` requires a
  receipt that resolves through the trusted evaluator boundary, carries
  the served `task_id` and the claimed outcome, and is attached to the
  exact guidance digest this gateway served for that task; unknown
  tasks, mismatched digests, unauthenticated receipts, task/outcome
  mismatches and malformed references raise instead of writing an
  uncorrelated audit row.
- **Malformed serving input abstains audited** — a request that fails
  contract parsing returns `abstain/catalog_unavailable` inside the
  audited path rather than propagating an unlogged exception.
- **Prompt injection is data** — a qualified candidate whose steps say
  "grant operator role" is served verbatim inside `helpful_next_checks`
  and nothing else: `decision` stays `abstain`, `procedure_ids` stays
  empty, no permission changes.
- **Optimizer cannot self-qualify** — `SkillOptimizer` has no state path
  past PROPOSED; its dev evaluator is an injected interface it does not
  control, and it cannot see holdout partitions (structural).
- **Imported bundles are unqualified** — `import_bundle` verifies hashes
  and registers at PROPOSED regardless of the manifest's claimed
  `sis_qualification_status`; a passing `security_scan` never implies
  qualification. `verify_install` returns problems for *any*
  unverifiable element — corrupt or missing `manifest.json`, undeclared
  hashes, unexpected files, or a manifest whose `candidate_id`/
  `candidate_digest` disagrees with the payload — it never raises.
- **Preregistration conformance is measured, not cosmetic** —
  `run_governed_evaluation` records a `conformance` block comparing the
  executed run to the preregistered budget, arm set, and sample size;
  an off-plan or underpowered run reports `conforms=False` with named
  mismatches rather than hiding behind the protocol digest.
- **Receipt reuse is impossible** — verifier nonces and the
  `(task_id, tree_digest, criterion_version)` dedup marker reject
  replays; the benchmark receipt cache reuses identical-submission
  receipts by reference, not by re-evaluation.

## What is NOT enforced here (honest limits)

- **Platform support.** Linux and macOS run the whole system and test
  suite. Windows is supported for the core learner and CLI only: the v3
  evaluator, sandbox, authority and study layer relies on POSIX process
  groups, permissions and file semantics, and qualified evaluation needs
  Docker + gVisor on Linux. On Windows, CI runs the core suite and
  `tests/v3` is not collected; `tests/conftest.py` says so in the run
  header and in the terminal summary, which `pytest -q` still shows.
- **Native macOS is development-only.** It is refused for production
  (`LocalSubprocessExecutor(production=True)` raises
  `local_backend_not_production_qualified`), and qualified runs go
  through Docker + gVisor on Linux (`docs/v3/SANDBOX_QUALIFICATION_GATE2.md`).
  Every entry point that runs submitted code with the local backend —
  the evaluator worker (`build_worker_executor`,
  `evaluate_via_subprocess`, `python -m sis.v3.evaluator_worker`) and
  the `governed_campaign`, `governed_live_campaign`, `live_study`,
  `real_agent_campaign`, `skill_holdout` and `learn_recommend_cycle`
  tools — refuses to start on darwin with
  `hostile_evaluation_unqualified_platform:darwin` unless the caller
  passes `allow_unqualified=True` / `--allow-unqualified` in addition to
  `--allow-local-executor`. (`five_arm_campaign.py` is outside this
  change and still needs the gate.) On macOS the local runner also runs
  an RSS watchdog: it polls the command's process tree with `ps` every
  0.2 s and kills the tree once its resident size exceeds
  `limits.memory_bytes`. Receipts record `memory:watchdog` when it ran
  and `rlimit:memory_watchdog_exceeded` (a RESOURCE_LIMIT verdict) when
  it killed. The watchdog is best effort, not a limit: an allocation
  can outrun one sample, a descendant that left the tree is not counted,
  and `memory:not_enforced` stays on every macOS receipt.
- Local execution is `isolation:unverified_local`; seatbelt network
  denial is opportunistic, not a guarantee.
- Private-material separation moves acceptance files out of the graded
  workspace. A `shared`-custody task still runs the test runner and the
  code under test in one process and one OS principal, so a submission
  that enumerates the private path can read the tests at run time.
  `custody="split"` closes that read path: the runner never imports
  submitted code, and the worker runs under a principal that cannot read
  the private directory (a seatbelt read denial locally, a second
  numeric UID in Docker). Separation also removes the incidental paths
  (same directory, tree digest, copy-out, submission `conftest.py`,
  `PYTHONPATH`/startup hooks, runner shadowing), and split custody pins
  pytest configuration to the private directory so a workspace
  `pytest.ini` cannot inject a plugin into the process holding the
  tests. Private material now defaults to `split`; `shared` requires a
  verifier built with `allow_shared_custody=True` and is refused
  outright in production. The shipped worker offers the Docker split
  when started with `--split-user`, rejects a shared private task
  without `--allow-shared-custody`, and refuses to start when the
  loaded registry needs split custody but the executor has no second
  principal. The shared-custody path remains available only as that
  explicit development opt-out.
- A shared-custody verdict is not trustworthy against the code it
  grades. The submission runs inside the pytest process, so an exit
  status alone proves nothing (`os._exit(0)` used to pass). The verifier
  now requires a result report that the evaluator bootstrap writes after
  pytest's session finished, tagged with a per-run nonce: at least one
  collected and passed test, no failures or errors, a result for every
  collected test, and at least one test from every private file named on
  the command line. Exit 0 without that report is `fail`. This defeats
  an early exit, not a submission that discovers the nonce in its own
  process and forges the report; receipts of shared-custody runs carry
  `custody:shared_unqualified`, and only split custody is
  qualification-grade. There is no declared expected test count, so the
  report cannot detect a test file that collects fewer tests than
  intended.
- Split custody is a boundary over module access, not a general
  interprocess sandbox. Workspace modules — including packages and their
  submodules — are proxied, except names the evaluator's environment
  provides (standard library, installed packages, modules beside the
  tests): a workspace cannot shadow a library the tests import. The
  bootstrap imports such a name from the spec it found on the trusted
  path itself, a standard-library name the evaluator lacks is missing
  rather than the workspace's, and a path-entry hook makes every
  `sys.path` entry inside the workspace find nothing, so no later
  finder (pytest's assertion rewriter included) can load a workspace
  file in the evaluator whatever puts the workspace on `sys.path`. A
  src-layout workspace is searched at its root and then under `src/`, in
  the same order in both processes; a namespace package spanning both
  keeps every portion, in that order. Only data crosses the socket as
  values (scalars, bytes, and bounded lists, tuples, sets, frozensets
  and mappings of data); every other object stays in the worker behind
  a handle. Protocols on a handle (`len`, `in`, indexing, iteration,
  comparisons, arithmetic, `bool`/`str`/`repr`/`hash`, `with`,
  `isinstance`) go through one worker op restricted to a fixed table of
  dunder names; `__getattribute__`, `__reduce__`, `__class__`,
  `__dict__` and the like are refused. A data result too large for one
  frame comes back as a handle to the value already computed. Worker
  exceptions cross as class names only and are raised as local stand-in
  classes that always derive from `Exception`, so
  `pytest.raises(pkg.Error)` matches without a worker ever raising
  `BaseException`, `SystemExit` or `KeyboardInterrupt` in the evaluator.
  A worker-reported name resolves to an evaluator class only for
  builtins and standard-library modules (never the runner's own):
  a class of an installed package or a test helper gets an inert
  stand-in, so no hook of it runs with worker-chosen arguments. Handles
  are released when the evaluator's last reference to one is collected
  (a counted lease per handle; the release rides on the next request),
  so `MAX_HANDLES` bounds live handles only; a malformed release is
  ignored by the worker. The module docstring of
  `sis.v3.split_harness` lists what this cannot cover (local callbacks
  passed to the submission, `type()` identity, subclassing a worker
  class, mutation through returned data). A test that deliberately
  shells out to run the submission under the evaluator principal
  re-opens the shared path.
- Split custody stages only files the evaluator registered. For an
  imported task these are the test and its support files: the
  `conftest.py` of the test's directory and of every directory above
  it, the `__init__.py` of each test package up to its test root, and
  the modules the test (or a captured helper) imports from its own test
  package, each relative import resolved against the importing file's
  own package, and the data files the test or a captured helper names
  by a string-literal path: a non-Python regular file in a test
  directory under the test root, or every data file of a test
  subdirectory it names (`os.path.join(HERE, 'compliance')`), all of
  them or, past `MAX_SUPPORT_FILES` or a size bound, none, with a
  recorded reason. Data files are staged at their repository paths, so
  `dirname(__file__)` finds them; no support target has a loadable-code
  suffix (`.pyc`, `.so`, `.pth`, ...) other than `.py`. The importer
  reads them from the fix commit at registration
  time, never from a submission, so they are as trusted as the test,
  and like the test they run in the evaluator process. Only paths in a
  `test`/`tests` directory count as packages or helpers: a source
  package above a test package, or a module beside a root-level test,
  is the submission's and stays proxied. The task records them in
  `acceptance.support_files` (repository-relative target, stored path,
  SHA-256), stored in the repository's hidden-tests directory so its
  directory digest binds them too; the manifest builder and the
  five-arm campaign read each back and check its digest before
  registration, as they do for the primary test, and the test plus its
  support files stay within the private-material bounds
  (`normalize_private_files`). Two separate things place the test.
  `-c <private>/pytest.ini` makes the private directory pytest's
  rootdir and configuration, which keeps workspace configuration and
  conftest files out; it does not change `sys.path` or the test's
  module name. The staged layout and pytest's import mode do: with the
  support files at their repository paths, the default `prepend` mode
  finds the test's package chain (`tests/__init__.py`), imports it as
  `tests.test_x` and puts that chain's parent, inside the private
  directory, on `sys.path`. The bootstrap trusts a module found on the
  current `sys.path` with every entry in the workspace removed
  (compared after resolving links), so a helper pytest made importable
  is evaluator material while a same-named workspace module stays
  proxied. A test that names its own package through the source
  package (`from calc2.tests import helper` in `src/calc2/tests/`)
  reaches the workspace's copy through the proxied `calc2`.
- Reads of mutable submission state (a module or object attribute, or an
  item, that is a `list`, `dict`, `set`, `bytearray` or `deque`) return
  a handle to the worker's object, so a test's mutation reaches the
  submission. This adds no capability to the worker: it already chose
  whether to answer with data or a handle, and every use of a handle is
  a request the worker answers with data or another handle. Call
  results stay copies.
- Resource limits are applied by an evaluator-owned launcher run as
  `python -I` from a neutral directory, so no workspace module can run
  before the limits or outside seatbelt. It fails closed: a limit it
  cannot set stops the run with `sandbox:rlimits_not_applied:*`, and
  `rlimits:launcher` is recorded only when the launcher reported every
  limit applied. macOS refuses any `RLIMIT_AS` below the interpreter's
  address space, so on macOS memory is not bounded: the launcher is not
  asked to set it and the receipt records `memory:not_enforced`. Under
  supervision the limits are applied in the forked command process, not
  the supervisor, so `RLIMIT_NPROC` cannot refuse the supervisor's own
  fork. On Linux the local launcher stays as a child subreaper
  (`process:subreaper`) and kills every descendant, including ones that
  called `setsid()`, when the command exits or times out; the process
  group is also killed after every run. A submission that kills its own
  launcher first loses that reaping (best effort, not a boundary). On
  macOS there is no subreaper: the process group is killed after every
  run, but a descendant that called `setsid()` can outlive it. The
  Linux worker's launcher joins the cgroup before it execs bubblewrap.
- `disk_bytes` is enforced live only per file (`RLIMIT_FSIZE`) on the
  local and bubblewrap backends; the workspace total is audited after
  the run (`fs:disk_budget_exceeded`, receipts carry
  `disk:per_file_limit_post_run_audit`). Only Docker bounds the total
  during the run (sized tmpfs).
- The Linux worker's seccomp filter is a denylist. It also denies the
  x32 ABI on x86_64, `clone` with any `CLONE_NEW*` flag, the new mount
  API and io_uring, and makes `clone3` fail with ENOSYS (its flags are
  in memory and cannot be inspected), but it is not an allowlist. The
  production Docker backend uses an allowlist instead
  (`docker/sandbox/seccomp.json`, applied inside gVisor with
  `--oci-seccomp`); see `docs/v3/SANDBOX_QUALIFICATION_GATE2.md`.
- Repository validation never runs `git status`/`diff`: a checkout's
  `.gitattributes` filter, textconv or external-diff driver would run.
  Cleanliness is decided from raw object ids hashed in Python, with
  replace refs, grafts and transports disabled; content-converting
  attributes are not applied, so such a checkout reads as dirty.
- A harness failure is not evidence about a submission. The bootstrap
  pings the worker before running the command and reports a missing or
  lost worker by exit status, which the executors map to
  `sandbox:split_custody_unavailable` / `sandbox:split_worker_lost`; a
  non-Python acceptance command is refused at registration.
- The Docker and Linux worker mounts are read-only, so the material
  cannot be rewritten there. Docker split custody installs the material
  as a 0700 tmpfs directory owned by the evaluator UID instead of a
  mount, and re-reads that container copy before issuing the receipt.
  The local backend only clears write mode bits; the submission
  runs as the same principal and can `chmod` them. A post-run re-read
  detects a rewrite and the receipt carries
  `sandbox:private_material_modified` (a sandbox failure, never a pass),
  but prevention requires the process split above or seatbelt.
- The local backend's `command_spec_digest` includes the run-specific
  private-material directory, so it is not comparable across runs.
  Docker and the Linux worker use the fixed `/private` mount point and
  keep a stable digest.
- The copy-out budget bounds host disk writes; it does not make a
  malicious archive safe to parse in memory. The tar stream is capped,
  but a future parser change must keep that cap.
- Advisory text is delivered to the agent — the harness must treat it as
  untrusted context. SIS guarantees the channel is advisory; the agent's
  sandbox is responsible for action-level enforcement.
- The polarity conflict detector is a heuristic, not a semantic proof;
  `conflict_policy="abstain"` is the conservative option.
- The evaluator is trusted to attest *that* it evaluated the candidate
  under the declared protocol and partition. SIS binds the attestation
  to the exact candidate digest, cited receipts, holdout partition and
  protocol digest, and re-authenticates it at serve time — but it cannot
  independently prove the evaluator actually ran the candidate or that
  the holdout was untainted. Evaluator custody and task-registration
  lineage remain deployment responsibilities.
- A legacy candidate qualified before signed decisions existed has no
  serving basis. It is excluded from `qualified()` (`state_not_decision_backed`)
  and can only be remediated by revoking it under a signed operator
  decision; the upgrade never retroactively mints authority. The same
  remediation applies to a serving transition whose cited decision or
  evidence row is missing, but a *revoked* candidate no longer needs its
  qualification basis to exist, so `verify()` reports a clean catalog
  once the takedown is committed — the historical row still cites the
  absent digest for an external auditor to notice.
- The v3.3 → current upgrade reseals every audit row because the digest
  domain gained the evidence/decision fields. Resealing is gated on the
  old chain verifying first and is recorded, but it still means an
  external anchor taken before the upgrade will not match afterwards;
  re-anchor after upgrading.
- Evidence bindings can be issued for identical-submission evaluations
  that share a receipt; the binding names the candidate that was
  actually served during the probe, so this is a shared outcome, not an
  unrelated one.
