# Upgrade guide

> **Mixed document.** The v3.3.7 → v3.3.8 notes are current; the sections
> below them describe earlier lines. The current package version is 3.3.8.
> See `docs/v3/MIGRATION.md`, `docs/V332_OPERATIONS.md`, and
> `docs/v3/QUALIFICATION_REPORT_V3_3_8.md` for the current upgrade path.

## Upgrading from v3.3.7 to v3.3.8

v3.3.8 moves evaluator execution of untrusted submitted code into a
Docker sandbox. It is a containment release, not an efficacy result.

### Build the evaluator image

```bash
docker build --platform linux/arm64 -t sis-evaluator:3.3.8 docker/sandbox
```

The image carries the pinned test runner and runs as an unprivileged
user. A tag-only image is acceptable for development; receipts record
`docker:image_tag_only`. Production must pin the image by digest.

### Run the cycle with the sandbox

```bash
PYTHONPATH=src:. python3 tools/learn_recommend_cycle.py   --agent codex --sandbox docker --wall 150 -o /tmp/cycle.json
```

The tool probes the sandbox before evaluating and aborts if any
containment check fails. The probe covers network denial, read-only root,
workspace write, non-root execution, memory and pid limits. Evidence:
`evidence/sandbox/docker_sandbox_probe.json`.

### Production is still gated

The Docker receipt markers (`isolation:docker_sandbox`, `docker:*`) are
factual launch controls, not a signed containment proof. Production
qualification still requires a digest-pinned image and an
`IsolationAttestationV1` from a separately trusted isolator.

### Post-seal repair: workspace ownership and limits

The evaluator was repaired after the v3.3.8 seal. A `Workspace` handle is
now a capability: execution and deletion resolve it through the backend's
private registry and reject a substituted path. The Docker workspace is a
quota-limited tmpfs (read-only `/submission` bind, copy-in before the
command, filtered copy-out afterwards) instead of a writable host bind,
so `disk_bytes` is enforced during the run. CPU time is a kernel
`RLIMIT_CPU`, the pids and output caps are the minimum of the executor
and spec values, and `nofile` is a bounded `nofile_limit` (default 1024).

Operators must know:

- `DockerSandboxExecutor(user=...)` must be a numeric `uid[:gid]` and
  must not be root.
- A protected path may not contain the executor root. A deployment that
  placed the executor root under the evaluator registry directory now
  fails at verifier construction.
- `destroy()` can raise `workspace_busy` or `workspace_remove_failed`.
- A submission larger than `disk_bytes` fails at copy-in instead of
  producing a `fs:disk_budget_exceeded` receipt.

See the 2026-11-11 CHANGELOG entry. The sealed archive and its evidence
predate the repair; regenerate them with `tools/package_release.py`
before making a release claim.

### Post-seal repair: patch verification and release inventory

`PatchProposalV1` now commits to the exact source span (offset and length)
and the full patched-content digest. `verify_proposal()` checks the source
digest even for empty files, rejects substituted output bytes, replays the
one permitted span replacement, and requires the supplied diff to be the
canonical diff of that transformation. Serialized proposals without the
new fields fail closed.

`.coverage` and `.coverage.*` are no longer release-inventory inputs;
`RELEASE_SHA256.json` was regenerated over 440 files. The sealed
`SIS-v3.3.8.zip` still carries the old 441-file inventory including
`.coverage`, so it is a historical artifact, not a seal for this tree.

See the 2026-11-12 CHANGELOG entry.

### Post-seal repair: Gate 2 containment and evaluation defaults

Five containment/evaluation defects were repaired after the v3.3.8 seal.
None of them changes a signed artifact; the sealed archive and evidence
still describe the pre-repair tree.

- **Copy-out budget.** `DockerSandboxExecutor._copy_out` now enforces the
  run's `disk_bytes` and the workspace file-count bound while it reads
  the tar stream. A regular member larger than the remaining budget is
  rejected before its bytes are written, sparse members are refused, and
  the stream itself is capped. A violation preserves the prepared
  workspace and reports a reason-specific marker
  (`fs:disk_budget_exceeded`, `fs:file_count_exceeded`,
  `fs:sparse_member_rejected`), plus `fs:workspace_state_unavailable` and
  `fs:copy_out_rejected:<reason>`; it can never classify as a pass.
- **Workspace preservation.** The copy-out swap renames the prepared
  workspace aside, renames the staged tree into place, and restores the
  original if the second rename fails. A failed copy-out no longer
  deletes the only copy of the workspace.
- **Private acceptance material.** `OutcomeVerifier` no longer writes
  registered acceptance files into the workspace being graded when the
  backend supports private material. The files are staged beside the
  executor's workspaces and exposed read-only at `/private` (Docker,
  Linux worker) or as an absolute host path (local). Registered argv
  tokens that name a private file are rewritten to that path. The
  workspace is **not** put on `PYTHONPATH`; a Python acceptance command
  runs through a staged, read-only bootstrap that imports the test
  runner and only then adds the workspace to `sys.path`. That blocks a
  submission `pytest.py` from shadowing the runner and a submission
  `sitecustomize.py` from running at interpreter startup — both
  previously forced exit 0 (a pass) without running the tests. A missing
  `-m` runner fails closed (`evaluation_runner_unavailable`, exit 70)
  before the workspace is importable, direct scripts install an import
  guard that refuses a workspace `pytest` module, and that marker
  classifies as an evaluator bootstrap error even at exit 0. The
  execution receipt carries `evaluation:private_material_separated`.
  Staging is bounded (64 files, 1 MiB each, 8 MiB total), and
  `register_task()` enforces the same bounds. A `shared`-custody task
  still runs the runner and the submitted code in one process, so a
  submission that enumerates `/private` can read the tests. Register the
  task with `custody="split"` to remove that path; see below. The local
  backend's material is mode-protected, not OS-read-only: a rewrite is
  detected after the run (`sandbox:private_material_modified`, a sandbox
  failure) rather than prevented.
- **Execution default.** `sis.v3.evaluator_worker` constructs a
  `DockerSandboxExecutor` by default and refuses to start without an
  image. Local execution requires `allow_local_executor=True` (CLI:
  `--allow-local-executor`). `tools/learn_recommend_cycle.py` defaults
  to `--sandbox docker` and refuses `--sandbox local` without the same
  flag; `scripts/v3/run_codex_episode.py` requires it too. The remaining
  campaign scripts under `tools/` (`five_arm_campaign.py`,
  `governed_campaign.py`, `governed_live_campaign.py`, `live_study.py`,
  `real_agent_campaign.py`, `skill_holdout.py`) still construct the
  local backend directly. They are development/diagnostic harnesses,
  not production qualification entrypoints: their receipts are
  `isolation:unverified_local` and cannot pass production
  classification.
- **Release README.** `tools/package_release.py` now regenerates
  `release/README.md` from `release_manifest.json`. The archive hash,
  source commit, file count and test result can no longer survive a new
  seal; the old README still named the pre-repair hash, commit and
  448-file inventory.
- **Patch verification.** `verify_proposal()` now rejects a target that
  resolves outside the base directory (`target_escapes_base`), matching
  `propose_edit()`.

New regressions live in `tests/v3/test_gate2_containment_repairs.py`.
The full suite is 1452 passed, 13 skipped after the repaired tree is
re-sealed. Regenerate the sealed archive and its evidence with
`tools/package_release.py` before making a release claim.

### Post-seal repair: process-split acceptance custody

A `shared`-custody task still runs the acceptance runner and the
submitted code in one process and one OS principal. Registering the task
with `custody="split"` removes that read path:

```python
verifier.register_task(
    actor_role="evaluator", task_id="task-calc",
    criterion_version="v1", argv=(sys.executable, "-m", "pytest",
                                  "-q", "acceptance.py"),
    files={"acceptance.py": acceptance_source}, custody="split")
```

The acceptance command now runs in the evaluator's process and never
imports submitted code. A meta-path finder replaces each workspace
module — including a submission laid out as a package, and that
package's submodules — with a proxy whose attribute reads and calls are
marshalled over a Unix socket to a worker. The worker runs under a
principal that cannot read the private directory:

- Local backend: a separate process under seatbelt with
  `(deny file-read* (subpath <private>))`. It shares your UID, so the
  kernel read denial is the boundary; the receipt carries
  `split:custody:seatbelt_read_denied`.
- Docker backend: a second numeric UID through `docker exec --user`,
  with the material installed as the evaluator UID in a 0700 tmpfs
  directory. The receipt carries `split:custody:separate_uid`. Configure
  the second identity with `DockerSandboxExecutor(split_user="2002:2002")`;
  it must differ from `user` and must not be root. `evaluator_worker`
  exposes the same setting as `--split-user` (see the repair below).

Both paths carry `evaluation:process_split`. The wire codec is JSON over
a closed type set, so submission-produced bytes are never unpickled in
the evaluator process.

Operators must know:

- Split custody requires the backend capability. A split task on a
  backend without it is rejected as `split_custody_unavailable` (an
  evaluator bootstrap error) instead of falling back to shared custody.
  `LinuxRootlessWorker` has no second principal — bwrap maps the
  caller's UID into the namespace — so it refuses split tasks.
- A receipt that does not carry `evaluation:process_split` is rejected
  as `split_custody_unverified` (a sandbox failure).
- The acceptance command must be a Python invocation; registration
  refuses anything else. Handing the Python bootstrap to a shell or a
  test binary would fail as if the submission had.
- A harness failure is never a verdict about the submission. The
  bootstrap pings the worker before running the command and exits with a
  dedicated status if it is missing or dies; the receipt then carries
  `sandbox:split_custody_unavailable` or `sandbox:split_worker_lost` and
  the outcome is an error, not a failed submission.
- Only primitives, callables and composites of primitives cross the
  socket. A test that passes an arbitrary object, or expects a
  non-primitive return value, fails the call rather than widening the
  codec.
- Split custody pins pytest to evaluator-owned configuration
  (`-c`, `--confcutdir`, `-p no:cacheprovider`), so a workspace
  `pytest.ini`, `pyproject.toml` or `conftest.py` cannot inject a plugin
  into the process that holds the tests.
- The Docker backend re-reads the container copy of the private
  material, not the host staging directory, before issuing the receipt.
- The Docker split is unit-tested against a Docker CLI double; it is not
  live-qualified on every host. Re-run the Docker containment probe on
  the exact image before claiming production isolation.
- The split does not make the evaluator's own test code trustworthy. A
  test that deliberately shells out to run the submission under the
  evaluator principal re-opens the shared-custody path.

Regressions live in `tests/v3/test_split_custody.py`.

### Post-seal repair: split-custody worker configuration

The process-split boundary was unreachable through the shipped worker:
`evaluator_worker` constructed its Docker executor without a second UID,
so `supports_split_custody` was false and every split task was rejected.

- `build_worker_executor()` and `evaluate_via_subprocess()` accept
  `split_user`; the CLI adds `--split-user uid[:gid]`. The value is
  validated by the Docker executor (numeric, non-root, distinct from the
  evaluator UID). The local backend refuses a split user: its boundary
  is a seatbelt read denial, not a second UID.
- `OutcomeVerifier` accepts `require_split_custody=True` (CLI
  `--require-split-custody`). With the policy on:
  - construction fails with `split_custody_required_but_unavailable`
    when the backend has no second principal, so an unsupported
    deployment does not start;
  - `register_task()` refuses private acceptance files under shared
    custody with `split_custody_required_for_private_material`;
  - `evaluate()` rejects a registration that predates the policy with
    `split_custody_required` (an evaluator bootstrap error), so an old
    shared-custody task cannot be graded beside its tests.
- Configuring `--split-user` turns the policy on implicitly. The two
  settings are not independent: a worker told which second UID to use
  should not keep accepting shared custody for hidden tests.

A worker without `--split-user` still refuses split tasks (fail-closed),
but shared custody remains available for development. Production
deployments that hide acceptance material should pass both settings.

New regressions live in `tests/v3/test_split_custody.py`.

### Verifying the v3.3.8 release

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/verify_release.py --compile .
python3 tools/verify_release.py release/SIS-v3.3.8.zip
python3 tools/check_release_ci.py --mode release
```

## Upgrading from v3.3.6 to v3.3.7

v3.3.7 connects a verified real-agent episode to a qualified procedure
that a sibling task can retrieve. It is a correctness release, not an
efficacy result.

### Learned procedures use a failure class, not the dev task signature

`experience_to_record` converts one verified pass into a candidate
procedure whose preconditions name a failure class. The record must
already carry that class in `failure_category`; the conversion refuses to
relabel evidence (`failure_class_not_bound_to_record`).

Existing procedures that still name the originating task's own signature
will not match sibling tasks. Re-derive them from a verified episode, or
update their preconditions, before expecting cross-task retrieval.

### Failure classes are registered with the evaluator

`OutcomeVerifier.register_task` accepts an optional `failure_class`. It is
bound into the task commitment only when declared, persisted in
`tasks.json`, and exposed through `failure_class_for(task_id)`. Outcome
receipts carry the class as an optional signed field; receipts that omit
it keep their historical canonical form, digest and signature.

### Scope grants require cited or classed transfer evidence

`ScopeGrantAuthority` now defaults to `require_cited_evidence=True`. Each
transfer witness must either carry the procedure's failure class or be
cited by the qualified revision. A mismatched class fails with
`evidence_class_mismatch`; an uncited legacy witness fails with
`evidence_not_cited_by_procedure`. Pass `require_cited_evidence=False`
only for legacy test custody, and record why.

### Verifying the v3.3.7 release

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/verify_release.py --compile .
python3 tools/verify_release.py release/SIS-v3.3.7.zip
python3 tools/check_release_ci.py --mode release
```

The release is `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`.
It does not qualify a production sandbox and does not establish that SIS
improves a real coding agent.

## Upgrading from v3.3.5 to v3.3.6

v3.3.6 is a security/correctness repair release, not a feature release.

### Memory trust profiles are a closed enumeration

`MemoryTrustProfile` now validates at construction. Only `development` and
`production` modes exist; production must enable every control and
development must enable none. A custom profile such as
`name="production"` with every requirement disabled now raises
`production_profile_requires_every_trust_control` instead of constructing
a store that reports unsigned legacy records as `trusted`.

`trust_status()` derives trust from the full production contract *and*
the controls the store actually holds (signer keys, chain key, witness,
verifier). A production store also refuses construction when its verifier
cannot perform `registered_task` verification. Development stores are
unchanged apart from the stricter profile shape.

### Enforced induction adds a process-level hard-memory path

`SearchBudget.max_memory_bytes` remains the soft, diagnostic
`tracemalloc` budget. New `sis.enforced_induction.run_induction_enforced`
runs the search in a separate POSIX process capped by `RLIMIT_AS` and
returns `EnforcedInduction` with a `MemoryEnforcementReceipt`.
`hard_memory_verified` is true only for a valid receipt, a completed
child and no memory kill; timeouts, forged reports, mismatched limits and
signal deaths never report hard success. macOS cannot lower `RLIMIT_AS`
below the interpreter's current address space, so meaningful hard-cap
qualification remains a Linux-worker gate.

### Benchmark metrics no longer equate a candidate with recovery

`tools/benchmark_induction.py` removes `rule_recovered`. Reports now
carry `candidate_found`, `target_structure_recovered`,
`equivalence_verified`, `equivalence_scope`, `holdout_accuracy`,
`search_complete`, `ambiguous` and `exact_recovery_verified`. Only the
last field claims the intended rule, and it requires a non-ambiguous
result. Consumers that read `rule_recovered` must switch to the metric
that matches their claim. `--input-min` and `--equivalence z3` are new
options for negative-value and bounded-equivalence runs.

### Verifying the v3.3.6 release

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/verify_release.py --compile .
python3 tools/verify_release.py release/SIS-v3.3.6.zip
python3 tools/check_release_ci.py --mode release
```

The release is `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`:
it does not qualify a production sandbox and does not establish that SIS
improves a real coding agent. Provenance is signed only when an externally
trusted release key is supplied; see `release/release_manifest.json` for
whether this bundle carries a signature.

## Upgrading from v3.3.4 to v3.3.5

v3.3.5 is a repair release, not a feature release. Three behaviour changes
can affect existing callers.

### Memory budgets fail closed when their measurement disappears

`SearchBudget.max_memory_bytes` now reports `resource_exhausted` when the
`tracemalloc` tracer it depends on is stopped or restarted during a search.
Results may carry two new `limits_hit` reasons: `memory_tracer_lost` and
`memory_tracer_restarted`. A search that previously reported `completed`
with a zero-growth reading after an external `tracemalloc.stop()` now
reports `resource_exhausted`.

The cap remains an incremental soft budget over Python allocations, not an
OS RSS limit; a hard bound belongs to the subprocess/cgroup/microVM layer.
Callers that already run `tracemalloc` keep their tracer: the search
measures from its current baseline and never stops it.

### Trusted memory reads require chain membership

A `MemoryStore` configured with `trusted_signer_keys` or `chain_key` now
requires the exact record being returned to own a `memory_chain` entry.
`trust_status` on a correctly signed record that was never ingested returns
`untrusted:experience_unchained:<id>` instead of `trusted`, and
`get`/`by_outcome` raise `experience_unchained:<id>` for an unchained row.

Development stores are unchanged: without a trust root they keep reading
legacy rows that predate the chain. Stores that predate the chain already
fail as `memory_unmigrated`; `repair_chain()` backfills rows, but a
production store still refuses to chain legacy or untrusted rows.

### Production verdicts have no caller-supplied shortcut

`classify_execution` no longer accepts `isolation_verification`, and
`production=True` always returns `SANDBOX_FAILURE`. The only route to
`TASK_PASS` under production conditions is
`classify_production_execution(receipt, attestation, policy, ...)` with a
real `IsolationAttestationV1`. `ProductionIsolationPolicy` gains
`revoked_keys`, and a revoked signer is rejected as `signer_revoked`.

`ProductionIsolationPolicy.digest` now commits to `revoked_keys`, so
**every** policy digest changes in this release, including a policy with
no revocations. Any deployment that pins a policy digest externally must
recompute it after upgrading. Verification itself is unaffected: the
attestation's `policy_digest` is compared against the caller-supplied
`required_policy_digest`, not against the computed digest.

### Verifying the v3.3.5 release

```bash
python3 -m venv /tmp/sis-venv
/tmp/sis-venv/bin/python -m pip install pytest==8.4.2
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src /tmp/sis-venv/bin/python -m pytest -q
python3 tools/verify_release.py --compile .
python3 tools/verify_release.py release/SIS-v3.3.5.zip
python3 tools/verify_provenance.py --envelope release/provenance.dsse.json \
  --archive release/SIS-v3.3.5.zip --public-key release/provenance_public_key.hex
```

The release is `ENGINEERING_VERIFIED` / `IMPLEMENTED_NOT_EFFICACY_QUALIFIED`:
it does not qualify a production sandbox and does not establish that SIS
improves a real coding agent.

## Historical: the reviewed v2.4.0 source

This guide covers the repository updates made after the v2.4.0 review. The Python package version remains `2.4.0`; the changes harden evaluation custody, improve task instructions sent to model arms, and make release verification stricter.

### Before upgrading

- Back up the SIS registry database and evaluator vaults. Keep evaluator vaults and HMAC keys in an evaluator-controlled account and directory.
- Preserve old signed datasets, protocols, receipts, and training exports as historical evidence. Do not edit old signed artifacts to make them match the newer formats.
- Pull the repository update and reinstall the local package if it was installed in editable or wheel form:

  ```bash
  git pull --ff-only
  python3 -m pip install -e .
  ```

The core SIS registry database does not require a schema migration for these updates. Existing evaluation artifacts remain historical records; regenerate and sign artifacts when using the updated evaluation formats.

### Evaluation format changes

#### Family evaluation

Family datasets now use `sis.family_dataset.v2` and require a plain-language `task_description`. The description is included in each model arm's prompt and bound into the signed protocol. Family v1 datasets and protocols are rejected by the updated evaluator; create a new v2 dataset and precommitment rather than changing a signed v1 artifact.

#### Neural comparison and distillation

Neural comparison datasets now require `task_description`, which is included with each unlabeled input sent to the model arms. Neural comparison reports use format v2. New distillation exports use `sis.skill_distillation.v2`; their signed manifests and training rows bind the task description. Regenerate exports from a qualified evaluation before training with the updated validator.

#### Procedural skill holdouts

The skill holdout protocol still accepts legacy private datasets without `task_description` and supplies a generic default. New datasets should include a specific description so evaluation prompts and distillation records state the intended transformation.

### Evaluator vault storage

All evaluator SQLite vaults now require private storage:

- On POSIX, the vault file is created with mode `0600`; its parent directory must deny group and other access. Create a dedicated directory with `mkdir -m 700 evaluator-vault` and keep the vault inside it. Existing shared directories or vault files with broad permissions are rejected.
- On Windows, the vault file receives a protected ACL for the current user and SYSTEM. The parent directory ACL is checked for broad principals. Use a dedicated evaluator directory that candidate accounts cannot access.

The vault remains unencrypted, and filesystem checks cannot protect it from an administrator or a process running as the evaluator account. Continue to protect the HMAC key and preserve backups outside candidate-controlled environments.

### Recovering a committed evaluation receipt

The v1.4 evaluator CLI now provides `eval-recover`. If scoring committed a receipt to the vault but writing the output file failed, recover it without scoring the evaluation again:

```bash
sis eval-recover public.json \
  --vault evaluator-vault/private.sqlite3 \
  --receipt recovered-receipt.json
```

The command verifies the stored receipt against the public manifest and vault, and refuses to overwrite an existing output file. It cannot recover a receipt until scoring has committed one.

### Verify the updated checkout

From the repository root:

```bash
python3 tools/check_source_manifest.py
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 tools/smoke_integration.py
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v2.4.0.zip
```

The release verifier checks the ZIP inventory, manifest, member paths, duplicate entries, symlinks, and bounded compressed and uncompressed sizes. Its SHA-256 manifest detects changes against a known authentic archive; it is not a publisher signature.
