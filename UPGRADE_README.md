# Upgrade guide

> **Mixed document.** The v3.3.6 → v3.3.7 notes are current; the sections
> below them describe earlier lines. The current package version is 3.3.7.
> See `docs/v3/MIGRATION.md`, `docs/V332_OPERATIONS.md`, and
> `docs/v3/QUALIFICATION_REPORT_V3_3_7.md` for the current upgrade path.

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
