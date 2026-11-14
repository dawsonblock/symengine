# SIS v3.3.9 (build 11) qualification plan

Status date: 2026-11-14. This is a plan, not a release claim. It records
the gates build 11 must pass and the work each gate requires. It does not
change behavior, and it does not authorize an efficacy claim.

## Definition

Build 11 is a **security-and-efficacy qualification release**. No new
learning features. The only code changes allowed are those needed to
close a gate below, plus tests and documentation.

Tag `SIS-v3.3.9` only when **G1, G2 and G3** pass. **G4** decides
whether the release may claim efficacy; without it the status is
`SECURITY_QUALIFIED_EFFICACY_PENDING`. **G5** is a research track and
does not block the tag.

## Starting point (measured 2026-11-14)

| Check | Result |
| --- | --- |
| `pytest tests/ -q` (Python 3.12.0, Docker 29.9.3, image `27415edf…`) | 1500 passed, 13 skipped |
| `pytest tests/v3/test_split_custody.py -q` | 38 passed |
| Docker-absent simulation (`DOCKER_HOST=unix:///nonexistent/docker.sock`) | 2 errors, both configuration tests |
| `release/release_manifest.json` provenance | `signed: false`, trust root `qualification-only` |
| Stored isolation attestation | issued `08:18:33Z`, expires `08:23:33Z` — expired by design |

Two corrections to the audit that motivated this plan:

- The unittest errors reported against the sealed snapshot were an
  environment artifact. With `pytest==8.4.2` installed the suite is
  green. The real portability defect is the two Docker-construction
  tests in `tests/v3/test_split_custody.py`
  (`WorkerSplitConfigurationTests.test_docker_executor_carries_the_split_user`
  and `..._without_a_split_user_has_no_split`).
- Release integrity is already closed in this tree: the archive exists,
  453 files verify, and fresh-extraction compile and smoke checks are
  built into `tools/package_release.py`. What remains is *external*
  authenticity, not internal consistency.

## Gate summary

| Gate | Question | Pass condition |
| --- | --- | --- |
| **G1 Custody** | Can private tests be graded under shared custody anywhere in a production path? | No. Registration and evaluation fail closed; a real-container submission cannot read or replace hidden tests. |
| **G2 Authenticity** | Is the release signed by keys held outside the evaluated machine? | Signed provenance plus external isolator verification recorded at seal time; negative controls fail. |
| **G3 Portability** | Does the suite pass or skip cleanly without Docker, and on Windows? | Zero failures or errors with Docker absent; Windows job blocking or explicitly unsupported. |
| **G4 Efficacy** | Do real agents solve more unseen tasks with SIS? | Preregistered, powered, repository-disjoint run; complete; analysis reported with exact McNemar and confidence intervals. |
| **G5 Symbolic** | Does induction generalize beyond one formula family? | Multi-family, multi-seed benchmark with exact-recovery rates and Z3 equivalence. |

## Phase 1 — Private evaluation secure by default

**Objective:** private acceptance material can only run under split
custody; shared custody is an explicit, recorded, development-only
opt-out that production refuses.

**Current gaps**

- `OutcomeVerifier.register_task()` defaults to `custody="shared"`
  (`src/sis/v3/verifier.py`).
- `tools/learn_recommend_cycle.py` registers private tests without a
  custody argument and builds a Docker executor without a second UID.
- `sis.v3.evaluator_worker` turns `--split-user` into
  `require_split_custody`, but `--require-split-custody` alone remains
  opt-in.
- `ProductionIsolationPolicy` has no custody requirement, so a shared
  registration with private files is accepted when
  `require_split_custody` is false.

**Work items**

1. **Custody resolver.** Change `register_task(custody: str | None = None)`:
   - no private files → `"shared"`;
   - private files and the backend supports split → `"split"`;
   - private files and no split → raise
     `split_custody_unavailable_for_private_material` unless
     `allow_shared_custody=True`.
   Keep `_suite_commitment` and `_recover_custody` compatible; persisted
   rows keep their recorded mode.
2. **Explicit development opt-out.** Add
   `OutcomeVerifier(allow_shared_custody: bool = False)`. It must
   conflict with `require_split_custody` and with `isolation_policy`.
   Route the existing test fixtures through one testkit helper rather
   than editing 44 constructions ad hoc.
3. **Production refusal.** In `evaluate()` and `register_task()`, when
   `isolation_policy is not None` and private files exist, a custody
   mode other than `"split"` is rejected as
   `production_requires_split_custody`. Enforce this in the verifier,
   not by adding a field to `ProductionIsolationPolicy`: the policy
   digest is pinned into attestations.
4. **Worker secure default.**
   `evaluate_via_subprocess(require_split_custody: bool | None = None)`;
   the worker requires split custody whenever private material is
   registered. The Docker worker refuses to start without `--split-user`
   unless `--allow-shared-custody` is passed, and that flag is refused
   together with `--require-split-custody`.
5. **Cycle wiring.** `tools/learn_recommend_cycle.py` gains
   `--split-user` (default `2002:2002` for Docker), passes it to
   `DockerSandboxExecutor`, registers `custody="split"`, aborts when the
   probe's split check fails, and records `evaluation:process_split`
   counts in the cycle report.
6. **Probe.** Add a fourteenth check to
   `DockerSandboxExecutor.probe()`: execute `python -c pass` as the
   split UID. This proves the second identity is usable, not merely
   configured.
7. **Development harnesses.** `tools/live_study.py`,
   `tools/governed_live_campaign.py`, `tools/five_arm_campaign.py`,
   `tools/real_agent_campaign.py`, `tools/skill_holdout.py` and
   `scripts/v3/run_codex_episode.py` either use split custody (seatbelt
   on macOS, Docker elsewhere) or pass `allow_shared_custody=True` and
   stamp `custody: shared_dev` in their reports. A static test scans
   every `register_task()` call in `tools/` and `scripts/` and fails on
   an unmarked private registration.
8. **Adversarial tests.** In a real container, a submission attempts to
   read, list, chmod and replace `/private`, imports a shadow `pytest`,
   and reads the environment. Expect denial, `evaluation:process_split`,
   and the correct verdict. Also test registry tampering (editing
   `custody` fails the commitment) and a downgrade attempt through a
   legacy row.

**Exit (G1)**

```bash
pytest tests/v3/test_split_custody.py tests/v3/test_execution_identity_custody.py -q
# green, including the real-container tests

PYTHONPATH=src:. python3 tools/learn_recommend_cycle.py \
  --agent scripted --sandbox docker --split-user 2002:2002 -o /tmp/cycle.json
# every receipt carries evaluation:process_split; report custody == "split"
```

**Risk:** local split custody on Linux has no seatbelt, so
`LocalSubprocessExecutor` cannot support it. Linux development paths must
opt out explicitly; production uses Docker. Do not weaken the default to
accommodate them.

## Phase 2 — Release authenticity

**Objective:** the sealed archive is signed by a key the evaluated
machine does not hold, and production isolation is attested by an
independent isolator.

**Current state:** the tooling exists. `tools/package_release.py`
accepts `--provenance-key`, `tools/verify_external_attestation.py`
verifies an external attestation, and fresh extraction is already
checked. The missing pieces are ceremony, gates, and a fresh attestation
at seal time.

**Work items**

1. **Provenance ceremony.** Run `package_release.py` with
   `--provenance-key <offline seed>` and
   `--provenance-trust-root production`. Publish
   `provenance_public_key.hex` and its SHA-256 fingerprint out of band
   (tag message and release notes) and pin the fingerprint in
   `docs/v3/RELEASE_PROCESS.md`.
2. **Release gate.** `tools/check_release_ci.py --mode release` must
   require `release_manifest.provenance.signed == true`, verify the DSSE
   envelope against the pinned fingerprint, and bind it to the archive
   digest. Add a negative test: an unsigned manifest exits non-zero.
3. **External isolator.** On the isolator host, run
   `tools/qualify_docker_isolation.py --trust-root production
   --seed-file <offline>`; sign the receipt; verify with
   `tools/verify_external_attestation.py` using the relying party's copy
   of the public key. Commit only the verification record, never the
   seed.
4. **Seal-time freshness.** The attestation lives five minutes. The
   release gate verifies it during the seal and archives the
   verification record with its timestamp, receipt digest, image digest
   and policy digest. A later verifier checks the record, not the
   expired attestation.
5. **Seal.** Bump to `3.3.9`, run the suite, generate machine-readable
   test evidence (Phase 3), package with `--test-evidence`, verify fresh
   extraction, then tag.

**Exit (G2)**

```bash
python3 tools/verify_provenance.py --envelope release/provenance.dsse.json \
  --archive release/SIS-v3.3.9.zip --public-key <out-of-band key>
python3 tools/verify_external_attestation.py ...   # bound to the sealed image
python3 tools/check_release_ci.py --mode release   # fails unsigned, passes signed
```

**Organizational dependency:** if no external key custodian is
available, build 11 can still ship, but its status remains
`SECURITY_QUALIFIED_UNSIGNED` and G2 stays red. Do not generate the
"external" key on this machine.

## Phase 3 — Test matrix and release evidence

**Objective:** the suite is green or cleanly skipped on every supported
platform, and the release's test numbers come from an executed run bound
to the sealed commit.

**Work items**

1. **Fix the two Docker-absent tests.** They are configuration tests, so
   patch `_require_docker` the way the surrounding tests already do, or
   guard them with `skipUnless`. Do not weaken the real-container tests.
2. **Docker-absent CI job.** Add a Linux job with
   `DOCKER_HOST=unix:///nonexistent/docker.sock` and require zero
   failures or errors. This surfaces any other unguarded construction;
   fix them all.
3. **Official runner.** `pytest==8.4.2` is the supported runner. Add
   `tools/run_tests.py` that verifies the version, runs the suite, and
   writes `evidence/ci/test_report.json` with commit, command,
   environment and counts. Document unittest discovery as unsupported.
4. **Windows.** Either make the Windows job blocking with a documented
   skip allowlist, or declare Windows unsupported for the evaluator and
   keep the job non-blocking. Decide explicitly; do not leave the matrix
   ambiguous.
5. **Dependency lock.** Add `docker/sandbox/requirements.lock` with
   hashes and `pip install --require-hashes`; test that the image's
   `pip freeze` matches. The base image digest is already pinned; add a
   check that the Dockerfile digest is unchanged.
6. **Evidence-bound packaging.** Replace operator-entered
   `--passed/--skipped/--failed` with `--test-evidence <json>`; refuse
   evidence whose commit differs from `source_commit`, whose `failed`
   count is non-zero, or whose command is not the documented one.

**Exit (G3):** full suite green with Docker; zero failures or errors with
Docker absent; Windows decision implemented; `package_release.py`
refuses stale or hand-entered counts.

## Phase 4 — Demonstrate genuine learning

**Objective:** answer the only question that justifies "self-improving":
does SIS guidance improve a real agent on repositories it has never seen?

**Current state:** the machinery is real (`FiveArmCampaign`,
`preregister`, exact McNemar, disjointness), but the archived run is
`INVALID_INFRASTRUCTURE` after 20 of 40 arm runs, and the smaller
comparison is exploratory.

**Design decision first.** A powered five-arm test is expensive:

| Baseline → treatment | `required_sample_size` | Paired runs (5 arms) |
| --- | --- | --- |
| 0.60 → 0.40 | 103 | 515 |
| 0.60 → 0.45 | 178 | 890 |

Choose one:

- **A. Powered five-arm** at n=103 (0.60 → 0.40). Strongest claim;
  highest cost.
- **B. Powered primary contrast** A vs E at n=103, with B–D on a subset
  labeled exploratory. Cheaper, still confirmatory for the integrated
  system.
- **C. Explicit exploratory** run with `allow_underpowered=True`; no
  efficacy claim.

Recommendation: **B**, unless the agent budget supports A.

**Work items**

1. **Corpus.** Ten or more real repositories, 45–100 tasks, per-task
   pinned commit, prompt, evaluator-owned hidden tests, failure class
   and partition. Enforce repository disjointness structurally. Keep
   hidden tests out of the public archive; archive hashes only.
2. **Preregistration.** Commit the protocol JSON (metric, method, alpha,
   minimum effect, sample size, budget, arms, expectations) before any
   holdout run. Record the digest in the report.
3. **Learning material.** Induce only from the induction partition;
   freeze bundles; assert no holdout repository digest appears in
   learned material. Add a negative-transfer suite with deliberately
   misleading procedures.
4. **Execution.** Real agent, pinned model and CLI version, fixed
   budget, randomized arm order. Add per-`(task, arm)` checkpointing and
   resume so a quota interruption yields `INVALID_INFRASTRUCTURE`
   without losing completed pairs. Preflight agent availability and
   quota.
5. **Analysis.** Verified solve rate, paired differences, exact McNemar,
   Wilson confidence intervals, negative transfer, token and tool cost,
   per-repository generalization, and a second independent run for
   persistence.
6. **Evidence placement.** `evidence/` is manifest-covered, so adding
   study evidence after a seal forces a new seal. Either finish the
   study before the final seal, or publish the evidence as an out-of-band
   bundle under `release/` and reference it from the qualification
   report.

**Exit (G4):** preregistered, powered, disjoint, complete, two runs;
result reported as a confirmatory positive or a clean null. A null is a
valid qualification outcome; it does not support an efficacy claim.

## Phase 5 — Expand symbolic reasoning (non-blocking)

**Objective:** replace "one formula family works" with a measured
recovery rate across families.

**Current limits:** `tools/benchmark_induction.py` rejects fields outside
`[2, 64]`; the grammar supports `field`, `item` (up to 16), `const`,
`if_eq`, `eq`, `add`, `sub`, `mul`, `min`, `max`, `neg` and `abs`; there
is no division, modulo, ordering comparison or boolean composition; Z3
is optional.

**Work items**

1. Add guarded `div`/`mod`, ordering comparisons and boolean composition
   with validation and cost.
2. Build a family generator with declared intended ASTs, randomized
   feature positions, decoys, noise, negative and large values.
3. Make Z3 a required development dependency and add
   counterexample-guided refinement: a rival that matches the sample but
   differs on a Z3 model is rejected.
4. Extend the benchmark beyond 64 features with a documented screening
   strategy; report candidate counts, time and memory.
5. Report exact recovery separately from observational match, across at
   least five families and twenty seeds, with confidence intervals. Keep
   the 64-field regression (129 candidates) as a floor.

**Exit (G5):** multi-family recovery rates published; Z3 equivalence for
recovered rules; no regression on the v3.3.8 benchmark; limits
documented.

## Sequence and dependencies

```text
M0  baseline freeze (this tree, green suite)
M1  Phase 1 + Phase 3.1/3.2        blocking
M2  Phase 2 seal (needs M1 + external keys)
M3  Phase 4 corpus/preregistration start in parallel with M1
    Phase 4 run                    after M2 code freeze, before final seal
M4  Phase 5                        after the tag, or in v3.4
```

Two sequencing traps:

- **Seal ordering.** If Phase 4 evidence lands after the seal, it forces
  a second seal. Prefer: freeze code, run the study, seal once with the
  evidence included. If the study is long, seal the code first and
  publish the study as an out-of-band bundle.
- **Custody blast radius.** Flipping the default touches roughly 44
  `OutcomeVerifier` constructions and 52 registrations with private
  files. Contain it with one testkit helper (`allow_shared_custody=True`)
  and a static entrypoint scan, not scattered edits.

## Decisions required

1. **Version:** `v3.3.9` (patch line, matches the release process) or
   `v3.4.0` (signals a qualification milestone)?
2. **External keys:** who holds the release signing key and the isolator
   key, and on what host? This determines whether G2 is achievable in
   build 11.
3. **Efficacy design:** A (powered five-arm), B (powered A vs E plus
   exploratory B–D), or C (exploratory only)?
4. **Corpus:** public benchmark tasks or hand-authored private tasks?
   Licensing and leakage constraints differ.
5. **Agent:** Codex CLI or another agent, and what quota can be
   committed?
6. **Windows:** blocking support or documented unsupported?

## Suggested first four commits

1. `Resolve custody explicitly at registration` — resolver,
   `allow_shared_custody`, testkit helper.
2. `Refuse shared custody for private material in production` —
   verifier gates and adversarial unit tests.
3. `Wire split custody through the worker and learning cycle` —
   `--split-user`, probe check, cycle report.
4. `Make Docker-absent configuration tests portable` — the two failing
   tests and the Docker-absent CI job.

## Effect on the current seal

Adding this document changes a manifest-covered file, so
`RELEASE_SHA256.json` no longer matches the tree and
`tools/check_release_ci.py --mode release` fails until the tree is
re-sealed. That is expected: Phase 2 re-seals over the build-11 tree.
Until then this tree is a development tree, not a release candidate.
