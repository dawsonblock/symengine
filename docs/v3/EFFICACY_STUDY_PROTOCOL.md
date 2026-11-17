# Five-arm real-agent efficacy study protocol

Status date: 2026-11-14. Status: **scaffolded, not executed**.

This protocol defines the Phase 6 question and the evidence that would
answer it. It is not an efficacy result. A valid manifest is a
prerequisite for a run, not proof that SIS improves coding performance.

## Question

Does SIS guidance improve a real coding agent on repositories the learner
has never seen, relative to the same agent without SIS?

The primary contrast is **A vs E**. Arms B–D isolate the components and
are secondary unless the study is powered for all five arms.

## Arms

| Arm | Guidance |
| --- | --- |
| A | Baseline: no SIS guidance |
| B | Baseline + qualified experience memory |
| C | Baseline + qualified evolved skills |
| D | Baseline + qualified symbolic procedures |
| E | Baseline + all governed learning components |

Every arm runs the same task, repository snapshot, agent model/CLI
version, prompt, budget and evaluator. Arm order is randomized per task.

## Design

- **Paired tasks.** Every task runs all five arms. The unit of analysis is
  the task, not the arm run.
- **Repository-disjoint holdout.** Induction repositories and holdout
  repositories are disjoint. No holdout repository digest may appear in
  learned material, and hidden tests never enter the public archive. No
  two holdout entries may resolve to the same codebase or the same
  repository lineage: a lineage is the history a checkout descends from
  (its Git root commits), not just its current file contents, so two
  revisions of one repository cannot count as independent evidence.
  Every repository declares a stable `lineage_id`; when the path is a
  Git checkout the validator derives the lineage from history.
- **Preregistration.** The protocol, sample size, minimum effect, alpha,
  budgets, arms and expectations are committed before the first holdout
  run. The manifest records the protocol digest.
- **Power target.** The planning heuristic gives:

  | Baseline → treatment | Required paired tasks | Five-arm runs | Two-arm runs |
  | --- | --- | --- | --- |
  | 0.40 → 0.60 | 103 | 515 | 206 |
  | 0.45 → 0.60 | 178 | 890 | 356 |

  The two-sided calculation is symmetric: the same effect size needs the
  same number of pairs whichever arm is expected to do better, so the
  planner accepts an expected improvement as readily as a regression.
  The 103-task figure is a design target for one assumed effect size, not
  a universal minimum. A study powered only for A vs E may run B–D on a
  subset and label them exploratory.
- **Primary contrast.** A vs E is the decisive comparison; B–D are
  mechanism controls. A two-arm study runs only A and E at the same
  preregistered floor, halving the agent runs without weakening the
  confirmatory test. It uses
  [efficacy_manifest_two_arm_template.json](efficacy_manifest_two_arm_template.json)
  with `kind: primary_contrast_efficacy_manifest` and protocol arms
  `["A","E"]`. The five-arm manifest remains valid; the manifest kind and
  the protocol arms must agree. `tools/five_arm_campaign.py --demo
  --arms primary` runs the scripted two-task demonstration; it is
  machinery evidence, never an efficacy result.
- **Equal budgets.** Every arm gets the same wall-clock, token and tool
  budget per task. Budget-exceeded runs are not passes.
- **Hidden, independently verified outcomes.** Acceptance tests are
  evaluator-owned, live outside the public repository, and are applied by
  the evaluator. The agent never sees the hidden tests.
- **Persistence.** A confirmatory result should be repeated in a second
  independent run before it is treated as stable.

## Manifest

The five-arm template is
[efficacy_manifest_template.json](efficacy_manifest_template.json); the
two-arm primary-contrast template is
[efficacy_manifest_two_arm_template.json](efficacy_manifest_two_arm_template.json).
Replace every `<placeholder>`, provide at least ten repositories (at
least five of them holdout repositories with distinct snapshots and
distinct lineages that each contribute tasks) and at least 103 paired
holdout tasks, and commit the manifest before any holdout run. Each
repository declares a `lineage_id` shared by every revision of that
repository and distinct from every other holdout lineage, plus a
`repo_execution_digest` that pins the permission and entry-type state
its content digest deliberately ignores, and the `origin` URL its
checkout must have. A manifest that omits the execution fingerprint or
the origin is invalid; rebuild an older manifest with the study kit.

Validate the template while editing:

```bash
PYTHONPATH=src python3 tools/check_efficacy_manifest.py \
  docs/v3/efficacy_manifest_template.json --allow-placeholders
```

Validate a real manifest before the run:

```bash
PYTHONPATH=src python3 tools/check_efficacy_manifest.py \
  /secure/study/manifest.json --check-paths
```

The validator enforces:

- the five arms exactly;
- a preregistered, powered protocol whose digest matches;
- `sample_size` at or above the recomputed power floor;
- repository-disjoint induction/holdout partitions, with distinct
  holdout codebases and lineages;
- at least ten repositories, of which at least five are holdout
  repositories, and at least `sample_size` tasks;
- `--check-paths` re-fingerprints every repository with the
  repository-content format (working tree, VCS metadata excluded),
  verifies the declared content digest (full-tree v2 and legacy v1
  records are accepted read-only) and the declared execution
  fingerprint (entry types, permission bits including setuid/setgid/
  sticky, root directory mode and symlink targets), derives Git
  lineage, and rejects duplicate codebases or shared lineages across
  holdout entries;
- `--check-paths` also binds every repository to its declared
  `base_commit`: the path must be the root of a Git checkout whose HEAD
  is that commit and whose working tree has no staged, unstaged or
  untracked changes. A fabricated commit, a dirty checkout or a
  directory that cannot prove its commit is rejected; the campaign
  repeats the check immediately before execution so a checkout that
  moves after validation cannot run;
- `--check-paths` verifies provenance separately: the checkout's
  `origin` remote must equal the declared origin, the history must not
  be shallow, and the base commit must be reachable from a
  remote-tracking ref. This is local consistency, not proof that the
  upstream contains the commit;
- hidden tests outside the public repository;
- safe relative acceptance-file paths;
- pinned agent kind/model/CLI version;
- positive equal-budget fields per task.

Exit status `0` means ready; `2` means structurally valid but not ready
(for example, underpowered or a diagnostic protocol); `1` means invalid.

### Build from a study spec

`tools/build_efficacy_manifest.py` turns a declarative spec into the
manifest above. It computes canonical repository digests, execution
fingerprints, Git base commits, lineage metadata and hidden-test
digests, then refuses to write unless the validator reports both
`valid` and `ready`. Every repository must be a clean Git checkout at
its root with a configured origin and a complete history; a path that
cannot prove its commit, origin or history is refused. It never invents
repositories, prompts, hidden tests or guidance.

```json
{
  "schema_version": 1,
  "kind": "five_arm_study_spec",
  "protocol": {
    "primary_metric": "paired solved_delta E vs A",
    "method": "mcnemar_exact",
    "alpha": 0.05,
    "min_effect": 0.2,
    "sample_size": 103,
    "budget": {"wall_seconds": 900, "token_budget": 100000,
                "tool_budget": 100},
    "arms": ["A", "B", "C", "D", "E"],
    "powered": true,
    "expected_baseline": 0.4,
    "expected_treatment": 0.6,
    "power": 0.8
  },
  "agent": {"kind": "codex-cli", "model": "<pinned-model>",
             "cli_version": "<pinned-cli-version>"},
  "preregistration": {"registered_at": "<ISO-8601 timestamp>",
                       "registered_by": "<operator>"},
  "repositories": [
    {"repository_id": "repo-induction", "path": "/secure/repos/induction",
     "partition": "induction", "lineage_id": "lineage-induction"},
    {"repository_id": "repo-holdout", "path": "/secure/repos/holdout",
     "partition": "holdout", "lineage_id": "lineage-holdout",
     "hidden_tests": {"path": "/secure/private/hidden.py"}}
  ],
  "tasks": [
    {"task_id": "task-001", "repository_id": "repo-holdout",
     "prompt": "<prompt given to every arm>", "failure_class": "bug_fix",
     "acceptance": {"argv": ["python3", "-m", "pytest", "-q", "hidden.py"],
                     "hidden_tests_path": "/secure/private/hidden.py"}}
  ],
  "guidance_bundle": "/secure/study/bundle.json"
}
```

```bash
PYTHONPATH=src python3 tools/build_efficacy_manifest.py \
  --spec /secure/study/spec.json \
  --output /secure/study/manifest.json
```

`--skip-agent-check` builds off-host without requiring an installed,
matching Codex CLI; the run host still enforces the pin. The output path
may not be inside a repository, because writing there would change the
tree digest the manifest just recorded.

For the two-arm primary contrast, set `kind` to
`primary_contrast_study_spec` and `protocol.arms` to `["A","E"]`; the
builder writes a `primary_contrast_efficacy_manifest`. Everything else,
including the power floor and the repository requirements, is unchanged.

## Execution

1. Freeze the learning material from the induction partition only.
2. Commit the manifest and its protocol digest.
3. Preflight the agent: binary, authentication, model and CLI version.
4. Run the declared arms with randomized order and per-`(task, arm)`
   checkpointing so a quota interruption is recorded as
   `INVALID_INFRASTRUCTURE` rather than silently dropping pairs. The
   current runner randomizes order but does not checkpoint: an
   interrupted run is aborted and must be repeated in full.
5. Verify every outcome with the evaluator-owned acceptance tests.
6. Preserve the raw report and receipts. Do not edit a failed or
   underpowered result after the fact.

The existing library interface is `sis.v3.learning_qualification.FiveArmCampaign`
and `CodexCliAgent`; `tools/five_arm_campaign.py --real-agent --manifest`
is the gate. A validated manifest is executed: the gate builds the
declared arms from the manifest, registers the evaluator-owned acceptance
material, runs the agent against each repository snapshot and writes the
paired report with a receipt digest per `(task, arm)`. The gate still
fails closed with `BLOCKED_REAL_AGENT` when Codex is unavailable or
unauthenticated, `BLOCKED_MANIFEST` when the manifest is invalid, not ready (a
diagnostic or unpowered plan) or a repository snapshot has drifted,
`BLOCKED_SPLIT_CUSTODY` when the
backend cannot keep acceptance tests out of the submission's process,
`BLOCKED_AGENT_VERSION` when the installed CLI does not match the
pinned `agent.cli_version`, and `BLOCKED_GUIDANCE` when a supplied
guidance bundle is unusable.

Executing a manifest is not evidence. A confirmatory label additionally
requires all of the following, recorded in the report's `provenance`
block and enforced by the classifier:

- the agent is the real `codex-cli` (an injected test agent is
  `invalid`, never `exploratory`);
- the installed CLI version matched the manifest;
- private acceptance tests ran under split custody;
- guidance came from `--guidance-bundle`, a frozen file whose every
  step resolves to a qualified candidate record; the built-in
  `Recall…`/`Workflow…`/`Procedure…` prompts are a fixed control
  condition and can never qualify;
- the manifest was committed before the run (Git anchor) and carries
  the precommitted `guidance_bundle_digest`;
- token and tool usage were fully metered by the agent runtime
  (`budget_accounting: verified`).

A learned bundle is a frozen JSON file supplied with
`--guidance-bundle`. A file that merely declares `"source": "learned"`
is not evidence: every step names the immutable candidate record it was
produced from, the training partitions are the manifest's induction
repositories, and the manifest precommits the bundle digest before the
run. Passing `--candidate-registry` additionally requires each
candidate to resolve to a qualified record whose evidence covers the
declared digest; without it the bundle is recorded as
`learned_unverified` and can never support a confirmatory label.

```json
{
  "schema_version": 2,
  "kind": "learned_guidance_bundle",
  "source": "learned",
  "training": {
    "repository_digests": ["<induction repo snapshot sha256>"]
  },
  "components": {
    "B": [{
      "candidate_id": "cand-memory-1",
      "candidate_digest": "<candidate record sha256>",
      "content_digest": "<candidate content sha256>",
      "evidence_digest": "<qualified evidence sha256>",
      "text": "<qualified memory step>"
    }],
    "C": [{"candidate_id": "...", "candidate_digest": "...",
           "content_digest": "...", "evidence_digest": "...",
           "text": "<qualified skill step>"}],
    "D": [{"candidate_id": "...", "candidate_digest": "...",
           "content_digest": "...", "evidence_digest": "...",
           "text": "<qualified symbolic step>"}]
  },
  "bundle_digest": "<canonical digest of the bundle body>"
}
```

The manifest carries the same digest as `guidance_bundle_digest`; the
gate refuses a bundle that does not match it, a bundle whose training
repositories are outside the induction partition, or a bundle whose
declared digest does not recompute. Arm E receives the B, C and D steps
in that order. The built-in prompts are never mixed into a learned
bundle.

The run writes `<report>.evidence/` next to the report: the signed
receipt bytes under `receipts/`, the evaluator public key, the exact
manifest and a `bundle.json` that binds the manifest digest, the report
digest and every receipt. The verifier's temporary key store is not the
evidence; the bundle is.

## Metrics

- Verified solve rate per arm.
- Paired wins/losses/ties for A vs E and E vs B/C/D.
- Exact McNemar p-value and Newcombe difference interval.
- Negative transfer: guidance makes a task worse than baseline.
- Token, tool-call and wall-clock cost per verified solution.
- Latency.
- Per-repository generalization on unseen repositories.
- Repository-clustered uncertainty: tasks within one repository are not
  independent draws, so per-repository outcomes and a cluster-robust
  check accompany the paired task-level analysis.
- Failure categories, including evaluator/bootstrap errors.

## Evidence classes

| Class | Meaning |
| --- | --- |
| `demonstration` | Scripted machinery evidence; never an efficacy claim |
| `exploratory` | Real agent, but underpowered or not preregistered |
| `confirmatory` | Real agent, hidden repository-disjoint holdout, protocol conformance and the preregistered sample size |
| `invalid` | Missing manifest, missing agent, infrastructure failure or protocol mismatch |

Only `confirmatory` evidence with a statistically supported A→E
improvement and no material negative transfer can support an efficacy
claim. A `confirmatory` run that finds no evidence is still a result and
must be preserved.

## Evidence placement

`evidence/` is manifest-covered. A completed study therefore either
finishes before a release seal or publishes its evidence as an
out-of-band bundle under `release/` and references it from the
qualification report. Do not add study evidence after a seal and leave
the seal claiming the old source.

## Current status

- The scaffold, template and validator are present.
- The runner executes a validated manifest, randomizes arm order, meters
  usage, records provenance and exports a signed-receipt evidence bundle.
- It does not yet checkpoint per `(task, arm)` and still constructs the
  local executor; a secure Linux run needs the Docker backend wired in.
- No confirmatory run has been executed: the built-in guidance is a
  fixed control condition, not learned components, and no preregistered
  task manifest exists on the development host.
- The accurate claim remains: the learning workflow functions; its
  general coding effectiveness is unproven.
