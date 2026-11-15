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
  learned material, and hidden tests never enter the public archive.
- **Preregistration.** The protocol, sample size, minimum effect, alpha,
  budgets, arms and expectations are committed before the first holdout
  run. The manifest records the protocol digest.
- **Power target.** The planning heuristic gives:

  | Baseline → treatment | Required paired tasks | Five-arm runs |
  | --- | --- | --- |
  | 0.60 → 0.40 | 103 | 515 |
  | 0.60 → 0.45 | 178 | 890 |

  The 103-task figure is a design target for one assumed effect size, not
  a universal minimum. A study powered only for A vs E may run B–D on a
  subset and label them exploratory.
- **Equal budgets.** Every arm gets the same wall-clock, token and tool
  budget per task. Budget-exceeded runs are not passes.
- **Hidden, independently verified outcomes.** Acceptance tests are
  evaluator-owned, live outside the public repository, and are applied by
  the evaluator. The agent never sees the hidden tests.
- **Persistence.** A confirmatory result should be repeated in a second
  independent run before it is treated as stable.

## Manifest

The template is [efficacy_manifest_template.json](efficacy_manifest_template.json).
Replace every `<placeholder>`, provide at least ten repositories (at
least five of them holdout repositories) and at least 103 paired
holdout tasks, and commit the manifest before any
holdout run.

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
- repository-disjoint induction/holdout partitions;
- at least ten repositories, of which at least five are holdout
  repositories, and at least `sample_size` tasks;
- hidden tests outside the public repository;
- safe relative acceptance-file paths;
- pinned agent kind/model/CLI version;
- positive equal-budget fields per task.

Exit status `0` means ready; `2` means structurally valid but not ready
(for example, underpowered or a diagnostic protocol); `1` means invalid.

## Execution

1. Freeze the learning material from the induction partition only.
2. Commit the manifest and its protocol digest.
3. Preflight the agent: binary, authentication, model and CLI version.
4. Run the five arms with randomized order and per-`(task, arm)`
   checkpointing so a quota interruption is recorded as
   `INVALID_INFRASTRUCTURE` rather than silently dropping pairs. The
   current runner randomizes order but does not checkpoint: an
   interrupted run is aborted and must be repeated in full.
5. Verify every outcome with the evaluator-owned acceptance tests.
6. Preserve the raw report and receipts. Do not edit a failed or
   underpowered result after the fact.

The existing library interface is `sis.v3.learning_qualification.FiveArmCampaign`
and `CodexCliAgent`; `tools/five_arm_campaign.py --real-agent --manifest`
is the gate. A validated manifest is executed: the gate builds the five
arms from the manifest, registers the evaluator-owned acceptance
material, runs the agent against each repository snapshot and writes the
paired report with a receipt digest per `(task, arm)`. The gate still
fails closed with `BLOCKED_REAL_AGENT` when Codex is unavailable or
unauthenticated, `BLOCKED_MANIFEST` when the manifest is invalid or a
repository snapshot has drifted, `BLOCKED_SPLIT_CUSTODY` when the
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
- guidance came from `--guidance-bundle`, a frozen file of learned
  components; the built-in `Recall…`/`Workflow…`/`Procedure…` prompts
  are a fixed control condition and can never qualify;
- the manifest was committed before the run (Git anchor);
- token and tool usage were fully metered by the agent runtime
  (`budget_accounting: verified`).

A learned bundle is a frozen JSON file supplied with
`--guidance-bundle`:

```json
{
  "schema_version": 1,
  "source": "learned",
  "bundles": {
    "B": ["<qualified memory step>"],
    "C": ["<qualified skill step>"],
    "D": ["<qualified symbolic step>"]
  }
}
```

Arm E receives the B, C and D steps in that order. The file is hashed
and recorded in the report's `guidance` block; the built-in prompts are
never mixed into a learned bundle.

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
