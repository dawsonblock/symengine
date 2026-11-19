# Evaluation Protocol and Learning Qualification

## Five arms

| Arm | Configuration |
| --- | --- |
| A | baseline coding agent, no SIS guidance |
| B | baseline + qualified experience memory |
| C | baseline + qualified evolved skills |
| D | baseline + qualified symbolic procedures |
| E | baseline + all governed learning components |

All arms use the same base model, task budgets, repository fixtures,
evaluator and sealed holdout. Candidate versions are frozen before the
run; the report records their digests.

## Partitions

`induction`, `development`, `holdout`, `monitoring`. Holdout and
monitoring repositories must be disjoint from every repository that
supplied learning evidence. Induction and development may overlap; dev
evidence is never generalization evidence. A run without a nonempty
holdout is not a generalization measurement.

## Preregistration

`preregister` freezes the primary metric, method, alpha, minimum effect,
sample size, budget and arm set into a domain-separated
`eval_protocol` digest before the holdout run. The report embeds the
digest. The protocol registry used by certificates verifies that digest.
A powered plan's declared effect `|expected_treatment - expected_baseline|`
may not exceed `min_effect`, and both expected rates must lie in (0, 1);
otherwise the plan could justify a sample too small for the effect of
interest. An optional `max_negative_transfer` preregisters the
negative-transfer threshold (default 0.10).

## Metrics

- `solved_task_rate`
- paired wins/losses/ties against A
- `verified_regression_rate` (baseline-solved tasks the arm no longer
  solves)
- negative transfer: paired losses (A solved, E did not) over paired
  tasks, always measured; `negative_transfer_rate` per arm is the
  served-misleading-task failure rate when misleading tasks are declared
- `abstention_rate`
- mean tokens, tool calls and wall seconds per task
- cost per verified solution
- evaluator/infrastructure failures
- per-arm failure categories

## Statistics

- every test and interval uses the preregistered `alpha` (validated in
  (0, 0.5)); 95% intervals are reported beside them;
- primary decision: exact repository-level sign-flip test on the
  per-repository E-minus-A totals, with a repository cluster bootstrap
  interval, because tasks within one repository are correlated;
- exact two-sided McNemar test for discordant pairs (task level,
  reported as secondary);
- E vs B/C/D contrasts are secondary mechanism controls with
  Holm-corrected significance;
- Wilson score intervals for per-arm solved rates;
- Newcombe hybrid-score interval for the paired difference;
- power analysis (`required_sample_size(0.6, 0.4)` by default);
- explicit `underpowered` flag when executed tasks < preregistered
  sample size.

## Evidence classes and release gates

`analyze_report` labels:

- `demonstration` for scripted/machinery runs;
- `invalid` when the holdout is not hidden/disjoint or protocol
  conformance fails;
- `exploratory` for a real run below the preregistered sample size, or
  with any provenance or design gap (for example, fewer than 20 holdout
  repositories contributing tasks);
- `confirmatory` only for a real agent, hidden holdout, conforming
  protocol, sufficient sample, at least 20 holdout repositories that
  contribute tasks (every task naming its repository), measured negative
  transfer, fully metered usage and guidance selected per task through
  the governed serving gateway.

Agent-side timeouts, CLI errors and budget overruns are scored as
ordinary failures (`attested_failure` accounting); they never demote a
study. Unmetered passes, evaluator errors and unterminated workspaces
still do.

`release_gate` is `EFFICACY_SUPPORTED` only for a confirmatory run whose
repository-level E-vs-A test is significant at the preregistered alpha
with a positive cluster-bootstrap lower bound, and whose negative
transfer is measured and not material. A significant task-level McNemar
test alone is not enough. A regression is preserved as
`NO_EFFICACY_CLAIM`. A scripted or underpowered run is
`IMPLEMENTED_NOT_EFFICACY_QUALIFIED`; no scripted run is substituted for
a confirmatory one.

## Real-agent gate

`codex_agent_status()` reports whether the Codex CLI is installed and
authenticated without calling it. `CodexCliAgent` is the working
interface: it builds a prompt with the task and advisory guidance, runs
`codex exec --json` in the disposable workspace under workspace-write,
counts tool events and returns usage. The evaluator independently
verifies the resulting tree.

`tools/five_arm_campaign.py --real-agent --manifest` executes a
validated, ready manifest. The manifest validator applies the same
20-repository floor (`MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES`): a powered
manifest is a `confirmatory` study and is refused with fewer than 20
contributing holdout repositories, unless it declares
`"study_tier": "exploratory"`, which keeps a floor of five and can only
produce an exploratory result. The gate builds the five arms,
registers the evaluator's acceptance material and writes the paired
report with receipt digests plus a `<report>.evidence/` bundle. A
confirmatory label additionally requires recorded provenance: a real
`codex-cli` agent, a matching installed version, split custody, learned
guidance from `--guidance-bundle`, a committed manifest and fully
metered usage. The
built-in prompts are a fixed control condition. It writes a
`BLOCKED_REAL_AGENT` / `BLOCKED_MANIFEST` / `BLOCKED_AGENT_VERSION`
report when a real run cannot be started or the inputs are unusable.
`tools/real_agent_campaign.py` is the executable runner used for the
v3.3.1 attempt; it fails closed on error/no-action events so a quota
failure cannot be scored as a task failure.

## v3.3.1 result

The scripted five-arm demo (2 tasks) shows the machinery and statistics:
A 0/2, B–E 2/2, paired wins 2, losses 0, exact p=0.5, 95% Newcombe
interval [0.07, 1.0]. It is labelled `demonstration`; the p-value shows
why a 2-task run cannot support an efficacy claim.

The v3.3.1 real-agent attempt ran eight preregistered synthetic tasks
across five Codex arms. Codex hit its usage limit after 20 of 40 arm
runs; four tasks had zero tool events and are infrastructure failures.
The attempt is recorded as `INVALID_INFRASTRUCTURE` and the gate as
`BLOCKED_EXTERNAL_AGENT_QUOTA`. No efficacy claim is made.
