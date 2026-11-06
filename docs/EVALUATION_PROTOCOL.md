# Evaluation Protocol and Learning Qualification

## Five arms

| Arm | Configuration |
|---|---|
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

## Metrics

- `solved_task_rate`
- paired wins/losses/ties against A
- `verified_regression_rate` (baseline-solved tasks the arm no longer
  solves)
- `negative_transfer_rate` (served misleading tasks that fail)
- `abstention_rate`
- mean tokens, tool calls and wall seconds per task
- cost per verified solution
- evaluator/infrastructure failures
- per-arm failure categories

## Statistics

- exact two-sided McNemar test for discordant pairs;
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
- `exploratory` for a real run below the preregistered sample size;
- `confirmatory` only for a real agent, hidden holdout, conforming
  protocol and sufficient sample.

`release_gate` is `EFFICACY_SUPPORTED` only for a confirmatory run whose
E-vs-A difference is positive, statistically significant and has a
positive lower confidence bound. A regression is preserved as
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

`tools/five_arm_campaign.py --real-agent` writes a
`BLOCKED_REAL_AGENT` / `BLOCKED_MANIFEST` report when a real run cannot
be started. `tools/real_agent_campaign.py` is the executable runner used
for the v3.3.1 attempt; it fails closed on error/no-action events so a
quota failure cannot be scored as a task failure.

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
