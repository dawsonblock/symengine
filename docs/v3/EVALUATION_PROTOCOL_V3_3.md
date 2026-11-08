# SIS v3.3 Evaluation Protocol

## Arms

| arm | configuration |
| --- | --- |
| A | base agent |
| B | base + qualified experience memory |
| C | base + evolved skill candidates |
| D | base + SIS symbolic procedures (strict gateway) |
| E | base + full governed integration (all qualified artifacts, composed) |

Same agent, same `BudgetCaps`, paired per task. Arm is opt-in via
`arms=`; the historical default remains `("A","B","C","D")`.

## Validity conditions (structural, not assumed)

1. **Sealed holdout** — `assert_partition_disjoint` rejects any shared
   `repo_snapshot_digest` between holdout/monitoring and
   induction/development before the run. Induction and development may
   overlap by design; dev evidence is never reported as generalization.
2. **Preregistration** — `preregister` freezes primary metric, method,
   alpha, min effect, sample size, budget, and arms into a
   domain-separated `protocol_digest` committed before the holdout run
   and embedded in the report. Three plan kinds are distinguished:
   - *powered* (default) — binds `power_analysis.required_n`, recomputed
     from the declared expectations and `alpha`. A powered plan whose
     declared `sample_size` is below that floor is refused at
     registration; `allow_underpowered=True` is the explicit,
     digest-visible opt-out (`power_analysis.underpowered_declared`) for
     a deliberately exploratory run, and the conformance block still
     reports the shortfall.
   - *diagnostic* (`powered=False`) — a deterministic screen such as a
     one-task candidate probe. It binds the same fields but makes no
     power claim and can never satisfy production qualification.
3. **Sample size** — `required_sample_size(p1, p2)` is a conservative
   normal-approx McNemar calculation; declare the effect size worth
   detecting and power before running. Conformance recomputes the floor
   from the registered expectations instead of trusting the plan's own
   `required_n`, so an edited result is reported as
   `power_analysis_required_n_mismatch` and a run short of the floor is
   reported as underpowered.
4. **Hidden labels** — arms receive only their injected guidance context;
   outcomes come only from signed `OutcomeReceiptV1`s issued by the
   evaluator against its own registered criteria.
5. **Repository disjointness** — `assert_repository_disjoint` additionally
   verifies the holdout repos never appeared in learned material.

## Metrics (per arm, from `compute_metrics`)

`solved_task_rate`, `failure_rate`, `verified_regression_rate`,
`abstention_rate`, `negative_transfer_rate` (served×failed on misleading
tasks), `paired_win_rate` / `paired_loss_rate` (vs baseline arm A),
`mean_tokens_per_task`, `mean_tool_calls_per_task`,
`mean_wall_seconds_per_task`, `mean_cost_per_verified_solve`,
`evaluation_integrity_failures`.

`failure_rate` is the absolute fraction of tasks the arm failed.
`verified_regression_rate` is relative to the baseline: the fraction of
tasks **arm A verified as solved** that this arm no longer solves (a
budget-exceeded or errored result counts as not solved). Arm A therefore
reports `0.0` against itself, and `None` when the baseline solved
nothing. A task both arms fail is not a regression; it is a shared
failure and appears in `failure_rate`.

Missing usage stays `None`/`unverified` — never fabricated; cost is
not metered, so `mean_cost_per_verified_solve` reports `None`.

`served_map[(task_id, arm)]` records whether guidance was actually
served, so abstention and negative transfer are *measured*, not
inferred.

## Statistics

- Primary contrast: paired `E` vs `A` wins/losses/ties with exact
  McNemar p (`mcnemar_p`) and Wilson intervals (`wilson_ci`) where
  reported.
- Exploratory vs confirmatory is declared in the report
  (`analysis_mode`); anything not preregistered is exploratory.
- Inconclusive is a legitimate verdict: report
  `EFFICACY_NOT_QUALIFIED` rather than a massaged pass.

## Negative-transfer suite

Include deliberately misleading memories and tasks where a previously
successful strategy is wrong. Measure: did the system abstain
(`abstention_rate`, counterexample suppression) or apply-and-fail
(`negative_transfer_rate`)? Both are reported per arm.

## Honest outcome vocabulary

- `solved` = receipt `pass` AND not `budget_exceeded` AND no arm error.
- `verified` usage = harness-metered `UsageMeter` counters only;
  stdout-parsed usage is `reported`; absent usage is `unverified`.
- A positive result on six tasks, or more unit tests, is not efficacy.
