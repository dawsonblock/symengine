# SIS v3.3 Skill Evolution (Track C)

EvoSkill-style bounded skill search on SIS rails: failure-driven
mutation, dev-set fitness, frontier maintenance — with no qualification
authority and no executable command construction.

## Optimizer — `SkillOptimizer`

```
seeds (skill payloads)
  -> for each parent, for each mutator (bounded):
       child = mutator(payload)            # pure dict->dict|None
       child CandidateV1 (content_digest)  # deduped by digest
       registry_submit(child)  -> PROPOSED # optional; intake only
       result = evaluator.evaluate(child, dev_tasks)  # injected
       fitness(result) -> FrontierEntry
  -> parents = frontier entries; repeat while budget remains
  -> return ranked frontier
```

- **Mutators are pure functions** (`append_step`, `specialize_step`,
  `drop_step`, `reorder_step`). No strings are ever interpolated into
  executable argv — the spec's command-injection class is absent by
  construction.
- **The evaluator is injected** (`EvaluationClient` protocol): the
  optimizer cannot grade itself, cannot see holdout tasks, and cannot
  mint receipts. `DevEvalResult` may carry `receipt_refs` when real
  receipts exist; they are provenance, not authority.
- **Budgets are hard** (`EvolutionBudget`): `max_iterations`,
  `max_evaluations`, `max_wall_seconds`, `max_candidates`,
  `frontier_size` — all checked inside the loop.
- **fitness** = solved_rate − 2×regression_rate − 0.1×token_cost:
  regressions dominate wins; cost is a tiebreaker.
- **Lineage**: child ids are `skill-<digest-prefix>`; content digests
  dedupe identical variants across iterations.

## What evolution deliberately cannot do

- Transition any candidate past `proposed→validated` intake edges.
- Read or write sealed evaluation partitions.
- Touch `AuthorityDB`, `PromotionController`, or signing material.
- Claim that dev-set success is generalization evidence — dev fitness
  selects candidates for the *independent* evaluator, full stop.

## Development vs qualification

| partition | consumer | visible to optimizer? |
|---|---|---|
| induction | episode/memory generation | yes (its inputs) |
| development | mutation fitness | yes |
| qualification (holdout) | independent evaluation | **no** — enforced by `assert_partition_disjoint` on repo digests |
| monitoring | post-release checks | no |

Repeated optimization against the development set produces *selection*
evidence only. The holdout — unseen repository snapshots — produces the
efficacy claim.
