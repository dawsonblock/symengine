# First complete learn → qualify → recommend cycle (2026-11-11)

Phase 2 milestone: a real agent solves two same-class dev tasks, an
independent evaluator verifies them, the verified episode becomes a
candidate procedure, signed decisions qualify it, and a sibling task in
the same failure class is served `recommend`. A different failure class
abstains.

Machine-readable evidence: `learn_cycle_live.json` (real Codex) and
`learn_cycle_scripted.json` (deterministic plumbing check). The raw
transcripts are not committed; the live run's key lines are quoted below.

## Command

```bash
PYTHONPATH=src:. python3 tools/learn_recommend_cycle.py \
  --agent codex --wall 150 -o evidence/qualification/learn_cycle_live.json
```

## Result (live run)

| Step | Observation |
| --- | --- |
| Dev task 1 (`task-money`), real Codex | `pass`, signed receipt `7f0ad057…` |
| Dev task 2 (`task-money2`), same class | `pass`, signed receipt `1c7d0e92…` |
| Episode → candidate → promotion | procedure `exp-exp-money`, `qualified`, cites both receipts |
| Same-class holdout (`task-money3`) | `recommend`, procedure `exp-exp-money` |
| Cross-class control (`task-slug2`) | `abstain`, `precondition_failed` |
| Holdout without guidance | `fail`, `no_action: true`, receipt `2b59bf35…` |
| Holdout with learned guidance | `pass`, `no_action: false`, receipt `20e97584…` |

The baseline transcript ends:

> Source left unchanged; no tests created.

The served transcript ends:

```diff
+from decimal import Decimal, ROUND_HALF_UP, localcontext
+
+
 def format_amount(x):
-    return f'{float(x):.2f}'
+    with localcontext() as context:
+        context.rounding = ROUND_HALF_UP
+        return format(Decimal(str(x)), '.2f')
```

The private test asserts `format_amount('1.005') == '1.01'`; half-up
passes, half-even fails. In this instance the baseline **declined to
guess** rather than guessing wrong. `no_action` records that distinction
from the receipt's evaluated tree, so a refusal is never reported as a
wrong attempt.

## Mechanism

- `experience_to_record` keys the learned procedure to a **failure
  class** (`convention_unknown:money`), not the dev task's own signature.
  Before this, every real campaign bound the procedure to `sig-money`
  while holdout requests carried `money2`/`slug2`, so the qualified arm
  could never match.
- The failure class comes from the **evaluator's task registry**
  (`OutcomeVerifier.failure_class_for`). It is bound into the task
  commitment, persisted, and signed into each outcome receipt as an
  optional field.
- Receipts omit the field from their canonical form when absent, so
  receipts signed before it existed keep their exact digests and
  signatures.
- Both transfer witnesses are same-class dev runs and both are cited by
  the qualified revision. The grant authority runs with
  `require_cited_evidence=True`; a witness must either carry the
  procedure's failure class or be cited by the revision. A mismatched
  class is rejected with `evidence_class_mismatch`; an uncited legacy
  witness with `evidence_not_cited_by_procedure`.

## What this establishes

- The end-to-end path executes with a real agent: verified episode →
  candidate → signed qualification → scoped serving → `recommend`.
- The learned procedure is reachable on a sibling task and is *not*
  reachable on a different failure class.
- The grant's transfer evidence is same-class, carries the procedure's
  signed failure class, and is cited by the procedure it authorizes.

## What this does not establish

- **No efficacy claim.** n = 1 per condition. Codex is stochastic; one
  paired observation proves the mechanism, not a solve-rate effect. A
  powered, repository-disjoint, preregistered study is still required.
- The lesson is **supervised capture**, not inference: the dev task's
  statement carries the convention, and the harness records it after the
  agent's verified pass. SIS did not discover the convention from the diff.
- The failure class is **declared by the fixture at task registration**.
  The learning path consumes it from the evaluator registry, and
  `experience_to_record` refuses to relabel a record whose
  `failure_category` differs, but a class that is too broad is still a
  generalization risk the retrieval gates cannot detect. The cross-class
  control tests one boundary only.
- The strict grant check binds *class and citation*, not *causal
  relevance*: the witnesses are agent outcomes on same-class tasks, not
  executions of the procedure itself.
- The registry still has no submission-identity concept, so each
  evaluated tree is registered as a separate `<repo>-evaluated` identity
  rather than overwriting the repository's base tree.
- Isolation is `unverified_local`; nothing here qualifies a production
  sandbox.
- Codex CLI 0.156.1, model `gpt-6-astra`, `-s workspace-write
  --skip-git-repo-check`. Dev prompts include the convention; the holdout
  prompt deliberately omits it.
