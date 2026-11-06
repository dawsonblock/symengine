# SIS v3.3 Architecture — Governed Learning

v3.3 adds a governed learning plane to the v3.2 authority-integrity
baseline. Three learning tracks feed one typed candidate registry; one
governed promotion boundary decides what may serve; one composition
policy merges what serves.

## Trust plane map

```
untrusted/agent side                 trusted side
--------------------                 --------------------------
coding agent (Codex/scripted)   -->  OutcomeVerifier  (signed receipts,
runner / executor               -->   statement-bound registration)
                                      |
ExperienceRecordV1  --[learner]-->    MemoryStore     (dedup, tamper-proof)
SkillOptimizer      --[learner]-->    CandidateRegistry (PROPOSED only)
ingest_skills.py    --[learner]-->    CandidateRegistry (PROPOSED only)
                                      |
                                  EVALUATING --[evaluator]--> dev/holdout
                                  receipts + CandidateEvidenceV1
                                  (binds receipts to the exact candidate)
                                      |
                                  CandidateDecisionV1 --[operator]--> QUALIFIED
                                  (binds the exact serving-state edge)
                                      |
                           GovernedServingGateway
                           (re-derives state from the audit chain;
                            re-authenticates decision + evidence;
                            scope + revocation + applicability +
                            counterexample + composition budget)
                                      |
                           GuidanceV1 advisory channel --> agent
```

## Components

| module | role |
|---|---|
| `candidates.py` | `CandidateRegistry`: WAL sqlite, role-gated state machine, append-only transition audit, digest-verified reads, signed-evidence/decision-gated serving state, audit-derived state projection, verified pre-migration chain reseal (recorded in `registry_migration`) |
| `candidate_authority.py` | `CandidateEvidenceAuthority` (evaluator-signed receipt→candidate binding) and `CandidateDecisionAuthority` (operator-signed exact-edge decision), both Ed25519 |
| `contracts.py` | `CandidateV1`, `CandidateEvidenceV1`, `CandidateDecisionV1`, `ExperienceRecordV1` records (canonical digests, bounded validation) |
| `memory.py` | `MemoryStore` (episode dedup, outcome index), `induce_candidate`, `retrieve_memories` (gates + abstention) |
| `evolution.py` | `SkillOptimizer`, pure-payload mutators, `Frontier`, `EvolutionBudget`; dev-eval via injected `EvaluationClient` |
| `composition.py` | `compose_guidance`: precedence by type, dedup, polarity conflicts, token budget, abstain |
| `governed_eval.py` | `EvaluationPartition` + sealed-holdout disjointness, `preregister`, `required_sample_size`, `compute_metrics`, `run_governed_evaluation` (5 arms), `run_candidate_probe` (per-candidate qualification probe under the same gates) |
| `serving.py` | `GovernedServingGateway`: registry-authenticated repo identity, per-candidate rejection audit, serve-time decision/evidence re-authentication, authenticated outcomes, advisory-only serving |
| `skill_package.py` | vskill-style bundles: manifest + payload + SHA256SUMS, `export_bundle`/`verify_install`/`import_bundle`/`security_scan` |
| `skill_ingest.py` | real skill directories (`SKILL.md` + resources) → bounded `CandidateV1` at PROPOSED; traversal/symlink/size limits, advisory scan |
| `tools/governed_campaign.py` | deterministic end-to-end campaign CLI (M9) |
| `tools/ingest_skills.py` | ingest a skill directory/tree/bundle into a candidate registry at PROPOSED (M10) |
| `tools/skill_holdout.py` | worked holdout examples: ingest → probe (E vs A) → signed qualification → serve (M10) |
| `tools/skill_holdouts.py` | holdout registry: worked examples, planned tiers, excluded skills with reasons (M10) |

## Learning tracks

- **A — symbolic induction** (existing `learning/`): verified source changes
  to bounded procedures; unchanged.
- **B — experience memory**: verified episodes to `ExperienceRecordV1` to
  `experience_memory` candidates. Facts and hypotheses stay separated;
  hypotheses never become causal truth without evaluation.
- **C — skill evolution**: pure-function payload mutations evaluated by an
  injected dev-set client under a hard evaluation budget; output is
  PROPOSED candidates only.

## Invariants

1. Candidate generation never confers promotion authority —
   `proposed→validated` is `candidate:write` (learner); `evaluating→qualified`
   is `promotion:approve` (operator) and requires three independent signed
   artifacts: an authenticated pass receipt, an evaluator-signed
   `CandidateEvidenceV1` that binds those receipts to *this* candidate's
   record/content digest on the holdout partition under the expected
   protocol, and an operator-signed `CandidateDecisionV1` for the exact
   edge. `qualified→revoked` requires its own decision. The registry
   requires deployment-supplied `receipt_authority`, `evidence_authority`
   and `decision_authority`; without them qualification/revocation is
   refused. Candidate generators hold none of these keys.
2. Receipts are the only outcome evidence handle; a receipt alone is not
   a qualification handle. Evidence must name the candidate it qualifies.
3. Learner/optimizer hold no signing keys and no authority-DB access.
4. Served text is data: delivered through `helpful_next_checks`, it can
   describe an action but cannot grant one.
5. Serving state is decision-backed, never a column. The registry folds
   the hash-chained transition log, requires the committed state column
   to match, and re-authenticates the decision and evidence behind every
   qualified candidate on every serve. A direct state flip or forged
   artifact abstains with `catalog_unavailable`; a missing artifact row
   or legacy qualification is excluded from serving without freezing the
   catalog, so a signed takedown still works. The evaluation protocol is
   pinned: a registry without it can neither qualify nor serve.
6. Promotion supports audit, revocation, rollback (`qualified→revoked` is
   terminal-audited; audit rows are append-only in the same transaction).
7. The qualification holdout is sealed: no shared `repo_snapshot_digest`
   with induction/development; enforced, not assumed.
8. Serving outcomes bind an authenticated receipt for the same task and
   outcome to the exact delivered guidance digest.
