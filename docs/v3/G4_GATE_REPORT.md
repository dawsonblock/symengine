# G4 Gate Report — Stage 2 completion (v3.1-alpha)

Scope: PR-05 through PR-08 — execution qualification, trustworthy
source-change capture, evidence-bound induction, and the
observe–learn–verify–reuse composition.

## Evidence

| Item | Result |
|---|---|
| Full test suite | 659 passed, 2 skipped |
| Hard wall-clock enforcement | benchmark arms interrupted at budget (`agent_timeout`) |
| Usage accounting | token/tool meters; agent-reported usage marked UNVERIFIED |
| Codex auth | adapter requires authenticated client probe |
| Source-change capture | all digests computed by capture path; agent-reported digests cannot enter |
| Induction binding | structural induction requires verified SourceChangeV1 + byte-exact contents |
| Strategy evidence | receipt_resolver required in pipeline; unresolved digests rejected |
| Optimization | bounded paired-win selection, evaluator-verified trials only (pre-existing) |
| Evaluation | repo-disjoint assertion + paired D-vs-A summary with preregistered decision rule |
| Release | RELEASE_SHA256.json 257 files; verify_release --compile passes |

## Explicit non-claims

- No efficacy: the D-vs-A decisive paired study has NOT been executed
  against live Codex on a repository-disjoint held-out task set.
- No v4.0 qualification: preregistered efficacy/security criteria are
  unmet by definition until that study runs and passes.
- No production-security claim: local executor remains
  `unverified_local`; custody/attestation hardening is deployment-side.
- Structural induction remains single-operator-AST-only by design.

## Verdict: G4 PASS (engineering stage), efficacy gate OPEN
