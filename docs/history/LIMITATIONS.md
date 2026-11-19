# Capability and evidence limits

> These limits describe the v1/v2 rule grammar. For v3 limits — evaluator
> isolation, real-agent efficacy and multi-host PostgreSQL — see
> `docs/V332_EFFICACY_STATUS.md` and `docs/history/v3/V33_LIMITATIONS.md`.

- The deterministic enumerator (learner v2) covers a declared space: typed pool programs up to cost 7 and depth 3,
  goal-directed completions up to depth 4, exact small-integer affine fits over at most three features, and
  **one-level** conditionals (`if_lt`/`if_eq` on leaves and observed constants). It is not universal program
  synthesis; nested conditionals, loops and real-valued fitting are out of scope.
- Rivals count toward ambiguity only within a cost margin (4) of the selected rule, so a much costlier rule that also
  fits every labelled row is not reported. A threshold that the data does not pin down is reported ambiguous rather
  than guessed.
- Only integers, booleans, short strings and fixed-size input lists; no vectors, images, time series, probabilities,
  continuous numeric fitting, or open-world relationships.
- Search is bounded and explicitly labeled incomplete if budget exhausted. Even when complete for this grammar/stage, an
  unknown rule outside the grammar might also fit.
- Synthetic input probes detect some ambiguous candidates, not all. Probe agreement does not imply candidate equivalence
  in general.
- Local validation may be tiny or biased. No external independent holdout or causal verification is included.
- The persistence layer tracks symbolic rules; it does NOT update neural model weights, do gradient descent, provide
  episodic semantic memory of arbitrary dialogues, or guarantee transfer.
- LLM-generated rules are constrained by the grammar, and unsupported suggestions are rejected. External LLM output may
  be wrong or malicious.
- Web server is a prototype with loopback-only default and optional shared key, not a public multiuser production
  runtime.
- Z3 is an optional extra and was not assumed installed for the release's core test result. It checks bounded formula
  disagreement and never the task's external truth.

Claims this prototype does **not** make: 'works with every proprietary model out of the box', 'general intelligence',
'production-ready', 'cryptographically independent evidence', 'formal proof of discovered facts', or 'learning without
ground truth'.


## v1.7 procedural-skill subsystem

See [V1_7_PROCEDURAL_SKILLS.md](V1_7_PROCEDURAL_SKILLS.md) for architecture, verification boundary, threat model and
explicit limitations. The procedural skill chain is local integrity evidence, not a separately anchored cryptographic
attestation.
