# Symbolic Induction Engine — Verified source upgrade

**Packaging status:** Updated full source archive, all baseline directories retained.
**Release designation:** `SIS-2026-10-24-ResearchUpgrade` (not a claimed v4.0 qualification).
**Origin:** `symbolic-engihe-main 3.zip`.

## Added or modified

1. **Release fix**: one canonical `RELEASE_SHA256.json` inside ZIP, no historical
   `SOURCE_SHA256.json` in the ZIP. The historical file remains in the source
   development snapshot but is not required for released-tree verification.
   Canonical builder uses stable timestamps, permissions and archive ordering.
2. **Benchmark validity fix**: a passing evaluator outcome with `budget_exceeded`
   no longer counts as a solve or a paired win. Monotonic fractional elapsed
   time is used for the gate; integer seconds are conservatively rounded up
   for canonical JSON. Usage counters, when available, are checked; the
   runtime remains responsible for hard enforcement and trustworthy metering.
3. **Nonce store**: SQLite transaction makes repeated consumption of an
   evaluator-signed `OutcomeEnvelopeV2` fail across process restarts. The
   original `verify_envelope` remains intentionally read-only.
4. **Strict guidance**: `StrictGuidanceGateway` requires an authentic,
   verified promotion-decision projection. Denies direct-store qualifications,
   stale authority, unknown repository ownership and ungranted cross-namespace
   retrieval. Supports revocation digests and operator kill switch.
5. **Symbolic change induction**: AST single-operator-difference extractor;
   never executes untrusted source and never claims semantic proof.
6. **Contrastive strategic learning**: deterministic intersection of observed
   diagnostic actions on successful independently verified episodes, linked
   to failure examples and provenance.
7. **Bounded candidate optimization**: paired improvement gate with signed,
   independently accepted evaluation flags, budget validity and repository
   lineage identifiers. No autonomous mutation or sealed-holdout access.
8. **Candidate conversion**: typed strategies and structural changes convert
   to `ProcedureRecordV1(status='candidate')`, never to qualified state.
9. **Tests**: extra adversarial regression and integration tests, synthetic
   offline demonstration, updated design and limitations documentation.

## Essential limitations / unresolved qualification gates

- `ProcedureStore.add(...allow_qualified=True)` and legacy `GuidanceGateway`
  remain for backwards-compatible fixtures and are NOT to be exposed to
  untrusted agents or production servers. Only strict guidance was hardened.
- Promotion writes the catalog record and decision journal separately; strict
  serving fails closed on incomplete writes, but crash-safe recovery and fully
  atomic durable promotion are still outstanding.
- Repository lineage remains external trusted data; tree digests are not
  repository identifiers. Cross-repository grants require an explicit trusted
  authorization callback, not request text.
- The original authenticated Codex SDK integration has not been exercised in
  this environment. No real coding-agent improvement has been demonstrated.
- AST operator changes only create proposals; semantic contracts, executable
  isolated tests, and independent holdouts are mandatory before promotion.
- The local subprocess runner is not a hardened sandbox for hostile code.
- Selection still requires a real evaluator to furnish trustworthy trial
  evidence, and repeated validation cannot be mistaken for a sealed holdout.

## Installation and evidence

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python examples/v3/learning_upgrade_demo.py
python tools/verify_release.py /path/to/release.zip
```

The archive is designed for use as a **complete source tree** for continued
engineering, not as an already-qualified autonomous learning product.

## Research implementation strategy

- ReasoningBank-inspired: positive/negative trajectory comparisons.
- EvoSkill-inspired: bounded evaluated candidate selection.
- Skill-V research-inspired: formal applicability/contract aspirations.
- The uploaded `vskill-main.zip` was a different skill-management tool, not
  the academic Skill-V implementation. No source was copied from these
  third-party repositories; they are reference designs only.
