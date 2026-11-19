# v1.3 upgrade guide

This version extends v1.2 without changing the SQLite schema or the on-disk
record formats. Back up database, HMAC checkpoints, and keys before upgrading.

## Behavior changes

- `SIS_API_KEY` no longer grants HTTP mutation authority. Set a separate
  `SIS_ADMIN_KEY` of at least 24 UTF-8 bytes. Mutation endpoints return HTTP 403
  when read authentication is configured but operator authorization is absent.
- Promotion may now reject a second rule that disagrees with an existing active
  rule under bounded probes. The original rule remains unchanged. Retire the
  earlier rule if an independently reviewed task redefinition requires it.
- `Registry.verify_audit` checks every transition. A previously stored row
  with a syntactically valid but logically inconsistent event replay may now
  fail closed. Investigate and restore an independently verified backup; never
  bypass this check to recover a corrupted rule.
- `Registry.list_rules` now raises `RuleRejected` on unverifiable history.
- Feedback must have the same output type as the interpreter prediction.
- Induction and benchmark matches now require exact output types. This can change
  results for inputs that formerly treated bool and int labels as equal.

## Quick checks

```bash
python3 -m unittest discover -s tests -q
python3 tools/evaluate_fixtures.py
python3 tools/smoke_integration.py
sis --db ./knowledge.sqlite3 audit
sis --db ./knowledge.sqlite3 anchor-verify ./your-preexisting-checkpoint.json
```

The checkpoint is only authoritative when its custody and key were independent
of the registry administrator. No automatic third-party attestation occurs.

## Rollback

Stop the HTTP server, restore the old v1.2 environment and an independently
verified database backup. No v1.3 migration is needed, but data mutated under
v1.3 should not be considered qualified for older verification rules without
revalidation. Do not reuse any exposed bearer tokens.
