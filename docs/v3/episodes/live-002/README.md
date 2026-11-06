# Live episode 002 — PASSING Codex task, independently verified

Status: **a real coding task completed end-to-end and was independently
verified — the M1 gate item.**

- `episode.jsonl` — 16 chained events from `codex exec --json` (codex-cli
  0.156.1, ChatGPT auth) in a disposable copy of
  `examples/v3/fixtures/buggy_calc`: reads, a failed command (exit 128), a
  `file_change` edit, a verification run (exit 0), `turn.completed` with real
  token usage (input 81327, output ~34, cached 72192), clean process exit.
- `head_anchor.json` — exported ledger head.
- `evaluator_public.key` — throwaway evaluator public key for this run; the
  seed stayed under 0600 evaluator custody in `/tmp`.
- `receipts.jsonl` — evaluator journal entry.
- `outcome_receipt.json` — the full signed `OutcomeReceiptV1`
  (`outcome: "pass"`), verifiable offline with the public key above:
  `verify_receipt_signature(receipt, public_key_hex)`.

## What Codex did

Found the docstring contract violation in `percentage(part, whole)` and
applied the minimal fix `return part / whole` → `return part / whole * 100`,
then ran a check command successfully. The evaluator injected the hidden
`acceptance_hidden.py` suite into a fresh workspace and scored `pass`.

## Honest scope

One solved task proves the pipeline, not lift. The task was small and the
prompt narrow; this is evidence that capture→storage→independent evaluation
works on a real agent, not that SIS improves outcomes.
