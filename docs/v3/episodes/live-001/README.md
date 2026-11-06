# Live episode 001 — real Codex CLI contact, quota-limited turn

Status: **real backend contact; agent turn failed on account quota; evidence
pipeline verified end-to-end.**

- `episode.jsonl` — append-only event log captured from `codex exec --json`
  (codex-cli 0.156.1, ChatGPT auth) inside a disposable copy of
  `examples/v3/fixtures/buggy_calc`. Five chained events:
  `thread.started → turn.started → error → turn.failed → sis/process_exit(1)`.
- `head_anchor.json` — exported ledger head (`anchor_head`).
- `evaluator_public.key` — the evaluator's throwaway public key for this run.
  The seed stayed under evaluator custody in `/tmp` (mode 0600) and is not
  committed.
- `receipts.jsonl` — the evaluator journal entry.

## Outcome

The backend replied: `You've hit your usage limit ... try again at 8:36 PM`.
The agent made no edits; the still-buggy tree was evaluated and the
independent verifier correctly signed `outcome: "fail"`. Offline signature
verification with the exported public key passed at run time.

This proves the M1 plumbing — real adapter events, chained storage,
evaluator-side hidden-test injection, signed receipt — while honestly showing
a failed agent attempt, not a solved task. A *passing* live episode requires
account quota and remains an open gate.
