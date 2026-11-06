# v1.4: Custodian-controlled one-use evaluation

## Threat model and trust assumptions

This harness is for experimental rule induction and *separation of evaluation ownership*. It does not certify learned reasoning, LLM general intelligence, independent peer review, secure enclaves, or permanent protection from an operator with full system access.

The **candidate** receives only `public.json` containing training labels, validation labels, schema and a keyed commitment to private tests. The **evaluator custodian** controls the private dataset, SQLite vault, `SIS_EVAL_HMAC_KEY`, and scoring/verification commands. The candidate is never given the private vault or secret. Public private-test commitments are *keyed HMACs*, not ordinary SHA-256 hashes susceptible to brute-force enumeration over small discrete answer spaces.

Under this split, the evaluator can score a candidate once and report **aggregate counts only**. The vault's local SQLite transaction (`BEGIN IMMEDIATE`) prevents two concurrent successful scores against the same sealed evaluation ID. Duplicated input samples within a dataset or within the same vault are rejected, even across separate tasks. Only ASTs agreeing with all public train/validation outputs are admissible. A rejected invalid candidate does not consume the private test.

## What this does NOT guarantee

- A developer who can read, overwrite, copy, restore, or replace the SQLite vault, **or knows the HMAC key**, can inspect labels or reset one-use status. The vault does not implement hardware isolation, secure remote attestations, outside time-stamping, or rollback-resistant monotonic counters.
- Sealing a locally generated or publicly known dataset cannot make the test independently generated. An external evaluator must generate and hold the test data *before* candidate optimization, and must control the custody boundary.
- HMAC receipts authenticate an evaluator-key holder's claim. They do not prove that a custodian is independent, that ground truth is accurate, or that the candidate never saw the original test elsewhere.
- A small test may leak information through released aggregate metrics. Only one admissible submission is allowed per evaluation ID; a custodian must not create replacement tasks containing the same test labels after seeing results.
- Split disjointness checks are by **input identity**, not by task template, rule family, or semantic overlap. Shifted inputs test value-range extrapolation, not unseen compositional tasks.
- Private datasets are stored **unencrypted** on the evaluator filesystem. Use an isolated evaluator machine or account, restrictive storage ACLs, encryption at rest, operator-controlled offsite receipts, and proper backups for consequential evaluations.
- Vault storage must be in a private directory. On POSIX, the vault file is created with mode `0600` and its parent directory must deny group/other access; on Windows, the vault file receives a protected ACL for the current user and SYSTEM, and the parent directory ACL is checked for broad principals before SQLite opens it. Choose a dedicated evaluator directory and do not grant candidate accounts access to it. These checks reduce accidental local exposure but cannot protect against an administrator or an operator who controls the evaluator account.
- Runs can be re-performed with an identical software version, but that does not by itself constitute independent reproduction.

## Dataset and submission contracts

Dataset (never send to candidate):

```json
{
  "namespace": "arith",
  "task_id": "named_task",
  "train": [{"inputs": {"x": 1}, "output": 3}, {"inputs": {"x": 2}, "output": 4}, {"inputs": {"x": 3}, "output": 5}],
  "validation": [{"inputs": {"x": 4}, "output": 6}, {"inputs": {"x": 5}, "output": 7}],
  "test": [{"inputs": {"x": 6}, "output": 8}, {"inputs": {"x": 7}, "output": 9}],
  "shifted_test": [{"inputs": {"x": -100}, "output": -98}, {"inputs": {"x": 1000}, "output": 1002}]
}
```

All partitions require exactly matching schemas, exact output types, and unique input records. `shifted_test` can be omitted or include at least two examples.

Candidate submission:

```json
{
  "evaluation_id": "copied-verbatim-from-public-task",
  "public_digest": "sha256-of-entire-public-JSON",
  "rule": {"op":"add","args":[{"op":"field","name":"x"},{"op":"const","value":2}]}
}
```

Use `sis eval-candidate` to generate a concrete submission from the public dataset, or write another AST supported by `sis.expression` with the same binding. The evaluator checks the public study signature and rejects unauthorized changes. The evaluator does not require the candidate to use any particular LLM or induction algorithm.

## Four-step CLI protocol

1. On an evaluator-owned machine, create a private directory for the vault (for example, `mkdir -m 700 evaluator-vault` on POSIX), then run `SIS_EVAL_HMAC_KEY=... sis eval-seal dataset.json public.json --vault evaluator-vault/private.sqlite3`. Never share `dataset.json`, `private.sqlite3`, or the signing secret.
2. Distribute **only `public.json`**. The candidate runs `sis eval-candidate public.json submission.json`, or creates a valid bound candidate through another engine.
3. Receive `submission.json` and score once: `sis eval-score public.json submission.json --vault private.sqlite3 --receipt receipt.json`. The command refuses to overwrite existing receipt files.
   If the score committed to the vault but the receipt file could not be written, recover it with `sis eval-recover public.json --vault private.sqlite3 --receipt recovered-receipt.json`.
4. Archive `receipt.json` outside the candidate-controlled environment, then run `sis eval-verify public.json receipt.json --vault private.sqlite3` to recheck its signature, backing row and private-label scoring.

## Evaluation reporting

Report `test` and `shifted_test` separately: total test cases, answered, correct, wrong, abstentions, coverage, selective accuracy, overall accuracy, and a train-majority baseline computed without access to heldout labels during candidate formation. Record candidate source, LLM and prompt versions, hardware, settings, time and compute budget before unsealing. Do not omit failures or regenerate a new test set based on the observed score. If there is a substantial shift failure, retire/revise the candidate and request a **new** independently generated evaluation.

For independent evidence, ask a trusted external evaluator to provide test data not previously accessible to the system designer, operate the private vault and key, preserve protected audit copies and receipts, and record attempted submissions and dataset provenance outside the repository.
