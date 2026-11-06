# Upgrade guide for the reviewed v2.4.0 source

> **Historical.** This guide describes the v2.4.0 source line. The current
> package version is 3.3.2; see `docs/v3/MIGRATION.md` and
> `docs/V332_OPERATIONS.md` for the current upgrade path.

This guide covers the repository updates made after the v2.4.0 review. The Python package version remains `2.4.0`; the changes harden evaluation custody, improve task instructions sent to model arms, and make release verification stricter.

## Before upgrading

- Back up the SIS registry database and evaluator vaults. Keep evaluator vaults and HMAC keys in an evaluator-controlled account and directory.
- Preserve old signed datasets, protocols, receipts, and training exports as historical evidence. Do not edit old signed artifacts to make them match the newer formats.
- Pull the repository update and reinstall the local package if it was installed in editable or wheel form:

  ```bash
  git pull --ff-only
  python3 -m pip install -e .
  ```

The core SIS registry database does not require a schema migration for these updates. Existing evaluation artifacts remain historical records; regenerate and sign artifacts when using the updated evaluation formats.

## Evaluation format changes

### Family evaluation

Family datasets now use `sis.family_dataset.v2` and require a plain-language `task_description`. The description is included in each model arm's prompt and bound into the signed protocol. Family v1 datasets and protocols are rejected by the updated evaluator; create a new v2 dataset and precommitment rather than changing a signed v1 artifact.

### Neural comparison and distillation

Neural comparison datasets now require `task_description`, which is included with each unlabeled input sent to the model arms. Neural comparison reports use format v2. New distillation exports use `sis.skill_distillation.v2`; their signed manifests and training rows bind the task description. Regenerate exports from a qualified evaluation before training with the updated validator.

### Procedural skill holdouts

The skill holdout protocol still accepts legacy private datasets without `task_description` and supplies a generic default. New datasets should include a specific description so evaluation prompts and distillation records state the intended transformation.

## Evaluator vault storage

All evaluator SQLite vaults now require private storage:

- On POSIX, the vault file is created with mode `0600`; its parent directory must deny group and other access. Create a dedicated directory with `mkdir -m 700 evaluator-vault` and keep the vault inside it. Existing shared directories or vault files with broad permissions are rejected.
- On Windows, the vault file receives a protected ACL for the current user and SYSTEM. The parent directory ACL is checked for broad principals. Use a dedicated evaluator directory that candidate accounts cannot access.

The vault remains unencrypted, and filesystem checks cannot protect it from an administrator or a process running as the evaluator account. Continue to protect the HMAC key and preserve backups outside candidate-controlled environments.

## Recovering a committed evaluation receipt

The v1.4 evaluator CLI now provides `eval-recover`. If scoring committed a receipt to the vault but writing the output file failed, recover it without scoring the evaluation again:

```bash
sis eval-recover public.json \
  --vault evaluator-vault/private.sqlite3 \
  --receipt recovered-receipt.json
```

The command verifies the stored receipt against the public manifest and vault, and refuses to overwrite an existing output file. It cannot recover a receipt until scoring has committed one.

## Verify the updated checkout

From the repository root:

```bash
python3 tools/check_source_manifest.py
PYTHONPATH=src python3 -m unittest discover -s tests
PYTHONPATH=src python3 tools/smoke_integration.py
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v2.4.0.zip
```

The release verifier checks the ZIP inventory, manifest, member paths, duplicate entries, symlinks, and bounded compressed and uncompressed sizes. Its SHA-256 manifest detects changes against a known authentic archive; it is not a publisher signature.
