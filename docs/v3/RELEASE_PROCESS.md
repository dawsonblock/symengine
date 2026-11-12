# Release process

Status date: 2026-11-11. This document records how SIS versions are cut,
sealed, tagged and verified. It describes the existing practice; it does
not introduce a new policy.

## Branches and versions

- `main` is the default branch. It moves by pull request from a
  `repair/*` or feature branch, never by direct commit.
- Development happens on a long-lived branch (currently
  `repair/v335-resource-security`). The branch carries the sealed
  release artifacts for every version it contains, so it can lag behind
  or run ahead of `main` while a repair line is open.
- A repair keeps the package version. `pyproject.toml` and
  `src/sis/__init__.py` are only bumped when a new minor or patch line
  starts, not for a post-seal repair of the same line.
- Every repair adds a numbered entry to `CHANGELOG.md` (`V338-05`,
  `V338-06`, …) and, where the behavior changes, an operator-facing
  section to `UPGRADE_README.md`.

## Tags

Each sealed release gets one annotated tag on its **seal commit**:

```bash
git tag -a SIS-v3.3.8 <seal-commit> -m "SIS v3.3.8 release seal"
git push origin SIS-v3.3.8
```

The tag name matches the release artifact name (`release/SIS-v3.3.8.zip`,
`release/release_manifest.json` → `release`). Re-seals of the same
version move the tag to the newest seal commit; tags are never rewritten
to point at a different version.

## The seal ritual

`release/` holds provenance about the archive, not payload. The archive
itself is out-of-band (`release/*.zip` is git-ignored).

1. Land every source change and make sure the tree is clean.
2. Run the full suite in the documented environment and record the exact
   counts.
3. Build the archive and provenance from that commit:

   ```bash
   PYTHONPATH=src:. python3 tools/package_release.py \
     --status ENGINEERING_VERIFIED \
     --passed 1381 --skipped 28 --failed 0
   ```

   The tool refuses a dirty tree, re-hashes every member against the tree
   it came from, and records the exact Git commit as `source_commit`.
4. Commit only the generated provenance:

   ```bash
   git commit -am "Seal SIS-v3.3.8"
   ```

5. Verify:

   ```bash
   PYTHONPATH=src python3 tools/verify_release.py --compile .
   PYTHONPATH=src python3 tools/verify_release.py release/SIS-v3.3.8.zip
   PYTHONPATH=src:. python3 tools/check_release_ci.py --mode development
   ```

## Why a doc change forces a re-seal

`release/release_manifest.json` records the commit every manifest-covered
file is byte-identical to. `tests/v3/test_v333_trust_boundary.py` checks
that no manifest-covered file differs between `source_commit` and `HEAD`,
and `tools/verify_release.py` checks the working tree against
`RELEASE_SHA256.json`. Any edit to a source, test, doc, tool or config
file therefore invalidates the seal until `package_release.py` runs
again. That is intentional: a release claim must name the exact bytes it
covers.

## Test environment

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 \
PYTHONPATH=src:. python3 -m pytest tests/ -q
```

- The three environment variables are part of the recorded command; CI
  sets the same ones.
- The Docker integration tests need a usable daemon and the
  `sis-evaluator:<version>` image. `_docker_ready()` probes for both and
  for the ability to create a container; when any is missing the class
  skips rather than fails, so the recorded skip count depends on the
  sealing environment.
- PostgreSQL replay tests skip without `SIS_POSTGRES_DSN`; the dedicated
  CI job supplies one and is the qualifying run for that profile.

## Static gate

`pyproject.toml` pins Ruff with `select = ["E9", "F"]` over `src`. The CI
`lint` job runs `ruff check src` and `compileall` over `src`, `tests` and
`tools`. Style rules are deliberately not enforced yet.

## Coverage

Measured 2026-11-11 on the repair tree, not gated:

```bash
python3 -m coverage run --source=src -m pytest tests/ -q
python3 -m coverage report
```

17,661 statements, 81% covered. There is no coverage floor in CI yet; a
floor should only be added once the Docker image is available to the
runner, otherwise the integration-covered paths make the number move for
environmental reasons.

## Known gaps

- No type checking (`mypy`) gate. `src/sis/v3` has no annotations policy
  beyond what individual modules chose.
- No coverage floor.
- The Linux rootless worker is exercised only where bubblewrap and a
  cgroup v2 hierarchy exist; the cgroup tests skip elsewhere.
- Windows remains experimental in CI (`continue-on-error`).
