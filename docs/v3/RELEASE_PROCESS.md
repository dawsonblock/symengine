# Release process

Status date: 2026-11-19. This document records how SIS versions are cut,
sealed, tagged and verified. It describes the existing practice, plus
the isolation re-attestation policy added on 2026-11-19 (SIS-FEAT-16).

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
git tag -a SIS-v3.3.9 <seal-commit> -m "SIS v3.3.9 release seal"
git push origin SIS-v3.3.9
```

The tag name matches the release artifact name (`release/SIS-v3.3.9.zip`,
`release/release_manifest.json` → `release`). Re-seals of the same
version move the tag to the newest seal commit; tags are never rewritten
to point at a different version.

## The seal ritual

`release/` holds provenance about the archive, not payload. The archive
itself is out-of-band (`release/*.zip` is git-ignored). A top-level
`.claude/` is local agent state (Claude Code worktrees and
`settings.local.json`) and is never inventoried or archived, even though
`git status` does not show it.

Release signing requires the constant-time Ed25519 backend. Install it
in the sealing environment first:

```bash
pip install -e .[production]   # pins cryptography
```

`package_release.py --provenance-key` and `check_release_ci.py --mode
release` refuse to run on the vendored pure-Python fallback, whose
scalar arithmetic is not constant-time, and say so; the seal exits
before it writes or builds anything. `requirements-lock.txt` does not
include `cryptography`, so the test suite keeps exercising the
fallback.

1. Land every source change and make sure the tree is clean. Then
   review every difference from the previous seal:

   ```bash
   python3 tools/reconcile_inventory.py \
     --markdown /tmp/sis-reconciliation.md --json /tmp/sis-reconciliation.json
   ```

   It classifies each path as unchanged, modified, missing or extra
   against `RELEASE_SHA256.json`, attributes every change to the
   commits (and PR merges) since the seal commit, and exits non-zero
   if any file is unattributed. Pass `--tree DIR` to check an
   extracted download instead of the checkout. Read the report
   before you rehash: drift you cannot attribute is not sealed.
2. Run the supported suite and write signed machine-readable evidence:

   ```bash
   PYTHONPATH=src python3 tools/run_tests.py \
     --json /tmp/sis-test-report.json \
     --signing-key /secure/ci-test-seed.hex \
     --key-id ci-test-runner
   ```

   Keep the evidence outside the tree: an in-tree file would make the
   working tree dirty before `package_release.py` runs. The runner
   refuses a pytest version other than the pin in
   `requirements-lock.txt`, and the evidence names the commit, command,
   exit status, output digest and parsed counts.
3. Produce the raw isolation evidence on a Linux host with gVisor
   (`runsc`) registered with Docker (see the `sandbox-qualification` CI
   job). The evaluator image must be digest-pinned; the receipt and
   signed attestation must describe the exact image and policy:

   ```bash
   PYTHONPATH=src python3 tools/probe_docker_sandbox.py \
     --image sis-evaluator:3.3.9@sha256:<digest>
   PYTHONPATH=src python3 tools/redteam_sandbox.py \
     --image sis-evaluator:3.3.9@sha256:<digest> \
     --output evidence/sandbox/redteam_report.json
   PYTHONPATH=src python3 tools/qualify_docker_isolation.py \
     --image sis-evaluator:3.3.9@sha256:<digest> \
     --probe-report evidence/sandbox/docker_sandbox_probe.json \
     --redteam-report evidence/sandbox/redteam_report.json \
     --output evidence/sandbox/gate2_isolation
   ```

   The stored `gate2-local-isolator` key is qualification-only. For a
   production seal, hand `receipt.json` and `policy.json` to the
   independent isolator and use the attestation it returns (see
   "Isolation re-attestation policy" below).
4. Build the archive and provenance from that commit:

   ```bash
   PYTHONPATH=src:. python3 tools/package_release.py \
     --status ENGINEERING_VERIFIED \
     --test-evidence /tmp/sis-test-report.json \
     --require-test-evidence \
     --require-signed-test-evidence \
     --test-evidence-public-key /secure/ci-test-public.hex \
     --test-evidence-key-id ci-test-runner \
     --provenance-key /secure/release-seed.hex \
     --provenance-trust-root production \
     --isolation-receipt evidence/sandbox/gate2_isolation/receipt.json \
     --isolation-attestation evidence/sandbox/gate2_isolation/attestation.json \
     --isolator-public-key /secure/isolator-public.hex \
     --isolation-image-digest <digest> \
     --isolation-policy-digest <digest> \
     --isolation-property net:denied \
     --isolation-property fs:root_read_only \
     --isolation-property fs:workspace_confined \
     --isolation-property user:non_root \
     --isolation-property caps:dropped \
     --isolation-property proc:no_new_privileges \
     --isolation-property limits:memory \
     --isolation-property limits:pids \
     --isolation-property limits:disk \
     --isolation-property limits:cpu_time \
     --isolation-property output:capped \
     --isolation-property kernel:gvisor \
     --isolation-property syscalls:seccomp_allowlist \
     --require-external-attestation
   ```

   The tool refuses a dirty tree, re-hashes every member against the tree
   it came from, and records the exact Git commit as `source_commit`. It
   writes `release/test_evidence.json`, `release/isolation_receipt.json`,
   `release/isolation_attestation.json`,
   `release/isolation_verification.json` and regenerates
   `release/README.md` from `release_manifest.json`.
5. Commit only the generated provenance:

   ```bash
   git commit -am "Seal SIS-v3.3.9"
   ```

6. Verify:

   ```bash
   PYTHONPATH=src python3 tools/verify_release.py --compile .
   PYTHONPATH=src python3 tools/verify_release.py --source . \
     release/SIS-v3.3.9.zip
   PYTHONPATH=src:. python3 tools/check_release_ci.py --mode development
   PYTHONPATH=src:. python3 tools/check_release_ci.py --mode release \
     --release-public-key /secure/release-public.hex \
     --test-evidence-public-key /secure/ci-test-public.hex \
     --isolator-public-key /secure/isolator-public.hex \
     --isolation-image-digest <digest> \
     --isolation-policy-digest <digest> \
     --isolation-property net:denied \
     --isolation-property fs:root_read_only \
     --isolation-property fs:workspace_confined \
     --isolation-property user:non_root \
     --isolation-property caps:dropped \
     --isolation-property proc:no_new_privileges \
     --isolation-property limits:memory \
     --isolation-property limits:pids \
     --isolation-property limits:disk \
     --isolation-property limits:cpu_time \
     --isolation-property output:capped \
     --isolation-property kernel:gvisor \
     --isolation-property syscalls:seccomp_allowlist
   ```

   The release gate refuses a property set that omits any entry of
   `sis.v3.docker_sandbox.PRODUCTION_PROPERTIES`, including
   `kernel:gvisor` and `syscalls:seccomp_allowlist`; in CI the set comes
   from the `SIS_ISOLATION_PROPERTIES` variable (comma-separated).

   Release mode refuses an environment without the constant-time
   signing backend, a missing release manifest or ZIP, a stale
   source binding, a duplicate/unexpected/modified archive member, an
   unsigned or non-production provenance envelope, an unsigned or
   inconsistent test report, a missing or expired isolation attestation,
   a receipt from another execution, or an image/policy mismatch. The
   public keys come from the relying party; a key shipped beside the
   artifact is not its own trust anchor.

## Isolation re-attestation policy

An isolation attestation describes one execution receipt, and the
production policy accepts it for at most one hour after issue
(`ProductionIsolationPolicy.max_attestation_age_seconds = 3600`, also the
default of `--isolation-max-age-seconds`). Its `expires_at` must be set
and must not have passed. An attestation is therefore never carried from
one release to the next:

- **Re-attest per release.** Every seal, and every re-seal of the same
  version, needs a fresh receipt from the pinned image and a fresh
  attestation from the independent isolator, issued within the hour
  before `package_release.py` and `check_release_ci.py --mode release`
  run.
- **Re-attest on any change to the launch.** A new image digest, a change
  to `docker/sandbox/seccomp.json`, the runtime or any executor launch
  flag changes the policy digest (`DockerSandboxExecutor.policy_digest()`)
  and invalidates every earlier attestation. Update
  `SIS_ISOLATION_IMAGE_DIGEST` and `SIS_ISOLATION_POLICY_DIGEST` to the
  new values first; the isolator signs only a policy it has seen
  (`policy.json`).
- **Maximum age.** Do not raise `--isolation-max-age-seconds` above 3600
  for a release. A longer window only helps a stale attestation pass.
- **Key rotation.** A new isolator key is accepted only after the
  fingerprint ritual in
  [SANDBOX_QUALIFICATION_GATE2.md](SANDBOX_QUALIFICATION_GATE2.md#isolator-key-custody-and-fingerprint-check).
  A key that may have been exposed is revoked (removed from
  `SIS_ISOLATOR_PUBLIC_KEY`) before the next release, and attestations it
  signed are not reused.
- **CI evidence is not attestation.** The `sandbox-qualification` job
  re-runs the probe, red-team suite and qualification on every push with
  a generated, qualification-only key. It shows whether the executor
  still behaves as qualified; it is never a substitute for the isolator's
  signature.

## Why a doc change forces a re-seal

`release/release_manifest.json` records the commit every manifest-covered
file is byte-identical to. `tests/v3/test_v333_trust_boundary.py` checks
that no manifest-covered file differs between `source_commit` and `HEAD`,
and `tools/verify_release.py` checks the working tree against
`RELEASE_SHA256.json`. Any edit to a source, test, doc, tool or config
file therefore invalidates the seal until `package_release.py` runs
again. That is intentional: a release claim must name the exact bytes it
covers.

## Release CI

The strict gate runs on tags and published releases, and `release/*.zip`
is git-ignored, so a fresh checkout has no archive for it to verify. The
`tests` job therefore provisions the archive before the gate:

1. a local `release/SIS-*.zip` is used if present (operator-supplied or
   restored from cache);
2. otherwise `gh release download <tag> --pattern 'SIS-*.zip'` fetches
   the asset attached to that release.

Nothing downloaded is trusted: `check_release_ci.py --mode release`
re-hashes the archive against `release/release_manifest.json`, checks
the source binding and re-verifies the signed provenance. A missing
archive fails with an explicit error naming the tag.

The suite runs first, on the vendored signing fallback from
`requirements-lock.txt`; the job then installs `.[production]` and only
then calls the gate, which refuses to qualify a release without the
constant-time backend.

The gate's trust anchors come from repository configuration
(`secrets.SIS_RELEASE_PUBLIC_KEY`, `secrets.SIS_TEST_EVIDENCE_PUBLIC_KEY`,
`secrets.SIS_ISOLATOR_PUBLIC_KEY`, `vars.SIS_ISOLATION_IMAGE_DIGEST`,
`vars.SIS_ISOLATION_POLICY_DIGEST`, `vars.SIS_ISOLATION_PROPERTIES`).
They are deliberately invisible to the workflow file, so an IDE schema
validator reports each reference as "context access might be invalid";
that warning is expected. The job checks all six before calling the
gate and fails with one error naming every missing anchor. The
release-only `test-evidence` job likewise fails with an explicit error
when `SIS_TEST_EVIDENCE_SIGNING_KEY` is absent rather than uploading an
unsigned report the seal cannot use.

The `archive` job runs on every push and pull request. It builds the
canonical source archive with `tools/build_canonical_zip.py` from a
scratch worktree (the committed seal is never rewritten), extracts it
into an empty directory, verifies the extracted tree against its own
inventory, installs from it and runs the suite there with no Git
checkout behind it. A file the archive omits but a test needs fails
that job rather than a downloaded release.

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
- `requirements-lock.txt` leaves `cryptography` out, so the suite runs
  on the vendored Ed25519 fallback. There the `OutcomeReceiptV2` and
  release-gate tests lift only the constant-time guard, the tests that
  sign with `cryptography` skip, and the tests of the refusal force the
  fallback and run everywhere.

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
