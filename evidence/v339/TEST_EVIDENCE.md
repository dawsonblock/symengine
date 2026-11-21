# Development test evidence for the v3.3.9 line (unsigned)

**Status: unsigned development evidence.** `test_report.json` has no
`signature` and no `signer_key_id`. It is not the signed CI test
evidence a release seal requires: `tools/package_release.py
--test-evidence` and `tools/check_release_ci.py --mode release` accept
only a report signed with the CI Ed25519 key held in repository
secrets, which only the release-only `test-evidence` job produces. The
report does pass `test_evidence.validate_evidence` with no signature
required (clean tree, pinned runner, full `tests/` suite, no extra
pytest arguments, counts re-parsed from the recorded output, output
digest matching); with a signature required it is rejected
("test evidence public key is required for authentication").

## Run

| Item | Value |
| --- | --- |
| Source revision | `f392e22934a5686c44b5d6b1d3891c9944c738ac`, clean (`dirty: false`) |
| Command | `SIS_TEST_AGENT_USER=sisagent PYTHONPATH=src PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONNOUSERSITE=1 python3 tools/run_tests.py --json <scratch>/test_report.json` |
| Recorded runner command | `/usr/local/bin/python3 -m pytest tests/ -q` |
| Exit status | 0 |
| Counts | 2254 passed, 0 failed, 40 skipped, 0 errors (580 s) |
| Python, pytest | CPython 3.13.18; pytest 8.4.2 (the `requirements-lock.txt` pin) |
| Platform | `Linux-6.18.44-fc-v726-x86_64-with-glibc2.39`, run as root |
| Docker | present: daemon 29.10.0, runc; image `sis-evaluator:3.3.9` present |
| Second user | `sisagent` (`SIS_TEST_AGENT_USER`), reached through `sudo -n -u` |
| Output SHA-256 | `7b79d0378c0016716140be1a67850d995f7ab99d00761bf531f8b7513e4cc6db` |

The report was written outside the tree and copied here afterwards, so
`git status` was clean when the runner recorded it. Commits after
`f392e22` add only this evidence and the changelog entry.

## Skip inventory

From `SIS_TEST_AGENT_USER=sisagent PYTHONPATH=src python3 -m pytest
tests -q -p no:cacheprovider -rs` at the same revision, same host, as
root: 2254 passed, 40 skipped, 0 failed. The skipped count equals the
report's; the two runs differ only in the hermetic variables, which
change nothing here (the optional packages live in the system site).

| Class | Skips | Tests and reason |
| --- | ---: | --- |
| Platform: Windows | 3 | `test_v240_review.py:68` Windows ACL; `test_vault_storage.py:268` Windows DACL; `test_vault_storage.py:411` Win32 SID round trip |
| Platform: macOS | 15 | `test_split_custody.py` (10) and `test_evaluation_runtime.py:294,311` (2): seatbelt; `test_darwin_dev_hardening.py:136,175` (2): macOS-only; `test_v336_memory_enforcement.py:341`: only macOS refuses an RLIMIT_AS below usage |
| Platform: non-Linux | 3 | `test_v334_linux_worker.py:189,259,267`: the off-Linux fail-closed paths; on Linux the real filter and backend probe run instead |
| Optional dependency: z3 | 4 | `test_learner_v2.py:96`; `test_v336_benchmark_semantics.py:145,158,174` |
| Optional dependency: PostgreSQL | 8 | `test_control_plane_postgres.py`: `SIS_POSTGRES_DSN` not configured (run separately below) |
| Optional dependency: codex CLI | 1 | `test_build_efficacy_manifest.py:665` |
| Environment: root | 1 | `test_agent_principal.py:500`: root reads a mode-000 file (runs as `sispilot`, below) |
| Environment: host | 1 | `test_v334_linux_worker.py:240`: cgroup v2 is not mounted in this container (v1 hierarchy) |
| Environment: release artifact | 2 | `test_v333_trust_boundary.py:1040,1059`: `release/SIS-v3.3.9.zip` is distributed out of band and not supplied |
| Other | 2 | `test_skill_ingest_hardening.py:313`: the `skills/vskill-main 2` corpus is not in the repository; `test_source_manifest.py:49`: the v2 baseline `daf0ccc` is not in this repository's history |
| **Total** | **40** | |

No Docker-dependent test skipped: with the daemon and image present,
every Docker, split-custody-under-Docker, red-team and agent-principal
integration test ran.

Hidden skips found:

- `test_source_manifest.py` pinned `--baseline-ref` to `daf0ccc`, a
  commit this repository has never contained (it was imported at
  v3.3.2), so `--baseline-ref` was untested in every checkout and CI
  job while the skip reason blamed a source distribution. Fixed: a new
  test verifies the inventory and blobs at the seal commit (the last
  commit touching `RELEASE_SHA256.json`) and the separate development
  delta; it runs in any checkout. The pinned test's reason now says
  why it skips.
- `test_skill_ingest_hardening.py:313` reads an external corpus that
  was never committed, so it skips everywhere. Reported, not fixed: the
  corpus is third-party data.

## Other runs on this revision

- **Non-root, from an export.** `git ls-files` exported to
  `/study/diag/sis-agentF`, owned by `sispilot` (member of `docker`,
  sudoers rule to `sisagent`), then `su - sispilot -c "cd
  /study/diag/sis-agentF && SIS_TEST_AGENT_USER=sisagent PYTHONPATH=src
  python3 -m pytest tests -q -p no:cacheprovider -rs"`: 2254 passed,
  40 skipped, 0 failed. The mode-000 test runs and passes; the
  seal-commit test skips (an export has no Git history). The other 39
  skips are the ones above.
- **PostgreSQL.** A `postgres:16` container (16.16) on a local port,
  `SIS_POSTGRES_DSN=postgresql://sis_test:sis_test@127.0.0.1:<port>/sis_control`:
  `tests/v3/test_control_plane_postgres.py` 8 passed. CI's `postgres`
  job covers the same tests.
- **Extracted canonical archive.** The `archive` CI job's steps by hand
  (Python 3.12 venv, root, no second user, no DSN): 2246 passed,
  45 skipped, 0 failed. The extra skips are expected there: the three
  agent-principal integration tests (no `SIS_TEST_AGENT_USER`), the
  seal-commit test (no Git history) and `test_receipt_signatures.py:110`
  (`cryptography` is not in `requirements-lock.txt`).

## Flake seen during collection

An earlier full run failed once in
`test_agent_principal.py::...::test_the_timeout_kills_every_agent_process`
(`real_agent_turn_incomplete`, and in a repeat `agent helper probe failed
as sisagent (exit -9)`). The cause was another agent's test run on the
same host using the same `sisagent` account: the principal's `kill`
helper kills every process of that user, including another run's
helper. Isolated reruns passed, and every run recorded above passed
it. Concurrent suites on one host need distinct agent users.
