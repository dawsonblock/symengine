# SIS v3.3.2 development qualification status

Updated: 2026-11-07. Base revision: `e644d81e7f96c571c49af7f9ca29429de435686b`
plus uncommitted evaluator-custody, power-floor, and release-check repairs.
Status: **IMPLEMENTED_NOT_EFFICACY_QUALIFIED**. This is an unsigned development
snapshot, not a newly published or signed release.

## Current scope and limitations

- Qualification now requires paired baseline outcomes by default and agreement
  between certificate primary metric and qualification policy. The explicit
  legacy opt-out remains digest-visible. Historical signed certificates are
  preserved; changed policies require new certificates (see `MIGRATION.md`).
- Production qualification recomputes the power floor from the registered
  expectations. `protocol_power_analysis_valid` and
  `sample_count_meets_power_analysis` reject a forged `required_n`, a
  diagnostic plan, or a run short of its own floor. `preregister` refuses a
  powered plan whose declared sample is below that floor unless the caller
  passes the explicit, digest-visible `allow_underpowered=True`.
- Six tests in `tests/v3/test_control_plane_sqlite.py` exercise real SQLite
  file-lock serialization, replay protection, outcome binding, and shared
  serving decisions. They are tracked in Git and covered by the source
  inventory. They do not qualify PostgreSQL or multi-host operation.
- PostgreSQL qualification is still unrun: no disposable DSN is configured,
  and the earlier private server setup was denied at `shmget`. No workaround
  or retry was attempted for this repair.
- An earlier repair round deselected twelve evaluator/campaign tests that hit
  `sandbox_apply: Operation not permitted`. In this round the full suite
  executed with **0 deselected**; the earlier 1011-passed run remains
  historical evidence, not a pass for this snapshot.
- Real-agent efficacy remains unestablished. A sealed, repository-disjoint,
  powered study, validated execution isolation, model availability and a
  precommitted run budget remain prerequisites. No live paid run was made.

## Verification of this development repair

- Broad suite: **1067 passed, 12 skipped, 0 deselected** (66–72 s across
  repeated runs), Python 3.12.0 / pytest 8.4.2 on macOS. Skips: 8 PostgreSQL
  (`SIS_POSTGRES_DSN` not configured), 2 Windows ACL integration tests,
  1 missing vskill sample corpus, 1 unavailable pinned Git baseline.
- Release inventory: `python3 tools/check_release_ci.py --mode release`
  verifies **382 files**; the manifest is current rather than drifted.
- CLI + authenticated loopback HTTP smoke: `tools/smoke_integration.py` passes.
- These are local results. The updated GitHub workflow has not been pushed or
  observed running remotely, and no full current-snapshot pass is claimed.

## Release verification policy

Tags and published GitHub releases run `tools/check_release_ci.py --mode
release`: stale, missing, malformed, or incomplete inventories fail the job.
Ordinary branch/PR CI uses explicit development mode, which permits inventory
drift but labels it **not release verification**. Missing/malformed manifests
still fail. Neither mode regenerates the manifest to hide a mismatch.

The development ZIP is rebuilt with `tools/build_canonical_zip.py --allow-dirty`,
then checked internally, against the complete current source tree, and after
fresh extraction. Its commit and dirty paths are recorded alongside its hash.
The output and local verification logs are in `build/release-repair-20261107/`;
`build/` is intentionally excluded from distributed source. The refreshed
`RELEASE_SHA256.json` is an unsigned inventory, not publisher authentication.
Historical signed provenance under `release/` is unchanged and does not attest
this development ZIP.

The custody/power-floor repair round did not rebuild that archive: the ZIP in
`build/release-repair-20261107/` predates it and does not attest this snapshot.
What was verified for this round is the suite, the strict release-inventory
check and the CLI/HTTP smoke listed above; the tree still carries a current
`RELEASE_SHA256.json`.

## Historical v3.3.0 qualification report

The v3.3.0 report is retained verbatim in
[`QUALIFICATION_REPORT_V3_3_0.md`](QUALIFICATION_REPORT_V3_3_0.md). It
records its original release and test environment only. Its 804-test
count, 306-file archive, gate passes, and release decision are not
current qualification claims for the development snapshot above.
