# SIS v3 M0 compatibility and migration notes

## Compatibility matrix

| Surface | v2.4.0 behavior | M0 change | Migration impact |
| --- | --- | --- | --- |
| Python package | `sis` v2.4 public modules | Additive `sis.v3` namespace and `SCHEMA_VERSION = 1` | Existing imports and function signatures remain unchanged |
| ToolBridge | Existing read-only tools, including experimental `sis_code_preview` | No new tool is registered in the legacy bridge | Agent behavior remains unchanged unless the v3 module is explicitly called |
| HTTP | Existing routes and keyed operator separation | Central explicit POST handler/access inventory; unknown policy is denied | Keyed reader/admin behavior remains; unkeyed loopback demo remains for compatibility |
| SQLite | Existing v2 tables and audit chains | No v3 tables or migrations | No database conversion or rollback operation is required |
| Source manifest | Exact release inventory | Baseline verification mode can verify a pinned Git tree and label development delta; in an extracted archive without `.git` the baseline test skips and plain worktree mode correctly fails on unmanifested dev files | Do not regenerate the release manifest during development |
| Optional dependencies | No mandatory runtime dependencies; optional extras remain optional | Pin build backend to `setuptools==82.0.1`; no new runtime dependency | Runner, store, signatures, and verifier are standard-library only; `cryptography` is used in tests only to cross-check Ed25519 |
| Execution | Host subprocesses only via existing demos | `sis.v3.runner` adds disposable workspace execution with `unverified_local` labeling; never presented as a security boundary | Callers must not run hostile code assuming OS isolation; replace backend before multi-tenant use |
| Evidence | v2 SQLite audit | `sis.v3.episode_store` + `sis.v3.verifier` add chained JSONL events, content-addressed artifacts, and Ed25519-signed outcome receipts | No v2 tables changed; v3 stores are separate directories, not SQLite migrations |

## Additive interface rules

V3 records are strict v1 JSON contracts. Unknown fields fail closed. The v3
guidance function currently abstains, and v2 registries are not imported into a
qualified v3 catalog. Legacy local evidence remains local research evidence;
it does not become an independently verified v3 outcome receipt.

No database migration is needed for M0. Future persisted schemas require
additive migration tests and a rollback plan before they can be enabled.

## Source integrity workflow

Run `python tools/check_source_manifest.py` only when the working tree is
expected to match its release manifest. It will correctly fail while the
development tree differs from the baseline manifest. During development or CI,
use `python tools/check_source_manifest.py --baseline-ref <verified-revision>`;
this verifies manifest-listed Git blobs at that revision and reports current
development changes separately. Release packaging may regenerate
`SOURCE_SHA256.json` only after the release inventory is frozen and authorized.

## Later migration gates

Codex SDK events, workspace execution, evaluator receipts, and the episode
store now exist as additive `sis.v3` modules; none of them are wired into the
v2 service, HTTP server, or SQLite schema. Qualified retrieval, promotion, and
any production wiring still require their own milestone, API compatibility
review, security tests, and independent evidence.

## v3.3.1 to v3.3.2: authority consistency

No candidate-registry schema change is required. The control-plane
schema (`session_nonce`, `authorization_receipt`, `guidance_outcome`,
`authority_head`) is created automatically on first open.

Operational steps:

1. Point production at `PostgresControlPlane` and install the `postgres`
   extra / `requirements-lock.txt`.
2. Bind a custody link signer and set `require_signed_links=True` before
   qualifying new candidates. Re-link legacy custody first.
3. Bind `custody.bind_on_change(journal.publish)` so revocations advance
   the signed checkpoint immediately.
4. The first production serve seeds `authority_head` from the latest
   signed checkpoint after verifying local candidate and custody state.
   If the local state is ahead (interrupted publication), run
   `registry.publish_pending()` first.
5. Configure v3 API keys with optional `expires_at`; enable
   `SIS_V3_ONLY=1` and terminate TLS at a reverse proxy.
6. Re-run the release inventory and packaging steps; 3.3.1 artifacts do
   not cover 3.3.2 source.

`GuidanceV1.decision` gains `advisory`. Consumers that assumed only
`recommend`/`abstain` must handle the new value; `advisory` never grants
procedure authority and always carries a reason.

## v3.3.2 security hardening

The hardening pass on v3.3.2 closes authorization and custody gaps found
in external review. Operational impact:

1. **Control-plane schema v2 (automatic).** Opening an existing
   SQLite/Postgres control plane migrates `authorization_receipt` with an
   additive `requester` column (`schema_meta.version` becomes 2). No dump
   or restore is needed; the column is additive and old databases remain
   usable. Receipts committed before the migration carry
   `requester=NULL` and only accept an outcome submitted without a
   requester.
2. **Signed custody links are required in production.** Production
   `serve()` now abstains (`evidence_custody_unsigned_links`) when the
   bound `EvidenceCustodyStore` was built with
   `require_signed_links=False`. Single-host development profiles are
   unaffected. Re-link legacy custody before enabling signed links.
3. **Outcomes bind the authorized requester.** `record_outcome` requires
   the same `requester` that the authorization was committed for; the
   HTTP service passes the authenticated key identity automatically.
   Custom callers must propagate the requester through
   `serve(requester_identity=...)` and `record_outcome(requester=...)`.
4. **Trust-key enrollment validates Ed25519 keys.** All trust roots now
   reject malformed, off-curve, or small-order public keys at
   construction (`*_public_key_invalid`). A deployment that previously
   started with such a key now fails fast; regenerate the key and
   re-issue affected signatures.
5. **Strict-procedure revocation window closed.** Combined serving
   includes `StrictGuidanceGateway.authority_fingerprint()` in the
   authorization snapshot and revalidates it before commit; a procedure
   revocation landing mid-decision now abstains instead of serving stale
   authority.
6. **Paired statistical claims are required and reconstructed.**
   Certificate `individual_task_receipts` carry `baseline_outcome`;
   `QualificationPolicy.require_paired_outcomes` now defaults to
   `True`, so every receipt must name a baseline outcome. The validator
   reconstructs the paired point estimate, the Newcombe interval at the
   claimed confidence level, and the regression floor — claims narrower
   than the data, or a `primary_metric` that does not agree three ways
   across policy, certificate and protocol, do not qualify. The legacy
   opt-out is explicit: set `require_paired_outcomes=False` on the
   policy for certificates minted before `baseline_outcome` existed.
   The flag is part of the policy digest, so a permissive policy is
   visible to every consumer. Note the digest changes with the new
   default: existing signed certificates remain valid historical
   artifacts, but they cannot be re-bound to a new policy digest —
   deployments moving to the default must issue *new* signed
   certificates under the recomputed policy digest.
7. **`_conflicts` polarity heuristic tightened.** A negated instruction
   conflicts with an affirmative or unqualified instruction on the same
   terms ("always deploy" vs "never deploy"), so
   `conflict_policy="abstain"` may abstain in cases the older overlap
   heuristic silently passed. The heuristic remains lexical, not
   semantic.
8. **Evaluator key custody is verified, not repaired.** The evaluator key
   directory must already be private — `0700` on POSIX, a DACL limited
   to the evaluator account, SYSTEM, and Administrators on Windows. A
   pre-existing directory is inspected and rejected if it is not,
   instead of being `chmod`-ed into place, so provision it explicitly
   (`mkdir -m 700 <key-dir>`) before starting the evaluator. The
   Ed25519 seed is published with an exclusive create: a concurrent
   start waits for the winner's payload instead of failing, a losing
   creator never replaces existing material, and an empty or truncated
   seed still fails closed in place. A missing `ed25519.pub` left by an
   interrupted publish is rebuilt from the seed; an existing full
   record is never rewritten.
9. **Production qualification recomputes the power floor.** A certificate
   bound to a protocol whose declared `sample_size` is below the floor
   recomputed from that protocol's own `expected_baseline`,
   `expected_treatment`, `power`, and `alpha` no longer qualifies
   (`sample_count_meets_power_analysis`). Protocol digests are
   immutable, so such a deployment must register a new powered protocol
   and issue a new certificate. `preregister` now refuses an
   underpowered plan at registration unless the caller passes
   `allow_underpowered=True`; that opt-out is part of the digest, is
   still reported as underpowered, and never qualifies. A deterministic
   screen (for example a one-task candidate probe) must be registered
   with `powered=False`; diagnostic and mixed diagnostic/power
   protocols never qualify.
