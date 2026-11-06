# Security model and known risks

> This document covers the legacy v1/v2 registry and HTTP surface. For the v3
> authority, custody, execution-identity and serving threat model, see
> `docs/SECURITY_THREAT_MODEL.md`.

This is a **local-first research prototype**, not an audited hardened multi-tenant server.

## Enforced

1. Rules are JSON expressions with a whitelisted interpreter, not Python source. All AST nodes and arguments are checked before evaluation. Numeric overflow and oversized inputs reject.
2. Training and validation have strict bounds; web request size is capped to 512 KiB.
3. The HTTP server binds to `127.0.0.1` unless changed. Non-loopback binds require `SIS_API_KEY`; any configured API key must be at least 24 UTF-8 bytes. Authentication uses constant-time comparison of `X-SIS-Key`. With an API key configured, train/feedback/retire/chat routes additionally require independent `SIS_ADMIN_KEY` via `X-SIS-Admin-Key` (otherwise HTTP 403). Without either key, loopback development mode allows mutation to anyone able to connect to the port.
4. Both `Service.study()` and the registry promotion boundary independently recompute induction from supplied examples and configuration. A direct Python caller cannot promote a fabricated induction result without reproducing the matching study. This still does not authenticate the origin or truth of the examples.
5. Model calls are off by default. An enabled LLM sees only explicit opt-in training input or chat context; API-provided LLM endpoints are not accepted (endpoint is controlled by environment). Outbound HTTP redirects are refused to avoid forwarding examples or bearer credentials to another URL.
6. Users cannot choose which SQL to run. SQL parameterization is used throughout.
7. The audit chain checks hash continuity, final DB projection, and now semantic event replay (promotion/feedback/retirement transitions). It does *not* stop a sufficiently privileged attacker from recomputing coherent history or truncating it.
8. The admission firewall rejects bounded counterexample disagreements with active rules using the same namespace and schema. It does not prove semantic equivalence or prevent malicious labels.

## Not implemented; do not assume

- Independent signing authority, external timestamping, or automatically externally anchored Merkle proofs. Manual checkpoints with optional HMAC now exist, but the operator must separately safeguard the checkpoint and signing key.
- Internet-facing TLS, API rate limiting, fine-grained IAM, comprehensive roles, tenant isolation, per-user quotas, or endpoint allowlists for operator-configured HTTPS model URL. The operator key is just a second shared secret, not per-user IAM.
- Container-level isolation or sandboxing of third-party Python packages; the bundled AST interpreter never executes user Python.
- A trusted ground-truth oracle for feedback or for validation data; user-supplied labels may be false.
- Formal mathematical proof of a task hypothesis. Z3 is used only for **bounded disagreements between formulas** when enabled.
- Untrusted public hosting. For a future network service deploy behind TLS, identity-aware proxy, workload isolation, and independently monitored audit storage, and perform an external security assessment.

## Privacy

The local registry stores rule expressions and schema identifiers, counts, hashes of training/validation sets, and feedback digests; it does not store raw training examples by default. Logs omit request bodies. A human who already knows the small set of likely labels may infer sensitive values from digests; do not treat hashes as anonymization. LLM-enabled sessions transfer examples or prompt context to the configured model endpoint. Review data sharing agreements and do not put secrets in examples.

## Safe default

Prefer local model inference, loopback API, synthetic/proprietary test fixtures with consent, and independent reviewed qualification before granting a rule authority over workflows.

## v1.1 stronger projection consistency and remaining limits

Audit events now include the complete post-transition rule projection so unexpected
changes to `rules` are detected against the linked log. Before prediction the
registry checks audit continuity and matches the last event projection to each
stored rule. Corrupt or unverifiable legacy records make prediction abstain.

This does **not** authenticate the event producer or protect against a database
administrator rewriting a complete history. The audit head must be checkpointed
outside the SQLite trust boundary to achieve stronger tamper detection. The package
provides the head through `sis audit` but implements no external trust anchor.

`ToolBridge` intentionally forbids model-issued promotion, training, retirement,
feedback, benchmarking, arbitrary code execution, and filesystem access. Keep
its allowlist narrow when integrating other model providers.

## v1.2 manual audit-anchor threat model

Use `sis anchor-export <path>` to create an operator-controlled, non-overwriting
checkpoint containing a canonical digest, count, and authenticated (if configured)
HMAC. `sis anchor-verify <path>` confirms the current SQLite audit retains that
**exact prefix** (even if subsequent events have been appended). The export does
not itself transmit anything off-host. Move the file to physically or logically
separate storage, and hold `SIS_ANCHOR_HMAC_KEY` outside the DB writer trust zone.
If a malicious operator controls the registry, the checkpoint *and* the secret,
no meaningful origin authentication remains. An unsigned digest can be rewritten
with a matching checksum; its authenticity relies entirely on independent custody.
This manual process is not an always-on attestation or audit of real-world events.

`Registry.promote` intentionally duplicates induction work to compare the actual
result with the full supplied study. The integrity boundary stops falsified result
objects, but does not verify labels and cannot guard against a malicious process
with arbitrary code execution inside the service process. Do not grant untrusted
clients arbitrary Python access.

## v1.3 operator authority and semantic replay

`SIS_API_KEY` is now read/prediction authorization only. With this variable
configured, any attempt to mutate rules or start an opt-in LLM chat through
HTTP requires the distinct `SIS_ADMIN_KEY` (24+ bytes), or fails with 403.
Backend Python `Service` callers remain trusted operators; role checks live
at the HTTP boundary and cannot secure the same-process Python interpreter.
Keys are sent in HTTP headers, so production external access needs HTTPS at a
properly configured reverse proxy, plus additional network controls.

Event replay rejects unauthorized status changes, metadata rewrites, and
counter jumps even if a hash chain is recomputed to match a final projection.
A database admin who can rewrite all event and rule rows can still create a
plausible new full history. Export externally controlled HMAC checkpoints.


## v1.7 procedural-skill subsystem

See [V1_7_PROCEDURAL_SKILLS.md](V1_7_PROCEDURAL_SKILLS.md) for architecture, verification boundary, threat model and explicit limitations. The procedural skill chain is local integrity evidence, not a separately anchored cryptographic attestation.


## v1.8 procedural skill evaluator and distillation trust boundaries

`SkillHoldoutVault` must operate in a separate evaluator-controlled process/host
with separately guarded private labels, HMAC key and vault. `skill-freeze`
produces hash-bound but not authenticated snapshots; without an evaluator
receipt a candidate can forge and recompute the bundle hash. The evaluator
precommits the exact bundle and policy, scores two disjoint secret splits at
most once, and signs aggregate receipts for deterministic replay. This does
not establish external dataset provenance, statistical independence, hardened
sandboxing against hostile in-process code, or prevention of key compromise.

Never expose evaluator credentials, secret labels or `skill-distill-export` to
an LLM. The export's candidate inputs must be selected independently of the
holdout labels. The exported target outputs are **synthetic pseudo-labels**, not
independently verified truth. A successful frozen score does not reactivate a
suspended live skill or automatically promote other skills. See
`V1_8_PROCEDURAL_HOLDOUT_AND_DISTILLATION.md`.

## v2.1 operator-side trace learning

Typed execution traces are replayed locally and converted into untrusted
procedural hypotheses; they are never an independent correctness oracle.
Validation traces are not accepted, and the tool bridge cannot invoke
trace studies or promote skills. See `docs/V2_1_TYPED_TRACE_LEARNING.md`.
