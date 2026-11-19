# Upgrading from SIS 1.0.0 to SIS 1.1.0

## Scope

This is a source-level, model-independent research integration. It uses a deliberately
small, bounded expression grammar; it cannot induce arbitrary programs, self-train an
LLM, or establish causal truth. The upgrade is backwards compatible for the train,
predict, feedback, chat, Python and HTTP request *formats*. It is NOT automatically
backwards compatible with unverified legacy SQLite audit records.

## New capabilities

* **Active experiment selection:** `sis query examples/query.json` discovers
  candidate disagreements and returns unlabeled inputs suitable for a trusted oracle.
  All returned outputs are hypotheses only. Selection uses training inputs only.
* **Split-local evaluation:** `sis benchmark examples/benchmark.json` enforces
  train/validation/test input disjointness, evaluates a rule on caller-supplied test
  data, reports abstention/coverage/correctness, and compares with a train-majority
  constant baseline. No rule is promoted by a benchmark call.
* **Rule projection verification:** every newly created rule promotion, feedback
  change, and retirement gets a complete projected rule snapshot in the SQLite
  hash-linked audit. `sis audit` cross-checks the final table state. Predictions
  abstain if a mismatch or legacy evidence gap is detected.
* **Explicit irreversible retirement:** `sis retire path/to/request.json`,
  `POST /v1/retire` or `Service.retire` prevents further use of a rule.
* **Agent tools:** `sis tools`, `GET /v1/tools` and `sis.bridge.ToolBridge` expose
  only read-only prediction and experiment-suggestion actions to arbitrary LLM
  frameworks. They intentionally do not expose training, promotion, feedback,
  retirement or benchmarking to untrusted agent tool calls.

## Migration and recovery

v1.0.0 recorded hashes of promotion and feedback events but did not record a complete
rule projection in those events. Because the source evidence is not stored in v1
SQLite, v1.1 **cannot safely reconstruct the audit evidence**, and will not bless
old records by guessing. Existing databases are readable but prediction will
abstain when the audit is unverifiable. Never silently rewrite a v1 history to
make it appear v1.1-verifiable.

To upgrade:

1. Keep a read-only backup of your old `.sqlite3` database and any `.sqlite3-wal`
   and `.sqlite3-shm` companions (use SQLite `.backup` while the database is live).
2. Start SIS 1.1 with a **new** database path.
3. Retrain with the *original* labeled training and local validation examples.
   Do not treat previously generated synthetic probes as ground-truth labels.
4. Promote only the newly evaluated rules and check `sis audit` before serving.
5. When available, freeze a separately controlled external holdout; do not use
   the bundled synthetic fixtures as evidence of production generalization.

## Known limitations

* The audit chain is only database-local. A capable attacker with DB write access
  can rewrite the entire chain and projection, or truncate a matching suffix.
  Anchor `head` externally in a trusted append-only service for stronger tamper
  detection. No remote anchoring service is implemented in this package.
* The benchmark can check disjoint inputs **inside one invocation** but cannot
  verify that the test data were not used in previous runs or in human selection.
* Active-learning suggestions are neither labeled facts nor verified rule proofs.
  The user/environment/oracle must independently provide correct labels.
* The limited grammar, heuristic enumeration, and bounded probes cannot establish
  exhaustive completeness, general intelligence, or universal LLM compatibility.
* A hosted LLM needs an appropriate tool-calling client or API gateway. The optional
  built-in proposal/chat adapter targets OpenAI-compatible chat completion APIs.
* The localhost HTTP API is a demonstration service without per-user isolation,
  built-in TLS, rate limiting or sophisticated authentication. Do not expose it
  directly to the public Internet.
