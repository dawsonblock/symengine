# v1.3.0 local verification report

Date: October 20, 2026. All results are local tests, not third-party
certification or independent LLM performance evidence.

## Reproducible validation

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -q
PYTHONPATH=src python3 tools/evaluate_fixtures.py
PYTHONPATH=src python3 tools/smoke_integration.py
python3 tools/build_release.py
python3 tools/verify_release.py ../symbolic-induction-engine-v1.3.0.zip
```

- **81 of 81 unit/regression tests passed** (includes 72 original baseline tests).
- Local arithmetic fixture: **3/3** supplied validation outputs matched.
- Local sequence fixture: **2/2** supplied validation outputs matched.
- Ambiguous synthetic fixture: **not promoted**.
- CLI training and batch predictions, manual anchor export and verification,
  and authenticated loopback HTTP smoke all passed.
- Operator authority: reader token denied mutation (HTTP 403); separate admin
  token accepted for a locally valid study (HTTP 200).
- Audit forgery fixture: hash-correct rewritten event with a forged feedback
  counter was rejected as an invalid state transition.
- Conflicting rule fixture: the second rule was rejected; first rule unchanged.
- Typed-output regression: Boolean prediction no longer matches integer label 1.

## Scope and limitations

No claims of independent holdout results, causal rule discovery, general-purpose
reasoning improvement, formally proven correctness, or audited security. Hash
links do not authenticate a fully rewritten history without independent anchors.
The compatibility firewall uses bounded probes and is not an equivalence proof.
The HTTP server still lacks TLS and rate limiting; use local deployment only.
