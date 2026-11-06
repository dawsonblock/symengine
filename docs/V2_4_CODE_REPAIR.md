# SIS v2.4.0 — Evidence-gated pure Python repair recipes

## Actual capability

SIS v2.4 observes a **bounded code transformation**, evaluates its behavior using a **restricted interpreter for Python AST arithmetic expressions**, and checks it against caller-supplied expected results. Repeated successes with the same operator transition produce a candidate reusable repair recipe. Operator-controlled promotion requires successful replay of 3–32 recorded examples and success on 2–64 separate source-program holdouts. Inference to new code is **preview-only**: SIS returns a unified diff and a complete proposed source string but **never writes it to disk or runs source as Python**.

The engine's only learned recipe kind is `binary_operator_swap`, with operator names `Add`, `Sub`, `Mult`, and `FloorDiv`. It can generalize one swap from `def foo(a,b): return a-b` to another named pure function containing one uniquely matching subtraction. This is **not** arbitrary coding-agent program synthesis; it does not learn how to search a repository, select patches autonomously, generate implementations, or use a real test runner.

## Installation and local end-to-end test

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -p 'test_v240_code_learning.py' -v
python3 tools/demo_code_learning.py
```

The demo demonstrates three captured repairs, two withheld source programs, validation-gated promotion into SQLite, read-only tool invocation, and audit integrity.

## Programmatic integration

```python
from sis.service import Service
from sis.bridge import ToolBridge
from sis.code_learning import capture_repair

recipe = {'kind':'binary_operator_swap','from_op':'Sub','to_op':'Add'}
capture = capture_repair({
    'source': 'def f(a,b):\n    return a-b\n',
    'filename': 'math.py', 'function': 'f', 'recipe': recipe,
    'cases': [
        {'args':{'a':2,'b':3}, 'expected':5},
        {'args':{'a':8,'b':-2}, 'expected':6},
    ],
})
# Gather two additional different function captures, plus at least two
# separate source-program holdouts with independently supplied outputs.
service = Service('skills.sqlite3')
result = service.code_study({'namespace':'arithmetic','promote':False,
                            'train_captures':[capture, ...], 'validation':[...]})
# Only an operator should change promote to True after inspecting evidence.
# Model integration is read-only:
bridge = ToolBridge(service)
# bridge.invoke('sis_code_preview', {
#    'namespace':'arithmetic', 'source':'def new(a,b):\n return a-b\n',
#    'filename':'new.py','function':'new'})
```

## Command line

```bash
sis code-capture capture_request.json
sis --db skills.sqlite3 code-study operator_study.json
sis --db skills.sqlite3 code-preview prediction.json
sis --db skills.sqlite3 code-list --namespace repair_demo
sis --db skills.sqlite3 code-audit
sis --db skills.sqlite3 code-retire operator_retirement.json
```

`code-capture` accepts `source`, `filename`, `function`, `recipe`, and `cases`; `code-study` accepts `namespace`, `promote`, `train_captures` (captured envelopes), and `validation` (raw unseen source cases). `code-preview` accepts `namespace`, optional `recipe_id`, `source`, `filename`, and `function`.

HTTP endpoints: `POST /v1/code/capture`, `/v1/code/study`, `/v1/code/preview`, `/v1/code/retire`, and `GET /v1/code`, `/v1/code/audit`. Study and retirement require separate operator authorization when an API key is enabled. `sis_code_preview` is the only model-facing code-specific tool.

## Trust and safety boundaries

- The AST evaluator does not run imports, call arbitrary Python functions, perform file I/O, use a network, execute tests in a subprocess, or run a shell.
- Only one top-level undecorated, one-statement, pure-return function is allowed. Expressions can contain integer literals, positional parameter names, unary negation, and bounded `+`, `-`, `*`, `//`.
- Training observations are replayed and compared byte-for-byte after recording. Their hashes are **not** signatures and do not certify that reported correct answers came from an independent authority.
- The caller supplies labels; poor labels cause poor learned recipes. Holdout samples can still be cherry-picked, so qualifying against them is only local evidence of behavior.
- Parsed source is capped at 48 KiB, cases at 32 per record, and numeric magnitudes are bounded. Filenames must be simple flat `.py` names, not filesystem paths.
- Preview can return proprietary code to the requesting agent, so agent permissions and model-provider data handling are a deployment consideration.
- `ast.unparse` regenerates the entire module and **does not preserve formatting or comments**. It also does not preserve byte-identical source, so every output requires human or independent evaluator review before application.
- One active code recipe per namespace prevents ambiguous default routing. Failure to match a target function causes abstention; a model cannot access promotion or retirement through the tool bridge.
- Hash-linked SQLite evidence can be rewritten by a privileged database custodian; independent signed attestation is not provided in v2.4.

## Future engineering work

1. Integrate a real coding agent's read/test/edit events under externally enforced permissions.
2. Add a **real OS-level sandbox** for untrusted code and independent unit-test execution; don't confuse AST interpretation with secure process sandboxing.
3. Learn additional typed AST and API-level transforms and retain input/output signatures and code-context applicability requirements.
4. Evaluate on independent unseen repositories and tasks, including no-SIS and placebo baselines. Measure regressions, risk and cost.

No claim of better LLM performance or general autonomous self-improvement is made.
