"""Optional Z3 counterexamples between candidate expressions on bounded integer inputs.

A sat witness disproves candidate equivalence. Unsat does NOT establish a rule is
correct relative to the real task, and is only over the configured bounded domain.
"""
from .errors import InvalidInput
from .expression import evaluate, z3_translate


def bounded_disagreement(a, b, schema, low=-20, high=20, timeout_ms=150):
    try:
        import z3
    except ImportError as exc:
        raise InvalidInput("Z3 requested but not installed: pip install '.[z3]'") from exc
    if not (-1000 <= low <= high <= 1000):
        raise InvalidInput("SMT search bounds must be within -1000..1000")
    vars = {}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for name, shape in schema.items():
        if isinstance(shape, list):
            if any(t != "int" for t in shape):
                return None, "unsupported_noninteger_schema"
            parts = []
            for i in range(len(shape)):
                var = z3.Int(f"v_{name}_{i}")
                solver.add(var >= low, var <= high)
                parts.append(var)
            vars[name] = parts
        elif shape == "int":
            var = z3.Int(f"v_{name}")
            solver.add(var >= low, var <= high)
            vars[name] = var
        else:
            return None, "unsupported_noninteger_schema"

    guards = []

    def translate(ast):
        return z3_translate(ast, vars, z3, guards)

    try:
        solver.add(translate(a) != translate(b))
        for guard in guards:
            solver.add(guard)
    except (KeyError, ValueError, IndexError, TypeError):
        return None, "unsupported_expression"
    verdict = solver.check()
    if verdict == z3.unsat:
        return None, "unsat_bounded_domain"
    if verdict != z3.sat:
        return None, "unknown_or_timeout"
    model = solver.model()
    case = {}
    for name, var in vars.items():
        if isinstance(var, list):
            case[name] = [model.eval(item, model_completion=True).as_long() for item in var]
        else:
            case[name] = model.eval(var, model_completion=True).as_long()
    try:
        va, vb = evaluate(a, case), evaluate(b, case)
    except (InvalidInput, KeyError, TypeError):
        return None, "witness_failed_runtime_validation"
    if va == vb:
        return None, "witness_failed_runtime_validation"
    return {"inputs": case, "candidate_output": va, "alternative_output": vb}, "sat_counterexample"
