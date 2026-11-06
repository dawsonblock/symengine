"""Bounded enumeration + falsification probes; never confuse fit with proof."""
from itertools import product
from .errors import InvalidInput
from .validation import check_examples, input_schema, namespace_name, canonical, digest
from .expression import validate_ast, evaluate, cost, fingerprint


def leaf_expressions(inputs):
    values = []
    for name, value in sorted(inputs.items()):
        if isinstance(value, list):
            values.extend(({"op": "item", "name": name, "index": i}, x) for i, x in enumerate(value))
        else:
            values.append(({"op": "field", "name": name}, value))
    return values


def candidates(train, max_candidates=12000):
    """Yield shallow first; deepen only if shallow is inadequate."""
    leaves = leaf_expressions(train[0]["inputs"])
    numeric = [expr for expr, v in leaves if type(v) is int]
    string = [expr for expr, v in leaves if type(v) is str]
    seen = set()
    count = 0

    def unique(stream):
        nonlocal count
        for ast in stream:
            sig = fingerprint(ast)
            if sig in seen:
                continue
            seen.add(sig)
            if count >= max_candidates:
                yield None
                return
            count += 1
            yield ast

    def first():
        for ast, _ in leaves:
            yield ast
        if len({canonical(e["output"]) for e in train}) == 1:
            yield {"op": "const", "value": train[0]["output"]}
        for leaf in numeric:
            for op in ("neg", "abs"):
                yield {"op": op, "arg": leaf}
        for leaf in string:
            for op in ("upper", "lower", "reverse"):
                yield {"op": op, "arg": leaf}
        terminals = numeric + [{"op": "const", "value": v} for v in (-2, -1, 0, 1, 2, 3)]
        for op in ("add", "sub", "mul", "min", "max", "absdiff"):
            for a in range(len(terminals)):
                for b in range(len(terminals)):
                    if a >= len(numeric) and b >= len(numeric):
                        continue
                    if op in ("add", "mul", "min", "max", "absdiff") and a > b:
                        continue
                    yield {"op": op, "args": [terminals[a], terminals[b]]}
        for a in range(len(leaves)):
            for b in range(a + 1, len(leaves)):
                if type(leaves[a][1]) == type(leaves[b][1]):
                    yield {"op": "eq", "args": [leaves[a][0], leaves[b][0]]}

    first_results = list(unique(first()))
    exceeded = bool(first_results and first_results[-1] is None)
    for ast in first_results:
        yield ast, 1, count, exceeded
    if exceeded:
        return
    # Deepening is bounded and only requested if no shallow rule fits the training set.
    output = [e["output"] for e in train]
    if any(_matches(ast, train, output) for ast in first_results):
        return
    shallow = [x for x in first_results if x["op"] in {"add", "sub", "mul", "min", "max", "absdiff", "neg", "abs"}]
    terminals = numeric + [{"op": "const", "value": v} for v in (-2, -1, 0, 1, 2, 3)]
    def second():
        for mid in shallow:
            for leaf in terminals:
                for op in ("add", "sub", "mul", "min", "max", "absdiff"):
                    yield {"op": op, "args": [mid, leaf]}
                    if op == "sub":
                        yield {"op": op, "args": [leaf, mid]}
    for ast in unique(second()):
        yield ast, 2, count, ast is None


def _matches(ast, examples, outputs=None):
    if ast is None:
        return False
    if outputs is None:
        outputs = [e["output"] for e in examples]
    try:
        for ex, out in zip(examples, outputs):
            predicted = evaluate(ast, ex["inputs"])
            if type(predicted) is not type(out) or predicted != out:
                return False
        return True
    except (InvalidInput, KeyError, IndexError, TypeError, ValueError, OverflowError):
        return False


def _probe_values(v):
    if type(v) is int: return [-3, -1, 0, 1, 2, 5, 11]
    if type(v) is str: return ["", "a", "b", "Z", "ab", "xy"]
    return [False, True]


def generated_probes(inputs, limit=256):
    """Deterministic *unlabeled* probes; these do not establish ground truth."""
    base = dict(inputs)
    leaves = []
    for name, value in sorted(base.items()):
        if isinstance(value, list):
            leaves.extend((name, i, x) for i, x in enumerate(value))
        else:
            leaves.append((name, None, value))
    seen = set()
    def make(changes):
        out = {k: list(v) if isinstance(v, list) else v for k, v in base.items()}
        for name, idx, v in changes:
            if idx is None: out[name] = v
            else: out[name][idx] = v
        return out
    def feed(value):
        key = canonical(value)
        if key not in seen:
            seen.add(key)
            return value
        return None
    seed = feed(base)
    if seed is not None: yield seed
    n = 1
    for name, idx, value in leaves:
        for other in _probe_values(value):
            item = feed(make([(name, idx, other)]))
            if item is not None:
                yield item
                n += 1
                if n >= limit: return
    if len(leaves) >= 2:
        (a, ia, av), (b, ib, bv) = leaves[:2]
        for x, y in product(_probe_values(av), _probe_values(bv)):
            item = feed(make([(a, ia, x), (b, ib, y)]))
            if item is not None:
                yield item
                n += 1
                if n >= limit: return


def _witness(best, rival, probes):
    for inputs in probes:
        try:
            left, right = evaluate(best, inputs), evaluate(rival, inputs)
        except (InvalidInput, KeyError, IndexError, TypeError):
            continue
        if type(left) is not type(right) or left != right:
            return {"inputs": inputs, "candidate_output": left, "alternative_output": right}
    return None


def induce(train, validation=None, *, namespace="default", max_candidates=12000, proposals=None, use_z3=False):
    namespace_name(namespace)
    if type(use_z3) is not bool:
        raise InvalidInput("use_z3 must be boolean")
    if use_z3:
        try:
            import z3  # noqa: F401 - availability probe; smt.py imports it
        except ImportError as exc:
            raise InvalidInput("Z3 requested but unavailable: pip install .[z3]") from exc
    train = check_examples(train, minimum=3)
    validation = check_examples(validation or [])
    if not 100 <= max_candidates <= 50000 or type(max_candidates) is not int:
        raise InvalidInput("max_candidates must be an integer between 100 and 50000")
    schema = input_schema(train[0]["inputs"])
    training_inputs = {canonical(x["inputs"]) for x in train}
    if len(training_inputs) != len(train):
        raise InvalidInput("training examples must have distinct input records")
    if validation:
        if any(input_schema(x["inputs"]) != schema for x in validation):
            raise InvalidInput("validation inputs must have the same schema as training inputs")
        if any(type(x["output"]) is not type(train[0]["output"]) for x in validation):
            raise InvalidInput("validation output type differs from training")
        vi = [canonical(x["inputs"]) for x in validation]
        if len(set(vi)) != len(vi) or training_inputs.intersection(vi):
            raise InvalidInput("validation must contain distinct inputs not present in training")
    if proposals is not None and (not isinstance(proposals, list) or len(proposals) > 10):
        raise InvalidInput("proposals must be a list of at most 10 AST objects")

    fits = []
    tested = 0
    truncated = False
    stage = 1
    for ast, stage, examined, exceeds in candidates(train, max_candidates):
        if exceeds or ast is None:
            truncated = True
            break
        tested += 1
        if _matches(ast, train):
            fits.append(ast)
    for ast in proposals or []:
        try:
            validate_ast(ast)
            if _matches(ast, train) and fingerprint(ast) not in {fingerprint(x) for x in fits}:
                fits.append(ast)
        except (InvalidInput, KeyError, TypeError):
            continue
    fits.sort(key=lambda x: (cost(x), fingerprint(x)))
    best = fits[0] if fits else None
    probe_list = list(generated_probes(train[0]["inputs"]))
    ambiguous = None
    if best is not None:
        for rival in fits[1:]:
            witness = _witness(best, rival, probe_list)
            if not witness and use_z3:
                from .smt import bounded_disagreement
                witness, _ = bounded_disagreement(best, rival, schema)
            if witness:
                ambiguous = witness
                break
    passes = sum(_matches(best, [ex]) for ex in validation) if best else 0
    if not best:
        status = "search_incomplete" if truncated else "no_rule"
    elif truncated:
        status = "search_incomplete"
    elif ambiguous:
        status = "ambiguous"
    elif len(validation) < 2:
        status = "provisional"
    elif passes != len(validation):
        status = "validation_failed"
    else:
        status = "locally_validated"
    return {
        "namespace": namespace,
        "status": status,
        "rule": best,
        "schema": schema,
        "train_count": len(train),
        "validation_count": len(validation),
        "validation_passed": passes,
        "train_digest": digest(train),
        "validation_digest": digest(validation),
        "candidates_evaluated": tested,
        "fitting_hypotheses": len(fits),
        "search_depth": stage,
        "search_truncated": truncated,
        "distinguishing_probe": ambiguous,
        "verification_scope": "bounded grammar, observed examples, deterministic unlabeled probes" + (" and optional bounded Z3 equivalence checks" if use_z3 else "") + "; not a mathematical or independent generalization proof",
    }
