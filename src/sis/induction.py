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


_EVAL_ERR = ("__sis_eval_error__",)


def _signature(ast, all_inputs):
    """Observational fingerprint: per-input (type, value) evaluation tuple."""
    sig = []
    for inputs in all_inputs:
        try:
            v = evaluate(ast, inputs)
            sig.append((type(v).__name__, v))
        except (InvalidInput, KeyError, IndexError, TypeError, ValueError, OverflowError):
            sig.append(_EVAL_ERR)
    return tuple(sig)


def _combine(op, a, b):
    """Evaluate binary op over two signature vectors; None on any error."""
    out = []
    for x, y in zip(a, b):
        if x is _EVAL_ERR or y is _EVAL_ERR:
            return None
        x, y = x[1], y[1]
        if type(x) is not int or type(y) is not int:
            return None
        try:
            if op == "add":
                v = x + y
            elif op == "sub":
                v = x - y
            elif op == "mul":
                v = x * y
            elif op == "min":
                v = min(x, y)
            elif op == "max":
                v = max(x, y)
            else:
                v = abs(x - y)
            if abs(v) > 1_000_000_000:
                return None
            out.append(v)
        except (TypeError, ValueError, OverflowError):
            return None
    return tuple(out)


def candidates(train, max_candidates=12000, observed_inputs=(), stats=None):
    """Yield shallow first; deepen only if shallow is inadequate.

    Stage 2 is signature-directed: instead of enumerating every
    (mid, terminal, op) combination and evaluating each, it compares
    evaluation signatures over the training inputs and only emits the
    combinations guaranteed to fit, plus constant completions for
    constant offsets/quotients. Relevant mids are visited first by
    residual-variance ranking; the full search space remains covered
    (dedup only removes observational equivalents and AST duplicates).
    """
    leaves = leaf_expressions(train[0]["inputs"])
    numeric = [expr for expr, v in leaves if type(v) is int]
    string = [expr for expr, v in leaves if type(v) is str]
    train_inputs = [e["inputs"] for e in train]
    all_inputs = train_inputs + list(observed_inputs)
    n_train = len(train_inputs)
    seen_fp = set()
    seen_sig = set()
    sigs = {}
    count = 0
    if stats is None:
        stats = {}
    stats["signature_checks"] = 0

    def signature(ast):
        key = fingerprint(ast)
        if key not in sigs:
            sigs[key] = _signature(ast, all_inputs)
        return sigs[key]

    def unique(stream):
        nonlocal count
        for ast in stream:
            fp = fingerprint(ast)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)
            stats["signature_checks"] += 1
            sig = signature(ast)
            if sig in seen_sig:
                continue
            seen_sig.add(sig)
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
    outputs = tuple(e["output"] for e in train)
    if any(_matches(ast, train, outputs) for ast in first_results):
        return
    if not all(type(o) is int for o in outputs):
        # Stage 2 only covers numeric operators.
        return
    shallow = [x for x in first_results
               if x["op"] in {"add", "sub", "mul", "min", "max", "absdiff", "neg", "abs"}]

    def resid_var(ast):
        sig = signature(ast)
        if any(s is _EVAL_ERR for s in sig[:n_train]):
            return None
        res = []
        for o, s in zip(outputs, sig[:n_train]):
            if s[0] != "int":
                return None
            res.append(o - s[1])
        mean = sum(res) / len(res)
        return sum((v - mean) ** 2 for v in res) / len(res)

    # Deterministic relevance ordering: mids whose residual over the
    # observed outputs is most structured are visited first, but every
    # mid is still covered (residual None → last, fingerprint tiebreak).
    shallow.sort(key=lambda m: ((lambda v: (v is None, v or 0.0))(resid_var(m)), fingerprint(m)))

    terminals = numeric + [{"op": "const", "value": v} for v in (-2, -1, 0, 1, 2, 3)]
    term_sigs = []
    seen_term = set()
    for tast in terminals:
        ts = signature(tast)
        if ts in seen_term:
            continue
        seen_term.add(ts)
        term_sigs.append((tast, ts))

    def const_completions(ms):
        res = tuple(o - s[1] for o, s in zip(outputs, ms))
        if len(set(res)) == 1 and res[0] != 0 and abs(res[0]) <= 1_000_000_000:
            yield {"op": "add", "args": [None, {"op": "const", "value": res[0]}]}
        back = tuple(s[1] - o for s, o in zip(ms, outputs))
        if len(set(back)) == 1 and back[0] != 0 and abs(back[0]) <= 1_000_000_000:
            yield {"op": "sub", "args": [None, {"op": "const", "value": back[0]}]}
        if all(s[1] != 0 for s in ms) and all(o % s[1] == 0 for o, s in zip(outputs, ms)):
            quot = tuple(o // s[1] for o, s in zip(outputs, ms))
            if len(set(quot)) == 1 and quot[0] not in (0, 1) and abs(quot[0]) <= 1_000_000_000:
                yield {"op": "mul", "args": [None, {"op": "const", "value": quot[0]}]}

    def second():
        for mid in shallow:
            ms = signature(mid)
            if any(s is _EVAL_ERR for s in ms[:n_train]):
                continue
            ms = ms[:n_train]
            if not all(s[0] == "int" for s in ms):
                continue
            for ast in const_completions(ms):
                ast["args"][0] = mid
                yield ast
            for tast, ts in term_sigs:
                ts = ts[:n_train]
                for op in ("add", "sub", "mul", "min", "max", "absdiff"):
                    stats["signature_checks"] += 1
                    if _combine(op, ms, ts) == outputs:
                        yield {"op": op, "args": [mid, tast]}
                    if op == "sub" and _combine(op, ts, ms) == outputs:
                        yield {"op": op, "args": [tast, mid]}
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
    stats = {}
    probe_list = list(generated_probes(train[0]["inputs"]))
    # Dedup distinguishes over every observable input: train, validation and
    # the deterministic unlabeled probes. Rivals that differ only off the
    # observed set still collapse — but observational equivalence over the
    # full probe space keeps ambiguity detection and signature checks sound.
    observed = [x["inputs"] for x in validation] + probe_list
    for ast, stage, examined, exceeds in candidates(
            train, max_candidates, observed_inputs=observed, stats=stats):
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
        "signature_checks": stats.get("signature_checks", 0),
        "fitting_hypotheses": len(fits),
        "search_depth": stage,
        "search_truncated": truncated,
        "distinguishing_probe": ambiguous,
        "verification_scope": "bounded grammar, observed examples, deterministic unlabeled probes" + (" and optional bounded Z3 equivalence checks" if use_z3 else "") + "; not a mathematical or independent generalization proof",
    }
