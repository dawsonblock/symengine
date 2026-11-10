"""Bounded enumeration + falsification probes; never confuse fit with proof.

Search is a two-stage, budget-bounded enumeration. Stage 1 visits shallow
expressions; stage 2 is signature-directed and only emits combinations
guaranteed to fit the training outputs. A shallow rule stops the search
only when it also fits the *development* examples — fitting training data
alone is not a reason to stop deepening. Development data is model
selection; a sealed holdout, when supplied, is the only set used for the
final generalization status.

Every limit is explicit and reported: candidate count, signature checks,
wall time, traced memory, and expression depth. The result says whether
the search completed, was truncated, or exhausted resources.
"""
import time
import tracemalloc
from dataclasses import dataclass, field
from itertools import product

from .errors import InvalidInput
from .validation import check_examples, input_schema, namespace_name, canonical, digest
from .expression import validate_ast, evaluate, cost, depth, fingerprint


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


@dataclass(frozen=True)
class SearchBudget:
    """Hard computation envelope for one induction search (Phase 4.2).

    ``max_candidates`` bounds unique observational candidates yielded.
    ``max_signature_checks`` bounds the actual comparison work, which
    candidate counting alone does not. ``max_wall_seconds`` bounds wall
    time. ``max_memory_bytes`` is an incremental soft budget over Python
    allocations traced from search start; ``None`` disables it. It is not
    an OS RSS limit, does not see native-extension allocations, and is
    sampled at resource-check points. Enabling it starts ``tracemalloc``
    when no tracer is running; a caller-owned tracer is measured from its
    current baseline and is never stopped by the search. If the tracer
    disappears or restarts mid-search the cap fails closed. For an
    OS-enforced hard bound, run the search through
    :func:`sis.enforced_induction.run_induction_enforced`; this budget
    remains soft and diagnostic.
    ``max_expression_depth`` excludes expressions deeper than the
    declared nesting level.
    """

    max_candidates: int = 12000
    max_signature_checks: int = 500_000
    max_wall_seconds: float = 30.0
    max_memory_bytes: int | None = None
    max_expression_depth: int = 5

    def __post_init__(self):
        if type(self.max_candidates) is not int or not 100 <= self.max_candidates <= 50000:
            raise InvalidInput("max_candidates must be an integer between 100 and 50000")
        if (type(self.max_signature_checks) is not int
                or not 1 <= self.max_signature_checks <= 10_000_000):
            raise InvalidInput(
                "max_signature_checks must be an integer between 1 and 10000000")
        if (type(self.max_wall_seconds) not in (int, float)
                or isinstance(self.max_wall_seconds, bool)
                or not 0 < self.max_wall_seconds <= 3600):
            raise InvalidInput("max_wall_seconds must be in (0, 3600]")
        if self.max_memory_bytes is not None and (
                type(self.max_memory_bytes) is not int
                or not (1 << 20) <= self.max_memory_bytes <= (1 << 40)):
            raise InvalidInput(
                "max_memory_bytes must be null or in [1 MiB, 1 TiB]")
        if (type(self.max_expression_depth) is not int
                or not 1 <= self.max_expression_depth <= 5):
            raise InvalidInput("max_expression_depth must be an integer in [1,5]")

    def as_dict(self) -> dict:
        return {
            "max_candidates": self.max_candidates,
            "max_signature_checks": self.max_signature_checks,
            "max_wall_seconds": self.max_wall_seconds,
            "max_memory_bytes": self.max_memory_bytes,
            "max_expression_depth": self.max_expression_depth,
        }


@dataclass
class SearchState:
    """Mutable budget consumption shared across refinement rounds.

    Memory accounting is an incremental soft budget over Python
    allocations traced from ``start()``: ``observed_peak_bytes`` is the
    largest sampled growth above the baseline, not process RSS. It cannot
    see native-extension allocations or enforce a hard OS limit; use a
    subprocess/cgroup/microVM limit for that. A caller-owned tracer is
    never stopped; a tracer this search started is stopped by ``close()``.

    The budget fails closed on lost measurement: if the tracer stops or
    is replaced while the search runs, growth is unmeasurable and the
    search reports ``resource_exhausted`` rather than claiming success.
    """

    budget: SearchBudget
    started: float = field(default_factory=time.monotonic)
    signature_checks: int = 0
    candidates: int = 0
    depth_excluded: int = 0
    limits_hit: list[str] = field(default_factory=list)
    memory_check_enabled: bool = False
    owns_tracer: bool = False
    baseline_traced_bytes: int = 0
    observed_peak_bytes: int = 0
    closed: bool = False
    _last_peak_bytes: int = 0

    def hit(self, reason: str) -> None:
        if reason not in self.limits_hit:
            self.limits_hit.append(reason)

    def start(self) -> None:
        """Begin accounting; enable the memory cap regardless of tracer owner."""
        self.started = time.monotonic()
        self.closed = False
        if self.budget.max_memory_bytes is None:
            return
        self.memory_check_enabled = True
        if tracemalloc.is_tracing():
            # A caller-owned tracer: measure growth from here, never
            # reset or stop the caller's tracer.
            current, peak = tracemalloc.get_traced_memory()
            self.baseline_traced_bytes = current
        else:
            tracemalloc.start()
            self.owns_tracer = True
            self.baseline_traced_bytes = 0
            current, peak = tracemalloc.get_traced_memory()
        self.observed_peak_bytes = 0
        self._last_peak_bytes = peak

    def close(self) -> None:
        """Stop tracing only when this search started it."""
        self.closed = True
        if self.owns_tracer:
            tracemalloc.stop()
            self.owns_tracer = False

    def spend_signature(self) -> bool:
        if self.signature_checks >= self.budget.max_signature_checks:
            self.hit("max_signature_checks")
            return False
        self.signature_checks += 1
        return True

    def check_resources(self) -> bool:
        if time.monotonic() - self.started > self.budget.max_wall_seconds:
            self.hit("max_wall_seconds")
            return False
        if self.memory_check_enabled and not self.closed:
            if not tracemalloc.is_tracing():
                # Another component stopped the tracer this budget
                # depends on. Growth is unmeasurable from here, so the
                # cap cannot be shown to hold: fail closed instead of
                # silently reporting success.
                self.hit("memory_tracer_lost")
                return False
            current, peak = tracemalloc.get_traced_memory()
            if peak < self._last_peak_bytes:
                # A tracer's peak never shrinks while it runs, so a drop
                # means the tracer was stopped and restarted (or its peak
                # was reset) mid-search: the baseline no longer refers to
                # this measurement.
                self.hit("memory_tracer_restarted")
                return False
            self._last_peak_bytes = peak
            growth = max(0, current - self.baseline_traced_bytes)
            if growth > self.observed_peak_bytes:
                self.observed_peak_bytes = growth
            if growth > self.budget.max_memory_bytes:
                self.hit("max_memory_bytes")
                return False
        return True

    @property
    def outcome(self) -> str:
        if any(reason in self.limits_hit
               for reason in ("max_wall_seconds", "max_memory_bytes",
                              "memory_tracer_lost",
                              "memory_tracer_restarted")):
            return "resource_exhausted"
        return "truncated" if self.limits_hit else "completed"


def candidates(train, max_candidates=12000, observed_inputs=(), stats=None,
               *, dev=None, state=None):
    """Yield shallow first; deepen only when development data rejects shallow.

    Stage 2 is signature-directed: instead of enumerating every
    (mid, terminal, op) combination and evaluating each, it compares
    evaluation signatures over the training inputs and only emits the
    combinations guaranteed to fit, plus constant completions for
    constant offsets/quotients. Relevant mids are visited first by
    residual-variance then complexity ranking; the full search space
    remains covered (dedup only removes observational equivalents and
    AST duplicates).

    ``dev`` is the development partition that decides whether a shallow
    rule is suitable. Passing it is what makes early stopping sound: a
    rule that fits only the training rows is not a reason to stop.
    """
    if state is None:
        state = SearchState(SearchBudget(max_candidates=max_candidates))
    dev = list(dev or [])
    leaves = leaf_expressions(train[0]["inputs"])
    numeric = [expr for expr, v in leaves if type(v) is int]
    string = [expr for expr, v in leaves if type(v) is str]
    train_inputs = [e["inputs"] for e in train]
    dev_inputs = [e["inputs"] for e in dev]
    cheap_inputs = train_inputs + dev_inputs
    all_inputs = train_inputs + list(observed_inputs)
    n_train = len(train_inputs)
    outputs = tuple(e["output"] for e in train)
    seen_fp = set()
    seen_cheap = set()
    seen_full = set()
    cheap_sigs = {}
    full_sigs = {}
    if stats is not None:
        stats["signature_checks"] = 0
        stats["limits_hit"] = []

    def spend():
        ok = state.spend_signature()
        if stats is not None:
            stats["signature_checks"] = state.signature_checks
            stats["limits_hit"] = list(state.limits_hit)
        return ok

    def cheap_signature(ast):
        key = fingerprint(ast)
        if key not in cheap_sigs:
            cheap_sigs[key] = _signature(ast, cheap_inputs)
        return cheap_sigs[key]

    def full_signature(ast):
        key = fingerprint(ast)
        if key not in full_sigs:
            full_sigs[key] = _signature(ast, all_inputs)
        return full_sigs[key]

    def fits_training(sig):
        for (kind, value), out in zip(sig, outputs):
            if kind != type(out).__name__ or value != out:
                return False
        return True

    def unique(stream):
        for ast in stream:
            if not state.check_resources():
                yield None
                return
            fp = fingerprint(ast)
            if fp in seen_fp:
                continue
            seen_fp.add(fp)
            if depth(ast) > state.budget.max_expression_depth:
                state.depth_excluded += 1
                state.hit("max_expression_depth")
                continue
            if not spend():
                yield None
                return
            # Enumeration only needs the labeled inputs. Probe inputs are
            # used to keep genuinely distinct fits as ambiguity rivals,
            # not to price every non-fitting candidate.
            cheap = cheap_signature(ast)
            fit = fits_training(cheap[:n_train])
            if cheap in seen_cheap:
                if not fit:
                    continue
                full = full_signature(ast)
                if full in seen_full:
                    continue
                seen_full.add(full)
                if state.candidates >= state.budget.max_candidates:
                    state.hit("max_candidates")
                    yield None
                    return
                state.candidates += 1
                yield ast
                continue
            seen_cheap.add(cheap)
            if fit:
                seen_full.add(full_signature(ast))
            if state.candidates >= state.budget.max_candidates:
                state.hit("max_candidates")
                yield None
                return
            state.candidates += 1
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
        yield ast, 1, state.candidates, exceeded
    if exceeded:
        return
    # Deepening is bounded and only requested when no shallow rule fits
    # both the training rows and the development partition.
    if any(_matches(ast, train, outputs) and _matches(ast, dev)
           for ast in first_results):
        return
    if not all(type(o) is int for o in outputs):
        # Stage 2 only covers numeric operators.
        return
    shallow = [x for x in first_results
               if x["op"] in {"add", "sub", "mul", "min", "max", "absdiff", "neg", "abs"}]

    def resid_var(ast):
        sig = cheap_signature(ast)
        if any(s is _EVAL_ERR for s in sig[:n_train]):
            return None
        res = []
        for o, s in zip(outputs, sig[:n_train]):
            if s[0] != "int":
                return None
            res.append(o - s[1])
        mean = sum(res) / len(res)
        return sum((v - mean) ** 2 for v in res) / len(res)

    # Deterministic relevance ordering: residual over the training
    # outputs first, then expression complexity, then fingerprint. Every
    # mid is still covered; the ordering only decides what the budget
    # reaches first.
    shallow.sort(key=lambda m: (
        (lambda v: (v is None, v or 0.0))(resid_var(m)),
        cost(m),
        fingerprint(m)))

    terminals = numeric + [{"op": "const", "value": v} for v in (-2, -1, 0, 1, 2, 3)]
    term_sigs = []
    seen_term = set()
    for tast in terminals:
        ts = cheap_signature(tast)
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
            if not state.check_resources():
                return
            ms = cheap_signature(mid)
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
                    if not spend():
                        return
                    if _combine(op, ms, ts) == outputs:
                        yield {"op": op, "args": [mid, tast]}
                    if op == "sub" and _combine(op, ts, ms) == outputs:
                        yield {"op": op, "args": [tast, mid]}
    for ast in unique(second()):
        yield ast, 2, state.candidates, ast is None


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


def _check_partition(train, dev, holdout):
    """Require disjoint, schema-consistent train/dev/holdout partitions."""
    schema = input_schema(train[0]["inputs"])
    out_type = type(train[0]["output"])
    seen = set()
    partitions = [("training", train), ("development", dev)]
    if holdout is not dev:
        partitions.append(("holdout", holdout))
    for label, examples in partitions:
        inputs = [canonical(x["inputs"]) for x in examples]
        if len(set(inputs)) != len(inputs):
            raise InvalidInput(f"{label} examples must have distinct input records")
        if seen.intersection(inputs):
            raise InvalidInput(
                f"{label} inputs must not overlap training or development")
        seen.update(inputs)
        for x in examples:
            if input_schema(x["inputs"]) != schema:
                raise InvalidInput(
                    f"{label} inputs must have the same schema as training inputs")
            if type(x["output"]) is not out_type:
                raise InvalidInput(f"{label} output type differs from training")


def _search_once(train, dev, observed, probes, state, proposals, use_z3):
    fits = []
    stage = 1
    outputs = tuple(e["output"] for e in train)
    for ast, stage, examined, exceeds in candidates(
            train, observed_inputs=observed, dev=dev, state=state):
        if exceeds or ast is None:
            break
        if _matches(ast, train, outputs):
            fits.append(ast)
    for ast in proposals or []:
        try:
            validate_ast(ast)
            if _matches(ast, train) and fingerprint(ast) not in {fingerprint(x) for x in fits}:
                fits.append(ast)
        except (InvalidInput, KeyError, TypeError):
            continue

    def dev_failures(ast):
        return sum(1 for ex in dev if not _matches(ast, [ex]))

    # Development data decides selection: a cheaper rule that fails the
    # development partition never outranks a rule that fits it.
    fits.sort(key=lambda x: (dev_failures(x), cost(x), fingerprint(x)))
    best = fits[0] if fits else None
    ambiguous = None
    if best is not None:
        for rival in fits[1:]:
            witness = _witness(best, rival, probes)
            if not witness and use_z3:
                from .smt import bounded_disagreement
                witness, _ = bounded_disagreement(
                    best, rival, input_schema(train[0]["inputs"]))
            if witness:
                ambiguous = witness
                break
    return {"best": best, "fits": fits, "ambiguous": ambiguous, "stage": stage}


def induce(train, validation=None, *, namespace="default", max_candidates=12000,
           proposals=None, use_z3=False, budget=None, dev=None, holdout=None,
           counterexample_oracle=None, max_refinement_rounds=2):
    """Induce a bounded rule; never confuse fit with proof.

    ``dev`` is the development partition used for early stopping,
    candidate selection and refinement. When omitted, ``validation``
    serves that role for backward compatibility. ``holdout`` is the
    sealed partition used only for the final status; when omitted and
    ``dev`` is supplied, ``validation`` becomes the holdout if present.
    Without any sealed holdout the result reports ``holdout_sealed:
    false`` and its ``locally_validated`` status is selection evidence,
    not independent generalization evidence.

    ``counterexample_oracle(inputs) -> output`` labels distinguishing
    inputs when an authoritative function exists (for example a
    mathematical specification). Generated probes alone are never
    treated as ground truth.
    """
    namespace_name(namespace)
    if type(use_z3) is not bool:
        raise InvalidInput("use_z3 must be boolean")
    if use_z3:
        try:
            import z3  # noqa: F401 - availability probe; smt.py imports it
        except ImportError as exc:
            raise InvalidInput("Z3 requested but unavailable: pip install .[z3]") from exc
    if budget is None:
        budget = SearchBudget(max_candidates=max_candidates)
    elif not isinstance(budget, SearchBudget):
        raise InvalidInput("budget must be a SearchBudget")
    elif max_candidates != 12000:
        raise InvalidInput("pass either max_candidates or budget, not both")
    if (type(max_refinement_rounds) is not int
            or not 0 <= max_refinement_rounds <= 8):
        raise InvalidInput("max_refinement_rounds must be an integer in [0,8]")
    if counterexample_oracle is not None and not callable(counterexample_oracle):
        raise InvalidInput("counterexample_oracle must be callable")

    original_train = check_examples(train, minimum=3)
    legacy = check_examples(validation or [])
    dev_examples = check_examples(dev) if dev is not None else legacy
    sealed = holdout is not None or (dev is not None and validation is not None)
    if holdout is not None:
        holdout_examples = check_examples(holdout)
    elif dev is not None and validation is not None:
        holdout_examples = legacy
    elif dev is not None:
        holdout_examples = []
    else:
        holdout_examples = dev_examples
    _check_partition(original_train, dev_examples, holdout_examples)
    if proposals is not None and (not isinstance(proposals, list) or len(proposals) > 10):
        raise InvalidInput("proposals must be a list of at most 10 AST objects")

    probe_list = list(generated_probes(original_train[0]["inputs"]))
    observed = [x["inputs"] for x in dev_examples] + probe_list
    state = SearchState(budget)
    state.start()
    try:
        examples = list(original_train)
        rounds = 0
        counterexamples_added = 0
        oracle_calls = 0

        def quality(result):
            """Rank a search across refinement rounds.

            A rule beats no rule; then fewer development failures, no
            remaining ambiguity, lower complexity, and finally
            fingerprint.
            """
            candidate = result["best"]
            if candidate is None:
                return (1, 0, 0, 0, "")
            return (
                0,
                sum(1 for ex in dev_examples if not _matches(candidate, [ex])),
                0 if result["ambiguous"] is None else 1,
                cost(candidate),
                fingerprint(candidate),
            )

        search = _search_once(
            examples, dev_examples, observed, probe_list, state, proposals, use_z3)
        reported = search
        while True:
            best = search["best"]
            if best is None:
                break
            failures = [ex for ex in dev_examples if not _matches(best, [ex])]
            if failures and rounds < max_refinement_rounds:
                examples = examples + failures
                counterexamples_added += len(failures)
                rounds += 1
                refined = _search_once(
                    examples, dev_examples, observed, probe_list,
                    state, proposals, use_z3)
                search = refined
                if refined["best"] is None:
                    # The added counterexamples are unsatisfiable by this
                    # grammar; keep the best rule that fit the original
                    # examples instead of erasing the diagnosis.
                    break
                if quality(refined) < quality(reported):
                    reported = refined
                    continue
                # The refinement did not improve development performance;
                # keep the earlier diagnosis rather than overfit the
                # counterexample set.
                break
            witness = search["ambiguous"]
            if (witness is not None and counterexample_oracle is not None
                    and rounds < max_refinement_rounds):
                try:
                    label = counterexample_oracle(witness["inputs"])
                except (InvalidInput, KeyError, TypeError, ValueError):
                    label = None
                oracle_calls += 1
                if label is not None and type(label) is type(original_train[0]["output"]):
                    examples = examples + [
                        {"inputs": witness["inputs"], "output": label}]
                    counterexamples_added += 1
                    rounds += 1
                    refined = _search_once(
                        examples, dev_examples, observed, probe_list,
                        state, proposals, use_z3)
                    search = refined
                    if refined["best"] is None:
                        break
                    if quality(refined) <= quality(reported):
                        # Equal quality is still progress here: the new
                        # oracle label eliminated one rival, and the next
                        # round can label the next distinguishing input.
                        reported = refined
                        continue
                    break
            break
    finally:
        state.close()

    best = reported["best"]
    ambiguous = reported["ambiguous"]
    stage = reported["stage"]
    fitting = len(reported["fits"])
    holdout_passes = (sum(_matches(best, [ex]) for ex in holdout_examples)
                      if best else 0)
    dev_passes = sum(_matches(best, [ex]) for ex in dev_examples) if best else 0
    outcome = state.outcome
    truncated = outcome != "completed"
    if not best:
        status = "search_incomplete" if truncated else "no_rule"
    elif truncated:
        status = "search_incomplete"
    elif len(holdout_examples) >= 2 and holdout_passes != len(holdout_examples):
        # A rule that fails the holdout is not promotion evidence even if
        # several train-fitting rivals also disagree off-sample.
        status = "validation_failed"
    elif ambiguous:
        status = "ambiguous"
    elif len(holdout_examples) < 2:
        status = "provisional"
    else:
        status = "locally_validated"
    scope = ("bounded grammar, observed examples, deterministic unlabeled probes"
             + (" and optional bounded Z3 equivalence checks" if use_z3 else ""))
    scope += ("; sealed holdout" if sealed
              else "; validation also drove selection, so this is not independent "
                   "generalization evidence")
    scope += "; not a mathematical or independent generalization proof"
    return {
        "namespace": namespace,
        "status": status,
        "rule": best,
        "schema": input_schema(original_train[0]["inputs"]),
        "train_count": len(original_train),
        "validation_count": len(holdout_examples),
        "validation_passed": holdout_passes,
        "dev_count": len(dev_examples),
        "dev_passed": dev_passes,
        "holdout_count": len(holdout_examples),
        "holdout_passed": holdout_passes,
        "holdout_sealed": sealed,
        "train_digest": digest(original_train),
        "validation_digest": digest(holdout_examples),
        "candidates_evaluated": state.candidates,
        "signature_checks": state.signature_checks,
        "fitting_hypotheses": fitting,
        "search_depth": stage,
        "search_truncated": truncated,
        "search_outcome": outcome,
        "limits_hit": list(state.limits_hit),
        "observed_peak_bytes": state.observed_peak_bytes,
        "memory_limit_source": (
            "tracemalloc_incremental" if state.memory_check_enabled else None),
        "budget": budget.as_dict(),
        "refinement_rounds": rounds,
        "counterexamples_added": counterexamples_added,
        "oracle_calls": oracle_calls,
        "distinguishing_probe": ambiguous,
        "verification_scope": scope,
    }
