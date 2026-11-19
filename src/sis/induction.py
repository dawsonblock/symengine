"""Bounded enumeration + falsification probes; never confuse fit with proof.

Search is a typed, cost-ordered, budget-bounded enumeration
(:mod:`sis.synthesis`): leaves and small constants first, then exact
small-integer affine fits, then pool programs of increasing cost with
goal-directed completions, and finally one-level conditionals when no
unconditional rule fits. A rule stops the search only when it also fits
the *development* examples; fitting training data alone is not a reason
to stop. Development data is model selection; a sealed holdout, when
supplied, is the only set used for the final generalization status.

After selection, a rival scan resumes the same enumerator to the end of
its declared space and reports the rule ``ambiguous`` when another rule
fits every labelled row but disagrees on an unlabeled probe. A
conditional rule is ``provisional`` unless the holdout exercises both of
its branches.

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
from .expression import (CONDITIONAL, GRAMMAR_VERSION, OPS, cost, depth, evaluate,
                         fingerprint, validate_ast)
from . import synthesis

#: Version of the search procedure. With ``GRAMMAR_VERSION`` it is stamped
#: on every induction result; promotion and sealed evaluation re-run the
#: search and refuse a result produced under another engine or grammar.
ENGINE_VERSION = "sis-induce-2"


def leaf_expressions(inputs):
    values = []
    for name, value in sorted(inputs.items()):
        if isinstance(value, list):
            values.extend(({"op": "item", "name": name, "index": i}, x) for i, x in enumerate(value))
        else:
            values.append(({"op": "field", "name": name}, value))
    return values


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
    """Yield ``(ast, depth, candidates_examined, exhausted)`` for training fits.

    Runs the typed enumerator over its whole unconditional space (no early
    stop) and yields every distinct program that fits ``train``, cheapest
    first. When the budget stops the enumeration, a final ``(None, ...,
    True)`` marks the hypothesis set as incomplete. ``observed_inputs``
    are unlabeled probes that keep observationally distinct fits apart.
    """
    if state is None:
        state = SearchState(SearchBudget(max_candidates=max_candidates))
    engine = synthesis.Engine(
        train, list(dev or []), list(observed_inputs), state,
        depth_budget=state.budget.max_expression_depth)
    while engine.step():
        pass
    if stats is not None:
        stats["signature_checks"] = state.signature_checks
        stats["limits_hit"] = list(state.limits_hit)
    fits = sorted(engine.fit_order, key=lambda p: (p.cost, fingerprint(p.ast)))
    for prog in fits:
        yield prog.ast, prog.depth, state.candidates, False
    if engine.exhausted:
        yield None, engine.level_reached, state.candidates, True


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


_EXTRA_INT_PROBES = (3, 4, 7, 10, -7, 25, -12, 100)
_EXTRA_STR_PROBES = ("abc", "hello", "aB", "zz", "abcd", "xyzzy", "a1")


def extended_probes(train_inputs, limit=160):
    """Deterministic unlabeled probes for the grammar-2 ops.

    ``generated_probes`` varies each leaf over a small fixed set. These add
    values that separate the new operations (divisors and remainders,
    longer strings for slices and containment) and data-derived boundary
    values: every observed integer and its neighbours, and records where
    two integer leaves are equal, so ``lt``/``le`` and threshold rivals are
    told apart. They are never labels.
    """
    rows = [dict(x) for x in train_inputs[:2]]
    if not rows:
        return []
    leaves = []
    for name, value in sorted(rows[0].items()):
        if isinstance(value, list):
            leaves.extend((name, i, x) for i, x in enumerate(value))
        else:
            leaves.append((name, None, value))
    observed = {}
    for inputs in train_inputs:
        for name, idx, _ in leaves:
            value = inputs[name] if idx is None else inputs[name][idx]
            bucket = observed.setdefault((name, idx), [])
            if value not in bucket:
                bucket.append(value)
    seen = {canonical(x) for x in train_inputs}
    out = []

    def make(base, changes):
        record = {k: list(v) if isinstance(v, list) else v for k, v in base.items()}
        for name, idx, value in changes:
            if idx is None:
                record[name] = value
            else:
                record[name][idx] = value
        return record

    def feed(record):
        key = canonical(record)
        if key in seen:
            return False
        seen.add(key)
        out.append(record)
        return len(out) >= limit

    for base in rows:
        for name, idx, value in leaves:
            if type(value) is int:
                values = list(_EXTRA_INT_PROBES)
                for v in sorted(x for x in observed[(name, idx)] if type(x) is int):
                    values.extend((v - 1, v + 1))
            elif type(value) is str:
                values = list(_EXTRA_STR_PROBES)
                values.extend(x + x for x in observed[(name, idx)][:3]
                              if type(x) is str and len(x) <= 32)
            else:
                values = [False, True]
            for v in values:
                if type(v) is int and abs(v) > 1_000_000_000:
                    continue
                if feed(make(base, [(name, idx, v)])):
                    return out
        ints = [(n, i, v) for n, i, v in leaves if type(v) is int]
        for (an, ai, _av), (bn, bi, _bv) in product(ints, ints):
            if (an, ai) == (bn, bi):
                continue
            source = base[an] if ai is None else base[an][ai]
            if feed(make(base, [(bn, bi, source)])):
                return out
    return out


def _interleave(first, second):
    out = []
    for a, b in zip(first, second):
        out.extend((a, b))
    longer = first if len(first) > len(second) else second
    out.extend(longer[min(len(first), len(second)):])
    return out


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


def _sig_witness(engine, best, rival):
    """First probe where two engine programs both evaluate and differ."""
    left, right = engine.full_sig(best), engine.full_sig(rival)
    for inputs, a, b in zip(engine.probes, left, right):
        if a is synthesis.ERR or b is synthesis.ERR:
            continue
        if type(a) is not type(b) or a != b:
            return {"inputs": inputs, "candidate_output": a, "alternative_output": b}
    return None


def _rival_witness(engine, best, rival, use_z3, schema):
    """Witness that ``rival`` differs from ``best``; probes first, then z3."""
    progs = engine.prog_by_fp
    bp, rp = progs.get(fingerprint(best)), progs.get(fingerprint(rival))
    if bp is not None and rp is not None:
        witness = _sig_witness(engine, bp, rp)
    else:
        witness = _witness(best, rival, engine.probes)
    if not witness and use_z3:
        from .smt import bounded_disagreement
        witness, _ = bounded_disagreement(best, rival, schema)
    return witness


def _search_depth(engine):
    """Expression depth the primary search covered (for reporting)."""
    if engine.conditionals_run:
        return synthesis.TEMPLATE_DEPTH
    if engine.level_reached >= 4:
        return synthesis.SEARCH_DEPTH
    return 1 if engine.level_reached <= 2 else 2


def _search_once(train, dev, observed, probes, state, proposals, use_z3):
    """One selection pass over ``train`` with ``dev`` as selection data.

    Runs the enumerator until a program fits training and development
    data (finishing that stage), or to the end of its unconditional space
    and then the conditional stage. Only training and development rows are
    ever seen here; holdout rows never are.
    """
    engine = synthesis.Engine(
        train, dev, probes, state,
        depth_budget=state.budget.max_expression_depth)
    while engine.step():
        if engine.has_dev_fit():
            break
    if (not engine.exhausted and engine.horizon_reached
            and not engine.has_dev_fit()):
        engine.run_conditionals()
    outputs = tuple(e["output"] for e in train)
    fits = []
    seen = set()
    for prog in engine.fit_order:
        fp = fingerprint(prog.ast)
        if fp in seen or not _matches(prog.ast, train, outputs):
            continue
        seen.add(fp)
        fits.append(prog.ast)
    for ast in proposals or []:
        try:
            validate_ast(ast)
            if _matches(ast, train) and fingerprint(ast) not in seen:
                seen.add(fingerprint(ast))
                fits.append(ast)
        except (InvalidInput, KeyError, TypeError):
            continue

    def dev_failures(ast):
        return sum(1 for ex in dev if not _matches(ast, [ex]))

    # Development data decides selection: a cheaper rule that fails the
    # development partition never outranks a rule that fits it.
    failures = {fingerprint(x): dev_failures(x) for x in fits}
    fits.sort(key=lambda x: (failures[fingerprint(x)], cost(x), fingerprint(x)))
    best = fits[0] if fits else None
    ambiguous = None
    if best is not None:
        schema = input_schema(train[0]["inputs"])
        limit = failures[fingerprint(best)]
        ceiling = cost(best) + RIVAL_COST_MARGIN
        for rival in fits[1:]:
            if cost(rival) > ceiling:
                continue
            # A rival refuted by more development rows than the selected
            # rule is not a competing explanation of the same evidence.
            if failures[fingerprint(rival)] > limit:
                continue
            witness = _rival_witness(engine, best, rival, use_z3, schema)
            if witness:
                ambiguous = witness
                break
    return {"best": best, "fits": fits, "ambiguous": ambiguous,
            "stage": _search_depth(engine), "engine": engine}


MAX_POST_SELECTION_ORACLE_CALLS = 4
RIVAL_SCAN_CANDIDATES = 12000
RIVAL_SCAN_SIGNATURE_CHECKS = 300_000
RIVAL_SCAN_WALL_SECONDS = 10.0


def _rival_scan(engine, budget):
    """Resume the selection enumerator to the end of its space.

    The primary search stops as soon as a rule fits training and
    development data, so costlier rules were never compared with it. This
    scan continues the same enumeration under its own budget, so it never
    truncates the primary search; it changes only the final status, never
    which rule is selected. Returns a report whose ``complete`` says
    whether the declared space was exhausted.
    """
    if engine.horizon_reached and engine.conditionals_run:
        return {"performed": True, "complete": not engine.exhausted,
                "candidates": 0}
    sub = SearchState(SearchBudget(
        max_candidates=min(RIVAL_SCAN_CANDIDATES, budget.max_candidates),
        max_signature_checks=min(RIVAL_SCAN_SIGNATURE_CHECKS,
                                 budget.max_signature_checks),
        max_wall_seconds=min(RIVAL_SCAN_WALL_SECONDS, budget.max_wall_seconds),
        max_memory_bytes=budget.max_memory_bytes,
        max_expression_depth=budget.max_expression_depth))
    sub.start()
    primary = engine.state
    engine.state = sub
    try:
        while engine.step():
            pass
        if engine.horizon_reached and not engine.conditionals_run:
            # Conditionals are rivals too: a clamp such as max(1, min(a, 2))
            # and if_lt(a, k, 1, 2) for every unpinned threshold k fit the
            # same rows but disagree between the observed values.
            engine.run_conditionals()
    finally:
        engine.state = primary
        sub.close()
    complete = (engine.horizon_reached and engine.conditionals_run
                and not engine.exhausted and not sub.limits_hit)
    return {"performed": True, "complete": complete, "candidates": sub.candidates}


#: A rival counts against the selected rule only when it is at most this
#: much costlier. Far costlier programs that happen to fit every labelled
#: row (``(a + b) - 1 // abs(b)`` against ``a + b``) are always available in
#: a rich grammar; the margin keeps the ambiguity check to alternatives of
#: comparable simplicity, as the old depth-2 rival scan did.
RIVAL_COST_MARGIN = 4


def _deep_rivals(engine, best, selected_fits, labelled, use_z3, schema):
    """Fits consistent with every labelled row that differ from ``best``.

    Candidates are the selection pass's fits (proposals included) and every
    fit the engine has found, including those of the rival scan.
    """
    best_fp = fingerprint(best)
    ceiling = cost(best) + RIVAL_COST_MARGIN
    pool = {fingerprint(x): x for x in selected_fits}
    for prog in engine.fit_order:
        pool.setdefault(fingerprint(prog.ast), prog.ast)
    for fp, ast in sorted(pool.items(), key=lambda kv: (cost(kv[1]), kv[0])):
        if cost(ast) > ceiling:
            break
        if fp == best_fp or not _matches(ast, labelled):
            continue
        witness = _rival_witness(engine, best, ast, use_z3, schema)
        if witness:
            yield ast, witness


def _selection_rival(search, selection_rows, budget, use_z3):
    """Resume the selection engine and return a rival's witness, if any."""
    engine = search.get("engine")
    best = search["best"]
    if engine is None or best is None:
        return None
    _rival_scan(engine, budget)
    schema = input_schema(selection_rows[0]["inputs"])
    for _rival, witness in _deep_rivals(
            engine, best, search["fits"], selection_rows, use_z3, schema):
        return witness
    return None


def branch_coverage(rule, examples):
    """Count ``examples`` taking each branch of a top-level conditional."""
    from .expression import _eval
    spec = OPS[rule["op"]]
    counts = {"then": 0, "else": 0}
    for ex in examples:
        try:
            left = _eval(rule["left"], ex["inputs"])
            right = _eval(rule["right"], ex["inputs"])
            counts["then" if spec.fn(left, right) else "else"] += 1
        except (InvalidInput, KeyError, IndexError, TypeError):
            continue
    return counts


MIN_HOLDOUT_EXAMPLES = 2

#: The sealed holdout must carry at least this much evidence before a rule
#: is locally validated. A holdout row whose label is common among the
#: labelled outputs is weak evidence: under the label distribution a wrong
#: rule matches it by chance with probability equal to that label's
#: frequency. Three binary holdout rows carry about 3 bits, so a coin-flip
#: rule would pass them one time in eight; such results stay provisional.
HOLDOUT_EVIDENCE_BITS = 4.0


def holdout_evidence_bits(holdout, labelled):
    """Bits of evidence the holdout carries under the labelled-output marginal."""
    from collections import Counter
    from math import log2
    counts = Counter(canonical(e["output"]) for e in labelled)
    total = sum(counts.values())
    if not total:
        return 0.0
    return sum(-log2(counts[canonical(e["output"])] / total)
               for e in holdout if counts[canonical(e["output"])])


def check_engine_version(result):
    """Raise ``RuleRejected`` unless ``result`` was induced under this engine.

    Promotion and sealed evaluation re-run the search and compare outputs;
    a result from another grammar or engine would only show up as an
    opaque mismatch, so the version stamp is checked first.
    """
    from .errors import RuleRejected
    grammar = result.get("grammar_version") if isinstance(result, dict) else None
    engine = result.get("engine_version") if isinstance(result, dict) else None
    if grammar != GRAMMAR_VERSION or engine != ENGINE_VERSION:
        raise RuleRejected(
            f"induction result was produced under grammar {grammar!r} and "
            f"engine {engine!r}, but this installation runs grammar "
            f"{GRAMMAR_VERSION!r} and engine {ENGINE_VERSION!r}; re-induce "
            "under the current engine")
    return result


def legacy_split(validation):
    """Deterministically split legacy ``validation`` into (dev, holdout).

    The holdout is the trailing ``max(2, ceil(n / 2))`` rows (all rows
    when fewer than two); the leading rows are development data. The two
    parts are disjoint, so the holdout never influences selection.
    """
    rows = list(validation)
    n = len(rows)
    size = n if n < MIN_HOLDOUT_EXAMPLES else max(
        MIN_HOLDOUT_EXAMPLES, n - n // 2)
    return rows[:n - size], rows[n - size:]


def induce(train, validation=None, *, namespace="default", max_candidates=12000,
           proposals=None, use_z3=False, budget=None, dev=None, holdout=None,
           counterexample_oracle=None, max_refinement_rounds=2,
           hard_limits=None, hard_limit_receipt_seed=None,
           hard_limit_receipt_key_id="resource-receipt"):
    """Induce a bounded rule; never confuse fit with proof.

    ``dev`` is the development partition used for early stopping,
    candidate selection and refinement. ``holdout`` is the sealed
    partition used only for the final status; when ``dev`` is supplied
    without ``holdout``, ``validation`` becomes the holdout if present.
    A legacy call with only ``validation`` splits it with
    :func:`legacy_split` into disjoint development rows and holdout rows,
    so the holdout never drives selection. Without any holdout rows the
    result reports ``holdout_sealed: false`` and cannot be
    ``locally_validated``.

    ``counterexample_oracle(inputs) -> output`` labels distinguishing
    inputs when an authoritative function exists (for example a
    mathematical specification). Generated probes alone are never
    treated as ground truth.

    ``hard_limits`` routes the search through
    :func:`sis.enforced_induction.run_induction_enforced`. It is a mapping
    with required ``memory_limit_bytes`` and ``wall_seconds`` and optional
    ``cpu_seconds`` and ``process_limit``. The child runs under OS limits
    and a parent monotonic deadline; a resource-exhausted run reports
    ``status: resource_exhausted`` and can never be mistaken for a
    successful search. ``hard_limit_receipt_seed`` signs the returned
    resource receipt so a later evaluation decision can authenticate it.
    Omitting ``hard_limits`` keeps the in-process cooperative budget,
    which is diagnostic only.
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

    if hard_limits is not None:
        if not isinstance(hard_limits, dict):
            raise InvalidInput("hard_limits must be a mapping")
        unknown = set(hard_limits) - {
            "memory_limit_bytes", "wall_seconds",
            "cpu_seconds", "process_limit"}
        if unknown:
            raise InvalidInput(
                "hard_limits has unknown keys: " + ", ".join(sorted(unknown)))
        if ("memory_limit_bytes" not in hard_limits
                or "wall_seconds" not in hard_limits):
            raise InvalidInput(
                "hard_limits requires memory_limit_bytes and wall_seconds")
        from .enforced_induction import run_induction_enforced
        enforced = run_induction_enforced(
            train, validation, dev=dev, holdout=holdout, budget=budget,
            namespace=namespace, proposals=proposals, use_z3=use_z3,
            max_refinement_rounds=max_refinement_rounds,
            memory_limit_bytes=hard_limits["memory_limit_bytes"],
            timeout_seconds=hard_limits["wall_seconds"],
            cpu_seconds=hard_limits.get("cpu_seconds"),
            process_limit=hard_limits.get("process_limit"),
            receipt_seed=hard_limit_receipt_seed,
            receipt_key_id=hard_limit_receipt_key_id)
        result = enforced.result
        if result is None:
            return {
                "namespace": namespace,
                "status": "resource_exhausted",
                "grammar_version": GRAMMAR_VERSION,
                "engine_version": ENGINE_VERSION,
                "search_outcome": "resource_exhausted",
                "limits_hit": enforced.receipt.resource_limits_hit,
                "budget_enforcement": "hard_subprocess",
                "enforcement_receipt": enforced.receipt.to_dict(),
            }
        result = dict(result)
        result["budget_enforcement"] = "hard_subprocess"
        result["enforcement_receipt"] = enforced.receipt.to_dict()
        if not enforced.hard_limits_verified:
            result["status"] = "resource_exhausted"
            result["search_outcome"] = "resource_exhausted"
        return result

    original_train = check_examples(train, minimum=3)
    legacy = check_examples(validation or [])
    partition_mode = "explicit"
    if dev is None and holdout is None:
        # Legacy two-way call: split ``validation`` into disjoint
        # development and holdout rows so the holdout is never used for
        # selection, early stopping or refinement.
        dev_examples, holdout_examples = legacy_split(legacy)
        partition_mode = "legacy_split"
    else:
        dev_examples = check_examples(dev) if dev is not None else legacy
        if holdout is not None:
            holdout_examples = check_examples(holdout)
        elif validation is not None:
            holdout_examples = legacy
        else:
            holdout_examples = []
    sealed = bool(holdout_examples)
    _check_partition(original_train, dev_examples, holdout_examples)
    if proposals is not None and (not isinstance(proposals, list) or len(proposals) > 10):
        raise InvalidInput("proposals must be a list of at most 10 AST objects")

    probe_list = _interleave(
        list(generated_probes(original_train[0]["inputs"])),
        extended_probes([x["inputs"] for x in original_train]))
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
            if (witness is None and counterexample_oracle is not None
                    and rounds < max_refinement_rounds
                    and state.outcome == "completed"):
                # The selection pass stopped at the first stage with a fit,
                # so costlier rivals were never compared. With an oracle,
                # look for one consistent with the selection data (never
                # the holdout) so its distinguishing input can be labelled.
                witness = _selection_rival(
                    search, examples + dev_examples, budget, use_z3)
                search["ambiguous"] = witness
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
    rival_scan = {"performed": False, "complete": None, "candidates": 0}
    labelled = examples + dev_examples + holdout_examples
    schema = input_schema(original_train[0]["inputs"])
    engine = reported.get("engine")
    if best is not None and engine is not None:
        # Ambiguity is decided against every labelled row: a rival counts
        # when it fits training, development and holdout rows alike and
        # disagrees with the selected rule on an unlabeled probe. The
        # holdout can refute a rival here but never changes which rule was
        # selected. A result that would otherwise be locally validated is
        # first checked against the rest of the declared space.
        searched_ambiguity = ambiguous
        if (outcome == "completed"
                and len(holdout_examples) >= MIN_HOLDOUT_EXAMPLES
                and dev_passes == len(dev_examples)
                and holdout_passes == len(holdout_examples)):
            rival_scan = _rival_scan(engine, budget)
        # An authoritative oracle may label a distinguishing input after
        # selection only when the selection pass itself was unambiguous
        # (otherwise the refinement loop above already consulted it).
        consult_oracle = (searched_ambiguity is None
                          and counterexample_oracle is not None)
        out_type = type(original_train[0]["output"])
        ambiguous = None
        refuted = set()
        while True:
            found = None
            for rival, witness in _deep_rivals(
                    engine, best, reported["fits"], labelled, use_z3, schema):
                if fingerprint(rival) not in refuted:
                    found = (rival, witness)
                    break
            if found is None:
                break
            ambiguous = found[1]
            if (not consult_oracle
                    or oracle_calls >= MAX_POST_SELECTION_ORACLE_CALLS
                    + max_refinement_rounds):
                break
            try:
                label = counterexample_oracle(ambiguous["inputs"])
            except (InvalidInput, KeyError, TypeError, ValueError):
                label = None
            oracle_calls += 1
            if (type(label) is not out_type
                    or label != ambiguous["candidate_output"]):
                break
            labelled = labelled + [
                {"inputs": ambiguous["inputs"], "output": label}]
            refuted.add(fingerprint(found[0]))
            ambiguous = None
        fitting = len({fingerprint(x) for x in reported["fits"]}
                      | {fingerprint(p.ast) for p in engine.fit_order})
    if rival_scan["performed"] and rival_scan["complete"]:
        ambiguity_scope = "full_search_space"
    elif rival_scan["performed"]:
        ambiguity_scope = "bounded_rival_scan"
    else:
        ambiguity_scope = "selection_pool_only"
    evidence_bits = holdout_evidence_bits(
        holdout_examples, original_train + dev_examples + holdout_examples)
    coverage = None
    if best is not None and best["op"] in CONDITIONAL:
        coverage = branch_coverage(best, holdout_examples)
    truncated = outcome != "completed"
    if not best:
        status = "search_incomplete" if truncated else "no_rule"
    elif truncated:
        status = "search_incomplete"
    elif holdout_examples and holdout_passes != len(holdout_examples):
        # A rule that fails the holdout is not promotion evidence even if
        # several train-fitting rivals also disagree off-sample.
        status = "validation_failed"
    elif dev_passes != len(dev_examples):
        # Nor is a rule that still fails development rows after refinement.
        status = "validation_failed"
    elif ambiguous:
        status = "ambiguous"
    elif len(holdout_examples) < MIN_HOLDOUT_EXAMPLES:
        status = "provisional"
    elif evidence_bits < HOLDOUT_EVIDENCE_BITS:
        # Too little independent evidence: a chance agreement with the
        # holdout labels is not unlikely enough to call this validated.
        status = "provisional"
    elif coverage is not None and min(coverage.values()) < 1:
        # A conditional whose holdout never exercises one branch has no
        # independent evidence for that branch.
        status = "provisional"
    else:
        status = "locally_validated"
    scope = ("bounded grammar, observed examples, deterministic unlabeled probes"
             + (" and optional bounded Z3 equivalence checks" if use_z3 else ""))
    scope += ("; sealed holdout disjoint from selection data" if sealed
              else "; no holdout rows, so this is not generalization evidence")
    scope += "; not a mathematical or independent generalization proof"
    return {
        "namespace": namespace,
        "status": status,
        "rule": best,
        "grammar_version": GRAMMAR_VERSION,
        "engine_version": ENGINE_VERSION,
        "schema": input_schema(original_train[0]["inputs"]),
        "train_count": len(original_train),
        "validation_count": len(holdout_examples),
        "validation_passed": holdout_passes,
        "dev_count": len(dev_examples),
        "dev_passed": dev_passes,
        "holdout_count": len(holdout_examples),
        "holdout_passed": holdout_passes,
        "holdout_sealed": sealed,
        "partition_mode": partition_mode,
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
        "ambiguity_scope": ambiguity_scope,
        "rival_scan": rival_scan,
        "branch_holdout_coverage": coverage,
        "holdout_evidence_bits": round(evidence_bits, 3),
        "rule_depth": depth(best) if best is not None else None,
        "verification_scope": scope,
    }
