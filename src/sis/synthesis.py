"""Typed bottom-up program enumeration for rule induction (learner v2).

The engine builds programs in increasing cost, one pool per result type
(``int``, ``str``, ``bool``), from the grammar registry in
:mod:`sis.expression`. Two programs that agree on every training and
development row *and* on a fixed prefix of unlabeled probes are
observationally equivalent and only the cheaper one is kept, so pruning
never merges functions that the ambiguity check could still tell apart on
those probes.

Search stages, in order:

1. Leaves, small constants and unary ops on leaves (pool levels 1-3).
2. Exact small-integer affine fitting ``c0 + sum(ci * xi)`` over at most
   three integer features: first the leaves, then the leaves plus one of
   the best-ranked depth-2 programs (residual variance ordering). Only an
   exact integer solution is accepted.
3. Goal-directed completions of the programs so far, then pool levels
   4..``HORIZON_COST`` with every new program ``X`` completed as it is
   added: ``add``/``sub``/``mul`` are inverted and the required operand is
   looked up in the pool (or is a constant); ``min``/``max``/``absdiff``
   and ``floordiv``/``mod`` by a constant are checked forward; for strings
   a prefix or suffix of the outputs is looked up for ``concat``.
   Completions start only after the affine stage, so a wide schema whose
   rule is affine in a ranked product is not charged quadratic work first.
   Within a stage the cheap hash-lookup completions run as each program is
   added; its forward checks (about one per terminal) are queued and run at
   the end of the same stage, so on a wide schema a ``mul`` pair is
   completed before the forward work of every earlier ``add`` pair has used
   the budget. Each fit keeps the position the one-pass order would have
   found it at (``DEFER_FORWARD``), so a search that is not truncated finds
   the same fits and selects the same rule either way.
4. One-level conditionals (``if_lt`` / ``if_eq``), run by the caller when
   no unconditional rule fits training and development data, and by the
   rival scan: predicates compare leaves with each other or with observed
   constants, the training rows are split by the predicate and each branch
   is learned separately from the same pool (plus constants and small
   affine fits).

The declared search space is: pool programs of cost <= ``HORIZON_COST`` and
depth <= ``POOL_DEPTH``; completions of depth <= ``SEARCH_DEPTH``; affine and
conditional templates of depth <= ``TEMPLATE_DEPTH``. A search that covers
it reports ``completed``. ``SearchBudget.max_expression_depth`` below the
engine's own depth excludes programs the space contains and is reported as
``max_expression_depth``. Candidate, signature, wall-clock and memory limits
end the engine (``exhausted``) and are recorded on the active
:class:`~sis.induction.SearchState`. Between stages the engine is suspended,
so a caller that stopped early can resume it under another budget.

A zero divisor (or any other evaluation error) makes a program invalid on
that row only; such a program never fits a row it cannot evaluate.
"""
from __future__ import annotations

from fractions import Fraction
from itertools import combinations

from .errors import InvalidInput
from .expression import OPS, ops_of
from .validation import MAX_MAGNITUDE, canonical

HORIZON_COST = 7
POOL_DEPTH = 3
SEARCH_DEPTH = 4
TEMPLATE_DEPTH = 5
INT_CONSTS = (-2, -1, 0, 1, 2, 3)
DIVISORS = tuple(range(2, 13))
SLICE_LENGTHS = (1, 2, 3)
AFFINE_MAX_FEATURES = 3
AFFINE_COEF_BOUND = 100
AFFINE_FEATURE_POOL = 8
AFFINE_EXTRA = 3
WIDE_RANK_FEATURES = 12
PROBE_SIGNATURE = 48
MIN_BRANCH_ROWS = 2
BRANCH_ALTERNATIVES = 2
BRANCH_MAX_COST = 5
MAX_PREDICATE_CONSTS = 24
MAX_EQ_CONSTS = 8
MAX_ALTERNATIVES_PER_KEY = 3
PAIRWISE_LIMIT = 48
#: Queue each stage's forward completions behind its hash-lookup ones.
#: ``False`` restores the one-pass order; the equivalence tests use it.
DEFER_FORWARD = True


class _Err:
    __slots__ = ()

    def __repr__(self):
        return "ERR"


ERR = _Err()


class Budget(Exception):
    """Raised inside the engine when the active SearchState refuses work."""


class Prog:
    """A program with its static type, cost, depth and row signature."""

    __slots__ = ("ast", "cost", "depth", "type", "sig", "kids", "op",
                 "has_leaf", "_psig", "_full")

    def __init__(self, ast, cost, depth, type_, sig, kids=(), has_leaf=True):
        self.ast = ast
        self.cost = cost
        self.depth = depth
        self.type = type_
        self.sig = sig
        self.kids = kids
        self.op = ast["op"]
        self.has_leaf = has_leaf
        self._psig = None
        self._full = None


def _apply(spec, values):
    try:
        return spec.fn(*values)
    except (InvalidInput, TypeError, ValueError, OverflowError, IndexError):
        return ERR


def _combine(spec, sigs):
    """Row-wise op application over child signatures."""
    out = []
    for values in zip(*sigs):
        if any(v is ERR for v in values):
            out.append(ERR)
        else:
            out.append(_apply(spec, values))
    return tuple(out)


def _cond_combine(spec, left, right, then, other):
    out = []
    for lv, rv, tv, ev in zip(left, right, then, other):
        if lv is ERR or rv is ERR:
            out.append(ERR)
            continue
        taken = _apply(spec, (lv, rv))
        if taken is ERR:
            out.append(ERR)
        else:
            out.append(tv if taken else ev)
    return tuple(out)


def _same(value, expected):
    return value is not ERR and type(value) is type(expected) and value == expected


def _leaf_values(inputs, ast):
    value = inputs[ast["name"]]
    if ast["op"] == "item":
        return value[ast["index"]]
    return value


class Engine:
    """Resumable typed enumerator over one train/dev partition.

    ``rows`` are the training inputs followed by the development inputs.
    ``probes`` are unlabeled inputs: the first ``PROBE_SIGNATURE`` refine
    observational equivalence, all of them separate distinct fits.
    """

    def __init__(self, train, dev, probes, state, *, depth_budget):
        self.state = state
        self.train = list(train)
        self.dev = list(dev)
        self.inputs = [e["inputs"] for e in self.train] + [e["inputs"] for e in self.dev]
        self.n_train = len(self.train)
        self.outputs = tuple(e["output"] for e in self.train)
        self.dev_outputs = tuple(e["output"] for e in self.dev)
        self.out_type = type(self.outputs[0]).__name__
        self.probes = list(probes)
        self.sig_probes = self.probes[:PROBE_SIGNATURE]
        self.depth_budget = depth_budget
        self.levels = {}
        self.pool = []
        self.index = {}
        self.train_index = {}
        self.fits = {}
        self.fit_order = []
        self.leaves = []
        self.consts = {}
        self.level_reached = 0
        self.horizon_reached = False
        self.stage = "start"
        self.exhausted = False
        self.conditionals_run = False
        self.completing = False
        self.prog_by_fp = {}
        # Discovery positions: every fit is stamped with the position the
        # one-pass order would have found it at, (slot, phase, sequence).
        # A slot is one program's completion (or a stage boundary); phase 1
        # is its forward checks. A duplicate keeps the earlier position, so
        # deferring forward checks never changes which program represents
        # a function.
        self.defer_forward = DEFER_FORWARD
        self.fit_pos = {}
        self._fit_index = {}
        self._forward_queue = []
        self._slot = 0
        self._phase = 0
        self._offer_seq = 0
        self.replaced_fits = 0
        self.useful = _useful_types(self.out_type)
        self._work = self._steps()

    # ------------------------------------------------------------ budget
    def spend(self):
        if not self.state.check_resources() or not self.state.spend_signature():
            raise Budget()

    def admit(self):
        if self.state.candidates >= self.state.budget.max_candidates:
            self.state.hit("max_candidates")
            raise Budget()
        self.state.candidates += 1

    def depth_ok(self, depth, engine_limit):
        """True if within the space; exclusions by the budget are reported."""
        if depth > engine_limit:
            return False
        if depth > self.depth_budget:
            self.state.depth_excluded += 1
            self.state.hit("max_expression_depth")
            return False
        return True

    # --------------------------------------------------------- signatures
    def psig(self, prog):
        """Signature over the probe prefix used for equivalence pruning."""
        if prog._psig is None:
            prog._psig = self._probe_sig(prog, self.sig_probes, "_psig")
        return prog._psig

    def full_sig(self, prog):
        """Signature over every probe; separates distinct training fits."""
        if prog._full is None:
            prog._full = self._probe_sig(prog, self.probes, "_full")
        return prog._full

    def _probe_sig(self, prog, probes, attr):
        op = prog.op
        if op in ("field", "item"):
            out = []
            for inputs in probes:
                try:
                    value = _leaf_values(inputs, prog.ast)
                    out.append(ERR if isinstance(value, list) else value)
                except (KeyError, IndexError, TypeError):
                    out.append(ERR)
            return tuple(out)
        if op == "const":
            return (prog.ast["value"],) * len(probes)
        kid_sigs = []
        for kid in prog.kids:
            cached = getattr(kid, attr)
            if cached is None:
                cached = self._probe_sig(kid, probes, attr)
                setattr(kid, attr, cached)
            kid_sigs.append(cached)
        spec = OPS[op]
        if spec.shape == "cond":
            return _cond_combine(spec, *kid_sigs)
        return _combine(spec, kid_sigs)

    # ---------------------------------------------------------- the pool
    def _add(self, prog):
        """Add a program to the pool unless an equivalent one exists."""
        train_sig = prog.sig[:self.n_train]
        if all(v is ERR for v in train_sig):
            return None
        key = (prog.type, prog.sig)
        bucket = self.index.get(key)
        if bucket is not None:
            mine = self.psig(prog)
            for other in bucket:
                if self.psig(other) == mine:
                    return None
        self.admit()
        if bucket is None:
            self.index[key] = [prog]
        else:
            bucket.append(prog)
        self.levels.setdefault(prog.cost, []).append(prog)
        self.pool.append(prog)
        tkey = (prog.type, train_sig)
        alts = self.train_index.setdefault(tkey, [])
        if len(alts) < MAX_ALTERNATIVES_PER_KEY:
            alts.append(prog)
        if prog.type == self.out_type:
            self._offer_fit(prog)
        return prog

    def _offer_fit(self, prog):
        sig = prog.sig
        for value, expected in zip(sig[:self.n_train], self.outputs):
            if not _same(value, expected):
                return False
        key = (sig, self.full_sig(prog))
        self._offer_seq += 1
        pos = (self._slot, self._phase, self._offer_seq)
        held = self.fits.get(key)
        if held is not None:
            if pos < self.fit_pos[key]:
                # A deferred forward check reached a function that the
                # one-pass order finds here first: this program represents
                # it, exactly as before. Not a new candidate.
                self.fits[key] = prog
                self.fit_pos[key] = pos
                self.fit_order[self._fit_index[key]] = prog
                old_fp = canonical(held.ast)
                if self.prog_by_fp.get(old_fp) is held:
                    del self.prog_by_fp[old_fp]
                self.prog_by_fp.setdefault(canonical(prog.ast), prog)
                self.replaced_fits += 1
            return False
        self.fits[key] = prog
        self.fit_pos[key] = pos
        self._fit_index[key] = len(self.fit_order)
        self.fit_order.append(prog)
        self.prog_by_fp.setdefault(canonical(prog.ast), prog)
        return True

    def dev_failures(self, prog):
        dev_sig = prog.sig[self.n_train:]
        return sum(1 for v, o in zip(dev_sig, self.dev_outputs) if not _same(v, o))

    def has_dev_fit(self):
        return any(self.dev_failures(p) == 0 for p in self.fit_order)

    # --------------------------------------------------------- builders
    def leaf(self, ast):
        values = []
        for inputs in self.inputs:
            value = _leaf_values(inputs, ast)
            values.append(value)
        return Prog(ast, OPS[ast["op"]].cost, 1, type(values[0]).__name__,
                    tuple(values))

    def const(self, value):
        key = (type(value).__name__, value)
        if key not in self.consts:
            ast = {"op": "const", "value": value}
            self.consts[key] = Prog(ast, OPS["const"].cost, 1, type(value).__name__,
                                    (value,) * len(self.inputs), has_leaf=False)
        return self.consts[key]

    def node(self, op, kids):
        spec = OPS[op]
        if spec.shape == "unary":
            ast = {"op": op, "arg": kids[0].ast}
        elif spec.shape == "binary":
            ast = {"op": op, "args": [kids[0].ast, kids[1].ast]}
        else:
            ast = {"op": op, "left": kids[0].ast, "right": kids[1].ast,
                   "then": kids[2].ast, "else": kids[3].ast}
        if spec.shape == "cond":
            sig = _cond_combine(spec, *(k.sig for k in kids))
            type_ = kids[2].type
        else:
            sig = _combine(spec, [k.sig for k in kids])
            type_ = spec.result_type
        return Prog(ast, spec.cost + sum(k.cost for k in kids),
                    1 + max(k.depth for k in kids), type_, sig, tuple(kids),
                    any(k.has_leaf for k in kids))

    # ------------------------------------------------------------- stages
    def step(self):
        """Advance by one stage; return False when no more work is possible.

        Between stages the engine is suspended, so a caller that stopped
        early (a rule already fits) can resume it later, for example with a
        separate rival-scan budget swapped into ``state``. A budget refusal
        inside a stage ends the engine for good (``exhausted``); the
        refusal reason is recorded on the active :class:`SearchState`.
        """
        if self.exhausted or self.horizon_reached:
            return False
        try:
            self.stage = next(self._work)
            return True
        except StopIteration:
            self.horizon_reached = True
            return False
        except Budget:
            self.exhausted = True
            return False

    def _steps(self):
        for value in INT_CONSTS:
            self.const(value)
        # Goal-directed completions start only after the cheap stages, so a
        # wide schema whose rule the affine stage finds is not charged the
        # quadratic completion work first.
        self.completing = False
        for leaf_ast, _value in self._leaf_asts():
            prog = self.leaf(leaf_ast)
            self.spend()
            self._add(prog)
            self.leaves.append(prog)
        if len(set((type(o).__name__, o) for o in self.outputs)) == 1:
            prog = self.const(self.outputs[0])
            if self._offer_fit(prog):
                self.admit()
        self.level_reached = 2
        yield "leaves"
        self._level(3)
        self.level_reached = 3
        yield "level"
        if self.out_type == "int":
            self._affine_stage()
            yield "affine"
        self.completing = True
        for prog in list(self.pool):
            self._new_slot()
            self._complete(prog)
        self._drain_forward()
        yield "completions"
        for level in range(4, HORIZON_COST + 1):
            self._level(level)
            self._drain_forward()
            self.level_reached = level
            yield "level"

    def _new_slot(self):
        """Start a discovery slot: later fits sort after earlier ones."""
        self._slot += 1
        self._phase = 0

    def _drain_forward(self):
        """Run the stage's queued forward checks, each at its own slot."""
        queue, self._forward_queue = self._forward_queue, []
        top = self._slot
        try:
            for x, slot in queue:
                self._slot, self._phase = slot, 1
                self._forward_int(x)
        finally:
            # Whatever the next stage offers sorts after every forward fit.
            self._slot = top
            self._new_slot()

    def _leaf_asts(self):
        first = self.train[0]["inputs"]
        out = []
        for name, value in sorted(first.items()):
            if isinstance(value, list):
                out.extend(({"op": "item", "name": name, "index": i}, x)
                           for i, x in enumerate(value))
            else:
                out.append(({"op": "field", "name": name}, value))
        return out

    def _operands(self, cost, type_):
        if cost == OPS["const"].cost and type_ == "int":
            return [self.consts[("int", v)] for v in INT_CONSTS]
        return [p for p in self.levels.get(cost, ()) if p.type == type_]

    def _level(self, level):
        """Generate every pool program of exactly ``level`` cost."""
        for spec in OPS.values():
            if spec.result_type not in self.useful:
                continue
            if spec.shape == "unary":
                child_cost = level - spec.cost
                if child_cost < 1:
                    continue
                for child in self._operands(child_cost, spec.arg_types[0]):
                    if not child.has_leaf:
                        continue
                    self._try_node(spec.name, (child,))
            elif spec.shape == "binary" and spec.result_type != "any":
                self._binary_level(spec, level)

    def _binary_level(self, spec, level):
        budget = level - spec.cost
        t1, t2 = spec.arg_types
        if t1 == "any":
            types = [("int", "int"), ("str", "str"), ("bool", "bool")]
        else:
            types = [(t1, t2)]
        const_arg = spec.const_arg is not None
        for ta, tb in types:
            if const_arg:
                child_cost = budget - OPS["const"].cost
                if child_cost < 1:
                    continue
                for child in self._operands(child_cost, ta):
                    for n in SLICE_LENGTHS:
                        self._try_node(spec.name, (child, self.const(n)))
                continue
            for ca in range(1, budget):
                cb = budget - ca
                if spec.commutative and ta == tb and ca > cb:
                    continue
                left = self._operands(ca, ta)
                right = self._operands(cb, tb)
                for i, x in enumerate(left):
                    start = i if (spec.commutative and ta == tb and ca == cb) else 0
                    for y in right[start:]:
                        if not (x.has_leaf or y.has_leaf):
                            continue
                        if spec.name in ("floordiv", "mod") and (
                                not x.has_leaf
                                or (not y.has_leaf and y.ast["value"] in (0, 1, -1))):
                            # A constant numerator (``1 // x``) is an
                            # indicator function, not arithmetic; a divisor
                            # of 0 or +-1 is undefined or the identity.
                            continue
                        self._try_node(spec.name, (x, y))

    def _try_node(self, op, kids):
        depth = 1 + max(k.depth for k in kids)
        if not self.depth_ok(depth, POOL_DEPTH):
            return
        self._new_slot()
        self.spend()
        prog = self.node(op, kids)
        added = self._add(prog)
        if added is not None and self.completing:
            self._complete(added)

    # ------------------------------------------------------ completions
    def _fit_candidate(self, op, kids, engine_limit=SEARCH_DEPTH):
        if OPS[op].commutative and len(kids) == 2:
            kids = tuple(sorted(kids, key=lambda k: (k.cost, canonical(k.ast))))
        depth = 1 + max(k.depth for k in kids)
        if not self.depth_ok(depth, engine_limit):
            return None
        prog = self.node(op, kids)
        if self._offer_fit(prog):
            self.admit()
            return prog
        return None

    def _complete(self, x):
        """Goal-directed completions with ``x`` as one operand."""
        n = self.n_train
        xs = x.sig[:n]
        if any(v is ERR for v in xs):
            return
        outs = self.outputs
        if self.out_type == "int" and x.type == "int":
            self.spend()
            self._lookup_int(x, "add", tuple(o - v for o, v in zip(outs, xs)), first=True)
            self._lookup_int(x, "sub", tuple(v - o for o, v in zip(outs, xs)), first=True,
                             allow_const=False)
            self._lookup_int(x, "sub", tuple(o + v for o, v in zip(outs, xs)), first=False)
            if all(v != 0 for v in xs) and all(o % v == 0 for o, v in zip(outs, xs)):
                self._lookup_int(x, "mul", tuple(o // v for o, v in zip(outs, xs)),
                                 first=True, skip_consts=(0, 1))
            if x.depth <= 2:
                if self.defer_forward:
                    self._forward_queue.append((x, self._slot))
                else:
                    self._phase = 1
                    try:
                        self._forward_int(x)
                    finally:
                        self._phase = 0
        elif self.out_type == "str" and x.type == "str" and "concat" in OPS:
            self.spend()
            if all(type(o) is str and o.startswith(v) for o, v in zip(outs, xs)):
                rest = tuple(o[len(v):] for o, v in zip(outs, xs))
                self._lookup_str(x, rest, first=True)
            if all(type(o) is str and o.endswith(v) for o, v in zip(outs, xs)):
                rest = tuple(o[:len(o) - len(v)] for o, v in zip(outs, xs))
                self._lookup_str(x, rest, first=False)

    def _lookup_int(self, x, op, needed, *, first, allow_const=True, skip_consts=(0,)):
        if any(abs(v) > MAX_MAGNITUDE for v in needed):
            return
        if allow_const and len(set(needed)) == 1 and needed[0] not in skip_consts:
            if op != "mul" and needed[0] == 0:
                return
            c = self.const(needed[0])
            self._fit_candidate(op, (x, c) if first else (c, x))
        for q in self.train_index.get(("int", needed), ()):
            if not q.has_leaf:
                continue
            self._fit_candidate(op, (x, q) if first else (q, x))

    def _lookup_str(self, x, needed, *, first):
        if len(set(needed)) == 1:
            if needed[0] != "":
                c = self.const(needed[0])
                self._fit_candidate("concat", (x, c) if first else (c, x))
            return
        for q in self.train_index.get(("str", needed), ()):
            self._fit_candidate("concat", (x, q) if first else (q, x))

    def _forward_int(self, x):
        n = self.n_train
        outs = self.outputs
        terminals = [p for p in self.leaves if p.type == "int"]
        terminals += [self.consts[("int", v)] for v in INT_CONSTS]
        small = [p for p in self.levels.get(3, ()) if p.type == "int"]
        if len(terminals) + len(small) <= PAIRWISE_LIMIT:
            # Few small operands: also pair x with unary programs of leaves,
            # so max(abs(a), abs(b)) is in the space as a rival.
            terminals += small
        for name in ("min", "max", "absdiff"):
            if name not in OPS:
                continue
            spec = OPS[name]
            for t in terminals:
                if t is x:
                    continue
                self.spend()
                if _combine(spec, [x.sig[:n], t.sig[:n]]) == outs:
                    self._fit_candidate(name, (x, t))
        for name in ("floordiv", "mod"):
            if name not in OPS:
                continue
            spec = OPS[name]
            for k in DIVISORS:
                self.spend()
                c = self.const(k)
                if all(_same(v, o) for v, o in zip(_combine(spec, [x.sig[:n], c.sig[:n]]), outs)):
                    self._fit_candidate(name, (x, c))

    # ----------------------------------------------------------- affine
    def _affine_stage(self):
        self._new_slot()
        ints = [p for p in self.leaves if p.type == "int"]
        n = self.n_train
        outs = self.outputs
        if len(ints) > AFFINE_FEATURE_POOL:
            ints = self._rank_by_correlation(ints)[:AFFINE_FEATURE_POOL]
        for size in range(1, min(AFFINE_MAX_FEATURES, len(ints)) + 1):
            for features in combinations(ints, size):
                self.spend()
                self._affine_fit(features, list(range(n)), outs)
        extras = self._rank_extra_features()
        for extra in extras[:AFFINE_EXTRA]:
            for size in range(0, min(AFFINE_MAX_FEATURES - 1, len(ints)) + 1):
                for features in combinations(ints, size):
                    self.spend()
                    self._affine_fit((extra,) + features, list(range(n)), outs)

    def _rank_by_correlation(self, feats):
        n = self.n_train
        outs = [float(o) for o in self.outputs]
        mo = sum(outs) / n

        def score(p):
            self.spend()
            xs = [float(v) for v in p.sig[:n]]
            mx = sum(xs) / n
            cov = sum((x - mx) * (o - mo) for x, o in zip(xs, outs))
            vx = sum((x - mx) ** 2 for x in xs)
            vo = sum((o - mo) ** 2 for o in outs)
            if vx == 0 or vo == 0:
                return 0.0
            return abs(cov) / (vx * vo) ** 0.5

        scored = [(-score(p), i, p) for i, p in enumerate(feats)]
        scored.sort(key=lambda item: (item[0], item[1]))
        return [p for _, _, p in scored]

    def _rank_extra_features(self):
        """Depth-2 integer programs ranked by residual variance (heuristic)."""
        ints = [p for p in self.leaves if p.type == "int"]
        if len(ints) > WIDE_RANK_FEATURES:
            ints = self._rank_by_correlation(ints)[:WIDE_RANK_FEATURES]
        n = self.n_train
        outs = self.outputs
        cands = []
        for p in self.levels.get(3, ()):
            if p.type == "int" and p.depth == 2:
                cands.append(p)
        for spec in ops_of("binary", arg_types=("int", "int"), result_type="int"):
            for i, x in enumerate(ints):
                for j, y in enumerate(ints):
                    if spec.commutative and j < i:
                        continue
                    if not self.depth_ok(2, POOL_DEPTH):
                        continue
                    self.spend()
                    cands.append(self.node(spec.name, (x, y)))
        scored = []
        for index, p in enumerate(cands):
            xs = p.sig[:n]
            if any(v is ERR or type(v) is not int for v in xs):
                continue
            res = [o - v for o, v in zip(outs, xs)]
            mean = sum(res) / n
            var = sum((r - mean) ** 2 for r in res) / n
            if len(set(xs)) == 1:
                continue
            scored.append((var, p.cost, index, p))
        scored.sort(key=lambda item: item[:3])
        seen = set()
        out = []
        for _, _, _, p in scored:
            key = p.sig[:n]
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
        return out

    def _affine_fit(self, features, rows, outs):
        """Offer the exact integer affine fit of ``features`` as a training fit."""
        prog = self._affine_rows(features, rows, tuple(outs[r] for r in rows))
        if prog is not None and self._offer_fit(prog):
            self.admit()
        return prog

    def _affine_prog(self, c0, terms):
        acc = None
        for coef, feat in terms:
            mag = abs(coef)
            term = feat if mag == 1 else self.node("mul", (self.const(mag), feat))
            if acc is None:
                if coef < 0:
                    term = (self.node("neg", (feat,)) if mag == 1
                            else self.node("mul", (self.const(coef), feat)))
                acc = term
            else:
                acc = self.node("add" if coef > 0 else "sub", (acc, term))
        if c0 > 0:
            acc = self.node("add", (acc, self.const(c0)))
        elif c0 < 0:
            acc = self.node("sub", (acc, self.const(-c0)))
        if not self.depth_ok(acc.depth, TEMPLATE_DEPTH):
            return None
        return acc

    # ------------------------------------------------------ conditionals
    def run_conditionals(self):
        """Run the conditional stage under the active budget."""
        self.conditionals_run = True
        self._new_slot()
        try:
            return self.conditionals()
        except Budget:
            self.exhausted = True
            return 0

    def conditionals(self):
        """One-level conditional synthesis; adds fits, returns their count."""
        n = self.n_train
        outs = self.outputs
        cond_ops = [name for name in ("if_lt", "if_eq") if name in OPS]
        if not cond_ops or n < 2 * MIN_BRANCH_ROWS:
            return 0
        groups = {}
        order = []
        for pred in self._predicates(cond_ops):
            self.spend()
            op, left, right = pred
            spec = OPS[op]
            truth = []
            for lv, rv in zip(left.sig[:n], right.sig[:n]):
                taken = ERR if (lv is ERR or rv is ERR) else _apply(spec, (lv, rv))
                truth.append(taken)
            if any(t is ERR for t in truth):
                continue
            split = tuple(bool(t) for t in truth)
            if split.count(True) < MIN_BRANCH_ROWS or split.count(False) < MIN_BRANCH_ROWS:
                continue
            if split not in groups:
                groups[split] = []
                order.append(split)
            groups[split].append(pred)
        added = 0
        for split in order:
            then_rows = [i for i in range(n) if split[i]]
            else_rows = [i for i in range(n) if not split[i]]
            then_alts = self._branch_solutions(then_rows, outs)
            if not then_alts:
                continue
            else_alts = self._branch_solutions(else_rows, outs)
            if not else_alts:
                continue
            for op, left, right in groups[split]:
                for t in then_alts:
                    for e in else_alts:
                        if t.sig == e.sig and self.full_sig(t) == self.full_sig(e):
                            continue
                        if self._fit_candidate(op, (left, right, t, e),
                                               engine_limit=TEMPLATE_DEPTH):
                            added += 1
        return added

    def _predicates(self, cond_ops):
        ints = [p for p in self.leaves if p.type == "int"]
        strs = [p for p in self.leaves if p.type == "str"]
        bools = [p for p in self.leaves if p.type == "bool"]
        n = self.n_train
        preds = []
        if "if_lt" in cond_ops:
            for x in ints:
                for y in ints:
                    if x is not y:
                        preds.append(("if_lt", x, y))
            for x in ints:
                observed = sorted(set(x.sig[:n]))
                consts = []
                for v in observed:
                    for k in (v, v + 1):
                        if k not in consts:
                            consts.append(k)
                if len(consts) > MAX_PREDICATE_CONSTS:
                    consts = consts[:MAX_PREDICATE_CONSTS]
                for k in consts:
                    preds.append(("if_lt", x, self.const(k)))
        if "if_eq" in cond_ops:
            for group in (ints, strs):
                for i, x in enumerate(group):
                    for y in group[i + 1:]:
                        preds.append(("if_eq", x, y))
                for x in group:
                    observed = sorted(set(x.sig[:n]))
                    if len(observed) <= MAX_EQ_CONSTS:
                        for k in observed:
                            preds.append(("if_eq", x, self.const(k)))
            for x in bools:
                preds.append(("if_eq", x, self.const(True)))
        return preds

    def _branch_solutions(self, rows, outs):
        """Cheapest distinct programs matching ``outs`` on ``rows``."""
        target = tuple(outs[i] for i in rows)
        found = []
        seen = set()

        def accept(prog):
            key = (prog.sig, self.full_sig(prog))
            if key in seen:
                return
            seen.add(key)
            found.append(prog)

        if len(set((type(v).__name__, v) for v in target)) == 1:
            accept(self.const(target[0]))
        for prog in self.pool:
            if prog.cost > BRANCH_MAX_COST:
                break
            if prog.type != self.out_type:
                continue
            self.spend()
            if all(_same(prog.sig[i], o) for i, o in zip(rows, target)):
                accept(prog)
            if len(found) >= BRANCH_ALTERNATIVES:
                break
        if len(found) < BRANCH_ALTERNATIVES and self.out_type == "int":
            ints = [p for p in self.leaves if p.type == "int"]
            if len(ints) > AFFINE_FEATURE_POOL:
                ints = self._rank_by_correlation(ints)[:AFFINE_FEATURE_POOL]
            for size in (1, 2):
                for features in combinations(ints, size):
                    self.spend()
                    prog = self._affine_rows(features, rows, target)
                    if prog is not None:
                        accept(prog)
                    if len(found) >= BRANCH_ALTERNATIVES:
                        break
        found.sort(key=lambda p: p.cost)
        return found[:BRANCH_ALTERNATIVES]

    def _affine_rows(self, features, rows, target):
        k = len(features)
        if len(rows) < k + 1:
            return None
        matrix = []
        for r, o in zip(rows, target):
            vals = [f.sig[r] for f in features]
            if any(v is ERR or type(v) is not int for v in vals):
                return None
            matrix.append([Fraction(1)] + [Fraction(v) for v in vals] + [Fraction(o)])
        solution = _solve_exact(matrix, k + 1)
        if solution is None or any(c.denominator != 1 for c in solution):
            return None
        coeffs = [int(c) for c in solution]
        if any(c == 0 for c in coeffs[1:]) or any(abs(c) > AFFINE_COEF_BOUND for c in coeffs[1:]):
            return None
        if abs(coeffs[0]) > MAX_MAGNITUDE:
            return None
        return self._affine_prog(coeffs[0], list(zip(coeffs[1:], features)))


def _useful_types(out_type):
    """Pool types from which some op chain can reach ``out_type``."""
    useful = {out_type}
    changed = True
    while changed:
        changed = False
        for spec in OPS.values():
            if spec.shape in ("unary", "binary") and spec.result_type in useful:
                for t in spec.arg_types:
                    if t == "any":
                        continue
                    if t not in useful:
                        useful.add(t)
                        changed = True
    return frozenset(useful)


def _solve_exact(rows, unknowns):
    """Unique exact solution of an overdetermined linear system, or None."""
    m = [list(r) for r in rows]
    n_rows = len(m)
    pivot_row = 0
    pivots = []
    for col in range(unknowns):
        pivot = None
        for r in range(pivot_row, n_rows):
            if m[r][col] != 0:
                pivot = r
                break
        if pivot is None:
            return None  # rank deficient: the coefficients are not determined
        m[pivot_row], m[pivot] = m[pivot], m[pivot_row]
        lead = m[pivot_row][col]
        m[pivot_row] = [v / lead for v in m[pivot_row]]
        for r in range(n_rows):
            if r != pivot_row and m[r][col] != 0:
                factor = m[r][col]
                m[r] = [a - factor * b for a, b in zip(m[r], m[pivot_row])]
        pivots.append(col)
        pivot_row += 1
    for r in range(pivot_row, n_rows):
        if m[r][unknowns] != 0:
            return None  # inconsistent: no exact affine fit
    return [m[i][unknowns] for i in range(unknowns)]
