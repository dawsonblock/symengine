"""Induction benchmark corpus: seeded generators for ~60 target functions.

Each target has a category, a per-field input domain, an *oracle* (a plain
Python function used only by the benchmark to label rows and to score a
learned rule on fresh points) and a seed. ``materialize()`` draws a fixed
train/validation split per target; ``corpus.json`` next to this file is
that materialisation, committed so every engine version is measured on the
same rows. ``tests/test_induction_corpus.py`` checks the two agree.

Categories:

- ``linear``: small-integer affine functions of up to three fields.
- ``nonlinear``: products, squares, min/max and absolute differences.
- ``divmod``: floor division and remainder by constants or fields.
- ``piecewise``: one-level conditionals on ``<`` or ``==``. Splits are
  drawn so the legacy validation split leaves at least one holdout row on
  every branch and training covers every branch at least twice.
- ``string``: case, reversal, concatenation, prefixes/suffixes, length,
  containment and integer formatting.
- ``distractor``: outputs that no rule explains (hash-derived labels,
  noisy near-rules). A learner should return ``no_rule`` / ``ambiguous`` /
  ``validation_failed`` here, never ``locally_validated``.

The oracles are benchmark-side ground truth only. Nothing here is loaded by
the SIS engine, and the engine never evaluates Python code.

``reference`` is the intended rule written in the SIS v2 grammar (data,
used only for a structural-match metric); ``None`` where the grammar has no
natural single expression (distractors).
"""
from __future__ import annotations

import hashlib
import json
import random

TRAIN_ROWS = 10
VALIDATION_ROWS = 6  # legacy split: 3 development rows, 3 holdout rows
FRESH_POINTS = 300


# --- AST helpers for reference rules (data only) -------------------------

def F(name):
    return {"op": "field", "name": name}


def C(value):
    return {"op": "const", "value": value}


def B(op, a, b):
    return {"op": op, "args": [a, b]}


def U(op, a):
    return {"op": op, "arg": a}


def IF(op, left, right, then, other):
    return {"op": op, "left": left, "right": right, "then": then,
            "else": other}


# --- domains --------------------------------------------------------------

def I(lo, hi, *, nonzero=False):
    return {"kind": "int", "lo": lo, "hi": hi, "nonzero": nonzero}


def S(alphabet="abcdxyz", lo=1, hi=6):
    return {"kind": "str", "alphabet": alphabet, "lo": lo, "hi": hi}


def BOOL():
    return {"kind": "bool"}


def widen(domain):
    """Fresh-point domain: a wider box than training, same constraints."""
    if domain["kind"] == "int":
        lo, hi = domain["lo"], domain["hi"]
        span = max(1, hi - lo)
        new_lo = lo - span // 2 if lo < 0 else lo
        return {**domain, "lo": new_lo, "hi": hi + span // 2}
    if domain["kind"] == "str":
        return {**domain, "lo": max(0, domain["lo"] - 1), "hi": domain["hi"] + 2}
    return domain


def draw(rng, domain):
    kind = domain["kind"]
    if kind == "int":
        while True:
            value = rng.randint(domain["lo"], domain["hi"])
            if not (domain["nonzero"] and value == 0):
                return value
    if kind == "str":
        length = rng.randint(domain["lo"], domain["hi"])
        return "".join(rng.choice(domain["alphabet"]) for _ in range(length))
    return rng.random() < 0.5


def _hash_int(inputs, modulus, salt):
    text = salt + json.dumps(inputs, sort_keys=True, separators=(",", ":"))
    return int(hashlib.sha256(text.encode("utf8")).hexdigest(), 16) % modulus


# --- targets ----------------------------------------------------------------

def T(name, category, fields, oracle, reference=None, *, branch=None,
      seed=None, fresh=None, pins=()):
    return {"name": name, "category": category, "fields": fields,
            "oracle": oracle, "reference": reference, "branch": branch,
            "seed": seed, "fresh": fresh, "pins": list(pins)}


a, b, c, d, n, s, t = (F(x) for x in "abcdnst")
abc = {"a": I(-9, 9), "b": I(-9, 9), "c": I(-9, 9)}
ab = {"a": I(-9, 9), "b": I(-9, 9)}

TARGETS = [
    # ---------------------------------------------------------------- linear
    T("lin_2a_b_1", "linear", ab, lambda x: 2 * x["a"] + x["b"] + 1,
      B("add", B("add", B("mul", C(2), a), b), C(1))),
    T("lin_3a_2b", "linear", ab, lambda x: 3 * x["a"] + 2 * x["b"],
      B("add", B("mul", C(3), a), B("mul", C(2), b))),
    T("lin_a_minus_b_5", "linear", ab, lambda x: x["a"] - x["b"] + 5,
      B("add", B("sub", a, b), C(5))),
    T("lin_4a_minus_3", "linear", {"a": I(-9, 9), "d": I(-9, 9)},
      lambda x: 4 * x["a"] - 3, B("sub", B("mul", C(4), a), C(3))),
    T("lin_a_b_c", "linear", abc, lambda x: x["a"] + x["b"] + x["c"],
      B("add", B("add", a, b), c)),
    T("lin_2a_minus_b_minus_c", "linear", abc,
      lambda x: 2 * x["a"] - x["b"] - x["c"],
      B("sub", B("sub", B("mul", C(2), a), b), c)),
    T("lin_5a_7", "linear", {"a": I(-9, 9)}, lambda x: 5 * x["a"] + 7,
      B("add", B("mul", C(5), a), C(7))),
    T("lin_3b_minus_a", "linear", ab, lambda x: 3 * x["b"] - x["a"],
      B("sub", B("mul", C(3), b), a)),
    T("lin_a_2b_m3c_4", "linear", abc,
      lambda x: x["a"] + 2 * x["b"] - 3 * x["c"] + 4,
      B("add", B("sub", B("add", a, B("mul", C(2), b)), B("mul", C(3), c)),
        C(4))),
    T("lin_10_minus_a", "linear", {"a": I(-9, 9), "b": I(-9, 9)},
      lambda x: 10 - x["a"], B("sub", C(10), a)),
    # ------------------------------------------------------------- nonlinear
    T("nl_a_times_b", "nonlinear", ab, lambda x: x["a"] * x["b"],
      B("mul", a, b)),
    T("nl_ab_plus_c", "nonlinear", abc, lambda x: x["a"] * x["b"] + x["c"],
      B("add", B("mul", a, b), c)),
    T("nl_a_squared", "nonlinear", {"a": I(-9, 9), "b": I(-9, 9)},
      lambda x: x["a"] * x["a"], B("mul", a, a)),
    T("nl_a_sq_plus_b", "nonlinear", ab, lambda x: x["a"] * x["a"] + x["b"],
      B("add", B("mul", a, a), b)),
    T("nl_max_ab", "nonlinear", ab, lambda x: max(x["a"], x["b"]),
      B("max", a, b)),
    T("nl_min_ab_plus_1", "nonlinear", ab, lambda x: min(x["a"], x["b"]) + 1,
      B("add", B("min", a, b), C(1))),
    T("nl_absdiff", "nonlinear", ab, lambda x: abs(x["a"] - x["b"]),
      B("absdiff", a, b)),
    T("nl_ab_minus_a", "nonlinear", ab, lambda x: x["a"] * x["b"] - x["a"],
      B("sub", B("mul", a, b), a)),
    T("nl_sum_times_c", "nonlinear", abc,
      lambda x: (x["a"] + x["b"]) * x["c"], B("mul", B("add", a, b), c)),
    T("nl_max_abs", "nonlinear", ab,
      lambda x: max(abs(x["a"]), abs(x["b"])),
      B("max", U("abs", a), U("abs", b))),
    # ---------------------------------------------------------------- divmod
    T("dm_half", "divmod", {"a": I(-30, 30)}, lambda x: x["a"] // 2,
      B("floordiv", a, C(2))),
    T("dm_mod3", "divmod", {"a": I(-30, 30)}, lambda x: x["a"] % 3,
      B("mod", a, C(3))),
    T("dm_a_div_b", "divmod", {"a": I(0, 60), "b": I(1, 9)},
      lambda x: x["a"] // x["b"], B("floordiv", a, b),
      fresh={"a": I(-60, 120), "b": I(-9, 15, nonzero=True)}),
    T("dm_a_mod_b", "divmod", {"a": I(0, 60), "b": I(1, 9)},
      lambda x: x["a"] % x["b"], B("mod", a, b),
      fresh={"a": I(-60, 120), "b": I(-9, 15, nonzero=True)}),
    T("dm_mean_floor", "divmod", {"a": I(-20, 20), "b": I(-20, 20)},
      lambda x: (x["a"] + x["b"]) // 2, B("floordiv", B("add", a, b), C(2))),
    T("dm_parity", "divmod", {"a": I(-30, 30), "b": I(-30, 30)},
      lambda x: x["a"] % 2, B("mod", a, C(2))),
    T("dm_div3_plus_b", "divmod", {"a": I(-30, 30), "b": I(-9, 9)},
      lambda x: x["a"] // 3 + x["b"], B("add", B("floordiv", a, C(3)), b)),
    T("dm_last_digit", "divmod", {"n": I(0, 999)}, lambda x: x["n"] % 10,
      B("mod", n, C(10))),
    T("dm_tens", "divmod", {"n": I(0, 999)}, lambda x: x["n"] // 10,
      B("floordiv", n, C(10))),
    T("dm_prod_mod7", "divmod", {"a": I(0, 20), "b": I(0, 20)},
      lambda x: (x["a"] * x["b"]) % 7, B("mod", B("mul", a, b), C(7))),
    # ------------------------------------------------------------- piecewise
    # ``pins`` are labelled rows forced into training so the boundary of each
    # predicate is identifiable from data; without them several thresholds
    # fit every row and the honest answer is ``ambiguous``.
    T("pw_relu_like", "piecewise", {"a": I(-9, 9)},
      lambda x: x["a"] + 1 if x["a"] >= 0 else -2 * x["a"],
      IF("if_lt", a, C(0), B("mul", C(-2), a), B("add", a, C(1))),
      branch=lambda x: x["a"] < 0, pins=[{"a": -1}, {"a": 0}]),
    T("pw_gap_or_double", "piecewise", ab,
      lambda x: x["b"] - x["a"] if x["a"] < x["b"] else 2 * x["a"],
      IF("if_lt", a, b, B("sub", b, a), B("mul", C(2), a)),
      branch=lambda x: x["a"] < x["b"], pins=[{"a": 3, "b": 3}]),
    T("pw_eq_zero_else_sum", "piecewise", {"a": I(-3, 3), "b": I(-3, 3)},
      lambda x: 0 if x["a"] == x["b"] else x["a"] + x["b"],
      IF("if_eq", a, b, C(0), B("add", a, b)),
      branch=lambda x: x["a"] == x["b"], pins=[{"a": 2, "b": 2}]),
    T("pw_step", "piecewise", {"a": I(-9, 15), "b": I(-9, 9)},
      lambda x: 1 if x["a"] < 5 else 2,
      IF("if_lt", a, C(5), C(1), C(2)), branch=lambda x: x["a"] < 5,
      pins=[{"a": 4}, {"a": 5}]),
    T("pw_sum_or_diff", "piecewise", ab,
      lambda x: x["a"] + x["b"] if x["a"] < x["b"] else x["a"] - x["b"],
      IF("if_lt", a, b, B("add", a, b), B("sub", a, b)),
      branch=lambda x: x["a"] < x["b"], pins=[{"a": 4, "b": 4}]),
    T("pw_tax", "piecewise", {"a": I(0, 30)},
      lambda x: x["a"] if x["a"] < 10 else 2 * x["a"] - 10,
      IF("if_lt", a, C(10), a, B("sub", B("mul", C(2), a), C(10))),
      branch=lambda x: x["a"] < 10, pins=[{"a": 9}, {"a": 11}]),
    T("pw_flag_select", "piecewise",
      {"f": BOOL(), "a": I(-9, 9), "b": I(-9, 9)},
      lambda x: x["a"] if x["f"] else x["b"],
      IF("if_eq", F("f"), C(True), a, b), branch=lambda x: x["f"]),
    T("pw_small_zero_else_prod", "piecewise",
      {"a": I(0, 9), "b": I(-9, 9)},
      lambda x: 0 if x["a"] < 3 else x["a"] * x["b"],
      IF("if_lt", a, C(3), C(0), B("mul", a, b)),
      branch=lambda x: x["a"] < 3, pins=[{"a": 2, "b": 4}, {"a": 3, "b": 5}]),
    T("pw_clamp_offset", "piecewise", {"a": I(-9, 20)},
      lambda x: x["a"] + 3 if x["a"] < 8 else 11,
      IF("if_lt", a, C(8), B("add", a, C(3)), C(11)),
      branch=lambda x: x["a"] < 8, pins=[{"a": 7}, {"a": 9}]),
    T("pw_str_key", "piecewise",
      {"k": S("xyzw", 1, 1), "a": I(-9, 9)},
      lambda x: x["a"] * 2 if x["k"] == "x" else x["a"] + 7,
      IF("if_eq", F("k"), C("x"), B("mul", C(2), a), B("add", a, C(7))),
      branch=lambda x: x["k"] == "x",
      fresh={"k": S("xyzw", 1, 1), "a": I(-18, 18)}),
    # ---------------------------------------------------------------- string
    T("str_upper", "string", {"s": S(), "t": S()}, lambda x: x["s"].upper(),
      U("upper", s)),
    T("str_concat", "string", {"s": S(), "t": S()},
      lambda x: x["s"] + x["t"], B("concat", s, t)),
    T("str_concat_rev_order", "string", {"s": S(), "t": S()},
      lambda x: x["t"] + x["s"], B("concat", t, s)),
    T("str_reverse", "string", {"s": S(), "n": I(0, 9)},
      lambda x: x["s"][::-1], U("reverse", s)),
    T("str_len", "string", {"s": S(lo=0, hi=9), "t": S()},
      lambda x: len(x["s"]), U("len", s)),
    T("str_len_sum", "string", {"s": S(lo=0, hi=9), "t": S(lo=0, hi=9)},
      lambda x: len(x["s"]) + len(x["t"]),
      B("add", U("len", s), U("len", t))),
    T("str_prefix3", "string", {"s": S(lo=3, hi=8), "t": S()},
      lambda x: x["s"][:3], B("slice_prefix", s, C(3))),
    T("str_suffix2", "string", {"s": S(lo=2, hi=8), "t": S()},
      lambda x: x["s"][-2:], B("slice_suffix", s, C(2))),
    T("str_contains", "string",
      {"s": S("ab", 2, 6), "t": S("ab", 1, 2)},
      lambda x: x["t"] in x["s"], B("contains", s, t)),
    T("str_of_int", "string", {"n": I(-99, 999), "s": S()},
      lambda x: str(x["n"]), U("str_of_int", n)),
    T("str_label_number", "string", {"s": S(), "n": I(0, 99)},
      lambda x: x["s"] + str(x["n"]),
      B("concat", s, U("str_of_int", n))),
    T("str_upper_prefix", "string", {"s": S(lo=2, hi=8), "t": S()},
      lambda x: x["s"][:2].upper(), U("upper", B("slice_prefix", s, C(2)))),
    # ------------------------------------------------------------ distractor
    T("dis_hash_small", "distractor", ab,
      lambda x: _hash_int(x, 4, "dis1")),
    T("dis_hash_wide", "distractor", abc,
      lambda x: _hash_int(x, 50, "dis2") - 25),
    T("dis_hash_bool", "distractor", ab,
      lambda x: _hash_int(x, 2, "dis3") == 1),
    T("dis_hash_str", "distractor", {"s": S(), "t": S()},
      lambda x: ["red", "green", "blue"][_hash_int(x, 3, "dis4")]),
    T("dis_noisy_sum", "distractor", ab,
      lambda x: x["a"] + x["b"] + (
          _hash_int(x, 7, "dis5") - 3 if _hash_int(x, 3, "dis6") == 0 else 0)),
    T("dis_noisy_double", "distractor", {"a": I(-9, 9), "b": I(-9, 9)},
      lambda x: 2 * x["a"] + (1 if _hash_int(x, 4, "dis7") == 0 else 0)),
    T("dis_hash_list", "distractor",
      {"v": [I(-9, 9), I(-9, 9), I(-9, 9)]},
      lambda x: _hash_int(x, 10, "dis8")),
    T("dis_hash_mod_like", "distractor", {"n": I(0, 999)},
      lambda x: _hash_int(x, 10, "dis9")),
    T("dis_hash_str_len", "distractor", {"s": S(lo=0, hi=9)},
      lambda x: _hash_int(x, 9, "dis10")),
    T("dis_parity_noise", "distractor", {"a": I(-30, 30), "b": I(-9, 9)},
      lambda x: (x["a"] % 2) ^ (1 if _hash_int(x, 5, "dis11") == 0 else 0)),
]


def _draw_inputs(rng, fields):
    out = {}
    for name in sorted(fields):
        domain = fields[name]
        if isinstance(domain, list):
            out[name] = [draw(rng, item) for item in domain]
        else:
            out[name] = draw(rng, domain)
    return out


def _key(inputs):
    return json.dumps(inputs, sort_keys=True, separators=(",", ":"))


def _seed(target):
    if target["seed"] is not None:
        return target["seed"]
    return int(hashlib.sha256(target["name"].encode()).hexdigest()[:8], 16)


def legacy_holdout(validation):
    """Mirror ``sis.induction.legacy_split``: trailing max(2, n - n//2) rows."""
    n = len(validation)
    size = n if n < 2 else max(2, n - n // 2)
    return validation[n - size:]


def _split_ok(target, train, validation):
    if target["branch"] is None:
        return True
    branch = target["branch"]
    train_sides = [bool(branch(row["inputs"])) for row in train]
    hold_sides = {bool(branch(row["inputs"])) for row in legacy_holdout(validation)}
    return (train_sides.count(True) >= 3 and train_sides.count(False) >= 3
            and hold_sides == {True, False})


def materialize_target(target):
    rng = random.Random(_seed(target))
    for _attempt in range(2000):
        seen = set()
        rows = []
        while len(rows) < TRAIN_ROWS + VALIDATION_ROWS:
            inputs = _draw_inputs(rng, target["fields"])
            if len(rows) < len(target["pins"]):
                inputs.update(target["pins"][len(rows)])
            key = _key(inputs)
            if key in seen:
                continue
            seen.add(key)
            rows.append({"inputs": inputs, "output": target["oracle"](inputs)})
        train, validation = rows[:TRAIN_ROWS], rows[TRAIN_ROWS:]
        if _split_ok(target, train, validation):
            return {"name": target["name"], "category": target["category"],
                    "reference": target["reference"], "seed": _seed(target),
                    "train": train, "validation": validation}
    raise RuntimeError(f"cannot draw a branch-covering split for {target['name']}")


def fresh_points(target, count=FRESH_POINTS):
    """Seeded fresh oracle points from a widened domain, disjoint from the split."""
    fields = target["fresh"] or {
        name: ([widen(x) for x in dom] if isinstance(dom, list) else widen(dom))
        for name, dom in target["fields"].items()}
    rng = random.Random(_seed(target) ^ 0x5EED)
    points = []
    seen = set()
    for _ in range(count * 20):
        if len(points) >= count:
            break
        inputs = _draw_inputs(rng, fields)
        key = _key(inputs)
        if key in seen:
            continue
        seen.add(key)
        points.append(inputs)
    return points


def materialize():
    return {"kind": "sis_induction_corpus", "version": 1,
            "train_rows": TRAIN_ROWS, "validation_rows": VALIDATION_ROWS,
            "targets": [materialize_target(t) for t in TARGETS]}


def by_name():
    return {t["name"]: t for t in TARGETS}


if __name__ == "__main__":
    import sys
    from pathlib import Path
    out = Path(__file__).with_name("corpus.json")
    text = json.dumps(materialize(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        raise SystemExit(0 if out.read_text() == text else 1)
    out.write_text(text)
    print(f"wrote {out}")
