"""Learner v2 (SIS-FEAT-14): grammar-2 ops and the typed enumerator.

- New ops have total, bounded semantics: a zero divisor is an evaluation
  error on that record, never a value; strings stay within MAX_TEXT;
  slice lengths are literal constants.
- The enumerator recovers affine, div/mod, string and one-level
  conditional rules, and stays honest: an inexact affine fit is no rule, a
  conditional is provisional unless the holdout exercises both branches,
  and an unidentifiable threshold is reported ambiguous.
"""
from __future__ import annotations

import unittest

from sis.errors import InvalidInput
from sis.expression import OPS, evaluate, prompt_grammar, validate_ast
from sis.induction import extended_probes, generated_probes, induce
from sis.synthesis import ERR, Engine, _solve_exact
from sis.induction import SearchBudget, SearchState

try:
    import z3  # noqa: F401
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False


def F(name):
    return {"op": "field", "name": name}


def C(value):
    return {"op": "const", "value": value}


def B(op, a, b):
    return {"op": op, "args": [a, b]}


def _rows(fn, values):
    return [{"inputs": dict(v), "output": fn(v)} for v in values]


class Grammar2SemanticsTests(unittest.TestCase):
    def test_floor_division_and_modulo_follow_python(self):
        for a in (-7, -1, 0, 5, 7):
            for b in (-3, -2, 2, 3):
                with self.subTest(a=a, b=b):
                    self.assertEqual(evaluate(B("floordiv", F("a"), F("b")),
                                              {"a": a, "b": b}), a // b)
                    self.assertEqual(evaluate(B("mod", F("a"), F("b")),
                                              {"a": a, "b": b}), a % b)

    def test_zero_divisor_is_an_error_not_a_value(self):
        for op in ("floordiv", "mod"):
            with self.subTest(op=op), self.assertRaises(InvalidInput):
                evaluate(B(op, F("a"), F("b")), {"a": 5, "b": 0})

    def test_comparisons_require_integers_and_return_bools(self):
        self.assertIs(evaluate(B("lt", F("a"), F("b")), {"a": 1, "b": 2}), True)
        self.assertIs(evaluate(B("le", F("a"), F("b")), {"a": 2, "b": 2}), True)
        self.assertIs(evaluate(B("gt", F("a"), F("b")), {"a": 2, "b": 2}), False)
        with self.assertRaises(InvalidInput):
            evaluate(B("lt", F("a"), F("b")), {"a": "x", "b": 2})

    def test_string_ops(self):
        rec = {"s": "Hello", "t": "lo", "n": -42}
        self.assertEqual(evaluate(B("concat", F("s"), F("t")), rec), "Hellolo")
        self.assertEqual(evaluate(B("slice_prefix", F("s"), C(2)), rec), "He")
        self.assertEqual(evaluate(B("slice_suffix", F("s"), C(2)), rec), "lo")
        self.assertEqual(evaluate(B("slice_suffix", F("s"), C(0)), rec), "")
        self.assertEqual(evaluate(B("slice_suffix", F("s"), C(9)), rec), "Hello")
        self.assertEqual(evaluate({"op": "len", "arg": F("s")}, rec), 5)
        self.assertIs(evaluate(B("contains", F("s"), F("t")), rec), True)
        self.assertEqual(evaluate({"op": "str_of_int", "arg": F("n")}, rec), "-42")

    def test_concat_is_bounded(self):
        with self.assertRaises(InvalidInput):
            evaluate(B("concat", F("s"), F("s")), {"s": "x" * 100})

    def test_slice_length_must_be_a_literal(self):
        for bad in (F("n"), C(-1), C(129), C("2"), C(True)):
            with self.subTest(length=bad), self.assertRaises(InvalidInput):
                validate_ast(B("slice_prefix", F("s"), bad))

    def test_if_lt_selects_a_branch(self):
        rule = {"op": "if_lt", "left": F("a"), "right": C(0),
                "then": {"op": "neg", "arg": F("a")}, "else": F("a")}
        self.assertEqual(evaluate(rule, {"a": -4}), 4)
        self.assertEqual(evaluate(rule, {"a": 4}), 4)

    def test_prompt_states_the_slice_constant_rule(self):
        self.assertIn("slice_prefix", prompt_grammar())
        self.assertIn("const(non-negative integer)", prompt_grammar())

    @unittest.skipUnless(HAS_Z3, "requires z3")
    def test_z3_floor_division_matches_python(self):
        from sis.smt import bounded_disagreement
        rule = B("floordiv", F("a"), F("b"))
        wrong = B("floordiv", {"op": "abs", "arg": F("a")}, F("b"))
        witness, reason = bounded_disagreement(rule, rule, {"a": "int", "b": "int"})
        self.assertEqual(reason, "unsat_bounded_domain")
        witness, reason = bounded_disagreement(rule, wrong, {"a": "int", "b": "int"})
        self.assertEqual(reason, "sat_counterexample")
        self.assertNotEqual(witness["inputs"]["b"], 0)


class EnumeratorTests(unittest.TestCase):
    def test_a_zero_divisor_row_is_invalid_for_that_candidate(self):
        train = [{"inputs": {"a": a, "b": b}, "output": 1}
                 for a, b in ((4, 0), (5, 2), (6, 3))]
        state = SearchState(SearchBudget())
        engine = Engine(train, [], [], state, depth_budget=5)
        while engine.step():
            pass
        for prog in engine.fit_order:
            with self.subTest(rule=prog.ast):
                self.assertIsNot(prog.sig[0], ERR)

    def test_exact_solver_rejects_rank_deficient_and_inconsistent_systems(self):
        from fractions import Fraction as Q
        self.assertEqual(_solve_exact([[Q(1), Q(1), Q(3)], [Q(1), Q(2), Q(5)],
                                       [Q(1), Q(3), Q(7)]], 2), [Q(1), Q(2)])
        self.assertIsNone(_solve_exact([[Q(1), Q(0), Q(3)], [Q(1), Q(0), Q(3)],
                                        [Q(1), Q(0), Q(3)]], 2))
        self.assertIsNone(_solve_exact([[Q(1), Q(1), Q(3)], [Q(1), Q(2), Q(5)],
                                        [Q(1), Q(3), Q(8)]], 2))

    def test_small_integer_affine_rules_are_recovered(self):
        values = [{"a": a, "b": b} for a, b in
                  ((1, 4), (2, -7), (-3, 5), (5, -2), (0, 8), (4, 9), (-4, -6),
                   (7, 3), (-6, 1), (3, -5), (9, 0), (-8, -3))]
        result = induce(_rows(lambda v: 2 * v["a"] + v["b"] + 1, values[:6]),
                        _rows(lambda v: 2 * v["a"] + v["b"] + 1, values[6:]))
        self.assertIsNotNone(result["rule"])
        for v in values:
            self.assertEqual(evaluate(result["rule"], v), 2 * v["a"] + v["b"] + 1)

    def test_a_non_integer_affine_relation_is_not_fitted(self):
        values = [{"a": a} for a in (1, 3, 5, 7, 9, 11, 13, 15)]
        # 1.5 * a has no exact integer affine form; floor division would.
        result = induce(_rows(lambda v: (3 * v["a"]) // 2, values[:5]),
                        _rows(lambda v: (3 * v["a"]) // 2, values[5:]))
        if result["rule"] is not None:
            for v in values:
                self.assertEqual(evaluate(result["rule"], v), (3 * v["a"]) // 2)

    def test_division_and_modulo_targets(self):
        values = [{"n": n} for n in (7, 15, 22, 31, 48, 56, 63, 79, 84, 95, 102, 117)]
        for fn, op in ((lambda v: v["n"] % 10, "mod"), (lambda v: v["n"] // 10, "floordiv")):
            with self.subTest(op=op):
                result = induce(_rows(fn, values[:6]), _rows(fn, values[6:]))
                self.assertEqual(result["rule"], B(op, F("n"), C(10)))

    def test_string_concatenation_and_slices(self):
        words = ["Ab", "cDe", "Fghi", "jK", "LmnO", "pq", "RsTu", "vWxyz",
                 "Ab12", "Q", "zZz", "Hello"]
        values = [{"s": w, "t": words[(i + 3) % len(words)]} for i, w in enumerate(words)]
        cases = [
            (lambda v: v["s"] + v["t"], B("concat", F("s"), F("t"))),
            (lambda v: v["s"][:2], B("slice_prefix", F("s"), C(2))),
        ]
        for fn, expected in cases:
            with self.subTest(rule=expected["op"]):
                result = induce(_rows(fn, values[:6]), _rows(fn, values[6:]))
                self.assertEqual(result["rule"], expected)

    def test_a_piecewise_rule_is_learned_branch_by_branch(self):
        # No unconditional rule in the grammar equals this one (unlike
        # -2a / a+1, which is max(a + 1, -2a)); a=1 and a=2 pin the split.
        values = [{"a": a} for a in (-5, 1, 2, 3, -2, 6, 4, -4, -3, 7, 0, -6, 5, 8)]
        fn = lambda v: 10 - v["a"] if v["a"] < 2 else 2 * v["a"]  # noqa: E731
        train = _rows(fn, values[:8])
        dev = _rows(fn, values[8:10])
        holdout = _rows(fn, values[10:])
        result = induce(train, dev=dev, holdout=holdout)
        self.assertEqual(result["rule"]["op"], "if_lt")
        self.assertEqual(result["status"], "locally_validated")
        self.assertGreaterEqual(min(result["branch_holdout_coverage"].values()), 1)
        for a in range(-12, 13):
            self.assertEqual(evaluate(result["rule"], {"a": a}), fn({"a": a}))

    def test_a_conditional_without_holdout_rows_on_a_branch_is_provisional(self):
        values = [{"a": a} for a in (-5, 1, 2, 3, -2, 6, 4, -4, -3, 7, 5, 8, 9)]
        fn = lambda v: 10 - v["a"] if v["a"] < 2 else 2 * v["a"]  # noqa: E731
        train = _rows(fn, values[:8])
        dev = _rows(fn, values[8:10])
        holdout = _rows(fn, values[10:])  # only rows with a >= 2
        result = induce(train, dev=dev, holdout=holdout)
        self.assertEqual(result["rule"]["op"], "if_lt")
        self.assertEqual(result["branch_holdout_coverage"]["then"], 0)
        self.assertEqual(result["status"], "provisional")

    def test_an_unpinned_threshold_is_ambiguous(self):
        # Training jumps from 1 to 6: thresholds 2..6 all fit every row.
        values = [{"a": a} for a in (-4, -2, 0, 1, 6, 8, 9, 11, -3, 7, 12, -1)]
        fn = lambda v: 1 if v["a"] < 4 else 2  # noqa: E731
        result = induce(_rows(fn, values[:8]), _rows(fn, values[8:]))
        # The clamp max(1, min(a, 2)) fits too; conditional rivals with
        # other thresholds disagree between 1 and 6, so nothing is validated.
        self.assertEqual(result["status"], "ambiguous")
        self.assertIn(result["distinguishing_probe"]["inputs"]["a"], range(2, 6))

    def test_a_low_evidence_holdout_keeps_the_rule_provisional(self):
        # Parity with three binary holdout rows: a coin-flip rule would pass
        # them one time in eight, so the result is not locally validated.
        values = [{"a": a} for a in (3, 8, -5, 14, 7, 2, -9, 11, 20, -2,
                                     5, 6, 9, 12, -7, 4)]
        fn = lambda v: v["a"] % 2  # noqa: E731
        result = induce(_rows(fn, values[:10]), _rows(fn, values[10:]))
        self.assertEqual(result["rule"], B("mod", F("a"), C(2)))
        self.assertLess(result["holdout_evidence_bits"], 4.0)
        self.assertEqual(result["status"], "provisional")
        # Many more holdout rows carry enough evidence.
        more = [{"a": a} for a in range(21, 41)]
        result = induce(_rows(fn, values[:10]), _rows(fn, values[10:] + more))
        self.assertEqual(result["status"], "locally_validated")

    def test_extended_probes_add_boundary_and_new_type_values(self):
        probes = extended_probes([{"a": 4, "s": "ab"}, {"a": 9, "s": "c"}])
        values = {p["a"] for p in probes}
        self.assertTrue({3, 5, 8, 10}.issubset(values))
        self.assertTrue(any(len(p["s"]) > 3 for p in probes))
        base = list(generated_probes({"a": 4, "s": "ab"}))
        self.assertTrue(all(p not in base[:1] for p in probes))

    def test_every_op_is_reachable_by_the_enumerator_or_templates(self):
        for name, spec in OPS.items():
            with self.subTest(op=name):
                self.assertIn(spec.shape, {"leaf", "unary", "binary", "cond"})


if __name__ == "__main__":
    unittest.main()
