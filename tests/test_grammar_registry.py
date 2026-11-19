"""The grammar has one op registry and every induction result is version-stamped.

- Every consumer (evaluation, cost, SMT translation, schema transfer, the
  LLM prompt and the benchmark's structural form) reads ``expression.OPS``.
- ``induce`` stamps ``grammar_version`` and ``engine_version``; promotion and
  sealed evaluation refuse a result or submission from another engine with
  a message that says to re-induce, instead of an opaque mismatch.
- Rules stored by an earlier engine keep their ids and still validate.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from sis import expression
from sis.errors import RuleRejected
from sis.expression import (GRAMMAR_VERSION, OPS, cost, depth, evaluate,
                            prompt_grammar, validate_ast)
from sis.induction import ENGINE_VERSION, induce
from sis.registry import Registry
from sis.transfer import map_expression
from sis.validation import digest

ROOT = Path(__file__).resolve().parents[1]


def _study():
    return json.loads((ROOT / "examples" / "arithmetic_study.json").read_text())


class RegistryShapeTests(unittest.TestCase):
    def test_every_op_is_fully_declared(self):
        for name, spec in OPS.items():
            with self.subTest(op=name):
                self.assertEqual(spec.name, name)
                self.assertIn(spec.shape, {"leaf", "unary", "binary", "cond"})
                if spec.shape != "leaf":
                    self.assertTrue(callable(spec.fn))
                    self.assertGreaterEqual(spec.cost, 1)
                arity = {"leaf": 0, "unary": 1, "binary": 2, "cond": 2}[spec.shape]
                self.assertEqual(len(spec.arg_types), arity)

    def test_prompt_lists_every_registered_op(self):
        text = prompt_grammar()
        for name, spec in OPS.items():
            if spec.shape != "leaf":
                self.assertIn(name, text)

    def test_transfer_rewrites_every_shape(self):
        rule = {"op": "if_eq", "left": {"op": "field", "name": "a"},
                "right": {"op": "const", "value": 1},
                "then": {"op": "neg", "arg": {"op": "field", "name": "b"}},
                "else": {"op": "add", "args": [{"op": "field", "name": "a"},
                                               {"op": "field", "name": "b"}]}}
        mapped = map_expression(rule, {"a": "int", "b": "int"},
                                {"x": 1, "y": 2}, {"a": "x", "b": "y"})
        self.assertEqual(evaluate(mapped, {"x": 1, "y": 2}), -2)
        self.assertEqual(evaluate(mapped, {"x": 3, "y": 2}), 5)

    def test_depth_counts_leaves_as_one_level_everywhere(self):
        ast = {"op": "field", "name": "a"}
        for _ in range(expression.MAX_AST_DEPTH - 1):
            ast = {"op": "neg", "arg": ast}
        self.assertEqual(depth(ast), expression.MAX_AST_DEPTH)
        validate_ast(ast)
        with self.assertRaises(Exception):
            validate_ast({"op": "neg", "arg": ast})

    def test_costs_are_unchanged_for_stored_rules(self):
        rule = {"op": "add", "args": [{"op": "field", "name": "a"},
                                      {"op": "const", "value": 2}]}
        self.assertEqual(cost(rule), 5)


class VersionStampTests(unittest.TestCase):
    def test_results_carry_the_versions(self):
        study = _study()
        result = induce(study["train"], study["validation"])
        self.assertEqual(result["grammar_version"], GRAMMAR_VERSION)
        self.assertEqual(result["engine_version"], ENGINE_VERSION)

    def test_promotion_rejects_a_result_from_another_engine(self):
        study = _study()
        result = induce(study["train"], study["validation"],
                        namespace=study["namespace"])
        for key in ("grammar_version", "engine_version"):
            with self.subTest(key=key):
                stale = dict(result, **{key: "sis-old-0"})
                with tempfile.TemporaryDirectory() as temp:
                    registry = Registry(Path(temp) / "k.sqlite3")
                    try:
                        with self.assertRaisesRegex(
                                RuleRejected, "re-induce under the current engine"):
                            registry.promote(stale, train=study["train"],
                                             validation=study["validation"])
                    finally:
                        registry.close()
        unstamped = {k: v for k, v in result.items()
                     if k not in ("grammar_version", "engine_version")}
        with tempfile.TemporaryDirectory() as temp:
            registry = Registry(Path(temp) / "k.sqlite3")
            try:
                with self.assertRaisesRegex(RuleRejected, "re-induce"):
                    registry.promote(unstamped, train=study["train"],
                                     validation=study["validation"])
            finally:
                registry.close()

    def test_rule_ids_do_not_depend_on_the_grammar_version(self):
        study = _study()
        result = induce(study["train"], study["validation"],
                        namespace=study["namespace"])
        with tempfile.TemporaryDirectory() as temp:
            registry = Registry(Path(temp) / "k.sqlite3")
            try:
                promoted = registry.promote(result, train=study["train"],
                                            validation=study["validation"])
                self.assertEqual(promoted["id"], digest({
                    "namespace": study["namespace"], "schema": result["schema"],
                    "expr": result["rule"]}))
                self.assertTrue(registry.verify_audit()["valid"])
            finally:
                registry.close()


class SealedEvaluationVersionTests(unittest.TestCase):
    def setUp(self):
        from sis.sealed_eval import EvaluatorVault
        from sis.vault_storage import private_directory
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        path = private_directory(Path(self.tmp.name) / "vault") / "v.sqlite3"
        self.vault = EvaluatorVault(path, key=b"k" * 32)
        self.addCleanup(self.vault.close)
        self.Vault = EvaluatorVault

    def _public(self):
        rows = [(1, 4), (2, 7), (-3, 5), (5, -2), (0, 8), (4, 9), (-4, -6),
                (11, 3), (6, 6), (-7, 2), (9, -9), (3, 3)]
        ex = [{"inputs": {"a": a, "b": b}, "output": a + b} for a, b in rows]
        return self.vault.seal({"namespace": "versioned", "train": ex[:5],
                                "validation": ex[5:8], "test": ex[8:]})

    def test_submission_and_receipt_carry_the_grammar(self):
        public = self._public()
        made = self.Vault.make_submission(public)
        self.assertEqual(made["status"], "candidate")
        self.assertEqual(made["submission"]["grammar_version"], GRAMMAR_VERSION)
        receipt = self.vault.score(public, made["submission"])
        self.assertEqual(receipt["grammar_version"], GRAMMAR_VERSION)
        self.assertTrue(self.vault.verify(public, receipt)["valid"])

    def test_a_submission_from_another_grammar_is_refused_clearly(self):
        public = self._public()
        submission = dict(self.Vault.make_submission(public)["submission"],
                          grammar_version="sis-old-0")
        with self.assertRaisesRegex(RuleRejected, "re-induce under the current engine"):
            self.vault.score(public, submission)
        # The refusal consumed nothing: the current-grammar submission scores.
        fresh = self.Vault.make_submission(public)["submission"]
        self.assertEqual(self.vault.score(public, fresh)["metrics"]["test"]["count"], 4)


if __name__ == "__main__":
    unittest.main()
