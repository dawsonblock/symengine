"""Cheap completions run before forward checks (SIS-FIX-26).

Learner v2 completed every new pool program at once: hash lookups for the
``add``/``sub``/``mul`` inverses, then ``_forward_int``, which checks
``min``/``max``/``absdiff`` against every terminal and ``floordiv``/``mod``
by every divisor (about 230 signature checks per program on a 64-field
schema). Pool level 4 starts with the 2,080 ``add`` pairs, so on 64 fields
the forward checks used the whole signature budget before any ``mul`` pair
was built and the benchmark target ``x62 * x63 + 2`` was never found.

The engine now queues each stage's forward checks and runs them at the end
of the same stage. Every fit keeps the position the old order would have
found it at, and a duplicate keeps the earlier one, so a search that
completes is unchanged: the same fits, the same selected rule, the same
budget use. Only a truncated search differs, by finding cheap fits first.
"""
from __future__ import annotations

import importlib.util
import random
import unittest
from pathlib import Path
from unittest import mock

from sis import synthesis
from sis.expression import canonical, evaluate
from sis.induction import SearchBudget, SearchState, generated_probes, induce

_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "benchmark_induction", _ROOT / "tools" / "benchmark_induction.py")
benchmark = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(benchmark)


def _run_engine(train, dev, probes, budget):
    state = SearchState(budget)
    state.start()
    try:
        engine = synthesis.Engine(
            train, dev, probes, state,
            depth_budget=budget.max_expression_depth)
        while engine.step():
            pass
        if engine.horizon_reached and not engine.exhausted:
            engine.run_conditionals()
    finally:
        state.close()
    return engine, state


def _summary(engine, state):
    return {
        "fits": [canonical(p.ast) for p in engine.fit_order],
        "by_fp": sorted(engine.prog_by_fp),
        "candidates": state.candidates,
        "signature_checks": state.signature_checks,
        "level": engine.level_reached,
        "horizon": engine.horizon_reached,
        "exhausted": engine.exhausted,
    }


def _tasks():
    """Seeded small tasks that reach the completion levels."""
    rng = random.Random(20261121)
    rules = [
        ("min_plus", lambda v: min(v["a"], v["b"]) + v["c"]),
        ("absdiff", lambda v: abs(v["a"] - v["b"])),
        ("product", lambda v: v["a"] * v["b"] + 2),
        ("floordiv", lambda v: (v["a"] + v["b"]) // 3),
        ("mod", lambda v: v["a"] % 4),
        ("max_minus", lambda v: max(v["a"], v["c"]) - v["b"]),
        ("sum_mod", lambda v: (v["a"] + v["c"]) % 5),
        ("square", lambda v: v["a"] * v["a"] - v["b"]),
        ("min_abs", lambda v: min(v["a"], -v["b"])),
        ("max3", lambda v: max(v["a"], 3)),
    ]
    out = []
    for name, fn in rules:
        for fields in ("abc", "abcd"):
            rows = []
            for _ in range(9):
                inputs = {k: rng.randint(-6, 9) for k in fields}
                rows.append({"inputs": inputs, "output": fn(inputs)})
            out.append((f"{name}/{len(fields)}", rows[:6], rows[6:]))
    return out + _composed_tasks()


_BINARY = (min, max, lambda a, b: abs(a - b), lambda a, b: a + b,
           lambda a, b: a - b, lambda a, b: a * b, lambda a, b: a // 3,
           lambda a, b: a % 3, lambda a, b: a % 2)
#: Trials of the seeded generator below (seed 1) in which the deferred
#: order meets a duplicate the one-pass order found first. Small integer
#: domains make distinct programs coincide on every row and probe; those
#: are exactly the cases where the representative must not change.
_REPLACEMENT_TRIALS = (1, 32, 45, 52, 55, 64)


def _composed_tasks():
    rng = random.Random(1)
    out = []
    for trial in range(max(_REPLACEMENT_TRIALS) + 1):
        f1, f2, f3 = (rng.choice(_BINARY) for _ in range(3))
        names = "abcd"[:rng.choice([2, 3, 4])]
        lo, hi = rng.choice([(-6, 9), (0, 3), (0, 9), (-2, 2)])
        rows = []
        for _ in range(9):
            inputs = {k: rng.randint(lo, hi) for k in names}
            a, b, c = inputs["a"], inputs["b"], inputs.get("c", 1)
            rows.append({"inputs": inputs, "output": f3(f1(a, b), f2(b, c))})
        if trial in _REPLACEMENT_TRIALS:
            out.append((f"composed/{trial}", rows[:6], rows[6:]))
    return out


class WideSchemaTests(unittest.TestCase):
    def test_the_64_field_product_rule_is_found_within_the_signature_budget(self):
        # The evidence/v339 benchmark case at 64 fields, seed 0, on a
        # smaller signature budget than the recorded run: the inverse
        # lookups reach mul(x62, x63) well inside it.
        train, dev, holdout = benchmark.study(
            64, seed=0, train_n=6, dev_n=3, holdout_n=3)
        budget = SearchBudget(
            max_candidates=50_000, max_signature_checks=150_000,
            max_wall_seconds=120, max_expression_depth=5)
        result = induce(train, dev=dev, holdout=holdout, budget=budget)
        rule = result["rule"]
        self.assertIsNotNone(rule, result.get("status"))
        target = benchmark.target_rule(64)
        self.assertEqual(benchmark.structural_form(rule),
                         benchmark.structural_form(target))
        for example in holdout:
            self.assertEqual(evaluate(rule, example["inputs"]),
                             example["output"])


class CompletionOrderEquivalenceTests(unittest.TestCase):
    """Deferral changes nothing when the search is not truncated."""

    BUDGET = dict(max_candidates=50_000, max_signature_checks=3_000_000,
                  max_wall_seconds=120, max_expression_depth=5)

    def compare(self, name, train, dev):
        probes = list(generated_probes(train[0]["inputs"], limit=64))
        runs = {}
        for defer in (False, True):
            with mock.patch.object(synthesis, "DEFER_FORWARD", defer):
                engine, state = _run_engine(
                    train, dev, probes, SearchBudget(**self.BUDGET))
            runs[defer] = (engine, state)
        old, new = (_summary(*runs[False]), _summary(*runs[True]))
        if old["exhausted"] or new["exhausted"]:
            self.skipTest(f"{name}: budget exhausted; only complete runs compare")
        self.assertEqual(sorted(old["fits"]), sorted(new["fits"]), name)
        self.assertEqual(old["by_fp"], new["by_fp"], name)
        for key in ("candidates", "signature_checks", "level", "horizon"):
            self.assertEqual(old[key], new[key], f"{name}: {key}")
        return runs

    def test_complete_searches_find_the_same_fits_with_the_same_budget(self):
        compared = 0
        replaced = 0
        for name, train, dev in _tasks():
            with self.subTest(task=name):
                runs = self.compare(name, train, dev)
                compared += 1
                replaced += runs[True][0].replaced_fits
                self.assertEqual(runs[False][0].replaced_fits, 0)
        # The corpus must exercise the reordering, not just pass through it.
        self.assertGreater(compared, 10)
        self.assertGreater(replaced, 0)

    def test_complete_searches_select_the_same_rule(self):
        selected = 0
        for name, train, dev in _tasks():
            records = [canonical(e["inputs"]) for e in train + dev]
            if len(set(records)) != len(records):
                continue  # induce() requires distinct input records
            with self.subTest(task=name):
                selected += 1
                results = {}
                for defer in (False, True):
                    with mock.patch.object(synthesis, "DEFER_FORWARD", defer):
                        results[defer] = induce(
                            train, dev=dev,
                            budget=SearchBudget(**self.BUDGET))
                old, new = results[False], results[True]
                if old["search_truncated"] or new["search_truncated"]:
                    continue
                for key in ("rule", "status", "candidates_evaluated",
                            "signature_checks", "search_outcome"):
                    self.assertEqual(old.get(key), new.get(key),
                                     f"{name}: {key}")
        self.assertGreater(selected, 10)

    def test_without_deferral_no_fit_is_ever_replaced(self):
        name, train, dev = _tasks()[0]
        probes = list(generated_probes(train[0]["inputs"], limit=64))
        with mock.patch.object(synthesis, "DEFER_FORWARD", False):
            engine, _state = _run_engine(
                train, dev, probes, SearchBudget(**self.BUDGET))
        self.assertEqual(engine.replaced_fits, 0)


if __name__ == "__main__":
    unittest.main()
