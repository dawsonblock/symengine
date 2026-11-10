"""V335-01: memory-budget lifecycle and signature-check accounting.

The v3.3.4 defect: ``SearchState`` only checked ``max_memory_bytes`` when
it had started ``tracemalloc`` itself. A caller that had already started
tracing bypassed the cap entirely and could report ``completed`` with a
traced peak above the limit.

These tests pin the repaired contract: the cap applies regardless of who
owns the tracer, caller-owned tracing survives, engine-owned tracing is
stopped, the budget is incremental, and the reported signature count
never exceeds the declared cap.
"""
from __future__ import annotations

import tracemalloc
import unittest

from sis.induction import SearchBudget, SearchState, induce

CAP = 1 << 20


def _study(features=16, rows=9):
    names = [f"x{i}" for i in range(features)]
    examples = []
    for i in range(rows):
        inputs = {name: (i * 7 + j * 3) % 11 for j, name in enumerate(names)}
        inputs[names[-2]] = i % 9 + 1
        inputs[names[-1]] = (i * 2) % 9 + 1
        examples.append({
            "inputs": inputs,
            "output": inputs[names[-2]] * inputs[names[-1]] + 2,
        })
    return examples[:6], examples[6:]


class MemoryBudgetLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.train, self.dev = _study()
        self.budget = SearchBudget(
            max_candidates=50000, max_memory_bytes=CAP)

    def tearDown(self):
        if tracemalloc.is_tracing():
            tracemalloc.stop()

    def test_cap_applies_with_caller_started_tracer(self):
        tracemalloc.start()
        result = induce(self.train, dev=self.dev, budget=self.budget)
        self.assertTrue(tracemalloc.is_tracing())
        self.assertEqual(result["search_outcome"], "resource_exhausted")
        self.assertIn("max_memory_bytes", result["limits_hit"])
        self.assertEqual(
            result["memory_limit_source"], "tracemalloc_incremental")
        self.assertGreater(result["observed_peak_bytes"], CAP)

    def test_cap_applies_with_engine_started_tracer(self):
        self.assertFalse(tracemalloc.is_tracing())
        result = induce(self.train, dev=self.dev, budget=self.budget)
        self.assertFalse(tracemalloc.is_tracing())
        self.assertEqual(result["search_outcome"], "resource_exhausted")
        self.assertIn("max_memory_bytes", result["limits_hit"])

    def test_caller_tracer_survives_normal_return_and_error(self):
        tracemalloc.start()
        induce(self.train, dev=self.dev, budget=self.budget)
        self.assertTrue(tracemalloc.is_tracing())
        train = [{"inputs": {"a": a, "b": 0}, "output": a}
                 for a in (1, 2, 3, 4)]
        dev = [{"inputs": {"a": a, "b": 0}, "output": a}
               for a in (5, 6, 7)]

        def boom(inputs):
            raise RuntimeError("boom")

        with self.assertRaises(RuntimeError):
            induce(train, dev=dev, counterexample_oracle=boom,
                   budget=SearchBudget(max_memory_bytes=CAP))
        self.assertTrue(tracemalloc.is_tracing())

    def test_no_cap_does_not_start_tracing(self):
        self.assertFalse(tracemalloc.is_tracing())
        result = induce(self.train, dev=self.dev,
                        budget=SearchBudget(max_candidates=50000))
        self.assertFalse(tracemalloc.is_tracing())
        self.assertIsNone(result["memory_limit_source"])
        self.assertEqual(result["observed_peak_bytes"], 0)

    def test_sequential_searches_reset_baseline(self):
        tracemalloc.start()
        first = induce(self.train, dev=self.dev, budget=self.budget)
        second = induce(
            self.train, dev=self.dev,
            budget=SearchBudget(max_candidates=50000, max_memory_bytes=CAP))
        self.assertEqual(first["search_outcome"], "resource_exhausted")
        self.assertEqual(second["search_outcome"], "resource_exhausted")
        self.assertTrue(tracemalloc.is_tracing())

    def test_search_state_ownership(self):
        state = SearchState(SearchBudget(max_memory_bytes=CAP))
        state.start()
        self.assertTrue(tracemalloc.is_tracing())
        state.close()
        self.assertFalse(tracemalloc.is_tracing())

        tracemalloc.start()
        state = SearchState(SearchBudget(max_memory_bytes=CAP))
        state.start()
        state.close()
        self.assertTrue(tracemalloc.is_tracing())


class SignatureAccountingTests(unittest.TestCase):
    def test_signature_count_never_exceeds_cap(self):
        train, dev = _study()
        result = induce(train, dev=dev, budget=SearchBudget(
            max_candidates=50000, max_signature_checks=10))
        self.assertIn("max_signature_checks", result["limits_hit"])
        self.assertLessEqual(result["signature_checks"], 10)


if __name__ == "__main__":
    unittest.main()
