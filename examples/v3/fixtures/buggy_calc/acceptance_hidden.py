"""Evaluator-custodied acceptance tests for the buggy_calc fixture.

This file is registered with the OutcomeVerifier and injected only into the
evaluator's fresh workspace at evaluation time. It must not be placed in the
agent workspace, the task prompt, or any retrieval index.
"""
import unittest

from calc import add, percentage, subtract


class AcceptanceTest(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_subtract(self):
        self.assertEqual(subtract(10, 4), 6)

    def test_percentage_quarter(self):
        self.assertAlmostEqual(percentage(1, 4), 25.0)

    def test_percentage_whole(self):
        self.assertAlmostEqual(percentage(7, 7), 100.0)


if __name__ == "__main__":
    unittest.main()
