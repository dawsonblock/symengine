"""Repository-level power planning for the sign-flip efficacy decision."""
from __future__ import annotations

import random
import unittest

from sis.v3.contracts import ContractError
from sis.v3.governed_eval import (anova_icc, calibrate_effect_sd,
                                  pilot_planning_inputs, repository_power,
                                  required_repositories, required_sample_size,
                                  sign_flip_p_value)
from sis.v3.learning_qualification import (
    MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES, repository_sign_flip_test)


def _report(totals_by_repo):
    """A report whose per-repository wins-minus-losses are ``totals``."""
    rows = []
    for repo, total in totals_by_repo.items():
        for _ in range(abs(total)):
            win = total > 0
            rows.append({"repository_id": repo, "task_id": f"{repo}-{len(rows)}",
                         "arms": {"A": {"outcome": "fail" if win else "pass"},
                                  "E": {"outcome": "pass" if win else "fail"}}})
        rows.append({"repository_id": repo, "task_id": f"{repo}-tie",
                     "arms": {"A": {"outcome": "pass"},
                              "E": {"outcome": "pass"}}})
    return {"per_task": rows}


class SignFlipTests(unittest.TestCase):
    def test_matches_the_analysis_test(self):
        rng = random.Random(7)
        for _ in range(40):
            totals = {f"r{i}": rng.randint(-3, 3)
                      for i in range(rng.randint(1, 9))}
            expected = repository_sign_flip_test(_report(totals))["p_value"]
            self.assertAlmostEqual(
                sign_flip_p_value(list(totals.values())), expected, places=8)

    def test_floor_and_zeros(self):
        self.assertEqual(sign_flip_p_value([0, 0]), 1.0)
        self.assertEqual(sign_flip_p_value([1] * 5), 2 ** -4)


class PowerTests(unittest.TestCase):
    def test_power_is_deterministic_for_a_seed(self):
        kwargs = dict(tasks_per_repository=4, baseline_rate=0.4,
                      treatment_rate=0.6, icc=0.2, simulations=200, seed=3)
        self.assertEqual(repository_power(12, **kwargs),
                         repository_power(12, **kwargs))

    def test_no_effect_has_size_at_most_alpha(self):
        power = repository_power(
            20, tasks_per_repository=5, baseline_rate=0.5,
            treatment_rate=0.5, icc=0.3, simulations=600, seed=1)
        # One-sided support (positive delta) of a two-sided 0.05 test.
        self.assertLess(power, 0.05)

    def test_power_grows_with_repositories(self):
        kwargs = dict(tasks_per_repository=5, baseline_rate=0.3,
                      treatment_rate=0.6, icc=0.2, simulations=300, seed=0)
        self.assertLess(repository_power(6, **kwargs),
                        repository_power(30, **kwargs))

    def test_inputs_are_validated(self):
        with self.assertRaises(ContractError):
            repository_power(0, tasks_per_repository=1, baseline_rate=0.4,
                             treatment_rate=0.6, icc=0.1)
        with self.assertRaises(ContractError):
            repository_power(5, tasks_per_repository=1, baseline_rate=0.4,
                             treatment_rate=0.6, icc=1.0)
        with self.assertRaises(ContractError):
            required_repositories(baseline_rate=0.4, treatment_rate=0.4,
                                  tasks_per_repository=3, icc=0.1)


class PilotEstimateTests(unittest.TestCase):
    def test_anova_icc(self):
        self.assertIsNone(anova_icc([[1, 0]]))
        self.assertEqual(anova_icc([[1, 1], [0, 0]]), 1.0)
        self.assertEqual(anova_icc([[1, 0], [1, 0]]), 0.0)

    def test_pilot_inputs_come_from_the_report(self):
        report = _report({"r1": 2, "r2": -1, "r3": 0})
        inputs = pilot_planning_inputs(report)
        self.assertEqual(inputs["repositories"], 3)
        self.assertEqual(inputs["tasks"], 6)
        self.assertEqual(inputs["tasks_per_repository"], 2.0)
        self.assertAlmostEqual(inputs["baseline_rate"], 4 / 6, places=5)
        self.assertAlmostEqual(inputs["treatment_rate"], 5 / 6, places=5)
        self.assertIsNotNone(inputs["difference_icc"])

    def test_calibration_is_monotone(self):
        kwargs = dict(tasks_per_repository=5, baseline_rate=0.4,
                      treatment_rate=0.6, repositories=600)
        self.assertEqual(calibrate_effect_sd(0.0, **kwargs), 0.0)
        self.assertLess(calibrate_effect_sd(0.1, **kwargs),
                        calibrate_effect_sd(0.4, **kwargs))


class RequiredRepositoriesTests(unittest.TestCase):
    def plan(self, **overrides):
        kwargs = dict(baseline_rate=0.4, treatment_rate=0.6,
                      tasks_per_repository=5, icc=0.15, simulations=300,
                      seed=11)
        kwargs.update(overrides)
        return required_repositories(**kwargs)

    def test_finds_the_smallest_sufficient_count(self):
        plan = self.plan()
        self.assertTrue(plan["reached"])
        required = plan["required_repositories"]
        self.assertGreaterEqual(plan["achieved_power"], 0.8)
        below = plan["curve"].get(str(required - 1))
        if below is not None:
            self.assertLess(below, 0.8)
        self.assertEqual(plan["recommended_repositories"],
                         max(required, MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES))
        self.assertEqual(plan["recommended_tasks"],
                         plan["recommended_repositories"] * 5)
        self.assertEqual(plan["independent_task_n"],
                         required_sample_size(0.4, 0.6))
        self.assertEqual(plan, self.plan(), "deterministic for a seed")

    def test_effect_heterogeneity_needs_more_repositories(self):
        low = self.plan(effect_sd=0.0)["required_repositories"]
        high = self.plan(effect_sd=1.0)["required_repositories"]
        self.assertGreater(high, low)

    def test_a_pilot_difference_icc_is_calibrated(self):
        plan = self.plan(difference_icc=0.3)
        self.assertGreater(plan["effect_sd"], 0)
        self.assertEqual(plan["difference_icc"], 0.3)
        with self.assertRaises(ContractError):
            self.plan(difference_icc=0.3, effect_sd=0.5)

    def test_an_unreachable_target_is_reported(self):
        plan = self.plan(treatment_rate=0.42, max_repositories=8)
        self.assertFalse(plan["reached"])
        self.assertIsNone(plan["required_repositories"])
        self.assertLess(plan["power_at_max"], 0.8)

    def test_a_large_effect_still_meets_the_confirmatory_floor(self):
        plan = self.plan(baseline_rate=0.1, treatment_rate=0.9)
        self.assertLess(plan["required_repositories"],
                        MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES)
        self.assertEqual(plan["recommended_repositories"],
                         MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES)


if __name__ == "__main__":
    unittest.main()
