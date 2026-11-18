"""The manifest holdout floor agrees with the confirmatory analysis floor.

``analyze_report`` never labels a run confirmatory with fewer than
``MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES`` holdout repositories, so a
manifest built for a confirmatory study must not be accepted below that
floor. A powered study that cannot reach it must declare
``study_tier: exploratory`` (floor ``MIN_HOLDOUT_REPOSITORIES``); a
diagnostic protocol keeps that lower floor too.
"""
from __future__ import annotations

import unittest

from sis.v3 import efficacy_manifest, learning_qualification
from sis.v3.efficacy_manifest import (MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES,
                                      MIN_HOLDOUT_REPOSITORIES,
                                      validate_manifest)
from tests.v3.test_efficacy_manifest import manifest, protocol


def _diagnostic(document: dict) -> dict:
    diagnostic = protocol(powered=False, sample_size=4)
    document["protocol"] = diagnostic
    document["preregistration"]["protocol_digest"] = (
        diagnostic["protocol_digest"])
    return document


def _floor_problem(report: dict, tier: str, floor: int) -> bool:
    return any(f"at least {floor} must contribute tasks to a {tier} study"
               in problem for problem in report["problems"])


class ConfirmatoryHoldoutFloorTests(unittest.TestCase):
    def test_the_floor_has_a_single_source_of_truth(self):
        self.assertIs(
            efficacy_manifest.MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES,
            learning_qualification.MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES)
        self.assertEqual(MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES, 20)
        self.assertEqual(MIN_HOLDOUT_REPOSITORIES, 5)

    def test_a_confirmatory_manifest_with_19_repositories_is_refused(self):
        for declared in (None, "confirmatory"):
            with self.subTest(declared=declared):
                document = manifest(
                    holdout_count=MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES - 1)
                if declared is not None:
                    document["study_tier"] = declared
                report = validate_manifest(document)
                self.assertFalse(report["valid"])
                self.assertFalse(report["ready"])
                self.assertEqual(report["study_tier"], "confirmatory")
                self.assertEqual(report["holdout_repositories_used"], 19)
                self.assertEqual(report["min_holdout_repositories"], 20)
                self.assertTrue(_floor_problem(report, "confirmatory", 20),
                                report["problems"])
                # The refusal names the way out for a smaller study.
                self.assertTrue(any("declare study_tier exploratory" in p
                                    for p in report["problems"]))
                self.assertTrue(any("2^(1-R)" in p
                                    for p in report["problems"]))

    def test_a_confirmatory_manifest_with_20_repositories_is_accepted(self):
        for declared in (None, "confirmatory"):
            with self.subTest(declared=declared):
                document = manifest(
                    holdout_count=MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES)
                if declared is not None:
                    document["study_tier"] = declared
                report = validate_manifest(document)
                self.assertTrue(report["valid"], report["problems"])
                self.assertTrue(report["ready"])
                self.assertTrue(report["confirmatory"])
                self.assertEqual(report["study_tier"], "confirmatory")
                self.assertEqual(report["holdout_repositories_used"], 20)

    def test_twenty_ids_over_nineteen_codebases_are_refused(self):
        document = manifest(holdout_count=20)
        holdout = [item for item in document["repositories"]
                   if item["partition"] == "holdout"]
        holdout[1]["repo_snapshot_digest"] = (
            holdout[0]["repo_snapshot_digest"])
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertEqual(report["holdout_snapshots_used"], 19)
        self.assertTrue(any(
            "at least 20 independent codebases are required for a"
            " confirmatory study" in problem
            for problem in report["problems"]), report["problems"])

    def test_an_exploratory_manifest_keeps_the_lower_floor(self):
        document = manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES)
        document["study_tier"] = "exploratory"
        report = validate_manifest(document)
        self.assertTrue(report["valid"], report["problems"])
        # Still executable by the real-agent gate, never confirmatory.
        self.assertTrue(report["ready"])
        self.assertFalse(report["confirmatory"])
        self.assertEqual(report["study_tier"], "exploratory")
        self.assertEqual(report["min_holdout_repositories"], 5)

    def test_an_exploratory_manifest_below_five_is_refused(self):
        document = manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES)
        document["study_tier"] = "exploratory"
        target = document["repositories"][1]
        for task in document["tasks"]:
            if task["repository_id"] == document["repositories"][2][
                    "repository_id"]:
                task["repository_id"] = target["repository_id"]
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(_floor_problem(report, "exploratory", 5),
                        report["problems"])

    def test_an_exploratory_label_must_be_declared(self):
        # The same five-repository manifest without the label is read as
        # the confirmatory study a powered protocol implies.
        report = validate_manifest(
            manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES))
        self.assertFalse(report["valid"])
        self.assertTrue(_floor_problem(report, "confirmatory", 20),
                        report["problems"])

    def test_a_diagnostic_manifest_with_five_repositories_is_accepted(self):
        for declared in (None, "diagnostic"):
            with self.subTest(declared=declared):
                document = _diagnostic(
                    manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES))
                if declared is not None:
                    document["study_tier"] = declared
                report = validate_manifest(document)
                self.assertTrue(report["valid"], report["problems"])
                self.assertFalse(report["ready"])
                self.assertFalse(report["confirmatory"])
                self.assertEqual(report["study_tier"], "diagnostic")

    def test_a_diagnostic_manifest_below_five_is_refused(self):
        document = _diagnostic(
            manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES - 1))
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("at least 5 holdout repositories" in problem
                            for problem in report["problems"]))

    def test_the_tier_must_match_the_protocol(self):
        cases = [
            (manifest(), "diagnostic"),
            (_diagnostic(manifest(holdout_count=5)), "confirmatory"),
            (_diagnostic(manifest(holdout_count=5)), "exploratory"),
        ]
        for document, declared in cases:
            with self.subTest(declared=declared):
                document["study_tier"] = declared
                report = validate_manifest(document)
                self.assertFalse(report["valid"])
                self.assertFalse(report["ready"])
                self.assertTrue(any("does not match the protocol" in problem
                                    for problem in report["problems"]),
                                report["problems"])

    def test_an_unknown_tier_is_refused(self):
        for declared in ("powered", "", 1, ["confirmatory"]):
            with self.subTest(declared=declared):
                document = manifest()
                document["study_tier"] = declared
                report = validate_manifest(document)
                self.assertFalse(report["valid"])
                self.assertTrue(any("study_tier must be one of" in problem
                                    for problem in report["problems"]))

    def test_the_tier_is_bound_by_the_manifest_digest(self):
        document = manifest(holdout_count=MIN_HOLDOUT_REPOSITORIES)
        document["study_tier"] = "exploratory"
        before = validate_manifest(document)["manifest_digest"]
        document["study_tier"] = "confirmatory"
        self.assertNotEqual(validate_manifest(document)["manifest_digest"],
                            before)


if __name__ == "__main__":
    unittest.main()


class DeclaredTierBindsTheLabelTests(unittest.TestCase):
    """A study preregistered below confirmatory never becomes confirmatory."""

    def _analyze(self, **provenance):
        from sis.v3.governed_eval import preregister
        from sis.v3.learning_qualification import analyze_report
        from tests.v3.test_learning_qualification import (
            eligible_provenance, synthetic_report)
        protocol = preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=0.2,
            sample_size=103,
            budget={"wall_seconds": 60, "token_budget": 1000,
                    "tool_budget": 100})
        report = synthetic_report(103, a_pass=False, e_pass=True,
                                  repositories=20)
        return analyze_report(
            report, protocol=protocol, real_agent=True, hidden_holdout=True,
            provenance=eligible_provenance(**provenance))

    def test_declared_confirmatory_can_be_confirmatory(self):
        from sis.v3.learning_qualification import CONFIRMATORY
        analysis = self._analyze(study_tier="confirmatory")
        self.assertEqual(analysis["evidence_class"], CONFIRMATORY)

    def test_declared_exploratory_stays_exploratory_at_twenty_repos(self):
        from sis.v3.learning_qualification import EXPLORATORY
        analysis = self._analyze(study_tier="exploratory")
        self.assertEqual(analysis["evidence_class"], EXPLORATORY)
        self.assertNotEqual(analysis["release_gate"], "EFFICACY_SUPPORTED")
        self.assertTrue(any("study_tier" in item
                            for item in analysis["limitations"]))
