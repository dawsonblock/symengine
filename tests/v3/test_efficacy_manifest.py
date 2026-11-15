"""Phase 6 manifest scaffold: structure, power floor and custody checks."""
from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from sis.v3.efficacy_manifest import validate_manifest
from sis.v3.governed_eval import GOVERNED_ARMS, preregister

ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "docs" / "v3" / "efficacy_manifest_template.json"
BUDGET = {"wall_seconds": 900, "token_budget": 100000,
          "tool_budget": 100}


def protocol(**overrides):
    values = dict(
        primary_metric="paired solved_delta E vs A",
        method="mcnemar_exact", alpha=0.05, min_effect=0.2,
        sample_size=103, budget=BUDGET, arms=GOVERNED_ARMS,
        powered=True, expected_baseline=0.6, expected_treatment=0.4,
        power=0.8, allow_underpowered=False)
    values.update(overrides)
    document = preregister(**values)
    document["powered"] = values["powered"]
    document["schema_version"] = 1
    return document


def repository(index: int, partition: str) -> dict:
    digest = hashlib.sha256(f"repo-{index}".encode()).hexdigest()
    item = {
        "repository_id": f"repo-{index:02d}",
        "path": f"/secure/repos/repo-{index:02d}",
        "base_commit": "a" * 40,
        "repo_snapshot_digest": digest,
        "partition": partition,
    }
    if partition == "holdout":
        item["hidden_tests"] = {
            "path": f"/secure/evaluator/repo-{index:02d}",
            "digest": hashlib.sha256(
                f"hidden-{index}".encode()).hexdigest(),
        }
    return item


def manifest(*, sample_size=103) -> dict:
    registered = protocol(sample_size=sample_size)
    repositories = [repository(0, "induction")]
    repositories += [repository(index, "holdout")
                     for index in range(1, 10)]
    holdout = [item for item in repositories
               if item["partition"] == "holdout"]
    tasks = []
    for index in range(sample_size):
        repo = holdout[index % len(holdout)]
        tasks.append({
            "task_id": f"task-{index:03d}",
            "repository_id": repo["repository_id"],
            "base_commit": repo["base_commit"],
            "prompt": f"Task {index}",
            "failure_class": "sig-x",
            "partition": "holdout",
            "budgets": {
                "time_budget_seconds": 900,
                "token_budget": 100000,
                "tool_budget": 100,
            },
            "acceptance": {
                "argv": ["python3", "-m", "pytest", "-q",
                         "acceptance.py"],
                "files": {
                    "acceptance.py":
                        "def test_ok():\n    assert True\n",
                },
            },
        })
    return {
        "schema_version": 1,
        "kind": "five_arm_efficacy_manifest",
        "protocol": registered,
        "agent": {
            "kind": "codex-cli",
            "model": "gpt-5-codex",
            "cli_version": "1.2.3",
        },
        "partitions": {
            "induction": ["repo-00"],
            "holdout": [item["repository_id"] for item in holdout],
        },
        "repositories": repositories,
        "tasks": tasks,
        "preregistration": {
            "registered_at": "2026-11-14T00:00:00Z",
            "registered_by": "operator",
            "protocol_digest": registered["protocol_digest"],
        },
    }


class EfficacyManifestTests(unittest.TestCase):
    def test_the_template_is_structurally_valid(self):
        document = json.loads(TEMPLATE.read_text())
        report = validate_manifest(document, allow_placeholders=True)
        self.assertTrue(report["valid"], report["problems"])
        self.assertFalse(report["ready"])
        self.assertGreater(report["placeholders"], 0)
        self.assertEqual(
            report["protocol_digest"],
            "3e77a22dc9c5d678cfca75cddaf3cfa008abb06fc3dd4b52d0e84b13af431816")
        self.assertEqual(report["required_sample_size"], 103)

    def test_the_template_is_not_ready_in_strict_mode(self):
        document = json.loads(TEMPLATE.read_text())
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertFalse(report["ready"])

    def test_a_complete_manifest_is_ready(self):
        report = validate_manifest(manifest())
        self.assertTrue(report["valid"], report["problems"])
        self.assertTrue(report["ready"])
        self.assertEqual(report["tasks"], 103)
        self.assertEqual(report["repositories"], 10)
        self.assertEqual(report["holdout_repositories"], 9)
        self.assertEqual(report["holdout_repositories_used"], 9)
        self.assertEqual(report["holdout_snapshots_used"], 9)
        self.assertTrue(report["confirmatory"])

    def test_partition_overlap_is_rejected(self):
        document = manifest()
        document["partitions"]["holdout"].append("repo-00")
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("overlap" in problem
                            for problem in report["problems"]))

    def test_holdout_repository_minimum_is_enforced(self):
        document = manifest()
        holdout = [item for item in document["repositories"]
                   if item["partition"] == "holdout"]
        for repo in holdout[4:]:
            repo["partition"] = "induction"
            repo.pop("hidden_tests", None)
        document["partitions"]["induction"] = ["repo-00"] + [
            item["repository_id"] for item in holdout[4:]]
        document["partitions"]["holdout"] = [
            item["repository_id"] for item in holdout[:4]]
        for task in document["tasks"]:
            task["repository_id"] = holdout[0]["repository_id"]
            task["base_commit"] = holdout[0]["base_commit"]
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("holdout repositories" in problem
                            for problem in report["problems"]))

    def test_hidden_tests_inside_the_public_repo_are_rejected(self):
        document = manifest()
        for repo in document["repositories"]:
            if repo["partition"] == "holdout":
                repo["hidden_tests"]["path"] = repo["path"] + "/tests"
                break
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("inside the public repository" in problem
                            for problem in report["problems"]))

    def test_a_protocol_digest_mismatch_is_rejected(self):
        document = manifest()
        document["protocol"]["protocol_digest"] = "0" * 64
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("protocol_digest" in problem
                            for problem in report["problems"]))

    def test_an_explicitly_underpowered_protocol_is_rejected(self):
        document = manifest()
        underpowered = protocol(
            sample_size=10, allow_underpowered=True)
        document["protocol"] = underpowered
        document["preregistration"]["protocol_digest"] = (
            underpowered["protocol_digest"])
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("underpowered" in problem
                            for problem in report["problems"]))

    def test_an_unsafe_acceptance_path_is_rejected(self):
        document = manifest()
        document["tasks"][0]["acceptance"]["files"] = {
            "../escape.py": "x"}
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("unsafe acceptance path" in problem
                            for problem in report["problems"]))

    def test_a_diagnostic_protocol_is_valid_but_not_ready(self):
        document = manifest()
        diagnostic = protocol(powered=False, sample_size=4)
        document["protocol"] = diagnostic
        document["preregistration"]["protocol_digest"] = (
            diagnostic["protocol_digest"])
        report = validate_manifest(document)
        self.assertTrue(report["valid"], report["problems"])
        self.assertFalse(report["confirmatory"])
        self.assertFalse(report["ready"])

    def test_a_non_boolean_powered_flag_is_rejected(self):
        document = manifest()
        document["protocol"]["powered"] = "yes"
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertFalse(report["confirmatory"])
        self.assertTrue(any("powered must be a bool" in problem
                            for problem in report["problems"]))

    def test_a_powered_protocol_cannot_declare_diagnostic(self):
        document = manifest()
        document["protocol"]["analysis_kind"] = "diagnostic"
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertFalse(report["confirmatory"])
        self.assertTrue(any("analysis_kind" in problem
                            for problem in report["problems"]))

    def test_a_diagnostic_protocol_cannot_carry_a_power_block(self):
        document = manifest()
        diagnostic = protocol(powered=False, sample_size=4)
        diagnostic["power_analysis"] = {"required_n": 4}
        document["protocol"] = diagnostic
        document["preregistration"]["protocol_digest"] = (
            diagnostic["protocol_digest"])
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("must not carry power_analysis" in problem
                            for problem in report["problems"]))

    def test_a_null_power_block_is_treated_as_absent(self):
        absent = object()

        def report(block):
            document = manifest()
            diagnostic = protocol(powered=False, sample_size=4)
            if block is not absent:
                diagnostic["power_analysis"] = block
            document["protocol"] = diagnostic
            document["preregistration"]["protocol_digest"] = (
                diagnostic["protocol_digest"])
            return validate_manifest(document)

        self.assertEqual(report(None)["problems"],
                         report(absent)["problems"])
        self.assertTrue(any(
            "must not carry power_analysis" in problem
            for problem in report({"required_n": 4})["problems"]))

    def test_task_budgets_must_match_the_protocol(self):
        document = manifest()
        document["tasks"][0]["budgets"]["token_budget"] = 999
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertTrue(any("does not match the preregistered protocol"
                            in problem for problem in report["problems"]))

    def test_declared_holdout_repositories_must_contribute_tasks(self):
        document = manifest()
        # Five repositories are declared, but every task is drawn from one.
        target = document["repositories"][1]
        for task in document["tasks"]:
            task["repository_id"] = target["repository_id"]
            task["base_commit"] = target["base_commit"]
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertEqual(report["holdout_repositories_used"], 1)
        self.assertTrue(any("contribute no tasks" in problem
                            for problem in report["problems"]))
        self.assertTrue(any("tasks use only 1 holdout repositories"
                            in problem for problem in report["problems"]))

    def test_coverage_is_reported_per_repository(self):
        report = validate_manifest(manifest())
        self.assertEqual(report["holdout_repositories_used"], 9)
        self.assertEqual(report["holdout_snapshots_used"], 9)
        self.assertEqual(sum(report["tasks_per_holdout_repository"].values()),
                         103)

    def test_holdout_repositories_must_be_distinct_codebases(self):
        document = manifest()
        shared = document["repositories"][1]["repo_snapshot_digest"]
        for repository in document["repositories"]:
            if repository["partition"] == "holdout":
                repository["repo_snapshot_digest"] = shared
        report = validate_manifest(document)
        self.assertFalse(report["valid"])
        self.assertEqual(report["holdout_snapshots_used"], 1)
        self.assertTrue(any("distinct holdout" in problem
                            for problem in report["problems"]))

    def test_a_task_must_declare_the_holdout_partition(self):
        for declared in ("induction", None):
            with self.subTest(declared=declared):
                document = manifest()
                if declared is None:
                    del document["tasks"][0]["partition"]
                else:
                    document["tasks"][0]["partition"] = declared
                report = validate_manifest(document)
                self.assertFalse(report["valid"])
                self.assertTrue(any("partition must be holdout" in problem
                                    for problem in report["problems"]))


if __name__ == "__main__":
    unittest.main()
