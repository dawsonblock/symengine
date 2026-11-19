"""Study-kit manifest builder: a spec becomes a ready manifest or is refused."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import canonical_digest
from sis.v3.efficacy_manifest import validate_manifest
from sis.v3.governed_eval import GOVERNED_ARMS, PRIMARY_CONTRAST_ARMS
from sis.v3.runner import repository_execution_digest, tree_digest

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "build_efficacy_manifest", ROOT / "tools" / "build_efficacy_manifest.py")
builder = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(builder)
_CAMPAIGN = importlib.util.spec_from_file_location(
    "five_arm_campaign", ROOT / "tools" / "five_arm_campaign.py")
campaign = importlib.util.module_from_spec(_CAMPAIGN)
_CAMPAIGN.loader.exec_module(campaign)

GIT = shutil.which("git")
BUDGET = {"wall_seconds": 30, "token_budget": 1000, "tool_budget": 10}


def _git(repo: Path, *args: str):
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True)


def _commit(repo: Path):
    _git(repo, "-c", "user.name=SIS", "-c", "user.email=sis@example.invalid",
         "commit", "-qm", "base")


def _repository(root: Path, name: str, content: str) -> tuple[Path, str]:
    path = root / "repos" / name
    path.mkdir(parents=True)
    (path / "solution.py").write_text(content)
    _git(path, "init", "-q")
    _git(path, "add", ".")
    _commit(path)
    origin = f"https://example.invalid/{name}.git"
    _git(path, "remote", "add", "origin", origin)
    _git(path, "update-ref", "refs/remotes/origin/main", "HEAD")
    return path, origin


def study(root: Path) -> dict:
    repositories, tasks = [], []
    for index in range(5):
        path, origin = _repository(
            root, f"induction-{index}", f"SEED = {index}\n")
        repositories.append({
            "repository_id": f"repo-induction-{index}",
            "lineage_id": f"lineage-induction-{index}",
            "path": str(path),
            "origin": origin,
            "partition": "induction",
        })
    holdout = []
    for index in range(5):
        path, origin = _repository(
            root, f"holdout-{index}", f"NO = {index}\n")
        hidden = root / "private" / f"hidden-{index}.py"
        hidden.parent.mkdir(exist_ok=True)
        hidden.write_text("def test_ok():\n    assert True\n")
        item = {
            "repository_id": f"repo-holdout-{index}",
            "lineage_id": f"lineage-holdout-{index}",
            "path": str(path),
            "origin": origin,
            "partition": "holdout",
            "hidden_tests": {"path": str(hidden)},
        }
        repositories.append(item)
        holdout.append((item, hidden))
    for index in range(9):
        item, hidden = holdout[index % len(holdout)]
        tasks.append({
            "task_id": f"task-{index:03d}",
            "repository_id": item["repository_id"],
            "prompt": f"make task {index} pass",
            "failure_class": "bug_fix",
            "acceptance": {
                "argv": [sys.executable, "-m", "pytest", "-q", hidden.name],
                "hidden_tests_path": str(hidden),
            },
        })
    # Five holdout repositories meet only the exploratory floor; a
    # confirmatory study needs MIN_CONFIRMATORY_HOLDOUT_REPOSITORIES (20).
    return {
        "schema_version": 1,
        "kind": "five_arm_study_spec",
        "study_tier": "exploratory",
        "protocol": {
            "primary_metric": "paired solved_delta E vs A",
            "method": "mcnemar_exact",
            "alpha": 0.05,
            "min_effect": 1.0,
            "sample_size": 9,
            "budget": dict(BUDGET),
            "arms": list(GOVERNED_ARMS),
            "powered": True,
            "expected_baseline": 0.99,
            "expected_treatment": 0.01,
            "power": 0.8,
        },
        "agent": {
            "kind": "codex-cli",
            "model": "test-model",
            "cli_version": "0.0.0",
        },
        "preregistration": {
            "registered_at": "2026-11-16T00:00:00Z",
            "registered_by": "test",
        },
        "repositories": repositories,
        "tasks": tasks,
    }


class _RecordingVerifier:
    """Record task registrations; commit binding must fail before them."""

    def __init__(self):
        self.registrations = []

    def register_task(self, **kwargs):
        self.registrations.append(kwargs)


def _bundle(spec: dict) -> dict:
    induction = sorted(
        tree_digest(Path(repository["path"]), version=3)
        for repository in spec["repositories"]
        if repository["partition"] == "induction")
    components = {}
    for arm in ("B", "C", "D"):
        components[arm] = [{
            "candidate_id": f"candidate-{arm.lower()}",
            "candidate_digest": hashlib.sha256(arm.encode()).hexdigest(),
            "content_digest": hashlib.sha256(
                ("content-" + arm).encode()).hexdigest(),
            "evidence_digest": hashlib.sha256(
                ("evidence-" + arm).encode()).hexdigest(),
            "text": f"{arm} learned step",
        }]
    document = {
        "schema_version": 2,
        "kind": "learned_guidance_bundle",
        "source": "learned",
        "training": {"repository_digests": induction},
        "components": components,
    }
    document["bundle_digest"] = canonical_digest(
        "learned_guidance_bundle", 1, document)
    return document


@unittest.skipUnless(GIT, "git is required for base commits and lineage")
class StudyKitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = study(self.root)

    def test_a_complete_spec_becomes_a_ready_manifest(self):
        document, summary = builder.build_manifest(
            self.spec, check_agent=False)
        self.assertTrue(summary["ready"])
        self.assertEqual(summary["study_tier"], "exploratory")
        self.assertFalse(summary["confirmatory"])
        self.assertEqual(document["study_tier"], "exploratory")
        self.assertEqual(summary["repositories"], 10)
        self.assertEqual(summary["holdout_repositories_used"], 5)
        self.assertEqual(summary["holdout_snapshots_used"], 5)
        self.assertEqual(summary["distinct_holdout_lineages"], 5)
        self.assertEqual(summary["tasks"], 9)
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(report["valid"], report["problems"])
        self.assertTrue(report["ready"])
        self.assertEqual(report["manifest_digest"],
                         summary["manifest_digest"])

    def test_a_two_arm_spec_becomes_a_primary_contrast_manifest(self):
        spec = copy.deepcopy(self.spec)
        spec["kind"] = "primary_contrast_study_spec"
        spec["protocol"]["arms"] = list(PRIMARY_CONTRAST_ARMS)
        document, summary = builder.build_manifest(spec, check_agent=False)
        self.assertTrue(summary["ready"])
        self.assertEqual(document["kind"],
                         "primary_contrast_efficacy_manifest")
        self.assertEqual(document["protocol"]["arms"],
                         list(PRIMARY_CONTRAST_ARMS))
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(report["valid"], report["problems"])
        self.assertTrue(report["ready"])

    def test_a_confirmatory_spec_below_the_repository_floor_is_refused(self):
        for declared in (None, "confirmatory"):
            with self.subTest(declared=declared):
                spec = copy.deepcopy(self.spec)
                if declared is None:
                    del spec["study_tier"]
                else:
                    spec["study_tier"] = declared
                with self.assertRaisesRegex(
                        builder.StudySpecError,
                        "at least 20 must contribute tasks to a"
                        " confirmatory study"):
                    builder.build_manifest(spec, check_agent=False)

    def test_a_spec_cannot_declare_a_diagnostic_or_unknown_tier(self):
        for declared in ("diagnostic", "powered", None):
            with self.subTest(declared=declared):
                spec = copy.deepcopy(self.spec)
                spec["study_tier"] = declared
                with self.assertRaisesRegex(builder.StudySpecError,
                                            "study_tier must be"):
                    builder.build_manifest(spec, check_agent=False)

    def test_a_two_arm_spec_cannot_declare_five_arms(self):
        spec = copy.deepcopy(self.spec)
        spec["kind"] = "primary_contrast_study_spec"
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "arms must match"):
            builder.build_manifest(spec, check_agent=False)

    def test_the_cli_writes_a_manifest_that_validates(self):
        spec_path = self.root / "spec.json"
        spec_path.write_text(json.dumps(self.spec))
        output = self.root / "manifest.json"
        code = builder.main([
            "--spec", str(spec_path), "--output", str(output),
            "--skip-agent-check"])
        self.assertEqual(code, 0)
        report = validate_manifest(
            json.loads(output.read_text()), check_paths=True)
        self.assertTrue(report["ready"], report["problems"])

    def test_hidden_tests_inside_the_repository_are_refused(self):
        item = next(repository for repository in self.spec["repositories"]
                    if repository["partition"] == "holdout")
        inside = Path(item["path"]) / "hidden.py"
        inside.write_text("def test_ok():\n    assert True\n")
        item["hidden_tests"] = {"path": str(inside)}
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "inside the public repository"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_hidden_tests_inside_another_repository_are_refused(self):
        holdout = next(repository for repository in self.spec["repositories"]
                       if repository["partition"] == "holdout")
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        inside = Path(induction["path"]) / "hidden.py"
        inside.write_text("def test_ok():\n    assert True\n")
        holdout["hidden_tests"] = {"path": str(inside)}
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "inside repository"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_duplicate_holdout_lineages_are_refused(self):
        holdout = [repository for repository in self.spec["repositories"]
                   if repository["partition"] == "holdout"]
        holdout[1]["lineage_id"] = holdout[0]["lineage_id"]
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "share a lineage"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_task_must_target_a_holdout_repository(self):
        self.spec["tasks"][0]["repository_id"] = "repo-induction-0"
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "holdout repository"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_too_few_tasks_are_refused(self):
        self.spec["tasks"] = self.spec["tasks"][:8]
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "below the preregistered sample_size"):
            builder.build_manifest(self.spec, check_agent=False)

    @unittest.skipUnless(sys.platform != "win32", "symlink semantics are POSIX")
    def test_an_external_symlink_is_refused(self):
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        outside = self.root / "secret.txt"
        outside.write_text("EVALUATOR-ONLY")
        (Path(induction["path"]) / "escape").symlink_to(outside)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "external symlinks"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_dirty_repository_is_refused(self):
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        (Path(induction["path"]) / "solution.py").write_text("DIRTY = 1\n")
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "uncommitted changes"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_subdirectory_is_not_a_repository_root(self):
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        subdirectory = Path(induction["path"]) / "sub"
        subdirectory.mkdir()
        (subdirectory / "nested.py").write_text("NESTED = 1\n")
        induction["path"] = str(subdirectory)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "not the repository root"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_base_commit_must_match_the_checkout(self):
        self.spec["repositories"][0]["base_commit"] = "0" * 40
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "does not match the checkout"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_non_git_repository_is_refused(self):
        plain = self.root / "plain"
        plain.mkdir()
        (plain / "solution.py").write_text("NO = 9\n")
        self.spec["repositories"][0]["path"] = str(plain)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "not a Git checkout"):
            builder.build_manifest(self.spec, check_agent=False)
        self.spec["repositories"][0]["base_commit"] = "a" * 40
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "not a Git checkout"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_the_manifest_records_the_checkout_commits(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(report["ready"], report["problems"])
        self.assertEqual(len(report["repository_commits"]), 10)
        for repository in document["repositories"]:
            self.assertEqual(
                report["repository_commits"][repository["repository_id"]],
                repository["base_commit"])

    def test_the_manifest_records_the_execution_fingerprints(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(report["ready"], report["problems"])
        self.assertEqual(len(report["repository_execution"]), 10)
        for repository in document["repositories"]:
            self.assertEqual(
                report["repository_execution"][repository["repository_id"]],
                repository["repo_execution_digest"])

    def test_the_content_digest_ignores_modes(self):
        path = self.root / "modes"
        path.mkdir()
        script = path / "run.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        (path / "pkg").mkdir()
        (path / "pkg" / "mod.py").write_text("X = 1\n")
        content = tree_digest(path, version=3)
        execution = repository_execution_digest(path)
        os.chmod(script, 0o755)
        self.assertEqual(tree_digest(path, version=3), content)
        self.assertNotEqual(repository_execution_digest(path), execution)
        execution = repository_execution_digest(path)
        os.chmod(path / "pkg", 0o700)
        self.assertEqual(tree_digest(path, version=3), content)
        self.assertNotEqual(repository_execution_digest(path), execution)

    def test_the_validator_rejects_a_mode_change(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        os.chmod(Path(target["path"]) / "solution.py", 0o755)
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repository_execution_mismatch" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_campaign_rebinds_execution_state_before_execution(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        os.chmod(Path(target["path"]), 0o700)
        verifier = _RecordingVerifier()
        with self.assertRaisesRegex(ValueError,
                                    "repository_execution_mismatch"):
            campaign._real_tasks(document, verifier, custody="shared")
        self.assertEqual(verifier.registrations, [])

    def test_the_manifest_records_the_repository_origins(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        report = validate_manifest(document, check_paths=True)
        self.assertTrue(report["ready"], report["problems"])
        for repository in document["repositories"]:
            self.assertEqual(
                report["repository_origins"][repository["repository_id"]],
                repository["origin"])

    def test_a_repository_without_an_origin_is_refused(self):
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        _git(Path(induction["path"]), "remote", "remove", "origin")
        del induction["origin"]
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "has no origin remote"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_shallow_checkout_is_refused(self):
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        shallow = self.root / "shallow"
        subprocess.run(
            ["git", "clone", "-q", "--depth", "1",
             Path(induction["path"]).as_uri(), str(shallow)],
            check=True, capture_output=True)
        induction["path"] = str(shallow)
        induction["origin"] = _git(
            shallow, "remote", "get-url", "origin").stdout.strip()
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "shallow history"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_the_validator_rejects_an_origin_mismatch(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        target["origin"] = "https://example.invalid/other.git"
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repository_origin_mismatch" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_validator_rejects_a_commit_not_on_a_remote_ref(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        _git(Path(target["path"]), "-c", "user.name=SIS", "-c",
             "user.email=sis@example.invalid", "commit", "--allow-empty",
             "-qm", "local only")
        head = _git(Path(target["path"]), "rev-parse", "HEAD").stdout.strip()
        target["base_commit"] = head
        for task in document["tasks"]:
            if task["repository_id"] == target["repository_id"]:
                task["base_commit"] = head
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repository_commit_not_on_remote" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_campaign_rebinds_provenance_before_execution(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        _git(Path(target["path"]), "-c", "user.name=SIS", "-c",
             "user.email=sis@example.invalid", "commit", "--allow-empty",
             "-qm", "local only")
        head = _git(Path(target["path"]), "rev-parse", "HEAD").stdout.strip()
        target["base_commit"] = head
        for task in document["tasks"]:
            if task["repository_id"] == target["repository_id"]:
                task["base_commit"] = head
        verifier = _RecordingVerifier()
        with self.assertRaisesRegex(ValueError,
                                    "repository_commit_not_on_remote"):
            campaign._real_tasks(document, verifier, custody="shared")
        self.assertEqual(verifier.registrations, [])

    def test_the_validator_rejects_a_fabricated_base_commit(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        target["base_commit"] = "0" * 40
        for task in document["tasks"]:
            if task["repository_id"] == target["repository_id"]:
                task["base_commit"] = "0" * 40
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertFalse(report["ready"])
        self.assertTrue(any("repository_base_commit_mismatch" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_validator_rejects_a_dirty_checkout(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        (Path(target["path"]) / "solution.py").write_text("DIRTY = 1\n")
        target["repo_snapshot_digest"] = tree_digest(
            Path(target["path"]), version=3)
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repository_is_dirty" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_validator_rejects_a_checkout_without_git(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        plain = self.root / "plain-holdout"
        shutil.copytree(target["path"], plain,
                        ignore=shutil.ignore_patterns(".git"))
        target["path"] = str(plain)
        target["repo_snapshot_digest"] = tree_digest(plain, version=3)
        report = validate_manifest(document, check_paths=True)
        self.assertFalse(report["valid"])
        self.assertTrue(any("repository_head_unverifiable" in problem
                            for problem in report["problems"]),
                        report["problems"])

    def test_the_campaign_rebinds_every_commit_before_execution(self):
        document, _ = builder.build_manifest(self.spec, check_agent=False)
        target = next(item for item in document["repositories"]
                      if item["partition"] == "holdout")
        _git(Path(target["path"]), "-c", "user.name=SIS", "-c",
             "user.email=sis@example.invalid", "commit", "--allow-empty",
             "-qm", "moved after validation")
        verifier = _RecordingVerifier()
        with self.assertRaisesRegex(ValueError,
                                    "repository_base_commit_mismatch"):
            campaign._real_tasks(document, verifier, custody="shared")
        self.assertEqual(verifier.registrations, [])

    def test_a_missing_hidden_tests_record_is_refused(self):
        item = next(repository for repository in self.spec["repositories"]
                    if repository["partition"] == "holdout")
        del item["hidden_tests"]
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "hidden_tests must be an object"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_diagnostic_protocol_is_refused(self):
        self.spec["protocol"]["powered"] = False
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "powered confirmatory manifest"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_an_output_inside_a_repository_is_refused(self):
        spec_path = self.root / "spec.json"
        spec_path.write_text(json.dumps(self.spec))
        holdout = next(repository for repository in self.spec["repositories"]
                       if repository["partition"] == "holdout")
        output = Path(holdout["path"]) / "manifest.json"
        code = builder.main([
            "--spec", str(spec_path), "--output", str(output),
            "--skip-agent-check"])
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())

    def test_a_spec_inside_a_repository_is_refused(self):
        holdout = next(repository for repository in self.spec["repositories"]
                       if repository["partition"] == "holdout")
        spec_path = Path(holdout["path"]) / "spec.json"
        spec_path.write_text(json.dumps(self.spec))
        output = self.root / "manifest.json"
        code = builder.main([
            "--spec", str(spec_path), "--output", str(output),
            "--skip-agent-check"])
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())

    def test_a_bundle_inside_a_repository_is_refused(self):
        bundle = _bundle(self.spec)
        induction = next(repository for repository in self.spec["repositories"]
                         if repository["partition"] == "induction")
        path = Path(induction["path"]) / "bundle.json"
        path.write_text(json.dumps(bundle))
        self.spec["guidance_bundle"] = str(path)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "must not be inside repository"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_no_output_is_written_when_the_spec_is_rejected(self):
        self.spec["tasks"] = self.spec["tasks"][:1]
        spec_path = self.root / "spec.json"
        spec_path.write_text(json.dumps(self.spec))
        output = self.root / "manifest.json"
        code = builder.main([
            "--spec", str(spec_path), "--output", str(output),
            "--skip-agent-check"])
        self.assertEqual(code, 1)
        self.assertFalse(output.exists())

    def test_a_future_preregistration_is_refused(self):
        self.spec["preregistration"]["registered_at"] = "2099-01-01T00:00:00Z"
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "must not be in the future"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_the_guidance_bundle_digest_is_bound(self):
        bundle = _bundle(self.spec)
        path = self.root / "bundle.json"
        path.write_text(json.dumps(bundle))
        self.spec["guidance_bundle"] = str(path)
        document, summary = builder.build_manifest(
            self.spec, check_agent=False)
        self.assertEqual(document["guidance_bundle_digest"],
                         bundle["bundle_digest"])
        self.assertEqual(summary["guidance_bundle_digest"],
                         bundle["bundle_digest"])
        induction = tuple(sorted(
            repository["repo_snapshot_digest"]
            for repository in document["repositories"]
            if repository["partition"] == "induction"))
        holdout = tuple(sorted(
            repository["repo_snapshot_digest"]
            for repository in document["repositories"]
            if repository["partition"] == "holdout"))
        loaded = campaign._load_guidance_bundle(
            path, induction_digests=induction, holdout_digests=holdout,
            precommitted_digest=document["guidance_bundle_digest"])
        self.assertEqual(loaded["bundle_digest"], bundle["bundle_digest"])
        self.assertEqual(loaded["source"], "learned_unverified")

    def test_a_bundle_trained_on_holdout_is_refused(self):
        bundle = _bundle(self.spec)
        holdout = next(repository for repository in self.spec["repositories"]
                       if repository["partition"] == "holdout")
        bundle["training"]["repository_digests"] = [
            tree_digest(Path(holdout["path"]), version=3)]
        bundle["bundle_digest"] = canonical_digest(
            "learned_guidance_bundle", 1,
            {key: value for key, value in bundle.items()
             if key != "bundle_digest"})
        path = self.root / "bundle.json"
        path.write_text(json.dumps(bundle))
        self.spec["guidance_bundle"] = str(path)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "not induction partitions"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_a_bundle_with_a_wrong_internal_digest_is_refused(self):
        bundle = _bundle(self.spec)
        bundle["bundle_digest"] = "0" * 64
        path = self.root / "bundle.json"
        path.write_text(json.dumps(bundle))
        self.spec["guidance_bundle"] = str(path)
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "does not match its contents"):
            builder.build_manifest(self.spec, check_agent=False)

    def test_duplicate_spec_keys_are_refused(self):
        path = self.root / "duplicate.json"
        path.write_text('{"schema_version": 1, "schema_version": 1,'
                        ' "kind": "five_arm_study_spec"}')
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "duplicate JSON object key"):
            builder.load_spec(path)

    @unittest.skipUnless(shutil.which("codex"),
                         "codex CLI is not installed")
    def test_the_installed_agent_version_must_match(self):
        self.spec["agent"]["cli_version"] = "0.0.0"
        with self.assertRaisesRegex(builder.StudySpecError,
                                    "does not match the spec"):
            builder.build_manifest(self.spec, check_agent=True)


if __name__ == "__main__":
    unittest.main()
