"""Worked skill-holdout examples: ingest -> probe -> qualify -> serve."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

import skill_holdouts  # noqa: E402

SKILLS = {
    "write-skills": (
        "# Write skills\n\n"
        "- Trigger from the description: the frontmatter description is the "
        "only part read before the skill loads.\n"
        "- Keep the body short.\n"),
    "php2shell-check": (
        "# php2shell check\n\n"
        "- Docker official images: pin php:8.5.12, php:8.4.27, php:8.3.36 "
        "or php:8.2.35 and rebuild with --pull --no-cache.\n"
        "- Restart workers after the upgrade.\n"),
    "write-tests": (
        "# Write tests\n\n"
        "- Pin observable behavior through the outermost practical entry "
        "point, not the current implementation.\n"
        "- Prove the test can fail before calling it done.\n"),
}


def _write_skills(root: Path, names=SKILLS) -> Path:
    for name, body in names.items():
        skill = root / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: {name}\ndescription: Use when testing {name}.\n"
            f"---\n\n{body}", encoding="utf-8")
    return root


class RegistryTests(unittest.TestCase):
    def test_registry_is_consistent(self):
        names = skill_holdouts.registered_names()
        self.assertEqual(len(names), len(set(names)))
        task_ids = [holdout.task_id for holdout in skill_holdouts.HOLDOUTS]
        self.assertEqual(len(task_ids), len(set(task_ids)))
        for holdout in skill_holdouts.HOLDOUTS:
            self.assertIn(holdout.tier, {"A", "B"})
            self.assertTrue(holdout.fixture)
            self.assertTrue(holdout.good)
            self.assertTrue(holdout.test)
            self.assertTrue(holdout.keyword)
        registered = set(names)
        planned = set(skill_holdouts.PLANNED)
        excluded = set(skill_holdouts.EXCLUDED)
        self.assertFalse(registered & planned)
        self.assertFalse(registered & excluded)
        self.assertFalse(planned & excluded)

    def test_select_filters_by_tier_and_name(self):
        self.assertEqual(
            [h.skill for h in skill_holdouts.select(only="write-tests")],
            ["write-tests"])
        self.assertEqual(len(skill_holdouts.select(tier="A")),
                         len(skill_holdouts.HOLDOUTS))
        self.assertEqual(skill_holdouts.select(tier="B"), ())
        self.assertEqual(skill_holdouts.select(only="not-registered"), ())


class SkillHoldoutCLITests(unittest.TestCase):
    def _env(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src") + os.pathsep + str(REPO)
        return env

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(REPO / "tools" / "skill_holdout.py"),
             *args],
            capture_output=True, text=True, env=self._env(), cwd=REPO,
            timeout=300)

    def test_all_registered_examples_qualify_and_serve(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills")
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            report = json.loads(report_path.read_text())
            self.assertEqual(report["kind"], "skill_holdout")
            self.assertEqual(report["missing_skills"], [])
            self.assertEqual([r["skill"] for r in report["results"]],
                             ["write-skills", "php2shell-check",
                              "write-tests"])
            for entry in report["results"]:
                self.assertEqual(entry["status"], "qualified")
                self.assertEqual(entry["state"], "qualified")
                self.assertEqual(entry["probe"]["solved"]["A"], 0)
                self.assertEqual(entry["probe"]["solved"]["E"], 1)
                self.assertTrue(entry["probe"]["conformance"]["conforms"],
                                entry["probe"]["conformance"])
                self.assertTrue(entry["served"]["delivered_skill_steps"])
                self.assertEqual(entry["served"]["decision"], "advisory")
                self.assertEqual(entry["served"]["reason_code"],
                                 "no_qualified_procedure")
                self.assertEqual(len(entry["evidence_digest"]), 64)
                self.assertEqual(len(entry["decision_digest"]), 64)
            self.assertTrue(report["registry"]["verify"]["ok"])
            kinds = [row["kind"] for row in report["serving_audit"]]
            self.assertEqual(kinds, ["served_guidance", "serving_outcome"] * 3)

    def test_list_reports_tiers_and_exclusions(self):
        proc = self._run("--list")
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        registry = json.loads(proc.stdout)
        self.assertEqual([entry["skill"] for entry in registry["registered"]],
                         ["write-skills", "php2shell-check", "write-tests"])
        self.assertEqual({entry["tier"] for entry in registry["registered"]},
                         {"A"})
        self.assertTrue(registry["planned"])
        self.assertIn("greet-anton-abyzov", registry["excluded"])

    def test_only_filters_to_one_skill(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills")
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "--only", "write-tests", "-o", str(report_path))
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            report = json.loads(report_path.read_text())
            self.assertEqual(report["selected"], ["write-tests"])
            self.assertEqual([r["skill"] for r in report["results"]],
                             ["write-tests"])
            self.assertEqual(report["results"][0]["status"], "qualified")

    def test_planned_and_excluded_selections_are_explained(self):
        planned = self._run("--only", "implement-spec")
        self.assertEqual(planned.returncode, 2)
        self.assertEqual(json.loads(planned.stdout)["error"],
                         "holdout_not_registered")
        excluded = self._run("--only", "greet-anton-abyzov")
        self.assertEqual(excluded.returncode, 2)
        self.assertEqual(json.loads(excluded.stdout)["error"],
                         "holdout_excluded")
        tier = self._run("--tier", "B")
        self.assertEqual(tier.returncode, 2)
        payload = json.loads(tier.stdout)
        self.assertEqual(payload["error"],
                         "no_registered_holdouts_in_tier")
        self.assertTrue(payload["planned"])

    def test_missing_skill_is_reported_and_fails_the_run(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills",
                          {"write-skills": SKILLS["write-skills"]})
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 1)
            report = json.loads(report_path.read_text())
            self.assertEqual(report["missing_skills"],
                             ["php2shell-check", "write-tests"])
            statuses = {r["skill"]: r["status"] for r in report["results"]}
            self.assertEqual(statuses["write-skills"], "qualified")
            self.assertEqual(statuses["php2shell-check"], "missing_skill")
            self.assertEqual(statuses["write-tests"], "missing_skill")

    def test_unrelated_guidance_cannot_pass_the_holdout(self):
        # The php fixture's guidance keyword is absent, so the scripted
        # agent leaves the vulnerable Dockerfile and the private test fails.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_skills(root / "skills", {
                "write-skills": SKILLS["write-skills"],
                "write-tests": SKILLS["write-tests"],
                "php2shell-check": (
                    "# php2shell check\n\n- Restart workers after the "
                    "upgrade.\n"),
            })
            report_path = root / "holdout.json"
            proc = self._run("--skills-root", str(root / "skills"),
                             "-o", str(report_path))
            self.assertEqual(proc.returncode, 1)
            report = json.loads(report_path.read_text())
            statuses = {r["skill"]: r["status"] for r in report["results"]}
            self.assertEqual(statuses["write-skills"], "qualified")
            self.assertEqual(statuses["write-tests"], "qualified")
            self.assertEqual(statuses["php2shell-check"], "no_pass_evidence")
            php = next(r for r in report["results"]
                       if r["skill"] == "php2shell-check")
            self.assertEqual(php["probe"]["solved"], {"A": 0, "E": 0})


if __name__ == "__main__":
    unittest.main()
