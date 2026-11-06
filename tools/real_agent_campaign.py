#!/usr/bin/env python3
"""Run the five-arm real-agent qualification campaign (exploratory).

This executes real Codex CLI coding turns against eight synthetic,
repository-disjoint tasks and evaluates every arm with independently
signed receipts. The guidance bundles are fixed and frozen before the
run; they are not learned from these tasks. The run is therefore
reported as EXPLORATORY: it proves the real-agent path executes and
produces paired outcomes, not that SIS learning improves coding.

Usage:
    python3 tools/real_agent_campaign.py -o evidence/evaluation/real_agent_five_arm.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps  # noqa: E402
from sis.v3.contracts import GuidanceV1, TaskEnvelopeV1  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.governed_eval import GOVERNED_ARMS, preregister  # noqa: E402
from sis.v3.learning_qualification import (  # noqa: E402
    CodexCliAgent, FiveArmCampaign, build_context_provider,
    codex_agent_status, write_report)
from sis.v3.runner import (LocalSubprocessExecutor, ResourceLimits,  # noqa: E402
                           tree_digest)
from sis.v3.verifier import OutcomeVerifier  # noqa: E402

PY = sys.executable


@dataclass(frozen=True)
class TaskSpec:
    task_id: str
    family: str
    prompt: str
    files: dict
    test: str


def _specs() -> list[TaskSpec]:
    return [
        TaskSpec(
            "bug-average", "bug_fix",
            "Fix calc.py so average(values) returns the true arithmetic "
            "mean for integer and float inputs. Keep the function name and "
            "signature. Add or run a focused test.",
            {"calc.py": "def average(values):\n"
                        "    return sum(values) // len(values)\n"},
            "from calc import average\n\n"
            "def test_mean_float():\n"
            "    assert average([1, 2]) == 1.5\n\n"
            "def test_mean_int():\n"
            "    assert average([2, 2]) == 2.0\n"),
        TaskSpec(
            "bug-clamp", "bug_fix",
            "Fix limits.py so clamp(value, low, high) returns low below the "
            "range, high above it, and value inside it. Keep the public name.",
            {"limits.py": "def clamp(value, low, high):\n"
                          "    if value < low:\n        return high\n"
                          "    if value > high:\n        return low\n"
                          "    return value\n"},
            "from limits import clamp\n\n"
            "def test_clamp():\n"
            "    assert clamp(5, 0, 10) == 5\n"
            "    assert clamp(-1, 0, 10) == 0\n"
            "    assert clamp(11, 0, 10) == 10\n"),
        TaskSpec(
            "api-alias", "api_compatibility",
            "api.py exposes parse_amount(text). Existing callers also import "
            "parse_money(text). Add a backward-compatible parse_money alias "
            "without changing parse_amount behavior.",
            {"api.py": "def parse_amount(text):\n"
                       "    return int(str(text).replace(',', ''))\n"},
            "from api import parse_amount, parse_money\n\n"
            "def test_alias():\n"
            "    assert parse_money('1,200') == 1200\n"
            "    assert parse_amount('7') == 7\n"),
        TaskSpec(
            "multi-config", "multi_file_edit",
            "config.py owns TIMEOUT. client.py currently hardcodes 10. Make "
            "client.DEFAULT_TIMEOUT and client.timeout() use config.TIMEOUT "
            "without changing their names.",
            {"config.py": "TIMEOUT = 30\n",
             "client.py": "DEFAULT_TIMEOUT = 10\n\n"
                          "def timeout():\n    return 10\n"},
            "import client, config\n\n"
            "def test_single_source():\n"
            "    assert client.DEFAULT_TIMEOUT == config.TIMEOUT\n"
            "    assert client.timeout() == config.TIMEOUT\n"),
        TaskSpec(
            "refactor-discount", "refactoring",
            "pricing.py has two near-duplicate discount functions; "
            "discount_b is wrong by one unit. Remove the duplication, keep "
            "both public names, and make both return the same correct price.",
            {"pricing.py": "def discount_a(price, pct):\n"
                           "    return price - price * pct / 100\n\n"
                           "def discount_b(price, pct):\n"
                           "    return price - price * (pct / 100) + 1\n"},
            "from pricing import discount_a, discount_b\n\n"
            "def test_both():\n"
            "    assert discount_a(200, 10) == 180\n"
            "    assert discount_b(200, 10) == 180\n"),
        TaskSpec(
            "dep-import", "dependency_debugging",
            "pkg/core.py imports normalize from pkg.helpers, but the helper "
            "lives in pkg.utils. Fix the import without renaming the public "
            "process() function.",
            {"pkg/__init__.py": "",
             "pkg/utils.py": "def normalize(text):\n"
                             "    return text.strip().lower()\n",
             "pkg/core.py": "from pkg.helpers import normalize\n\n"
                            "def process(text):\n"
                            "    return normalize(text)\n"},
            "from pkg.core import process\n\n"
            "def test_process():\n"
            "    assert process('  Hi ') == 'hi'\n"),
        TaskSpec(
            "diag-bank", "failure_diagnosis",
            "bank.py Account.withdraw currently allows an overdraft. Diagnose "
            "the failing behavior and raise ValueError when the amount is "
            "negative or exceeds the balance. Return the new balance on "
            "success.",
            {"bank.py": "class Account:\n"
                        "    def __init__(self, balance):\n"
                        "        self.balance = balance\n\n"
                        "    def withdraw(self, amount):\n"
                        "        self.balance -= amount\n"
                        "        return self.balance\n"},
            "import pytest\nfrom bank import Account\n\n"
            "def test_overdraft_rejected():\n"
            "    with pytest.raises(ValueError):\n"
            "        Account(10).withdraw(11)\n\n"
            "def test_success():\n"
            "    assert Account(10).withdraw(4) == 6\n"),
        TaskSpec(
            "test-slug", "test_generation",
            "Add test_slugify.py with exact-output tests for slugify(text). "
            "Include a multi-word input and an input with punctuation. The "
            "tests must fail if slugify stops joining words with hyphens.",
            {"slugify.py": "import re\n\n"
                           "def slugify(text):\n"
                           "    value = re.sub(r'[^a-z0-9]+', '-', "
                           "text.lower()).strip('-')\n"
                           "    return value\n"},
            "import subprocess, sys\nfrom pathlib import Path\n\n"
            "def _run():\n"
            "    return subprocess.run(\n"
            "        [sys.executable, '-m', 'pytest', '-q', "
            "'test_slugify.py'], capture_output=True, text=True)\n\n"
            "def test_tests_catch_mutation():\n"
            "    tree = Path.cwd()\n"
            "    assert (tree / 'test_slugify.py').is_file()\n"
            "    assert _run().returncode == 0\n"
            "    target = tree / 'slugify.py'\n"
            "    target.write_text('def slugify(text):\\n"
            "    return text.lower()\\n')\n"
            "    assert _run().returncode != 0\n"),
    ]


MEMORY = {
    "bug_fix": "Recall: reproduce the failure, check empty/zero/negative "
               "and boundary inputs, preserve the public API.",
    "api_compatibility": "Recall: existing callers are part of the contract; "
                         "keep the old name working.",
    "multi_file_edit": "Recall: after changing a shared value or name, "
                       "update every caller.",
    "refactoring": "Recall: remove duplication without changing either "
                   "public behavior.",
    "dependency_debugging": "Recall: trace the import to the module that "
                            "actually defines the symbol.",
    "failure_diagnosis": "Recall: identify the invalid state, then raise the "
                         "documented error instead of silently accepting it.",
    "test_generation": "Recall: a good test pins exact behavior and fails on "
                       "a plausible mutant.",
}
SKILL = {
    "bug_fix": "Workflow: read the task, locate the public function, make the "
               "smallest change, run a focused test, then check edge cases.",
    "api_compatibility": "Workflow: keep the old symbol as an alias, then "
                         "verify both entry points.",
    "multi_file_edit": "Workflow: find every caller, update the shared source, "
                       "then run the focused test.",
    "refactoring": "Workflow: extract the shared helper, keep both public "
                   "names, and compare outputs.",
    "dependency_debugging": "Workflow: list the package, find the defining "
                            "module, fix the import, then import the public API.",
    "failure_diagnosis": "Workflow: reproduce the invalid state, add the guard, "
                         "and test both success and failure.",
    "test_generation": "Workflow: create test_slugify.py, assert exact outputs, "
                       "and include punctuation and multi-word cases.",
}
SYMBOLIC = {
    "bug_fix": "Procedure: expected vs actual; adjust the arithmetic operator; "
               "verify two examples.",
    "api_compatibility": "Procedure: old symbol -> same callable; verify old "
                         "and new names.",
    "multi_file_edit": "Procedure: shared constant -> one definition -> all "
                       "callers read it.",
    "refactoring": "Procedure: duplicate bodies -> one helper -> both names "
                   "delegate.",
    "dependency_debugging": "Procedure: unresolved symbol -> defining module "
                            "-> corrected import.",
    "failure_diagnosis": "Procedure: invalid transition -> explicit exception "
                         "-> success path unchanged.",
    "test_generation": "Procedure: input -> exact output; mutate behavior; "
                       "test must go red.",
}


def _guidance(family: str, arm: str) -> GuidanceV1 | None:
    if arm == "A":
        return None
    steps: list[str] = []
    if arm in {"B", "E"}:
        steps.append(MEMORY[family])
    if arm in {"C", "E"}:
        steps.append(SKILL[family])
    if arm in {"D", "E"}:
        steps.append(SYMBOLIC[family])
    return GuidanceV1(
        schema_version=1, decision="recommend",
        procedure_ids=("real-agent-guidance",), revision="0" * 64,
        matched_preconditions=({"kind": "language_is", "value": "python"},),
        contraindications=(), evidence_ids=("0" * 64,),
        policy_digest="0" * 64, helpful_next_checks=tuple(steps),
        reason_code=None, approximate_tokens=120)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", "-o", type=Path,
                        default=Path("evidence/evaluation/real_agent_five_arm.json"))
    parser.add_argument("--max-tasks", type=int, default=None)
    args = parser.parse_args()

    status = codex_agent_status()
    if not status["available"] or not status["authenticated"]:
        print(json.dumps({"error": "real_agent_unavailable", **status}))
        return 2

    specs = _specs()
    if args.max_tasks is not None:
        specs = specs[:args.max_tasks]
    with tempfile.TemporaryDirectory(prefix="sis-real-agent-") as temp:
        root = Path(temp)
        profile = EvaluationRuntimeProfile(
            cpu_seconds=60, wall_seconds=180, process_count=None,
            bootstrap_process_count=None)
        verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                root / "exec",
                protected_paths=(root / "keys", root / "registry")),
            key_dir=root / "keys", registry_dir=root / "registry",
            limits=ResourceLimits(
                wall_seconds=180, cpu_seconds=60,
                memory_bytes=profile.task_memory_bytes,
                process_count=None),
            runtime_profile=profile)
        prompts: dict[str, str] = {}
        tasks = []
        for spec in specs:
            repo = root / "repos" / spec.task_id
            repo.mkdir(parents=True)
            for relative, content in spec.files.items():
                target = repo / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
            statement = hashlib.sha256(spec.prompt.encode()).hexdigest()
            verifier.register_task(
                actor_role="evaluator", task_id=spec.task_id,
                criterion_version="v1",
                argv=(PY, "-m", "pytest", "-q", "eval_tests.py"),
                files={"eval_tests.py": spec.test.encode()},
                base_commit="abc1234", statement_digest=statement)
            tasks.append((TaskEnvelopeV1(
                schema_version=1, task_id=spec.task_id,
                repo_snapshot_digest=tree_digest(repo),
                base_commit="abc1234",
                task_statement_digest=statement,
                permitted_commands=("pytest",),
                isolation_profile="unverified_local",
                time_budget_seconds=300, token_budget=100000,
                tool_budget=1000, actor_id="agent",
                evaluator_task_ref=spec.task_id), repo))
            prompts[spec.task_id] = spec.prompt

        protocol = preregister(
            primary_metric="paired solved_delta E vs A",
            method="mcnemar_exact", alpha=0.05, min_effect=1.0,
            sample_size=len(specs),
            budget={"wall_seconds": 300, "token_budget": 100000,
                    "tool_budget": 1000},
            arms=GOVERNED_ARMS,
            expected_baseline=0.8, expected_treatment=0.2,
            notes=("Real Codex CLI; eight synthetic repository-disjoint "
                   "tasks; fixed guidance bundles frozen before the run; "
                   "exploratory because the preregistered power target is "
                   "larger than the executed sample."))
        family = {spec.task_id: spec.family for spec in specs}
        served: dict = {}

        def provider(task, arm):
            guidance = _guidance(family[task.task_id], arm)
            served[(task.task_id, arm)] = bool(
                guidance is not None and guidance.helpful_next_checks)
            return guidance

        base_agent = CodexCliAgent(
            wall_seconds=240, prompts=prompts)

        def agent(ctx):
            print(f"RUN {ctx.task.task_id} arm={ctx.arm}", flush=True)
            result = base_agent(ctx)
            print(f"DONE {ctx.task.task_id} arm={ctx.arm} "
                  f"tools={result.get('tools_used')}", flush=True)
            return result

        campaign = FiveArmCampaign(
            harness=BenchmarkHarness(
                verifier=verifier, work_root=root / "work"),
            tasks=tasks, agent=agent,
            budget=BudgetCaps(wall_seconds=300, token_budget=100000,
                              tool_budget=1000),
            protocol=protocol, context_provider=provider,
            served_map=served, learned_repo_digests=(), real_agent=True,
            hidden_holdout=True)
        report = campaign.run()
        base_agent.close()
        analysis = report["learning_qualification"]
        report["kind"] = "real_agent_five_arm_evaluation"
        report["codex_gate"] = status
        report["evaluator_runtime"] = profile.as_dict()
        report["evaluator_runtime_digest"] = profile.digest
        report["bootstrap"] = verifier.bootstrap().as_dict()
        report["guidance_bundles"] = {
            "memory": MEMORY, "skill": SKILL, "symbolic": SYMBOLIC}
        report["note"] = (
            "Real Codex CLI execution. Fixed guidance bundles, eight "
            "synthetic repository-disjoint tasks. Exploratory: the "
            "preregistered power target is larger than the executed sample; "
            "no confirmatory efficacy claim.")
        write_report(report, args.output)
        print(json.dumps({
            "kind": report["kind"],
            "tasks": analysis["tasks"],
            "evidence_class": analysis["evidence_class"],
            "efficacy_claim": analysis["efficacy_claim"],
            "release_gate": analysis["release_gate"],
            "underpowered": analysis["underpowered"],
            "decisive_contrast": analysis["decisive_contrast"],
            "output": str(args.output),
        }, indent=2))
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
