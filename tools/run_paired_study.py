#!/usr/bin/env python3
"""Run the preregistered repository-disjoint paired study (M6).

Loads a study spec JSON, enforces evaluation-repository disjointness,
executes the four-arm benchmark under hard budgets, and writes a
content-addressed summary with the D-vs-A decision rule outcome.

Spec format:
{
  "learned_repo_digests": ["<sha256>..."],
  "budget": {"wall_seconds": N, "token_budget": N, "tool_budget": N},
  "tasks": [{"task_id": "...", "repo_snapshot_digest": "...",
             "base_commit": "...", "task_statement_digest": "...",
             "permitted_commands": [...], "isolation_profile": "...",
             "time_budget_seconds": N, "token_budget": N,
             "tool_budget": N, "actor_id": "...",
             "evaluator_task_ref": null,
             "workspace": "path/to/fixture"}]
}

The agent is provided by a Python entry point:
  --agent module:callable   (AgentFn: (ArmContext) -> dict outcome)
Usage: tools/run_paired_study.py spec.json --agent mod:fn -o report.json
"""
from __future__ import annotations

import argparse
import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sis.v3.benchmark import BenchmarkHarness, BudgetCaps, report_digest
from sis.v3.contracts import ContractError, TaskEnvelopeV1
from sis.v3.evaluation import assert_repository_disjoint, paired_summary


def _load_spec(path: Path) -> dict:
    spec = json.loads(path.read_text())
    for key in ("learned_repo_digests", "budget", "tasks"):
        if key not in spec:
            raise ContractError(f"study spec missing {key}")
    return spec


def _envelopes(spec: dict) -> list[tuple[TaskEnvelopeV1, Path]]:
    tasks = []
    for entry in spec["tasks"]:
        workspace = entry.pop("workspace")
        env = TaskEnvelopeV1.from_dict(entry)
        tasks.append((env, Path(workspace)))
    return tasks


def _agent(ref: str):
    module_name, func = ref.split(":", 1)
    return getattr(importlib.import_module(module_name), func)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("spec", type=Path)
    parser.add_argument("--agent", required=True,
                        help="module:callable implementing AgentFn")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--context-provider", default=None,
                        help="module:callable implementing ContextFn")
    args = parser.parse_args()

    spec = _load_spec(args.spec)
    tasks = _envelopes(spec)
    assert_repository_disjoint(spec["learned_repo_digests"],
                               [t for t, _ in tasks])

    budget = BudgetCaps(
        wall_seconds=float(spec["budget"]["wall_seconds"]),
        token_budget=spec["budget"].get("token_budget"),
        tool_budget=spec["budget"].get("tool_budget"))
    harness = BenchmarkHarness()
    context = _agent(args.context_provider) if args.context_provider else None
    report = harness.run(tasks, _agent(args.agent), budget=budget,
                         context_provider=context)
    summary = paired_summary(report)
    digest = report_digest(report)
    outcome = {"report_digest": digest, "report": report,
               "summary": summary}
    args.output.write_text(json.dumps(outcome, indent=2, sort_keys=True))
    delta = summary["contrast"]["solved_delta"]
    p_value = float(summary["contrast"]["mcnemar_exact_p"])
    passed = delta > 0 and p_value <= 0.05
    print(f"report_digest: {digest}")
    print(f"D-vs-A solved_delta={delta} mcnemar_p={p_value}")
    print(f"efficacy_gate: {'PASS' if passed else 'NOT MET'}")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
