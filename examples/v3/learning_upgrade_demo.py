"""Offline candidate-learning demo (NOT proof of generalization).

Use: PYTHONPATH=src python examples/v3/learning_upgrade_demo.py
Sample receipts are synthetic and explicitly marked demo-only. Never promote
anything issued by this script or use these inputs as independent evidence.
"""
import json

from sis.v3.learning import (
    EpisodeEvidence, induce_strategies, induce_structural_change,
    strategy_to_record, structure_to_record,
)


def main():
    lessons = induce_strategies([
        EpisodeEvidence("demo-1", "repo-a", "pytest:exit_1", "pass", "1" * 64,
                        ("isolate failing test", "compare contract"), verified=True),
        EpisodeEvidence("demo-2", "repo-b", "pytest:exit_1", "pass", "2" * 64,
                        ("isolate failing test", "check assertions"), verified=True),
        EpisodeEvidence("demo-3", "repo-c", "pytest:exit_1", "fail", "3" * 64,
                        ("rerun entire suite",), verified=True),
    ])
    structural = induce_structural_change(
        "def fix(a, b):\n    return a - b\n",
        "def fix(a, b):\n    return a + b\n",
        semantic_contract_digest="4" * 64,
        independently_verified_receipt_digest="5" * 64,
    )
    records = [strategy_to_record(lesson, language="python") for lesson in lessons]
    if structural:
        records.append(structure_to_record(structural))
    print(json.dumps([{
        "id": r.procedure_id, "status": r.status, "evidence": list(r.evidence_refs),
        "steps": list(r.steps)
    } for r in records], indent=2))
    print("DEMO ONLY: all candidates are unqualified; receipt markers are synthetic")


if __name__ == "__main__":
    main()
