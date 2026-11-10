"""Induction scalability benchmark (SIS v3.3.4, Phase 4.5).

Runs the same representable rule at increasing feature counts and reports
what the bounded search actually did: candidates, signature checks,
runtime, traced peak memory, whether the rule was recovered, whether it
generalized to the sealed holdout, and whether it was a false positive
(passed selection but failed the holdout).

The target is ``x[n-2] * x[n-1] + 2`` so every feature count has the same
relevant pair and the rest are decoys. This is a search-cost benchmark,
not an efficacy study.

Usage:
    PYTHONPATH=src python3 tools/benchmark_induction.py
    PYTHONPATH=src python3 tools/benchmark_induction.py --fields 2,4,8
"""
from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import time
import tracemalloc
from datetime import datetime, timezone

from sis.expression import evaluate
from sis.induction import SearchBudget, induce


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="seconds").replace("+00:00", "Z")


def study(features: int, *, seed: int, train_n: int, dev_n: int,
          holdout_n: int):
    names = [f"x{i}" for i in range(features)]
    rng = random.Random(seed)
    rows: list[dict] = []
    seen: set[tuple] = set()
    while len(rows) < train_n + dev_n + holdout_n:
        inputs = {name: rng.randint(0, 9) for name in names}
        key = tuple(inputs[name] for name in names)
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "inputs": inputs,
            "output": inputs[names[-2]] * inputs[names[-1]] + 2,
        })
    return (rows[:train_n],
            rows[train_n:train_n + dev_n],
            rows[train_n + dev_n:])


def run_case(features: int, args) -> dict:
    train, dev, holdout = study(
        features, seed=args.seed,
        train_n=args.train, dev_n=args.dev, holdout_n=args.holdout)
    budget = SearchBudget(
        max_candidates=args.max_candidates,
        max_signature_checks=args.max_signature_checks,
        max_wall_seconds=args.max_wall_seconds,
        max_memory_bytes=args.max_memory_bytes,
        max_expression_depth=args.max_expression_depth,
    )
    tracemalloc.start()
    started = time.monotonic()
    try:
        result = induce(train, dev=dev, holdout=holdout, budget=budget)
    finally:
        elapsed = time.monotonic() - started
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    rule = result["rule"]
    correct = 0
    if rule is not None:
        for example in holdout:
            try:
                correct += int(
                    evaluate(rule, example["inputs"]) == example["output"])
            except Exception:
                pass
    return {
        "fields": features,
        "status": result["status"],
        "search_outcome": result["search_outcome"],
        "limits_hit": result["limits_hit"],
        "search_depth": result["search_depth"],
        "candidates_evaluated": result["candidates_evaluated"],
        "signature_checks": result["signature_checks"],
        "runtime_seconds": round(elapsed, 3),
        "peak_traced_bytes": peak,
        "observed_peak_bytes": result.get("observed_peak_bytes"),
        "memory_limit_source": result.get("memory_limit_source"),
        "rule_recovered": rule is not None,
        "holdout_passed": result["holdout_passed"],
        "holdout_count": result["holdout_count"],
        "holdout_correct": correct,
        "false_positive": bool(
            rule is not None and correct < len(holdout)),
        "rule": rule,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fields", default="2,4,8,16,32,64",
                        help="comma-separated feature counts")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--train", type=int, default=6)
    parser.add_argument("--dev", type=int, default=3)
    parser.add_argument("--holdout", type=int, default=3)
    parser.add_argument("--max-candidates", type=int, default=12000)
    parser.add_argument("--max-signature-checks", type=int, default=500_000)
    parser.add_argument("--max-wall-seconds", type=float, default=30.0)
    parser.add_argument("--max-memory-bytes", type=int, default=None)
    parser.add_argument("--max-expression-depth", type=int, default=5)
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)

    try:
        fields = [int(item) for item in args.fields.split(",") if item.strip()]
    except ValueError:
        parser.error("--fields must be a comma-separated list of integers")
    if not fields or any(not 2 <= value <= 64 for value in fields):
        parser.error("--fields values must be in [2,64]")

    budget = SearchBudget(
        max_candidates=args.max_candidates,
        max_signature_checks=args.max_signature_checks,
        max_wall_seconds=args.max_wall_seconds,
        max_memory_bytes=args.max_memory_bytes,
        max_expression_depth=args.max_expression_depth,
    )
    report = {
        "kind": "induction_scalability",
        "generated_at": _utcnow(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "target": "x[n-2] * x[n-1] + 2",
        "budget": budget.as_dict(),
        "partition": {
            "train": args.train, "dev": args.dev, "holdout": args.holdout,
        },
        "results": [run_case(features, args) for features in fields],
    }
    text = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        from pathlib import Path
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
