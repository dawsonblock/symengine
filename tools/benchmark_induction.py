"""Induction scalability benchmark (SIS v3.3.4, Phase 4.5).

Runs the same representable rule at increasing feature counts and reports
what the bounded search actually did: candidates, signature checks,
runtime, traced peak memory, whether a candidate exists, whether the
*intended structure* was recovered, whether the candidate is equivalent
to the target over a declared bounded domain, holdout accuracy, and
whether the search completed.

The target is ``x[n-2] * x[n-1] + 2`` so every feature count has the same
relevant pair and the rest are decoys. This is a search-cost benchmark,
not an efficacy study.

``candidate_found`` is not recovery. On the default non-negative domain
the search often returns ``absdiff(x[n-2] * x[n-1], -2)``, which matches
the target on that domain but is a different function and is reported
ambiguous. Use ``--input-min`` to include negative values and
``--equivalence z3`` to verify equivalence over the declared box; only
``exact_recovery_verified`` claims the intended rule.

Usage:
    PYTHONPATH=src python3 tools/benchmark_induction.py
    PYTHONPATH=src python3 tools/benchmark_induction.py --fields 2,4,8
    PYTHONPATH=src python3 tools/benchmark_induction.py \
        --input-min -9 --equivalence z3
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


def target_rule(features: int) -> dict:
    """The intended rule AST for a feature count."""
    return {
        "op": "add",
        "args": [
            {"op": "mul", "args": [
                {"op": "field", "name": f"x{features - 2}"},
                {"op": "field", "name": f"x{features - 1}"},
            ]},
            {"op": "const", "value": 2},
        ],
    }


_COMMUTATIVE = frozenset({"add", "mul", "min", "max", "absdiff"})


def structural_form(ast) -> tuple:
    """A commutative-normalized form used for structural comparison."""
    op = ast["op"]
    if op in _COMMUTATIVE:
        return (op, tuple(sorted(structural_form(child)
                                 for child in ast["args"])))
    if op == "field":
        return ("field", ast["name"])
    if op == "item":
        return ("item", ast["name"], ast["index"])
    if op == "const":
        return ("const", ast["value"])
    if op in ("neg", "abs"):
        return (op, structural_form(ast["arg"]))
    if op == "if_eq":
        return ("if_eq", structural_form(ast["left"]),
                structural_form(ast["then"]), structural_form(ast["else"]))
    return (op, tuple(structural_form(child) for child in ast["args"]))


def verify_equivalence(rule, target, schema, *, mode: str,
                       low: int = 0, high: int = 9):
    """Return ``(verified, scope, witness)`` over a declared bounded box.

    Only ``z3`` mode can verify; ``none`` reports the metric as not
    requested rather than inferring equivalence from matching examples.
    """
    if mode == "none":
        return False, "not_requested", None
    try:
        from sis.smt import bounded_disagreement
        witness, reason = bounded_disagreement(
            rule, target, schema, low=low, high=high)
    except ImportError:
        return False, "z3_unavailable", None
    except Exception:
        return False, "z3_error", None
    if witness is None and reason == "unsat_bounded_domain":
        return True, f"z3_box:{low}..{high}:all_features", None
    return False, f"z3:{reason}", witness


def study(features: int, *, seed: int, train_n: int, dev_n: int,
          holdout_n: int, input_min: int = 0, input_max: int = 9):
    names = [f"x{i}" for i in range(features)]
    rng = random.Random(seed)
    rows: list[dict] = []
    seen: set[tuple] = set()
    while len(rows) < train_n + dev_n + holdout_n:
        inputs = {name: rng.randint(input_min, input_max) for name in names}
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
        train_n=args.train, dev_n=args.dev, holdout_n=args.holdout,
        input_min=getattr(args, "input_min", 0),
        input_max=getattr(args, "input_max", 9))
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
    holdout_count = len(holdout)
    holdout_accuracy = (correct / holdout_count) if holdout_count else None
    candidate_found = rule is not None
    target = target_rule(features)
    target_structure_recovered = bool(
        rule is not None
        and structural_form(rule) == structural_form(target))
    equivalence_verified, equivalence_scope, equivalence_witness = (
        verify_equivalence(
            rule, target, result["schema"],
            mode=getattr(args, "equivalence", "none"),
            low=getattr(args, "input_min", 0),
            high=getattr(args, "input_max", 9))
        if rule is not None else (False, "no_candidate", None))
    search_complete = (
        result["search_outcome"] == "completed"
        and not result["search_truncated"])
    ambiguous = result["status"] == "ambiguous"
    exact_recovery_verified = bool(
        candidate_found
        and target_structure_recovered
        and equivalence_verified
        and not ambiguous
        and search_complete
        and holdout_accuracy == 1.0)
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
        "candidate_found": candidate_found,
        "target_structure_recovered": target_structure_recovered,
        "equivalence_verified": equivalence_verified,
        "equivalence_scope": equivalence_scope,
        "equivalence_witness": equivalence_witness,
        "holdout_accuracy": holdout_accuracy,
        "holdout_passed": result["holdout_passed"],
        "holdout_count": holdout_count,
        "holdout_correct": correct,
        "search_complete": search_complete,
        "ambiguous": ambiguous,
        "exact_recovery_verified": exact_recovery_verified,
        "false_positive": bool(
            candidate_found and holdout_accuracy is not None
            and holdout_accuracy < 1.0),
        "rule": rule,
    }


METRIC_DEFINITIONS = {
    "candidate_found": "the search returned some rule",
    "target_structure_recovered": (
        "the returned rule has the intended structure; commutative "
        "operands are normalized"),
    "equivalence_verified": (
        "the returned rule and the target were proved equivalent over the "
        "declared bounded input box (z3 only)"),
    "holdout_accuracy": (
        "fraction of sealed holdout examples the returned rule matches"),
    "search_complete": (
        "the search finished without truncation or resource exhaustion"),
    "exact_recovery_verified": (
        "candidate found, intended structure recovered, equivalence "
        "verified, holdout perfect, search complete and result not "
        "ambiguous; the only exact-recovery claim"),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fields", default="2,4,8,16,32,64",
                        help="comma-separated feature counts")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--train", type=int, default=6)
    parser.add_argument("--dev", type=int, default=3)
    parser.add_argument("--holdout", type=int, default=3)
    parser.add_argument("--input-min", type=int, default=0)
    parser.add_argument("--input-max", type=int, default=9)
    parser.add_argument("--max-candidates", type=int, default=12000)
    parser.add_argument("--max-signature-checks", type=int, default=500_000)
    parser.add_argument("--max-wall-seconds", type=float, default=30.0)
    parser.add_argument("--max-memory-bytes", type=int, default=None)
    parser.add_argument("--max-expression-depth", type=int, default=5)
    parser.add_argument("--equivalence", choices=("none", "z3"),
                        default="none",
                        help="bounded equivalence check against the target")
    parser.add_argument("--output", default=None)
    args = parser.parse_args(argv)

    try:
        fields = [int(item) for item in args.fields.split(",") if item.strip()]
    except ValueError:
        parser.error("--fields must be a comma-separated list of integers")
    if not fields or any(not 2 <= value <= 64 for value in fields):
        parser.error("--fields values must be in [2,64]")
    if not -1000 <= args.input_min <= args.input_max <= 1000:
        parser.error("--input-min/--input-max must satisfy -1000 <= min <= max <= 1000")

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
        "input_domain": [args.input_min, args.input_max],
        "equivalence_mode": args.equivalence,
        "metric_definitions": METRIC_DEFINITIONS,
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
