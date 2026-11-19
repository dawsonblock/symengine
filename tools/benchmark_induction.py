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

Corpus mode (``--corpus examples/induction_corpus``) runs the fixed
induction corpus instead: about sixty targets in six categories (linear,
nonlinear, divmod, piecewise, string, distractor), each induced with the
legacy ``induce(train, validation)`` call that ``sis train`` uses. Per
category it reports the recovery rate (status ``locally_validated`` and
the rule equals the oracle on every labelled row and every seeded fresh
oracle point), exact structural recovery, the false-positive rate
(``locally_validated`` but wrong on a fresh oracle point), the
``no_rule`` rate, and runtime p50/p95.

Usage:
    PYTHONPATH=src python3 tools/benchmark_induction.py
    PYTHONPATH=src python3 tools/benchmark_induction.py --fields 2,4,8
    PYTHONPATH=src python3 tools/benchmark_induction.py \
        --input-min -9 --equivalence z3
    PYTHONPATH=src python3 tools/benchmark_induction.py \
        --corpus examples/induction_corpus --output corpus.json
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
    if "arg" in ast:
        return (op, structural_form(ast["arg"]))
    if "left" in ast:
        return (op, structural_form(ast["left"]),
                structural_form(ast["right"]), structural_form(ast["then"]),
                structural_form(ast["else"]))
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


def _sample_indices(rng: random.Random, possible: int,
                    count: int) -> list[int]:
    """Draw ``count`` distinct indices from ``[0, possible)``.

    ``random.sample(range(possible), count)`` asks ``len(range(...))``
    for a machine-sized integer, which overflows once the domain exceeds
    ``sys.maxsize`` (32 decimal fields already do). Floyd's algorithm
    needs O(count) state and never materialises the domain, so it works
    for arbitrary-precision sizes.
    """
    chosen: set[int] = set()
    indices: list[int] = []
    for upper in range(possible - count, possible):
        pick = rng.randrange(upper + 1)
        if pick in chosen:
            pick = upper
        chosen.add(pick)
        indices.append(pick)
    return indices


def distinct_inputs(features: int, *, low: int, high: int, count: int,
                    seed: int) -> list[list[int]]:
    """Draw ``count`` distinct input rows, or fail before drawing.

    The previous rejection loop could spin forever when the requested
    partition exceeded the size of the input domain. Floyd's algorithm
    over the domain's integer indices terminates by construction, and the
    explicit feasibility check turns an impossible request into an
    immediate error.
    """
    domain = high - low + 1
    possible = domain ** features
    if count > possible:
        raise ValueError(
            f"impossible_sample: {count} distinct inputs requested, but "
            f"{features} fields over [{low},{high}] admit only {possible}")
    rng = random.Random(seed)
    rows = []
    for index in _sample_indices(rng, possible, count):
        values = []
        for _ in range(features):
            index, digit = divmod(index, domain)
            values.append(low + digit)
        rows.append(values[::-1])
    return rows


def study(features: int, *, seed: int, train_n: int, dev_n: int,
          holdout_n: int, input_min: int = 0, input_max: int = 9):
    if features < 2:
        raise ValueError("features must be at least 2")
    if train_n < 0 or dev_n < 0 or holdout_n < 0:
        raise ValueError("partition sizes must be nonnegative")
    names = [f"x{i}" for i in range(features)]
    total = train_n + dev_n + holdout_n
    rows: list[dict] = []
    for values in distinct_inputs(
            features, low=input_min, high=input_max, count=total, seed=seed):
        inputs = dict(zip(names, values))
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


# --------------------------------------------------------------- corpus mode

CORPUS_METRIC_DEFINITIONS = {
    "recovered": (
        "status locally_validated and the rule matches the oracle on every "
        "labelled row and every seeded fresh oracle point (exact structure "
        "or probe-equivalence over the fresh points)"),
    "exact_structure": (
        "the rule equals the reference rule up to commutative operand order"),
    "equivalent_any_status": (
        "the returned rule matches the oracle on all labelled and fresh "
        "points, whatever its status"),
    "false_positive": (
        "status locally_validated but the rule disagrees with the oracle on "
        "at least one fresh point; the metric a learner must keep at zero"),
    "wrong_rule_any_status": (
        "some rule was returned (any status) and it disagrees with the "
        "oracle on a fresh point"),
    "no_rule": "status no_rule",
}


def load_corpus(corpus_dir):
    """Return ``(materialised corpus, generator module)`` for a corpus dir."""
    import importlib.util
    from pathlib import Path
    root = Path(corpus_dir)
    spec = importlib.util.spec_from_file_location(
        "sis_induction_corpus_targets", root / "targets.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    corpus = json.loads((root / "corpus.json").read_text(encoding="utf-8"))
    return corpus, module


def _percentile(values, q):
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return round(ordered[index], 4)


def _oracle_agreement(rule, oracle, points):
    """Return ``(mismatches, first_witness)`` of ``rule`` against ``oracle``."""
    mismatches = 0
    witness = None
    for inputs in points:
        expected = oracle(inputs)
        try:
            got = evaluate(rule, inputs)
        except Exception:
            got = None
        if type(got) is not type(expected) or got != expected:
            mismatches += 1
            if witness is None:
                witness = {"inputs": inputs, "expected": expected,
                           "rule_output": got}
    return mismatches, witness


def run_corpus_target(entry, generator, *, budget=None):
    """Induce one corpus target and score it against its oracle."""
    target = generator.by_name()[entry["name"]]
    kwargs = {"namespace": "corpus"}
    if budget is not None:
        kwargs["budget"] = budget
    started = time.monotonic()
    result = induce(entry["train"], entry["validation"], **kwargs)
    elapsed = time.monotonic() - started
    rule = result.get("rule")
    status = result.get("status")
    labelled = [row["inputs"] for row in entry["train"] + entry["validation"]]
    fresh = generator.fresh_points(target)
    if rule is not None:
        mismatches, witness = _oracle_agreement(
            rule, target["oracle"], labelled + fresh)
    else:
        mismatches, witness = None, None
    equivalent = rule is not None and mismatches == 0
    reference = entry.get("reference")
    exact = bool(rule is not None and reference is not None
                 and structural_form(rule) == structural_form(reference))
    validated = status == "locally_validated"
    return {
        "name": entry["name"],
        "category": entry["category"],
        "status": status,
        "search_outcome": result.get("search_outcome"),
        "rule": rule,
        "runtime_seconds": round(elapsed, 4),
        "fresh_points": len(fresh),
        "fresh_mismatches": mismatches,
        "first_mismatch": witness,
        "exact_structure": exact,
        "equivalent_any_status": equivalent,
        "recovered": bool(validated and equivalent),
        "false_positive": bool(validated and not equivalent),
        "wrong_rule_any_status": bool(rule is not None and not equivalent),
        "no_rule": status == "no_rule",
        "candidates_evaluated": result.get("candidates_evaluated"),
        "signature_checks": result.get("signature_checks"),
        "grammar_version": result.get("grammar_version"),
        "engine_version": result.get("engine_version"),
    }


def summarize_corpus(rows):
    """Per-category and overall rates; ``ALL`` aggregates every target."""
    categories = {}
    for row in rows:
        categories.setdefault(row["category"], []).append(row)
    summary = {}
    for name, items in sorted(categories.items()) + [("ALL", rows)]:
        count = len(items)
        statuses = {}
        for item in items:
            statuses[item["status"]] = statuses.get(item["status"], 0) + 1
        runtimes = [item["runtime_seconds"] for item in items]

        def rate(key, items=items, count=count):
            return round(sum(1 for item in items if item[key]) / count, 4)

        summary[name] = {
            "targets": count,
            "recovered": sum(1 for item in items if item["recovered"]),
            "recovery_rate": rate("recovered"),
            "exact_structure_rate": rate("exact_structure"),
            "equivalent_any_status_rate": rate("equivalent_any_status"),
            "false_positives": sum(
                1 for item in items if item["false_positive"]),
            "false_positive_rate": rate("false_positive"),
            "wrong_rule_any_status_rate": rate("wrong_rule_any_status"),
            "no_rule_rate": rate("no_rule"),
            "status_counts": dict(sorted(statuses.items())),
            "runtime_p50_seconds": _percentile(runtimes, 0.5),
            "runtime_p95_seconds": _percentile(runtimes, 0.95),
        }
    return summary


def run_corpus(corpus_dir, *, names=None, categories=None, budget=None):
    corpus, generator = load_corpus(corpus_dir)
    entries = corpus["targets"]
    if names:
        wanted = set(names)
        unknown = wanted - {e["name"] for e in entries}
        if unknown:
            raise ValueError(
                "unknown corpus targets: " + ", ".join(sorted(unknown)))
        entries = [e for e in entries if e["name"] in wanted]
    if categories:
        entries = [e for e in entries if e["category"] in set(categories)]
    rows = [run_corpus_target(entry, generator, budget=budget)
            for entry in entries]
    from sis import induction as _induction
    return {
        "kind": "induction_corpus",
        "generated_at": _utcnow(),
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "grammar_version": getattr(_induction, "GRAMMAR_VERSION", None),
        "engine_version": getattr(_induction, "ENGINE_VERSION", None),
        "corpus_version": corpus.get("version"),
        "partition": {"train": corpus.get("train_rows"),
                      "validation": corpus.get("validation_rows"),
                      "call": "induce(train, validation) legacy split"},
        "equivalence": (
            "labelled rows plus seeded fresh oracle points from a widened "
            "domain; probe-equivalence, not a proof"),
        "budget": (budget or SearchBudget()).as_dict(),
        "metric_definitions": CORPUS_METRIC_DEFINITIONS,
        "summary": summarize_corpus(rows),
        "results": rows,
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
    parser.add_argument("--corpus", default=None,
                        help="run the induction corpus in this directory")
    parser.add_argument("--targets", default=None,
                        help="corpus mode: comma-separated target names")
    parser.add_argument("--categories", default=None,
                        help="corpus mode: comma-separated categories")
    args = parser.parse_args(argv)

    if args.corpus is not None:
        def split(text):
            return [x.strip() for x in text.split(",") if x.strip()] if text else None
        report = run_corpus(args.corpus, names=split(args.targets),
                            categories=split(args.categories))
        text = json.dumps(report, indent=2, sort_keys=True)
        if args.output:
            from pathlib import Path
            Path(args.output).write_text(text + "\n", encoding="utf-8")
        print(json.dumps(report["summary"], indent=2, sort_keys=True))
        return 0

    try:
        fields = [int(item) for item in args.fields.split(",") if item.strip()]
    except ValueError:
        parser.error("--fields must be a comma-separated list of integers")
    if not fields or any(not 2 <= value <= 64 for value in fields):
        parser.error("--fields values must be in [2,64]")
    if not -1000 <= args.input_min <= args.input_max <= 1000:
        parser.error("--input-min/--input-max must satisfy -1000 <= min <= max <= 1000")
    if args.train < 0 or args.dev < 0 or args.holdout < 0:
        parser.error("--train/--dev/--holdout must be nonnegative")
    total = args.train + args.dev + args.holdout
    if total < 1:
        parser.error("the study needs at least one example")
    domain = args.input_max - args.input_min + 1
    for value in fields:
        possible = domain ** value
        if total > possible:
            parser.error(
                f"impossible sample: {total} distinct inputs requested for "
                f"{value} fields over [{args.input_min},{args.input_max}], "
                f"which admits only {possible}")

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
