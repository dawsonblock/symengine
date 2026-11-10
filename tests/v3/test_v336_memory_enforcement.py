"""V336-02: hard memory claims require an OS-enforced receipt.

The v3.3.5 tracer detects a stop or restart, but in-process measurement
still cannot prove a hard cap: code that owns the interpreter can replace
the tracer. The repair adds a separately constrained child process and a
receipt that must validate before any hard-budget success is reported.

These regressions pin the distinction between a completed search, a valid
enforcement receipt, and a hard-budget claim.
"""
from __future__ import annotations

import os
import sys
import unittest
from unittest import mock

from sis import enforced_induction as enforcement
from sis.enforced_induction import (
    EnforcedInduction,
    EnforcementUnavailable,
    MemoryEnforcementReceipt,
    run_induction_enforced,
)
from sis.errors import InvalidInput
from sis.induction import SearchBudget

CAP = 1 << 30
# macOS refuses RLIMIT_AS below the interpreter's current address space,
# which is hundreds of GiB for a forked Python process. The protocol is
# still exercised there with the smallest limit the host accepts; the
# meaningful-cap qualification belongs to the Linux worker gate.
HARD_CAP = (1 << 39) if sys.platform == "darwin" else CAP


def _study(features=8, rows=9):
    names = [f"x{i}" for i in range(features)]
    examples = []
    for i in range(rows):
        inputs = {name: (i * 7 + j * 3) % 11 for j, name in enumerate(names)}
        inputs[names[-2]] = i % 9 + 1
        inputs[names[-1]] = (i * 2) % 9 + 1
        examples.append({
            "inputs": inputs,
            "output": inputs[names[-2]] * inputs[names[-1]] + 2,
        })
    return examples[:6], examples[6:]


def _receipt(**overrides) -> MemoryEnforcementReceipt:
    fields = dict(
        schema_version=1,
        mode="posix_rlimit_as",
        requested_limit_bytes=CAP,
        observed_soft_limit_bytes=CAP,
        observed_hard_limit_bytes=CAP,
        child_pid=1234,
        child_exit_status=0,
        child_signal=None,
        completed=True,
        timed_out=False,
        memory_limit_hit=False,
        stdout_digest="a" * 64,
        stderr_digest="b" * 64,
        result_digest="c" * 64,
        platform="test",
        python="3.12.0",
    )
    fields.update(overrides)
    return MemoryEnforcementReceipt(**fields)


def _report(result=None, *, soft=CAP, hard=CAP, mode="posix_rlimit_as"):
    report = {
        "enforcement": {
            "mode": mode,
            "observed_soft_limit_bytes": soft,
            "observed_hard_limit_bytes": hard,
        },
    }
    if result is not None:
        report["result"] = result
    return report


class ReceiptValidationTests(unittest.TestCase):
    def test_matching_observed_limits_validate(self):
        self.assertTrue(_receipt().valid)

    def test_soft_limit_mismatch_is_invalid(self):
        self.assertFalse(_receipt(observed_soft_limit_bytes=CAP + 1).valid)

    def test_hard_limit_mismatch_is_invalid(self):
        self.assertFalse(_receipt(observed_hard_limit_bytes=CAP + 1).valid)

    def test_unobserved_limit_is_invalid(self):
        self.assertFalse(_receipt(observed_soft_limit_bytes=None).valid)
        self.assertFalse(_receipt(observed_hard_limit_bytes=None).valid)

    def test_unknown_mode_is_invalid(self):
        self.assertFalse(_receipt(mode="inherited").valid)

    def test_receipt_digest_commits_to_the_body(self):
        first = _receipt()
        second = _receipt(child_pid=5678)
        self.assertEqual(first.receipt_digest, _receipt().receipt_digest)
        self.assertNotEqual(first.receipt_digest, second.receipt_digest)
        self.assertEqual(
            first.to_dict()["receipt_digest"], first.receipt_digest)


class ChildReportTests(unittest.TestCase):
    def receipt(self, report, *, exit_status=0, child_signal=None):
        return MemoryEnforcementReceipt.from_child_report(
            report,
            requested_limit_bytes=CAP,
            child_pid=42,
            child_exit_status=exit_status,
            child_signal=child_signal,
            stdout=b"out",
            stderr=b"err",
            platform_name="test",
            python_version="3.12.0")

    def test_forged_limit_with_completed_result_is_not_enforced(self):
        result = {"search_outcome": "completed"}
        receipt = self.receipt(
            _report(result, hard=2 * CAP))
        self.assertFalse(receipt.valid)
        self.assertFalse(
            EnforcedInduction(result, receipt).hard_memory_verified)

    def test_result_without_enforcement_block_is_not_enforced(self):
        result = {"search_outcome": "completed"}
        receipt = self.receipt({"result": result})
        self.assertFalse(receipt.valid)
        self.assertFalse(
            EnforcedInduction(result, receipt).hard_memory_verified)

    def test_memory_error_is_a_memory_hit_without_result(self):
        receipt = self.receipt({"enforcement": _report()["enforcement"],
                                "error": "MemoryError"})
        self.assertTrue(receipt.valid)
        self.assertTrue(receipt.memory_limit_hit)
        self.assertFalse(receipt.completed)
        self.assertFalse(
            EnforcedInduction(None, receipt).hard_memory_verified)

    def test_memory_signal_is_a_memory_hit(self):
        receipt = self.receipt(None, exit_status=-9, child_signal=9)
        self.assertTrue(receipt.memory_limit_hit)
        self.assertFalse(receipt.completed)

    def test_completed_matching_report_is_enforced(self):
        result = {"search_outcome": "completed"}
        receipt = self.receipt(_report(result))
        self.assertTrue(receipt.valid)
        self.assertTrue(receipt.completed)
        self.assertTrue(
            EnforcedInduction(result, receipt).hard_memory_verified)

    def test_non_mapping_result_is_not_completed(self):
        receipt = self.receipt(_report(["not", "a", "result"]))
        self.assertFalse(receipt.completed)
        self.assertFalse(
            EnforcedInduction(None, receipt).hard_memory_verified)


class EnforcedRunTests(unittest.TestCase):
    def setUp(self):
        self.train, self.dev = _study()

    def test_child_observes_the_requested_hard_limit(self):
        enforced = run_induction_enforced(
            self.train, dev=self.dev,
            budget=SearchBudget(max_candidates=50000),
            memory_limit_bytes=HARD_CAP, timeout_seconds=120)
        self.assertIsNotNone(enforced.result)
        self.assertTrue(enforced.receipt.valid)
        self.assertTrue(enforced.receipt.completed)
        self.assertFalse(enforced.receipt.memory_limit_hit)
        self.assertTrue(enforced.hard_memory_verified)
        self.assertEqual(
            enforced.receipt.observed_soft_limit_bytes, HARD_CAP)
        self.assertEqual(
            enforced.receipt.observed_hard_limit_bytes, HARD_CAP)
        self.assertNotEqual(enforced.receipt.child_pid, os.getpid())

    def test_soft_budget_stays_diagnostic_under_hard_cap(self):
        enforced = run_induction_enforced(
            self.train, dev=self.dev,
            budget=SearchBudget(
                max_candidates=50000, max_memory_bytes=1 << 20),
            memory_limit_bytes=HARD_CAP, timeout_seconds=120)
        self.assertIsNotNone(enforced.result)
        self.assertEqual(
            enforced.result["search_outcome"], "resource_exhausted")
        self.assertIn("max_memory_bytes", enforced.result["limits_hit"])
        self.assertTrue(enforced.receipt.valid)
        self.assertTrue(enforced.hard_memory_verified)

    def test_timeout_never_reports_hard_success(self):
        enforced = run_induction_enforced(
            self.train, dev=self.dev,
            budget=SearchBudget(max_candidates=50000),
            memory_limit_bytes=HARD_CAP, timeout_seconds=0.001)
        self.assertIsNone(enforced.result)
        self.assertFalse(enforced.receipt.valid)
        self.assertTrue(enforced.receipt.timed_out)
        self.assertFalse(enforced.receipt.memory_limit_hit)
        self.assertFalse(enforced.hard_memory_verified)

    def test_limit_range_is_validated(self):
        with self.assertRaises(InvalidInput):
            run_induction_enforced(
                self.train, dev=self.dev, memory_limit_bytes=1024)

    @unittest.skipUnless(
        sys.platform == "darwin",
        "Linux and other POSIX hosts can lower RLIMIT_AS below usage")
    def test_unenforceable_limit_is_refused(self):
        with self.assertRaises(EnforcementUnavailable):
            run_induction_enforced(
                self.train, dev=self.dev, memory_limit_bytes=CAP)

    def test_missing_rlimit_support_is_refused(self):
        with mock.patch.object(enforcement, "resource", None):
            with self.assertRaises(EnforcementUnavailable):
                run_induction_enforced(
                    self.train, dev=self.dev, memory_limit_bytes=CAP)


if __name__ == "__main__":
    unittest.main()
