"""Enforced induction applies its rlimits without ``preexec_fn``.

``subprocess``'s ``preexec_fn`` runs Python code between fork and exec,
which can deadlock when another thread holds a lock. The enforced path
now uses the evaluator-owned limit launcher from ``sis.v3.runner``. These
regressions pin that the limits still reach the child when the call is
made from a worker thread, and that a limit the launcher cannot set fails
closed with ``EnforcementUnavailable`` instead of being silently skipped.
"""
from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import unittest
from unittest import mock

from sis import enforced_induction as enforcement
from sis.enforced_induction import EnforcementUnavailable, run_induction_enforced
from sis.induction import SearchBudget
from sis.v3 import runner

POSIX = os.name == "posix"
CAP = (1 << 39) if sys.platform == "darwin" else (1 << 30)
TRAIN = [{"inputs": {"a": i, "b": i + 1}, "output": i * (i + 1)}
         for i in range(1, 6)]


@unittest.skipUnless(POSIX, "RLIMIT_AS requires POSIX")
class LauncherAppliedLimitsTests(unittest.TestCase):
    def test_limits_apply_in_child_when_called_from_a_worker_thread(self):
        real_popen = subprocess.Popen
        calls = []

        def spy(*args, **kwargs):
            calls.append((args, kwargs))
            return real_popen(*args, **kwargs)

        held = threading.Lock()
        held.acquire()  # another thread "holds a lock" during the spawn
        outcome = {}

        def worker():
            try:
                outcome["enforced"] = run_induction_enforced(
                    TRAIN, budget=SearchBudget(max_candidates=20000),
                    memory_limit_bytes=CAP, timeout_seconds=120,
                    cpu_seconds=60, process_limit=128)
            except BaseException as exc:  # surfaced below
                outcome["error"] = exc

        with mock.patch.object(enforcement.subprocess, "Popen", spy):
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(150)
        held.release()
        self.assertFalse(thread.is_alive(), "enforced run did not finish")
        self.assertNotIn("error", outcome)
        enforced = outcome["enforced"]

        # Popen is patched process-wide (``platform`` may spawn too); pick
        # the enforced launch by its child module.
        launches = [(args, kwargs) for args, kwargs in calls
                    if "sis.enforced_induction" in list(args[0])]
        self.assertEqual(len(launches), 1)
        (launch,), kwargs = launches[0]
        self.assertNotIn("preexec_fn", kwargs)
        self.assertEqual(launch[1:3], ["-I", "-c"])
        self.assertIn("RLIMIT_AS", launch)

        # The child reports resource.getrlimit for each limit it runs under.
        receipt = enforced.receipt
        self.assertEqual(receipt.observed_soft_limit_bytes, CAP)
        self.assertEqual(receipt.observed_hard_limit_bytes, CAP)
        self.assertEqual(receipt.observed_cpu_seconds, 60)
        self.assertEqual(receipt.observed_process_limit, 128)
        self.assertTrue(receipt.valid)
        self.assertIsNotNone(enforced.result)
        self.assertTrue(enforced.hard_limits_verified)

    def test_an_unknown_limit_fails_closed(self):
        real_argv = runner.limit_launcher_argv

        def with_bogus_limit(argv, triples, **kwargs):
            return real_argv(
                argv, [*triples, ("RLIMIT_NOT_A_LIMIT", 1, 1)], **kwargs)

        with mock.patch.object(runner, "limit_launcher_argv", with_bogus_limit):
            with self.assertRaises(EnforcementUnavailable) as ctx:
                run_induction_enforced(
                    TRAIN, memory_limit_bytes=CAP, timeout_seconds=60)
        self.assertEqual(str(ctx.exception), "hard_limit_not_applied")
        self.assertIn("rlimit_unavailable:RLIMIT_NOT_A_LIMIT",
                      str(ctx.exception.__cause__))

    def test_a_limit_above_the_hard_ceiling_fails_closed(self):
        # Run in a child whose hard RLIMIT_CPU is lowered first, so the
        # launcher cannot raise it to the requested value.
        script = textwrap.dedent("""
            import resource, sys
            from sis.enforced_induction import (
                EnforcementUnavailable, run_induction_enforced)
            resource.setrlimit(resource.RLIMIT_CPU, (100, 100))
            try:
                resource.setrlimit(resource.RLIMIT_CPU, (200, 200))
            except (OSError, ValueError):
                pass
            else:
                print("PRIVILEGED")
                sys.exit(0)
            try:
                run_induction_enforced(
                    [{"inputs": {"a": 1}, "output": 1}],
                    memory_limit_bytes=%d, timeout_seconds=60,
                    cpu_seconds=200)
            except EnforcementUnavailable as exc:
                print("REFUSED", exc, exc.__cause__)
            else:
                print("RAN")
        """ % CAP)
        done = subprocess.run(
            [sys.executable, "-c", script], capture_output=True,
            text=True, timeout=120)
        if done.stdout.startswith("PRIVILEGED"):
            self.skipTest("process may raise its hard RLIMIT_CPU")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.startswith("REFUSED hard_limit_not_applied"),
                        done.stdout + done.stderr)
        self.assertIn("rlimit_failed:RLIMIT_CPU", done.stdout)

    def test_a_missing_interpreter_is_refused(self):
        with self.assertRaises(EnforcementUnavailable):
            run_induction_enforced(
                TRAIN, memory_limit_bytes=CAP, timeout_seconds=60,
                python_executable="/nonexistent/sis-python")


if __name__ == "__main__":
    unittest.main()
