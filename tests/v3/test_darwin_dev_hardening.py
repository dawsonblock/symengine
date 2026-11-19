"""macOS stays development-only: RSS watchdog and the hostile-code gate (C6).

The watchdog logic is tested on every platform with a fake RSS sampler;
the real allocation test and the CLI refusal only run on macOS, where the
watchdog is on by default and native hostile evaluation is refused.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from sis.v3 import runner
from sis.v3.evaluation_runtime import RESOURCE_LIMIT, classify_execution
from sis.v3.evaluator_worker import EvaluatorWorkerError, build_worker_executor
from sis.v3.runner import (MARKER_MEMORY_WATCHDOG,
                           MARKER_MEMORY_WATCHDOG_KILLED, CommandSpec,
                           LocalSubprocessExecutor, ResourceLimits,
                           RssWatchdog, RunnerError, parse_process_table,
                           process_tree_rss,
                           refuse_unqualified_hostile_evaluation)

REPO = Path(__file__).resolve().parents[2]
PY = sys.executable
POSIX = os.name == "posix"


class ProcessTreeTests(unittest.TestCase):
    TABLE = """\
      1     0     1   9000
    100     1   100   1000
    101   100   100   2000
    102   101   102   4000
    200     1   200   8000
    garbage line
    """

    def test_parse_skips_malformed_lines(self):
        table = parse_process_table(self.TABLE)
        self.assertEqual(set(table), {1, 100, 101, 102, 200})
        self.assertEqual(table[101], (100, 100, 2000))

    def test_tree_counts_the_group_and_setsid_descendants_only(self):
        table = parse_process_table(self.TABLE)
        # 102 left the group with setsid but is still a descendant.
        self.assertEqual(process_tree_rss(100, table), 7000 * 1024)
        self.assertEqual(process_tree_rss(200, table), 8000 * 1024)
        self.assertEqual(process_tree_rss(999, table), 0)


class WatchdogTests(unittest.TestCase):
    def test_kills_once_over_the_limit(self):
        killed = threading.Event()
        samples = iter([10, 20, 5000, 10])
        watchdog = RssWatchdog(
            1, 1000, killed.set, interval=0.01,
            sampler=lambda _pid: next(samples)).start()
        self.assertTrue(killed.wait(5))
        watchdog.stop()
        self.assertTrue(watchdog.triggered)
        self.assertEqual(watchdog.peak_bytes, 5000)

    def test_stays_quiet_under_the_limit_and_tolerates_missing_samples(self):
        killed = threading.Event()
        watchdog = RssWatchdog(
            1, 1000, killed.set, interval=0.01,
            sampler=lambda _pid: None).start()
        time.sleep(0.1)
        watchdog.stop()
        self.assertFalse(killed.is_set())
        self.assertFalse(watchdog.triggered)
        self.assertEqual(watchdog.samples, 0)


@unittest.skipUnless(POSIX, "the local launcher and ps are POSIX")
class ExecutorWatchdogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.base.mkdir()
        (self.base / "x.txt").write_text("x")

    def run_with(self, executor, argv, **limits):
        workspace = executor.prepare(self.base)
        try:
            return executor.run(workspace, CommandSpec(
                argv=argv, limits=ResourceLimits(
                    wall_seconds=30, process_count=None, **limits)))
        finally:
            executor.destroy(workspace)

    def test_watchdog_kills_and_records_a_resource_limit(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False, memory_watchdog=True)
        start = time.monotonic()

        def growing(_pid):
            # Small while the launcher applies its limits, then too big.
            return 1024 if time.monotonic() - start < 1.0 else 1 << 40

        with mock.patch.object(runner, "sample_process_tree_rss", growing):
            receipt = self.run_with(
                executor, (PY, "-c", "import time; time.sleep(25)"))
        self.assertLess(time.monotonic() - start, 20)
        self.assertIn(MARKER_MEMORY_WATCHDOG, receipt.security_errors)
        self.assertIn(MARKER_MEMORY_WATCHDOG_KILLED, receipt.security_errors)
        self.assertNotEqual(receipt.exit_status, 0)
        self.assertEqual(classify_execution(receipt), RESOURCE_LIMIT)

    def test_watchdog_under_the_limit_only_marks_the_run(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False, memory_watchdog=True)
        with mock.patch.object(runner, "sample_process_tree_rss",
                               return_value=1024):
            receipt = self.run_with(executor, (PY, "-c", "print('ok')"))
        self.assertEqual(receipt.exit_status, 0)
        self.assertIn(MARKER_MEMORY_WATCHDOG, receipt.security_errors)
        self.assertNotIn(MARKER_MEMORY_WATCHDOG_KILLED,
                         receipt.security_errors)

    @unittest.skipIf(sys.platform == "darwin", "the watchdog is on on macOS")
    def test_watchdog_is_off_by_default_where_rlimit_as_applies(self):
        executor = LocalSubprocessExecutor(
            self.root / "exec", use_seatbelt=False)
        receipt = self.run_with(executor, (PY, "-c", "print('ok')"))
        self.assertNotIn(MARKER_MEMORY_WATCHDOG, receipt.security_errors)

    @unittest.skipUnless(sys.platform == "darwin", "macOS-only behaviour")
    def test_darwin_watchdog_stops_a_real_allocation(self):
        executor = LocalSubprocessExecutor(self.root / "exec")
        receipt = self.run_with(
            executor,
            (PY, "-c", "import time; x = b'\\x01' * (768 << 20);"
                       " time.sleep(20)"),
            memory_bytes=256 << 20)
        # Best effort, not a limit: the honest marker stays.
        self.assertIn("memory:not_enforced", receipt.security_errors)
        self.assertIn(MARKER_MEMORY_WATCHDOG, receipt.security_errors)
        self.assertIn(MARKER_MEMORY_WATCHDOG_KILLED, receipt.security_errors)
        self.assertEqual(classify_execution(receipt), RESOURCE_LIMIT)


class HostileEvaluationGateTests(unittest.TestCase):
    def test_darwin_requires_the_explicit_flag(self):
        with self.assertRaisesRegex(
                RunnerError, "hostile_evaluation_unqualified_platform:darwin"):
            refuse_unqualified_hostile_evaluation(
                allow_unqualified=False, platform_name="darwin")
        refuse_unqualified_hostile_evaluation(
            allow_unqualified=True, platform_name="darwin")
        refuse_unqualified_hostile_evaluation(
            allow_unqualified=False, platform_name="linux")

    def test_worker_builder_applies_the_gate(self):
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(runner.sys, "platform", "darwin"):
            with self.assertRaisesRegex(
                    EvaluatorWorkerError, "--allow-unqualified"):
                build_worker_executor(
                    executor="local", executor_root=temp,
                    allow_local_executor=True)
            executor = build_worker_executor(
                executor="local", executor_root=temp,
                allow_local_executor=True, allow_unqualified=True)
            self.assertIsInstance(executor, LocalSubprocessExecutor)

    @unittest.skipUnless(sys.platform == "darwin", "macOS-only behaviour")
    def test_campaign_cli_refuses_without_the_flag_on_darwin(self):
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO / "src")
        with tempfile.TemporaryDirectory() as temp:
            proc = subprocess.run(
                [PY, str(REPO / "tools" / "governed_campaign.py"),
                 "-o", temp, "--allow-local-executor"],
                capture_output=True, text=True, env=env, cwd=REPO,
                timeout=120)
        self.assertEqual(proc.returncode, 2, proc.stderr[-500:])
        self.assertIn("--allow-unqualified", proc.stderr)


if __name__ == "__main__":
    unittest.main()
