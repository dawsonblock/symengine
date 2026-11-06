import os
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.contracts import ContractError, ExecutionReceiptV1
from sis.v3.runner import (
    CommandSpec,
    LocalSubprocessExecutor,
    ResourceLimits,
    RunnerError,
    WorkspaceExecutor,
    command_spec_digest,
    scan_tree,
    tree_digest,
)


PY = sys.executable
POSIX = os.name == "posix"


def fast_limits(**overrides):
    values = {"cpu_seconds": 20, "wall_seconds": 15, "memory_bytes": 1 << 30,
              "output_bytes": 1 << 20, "disk_bytes": 16 << 20, "process_count": 64}
    values.update(overrides)
    return ResourceLimits(**values)


class RunnerFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.base = root / "base"
        (self.base / "pkg").mkdir(parents=True)
        (self.base / "pkg" / "mod.py").write_text("VALUE = 7\n", encoding="utf-8")
        (self.base / "README.txt").write_text("fixture\n", encoding="utf-8")
        self.executor = LocalSubprocessExecutor(root / "exec", use_seatbelt=False)

    def spec(self, code, **overrides):
        options = {"argv": (PY, "-c", code), "limits": fast_limits()}
        options.update(overrides)
        return CommandSpec(**options)


class RunnerContractTests(unittest.TestCase):
    def test_command_spec_rejects_traversal_env_injection_and_oversize(self):
        with self.assertRaises(ContractError):
            CommandSpec(argv=("../bin/sh",))
        with self.assertRaises(ContractError):
            CommandSpec(argv=("x",) * 33)
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY, "-c", "x" * 1_025))
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY,), env={"BAD NAME": "x"})
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY,), env={"K": "v" * 4_097})
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY,), cwd="../escape")
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY,), cwd="/abs")
        with self.assertRaises(ContractError):
            CommandSpec(argv=(PY,), stdin=b"x" * ((1 << 20) + 1))
        with self.assertRaises(ContractError):
            ResourceLimits(wall_seconds=0)
        with self.assertRaises(ContractError):
            ResourceLimits(output_bytes=1 << 31)

    def test_command_spec_digest_binds_exact_command(self):
        a = CommandSpec(argv=(PY, "-c", "print(1)"))
        b = CommandSpec(argv=(PY, "-c", "print(2)"))
        c = CommandSpec(argv=(PY, "-c", "print(1)"), env={"X": "1"})
        self.assertEqual(command_spec_digest(a), command_spec_digest(a))
        self.assertNotEqual(command_spec_digest(a), command_spec_digest(b))
        self.assertNotEqual(command_spec_digest(a), command_spec_digest(c))

    def test_tree_digest_is_stable_and_symlink_aware(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.txt").write_text("one")
            (root / "sub").mkdir()
            (root / "sub" / "b.txt").write_text("two")
            first = tree_digest(root)
            self.assertEqual(first, tree_digest(root))
            (root / "a.txt").write_text("changed")
            self.assertNotEqual(tree_digest(root), first)
            if POSIX:
                (root / "link").symlink_to("/etc/hosts")
                scan = scan_tree(root)
                self.assertIn("link", scan.external_symlinks)


class RunnerIsolationTests(RunnerFixture):
    def test_prepare_run_receipt_and_destroy(self):
        workspace = self.executor.prepare(self.base)
        self.assertIsInstance(self.executor, WorkspaceExecutor)
        receipt = self.executor.run(workspace, self.spec("import pkg.mod; print(pkg.mod.VALUE)"))
        self.assertIsInstance(receipt, ExecutionReceiptV1)
        self.assertEqual(receipt.exit_status, 0)
        self.assertFalse(receipt.timeout)
        self.assertEqual(receipt.before_tree_digest, workspace.before_tree_digest)
        self.assertEqual(receipt.after_tree_digest, scan_tree(workspace.path).digest)
        out, err = self.executor.output(receipt.execution_id)
        self.assertEqual(out, b"7\n")
        self.assertIn("isolation:unverified_local", receipt.security_errors)
        self.executor.destroy(workspace)
        self.assertFalse(workspace.path.exists())

    def test_infinite_loop_is_killed_and_leaves_no_live_worker(self):
        workspace = self.executor.prepare(self.base)
        receipt = self.executor.run(
            workspace, self.spec("while True: pass", limits=fast_limits(wall_seconds=3))
        )
        self.assertTrue(receipt.timeout)
        self.assertNotEqual(receipt.exit_status, 0)
        self.assertIn("process:wall_clock_killed", receipt.security_errors)
        self.assertEqual(self.executor._live, {})
        self.executor.destroy(workspace)

    def test_giant_stdout_is_capped_and_flagged(self):
        workspace = self.executor.prepare(self.base)
        receipt = self.executor.run(
            workspace,
            self.spec("import sys; sys.stdout.write('x' * 4_000_000)",
                      limits=fast_limits(output_bytes=1 << 20)),
        )
        out, _ = self.executor.output(receipt.execution_id)
        self.assertLessEqual(len(out), 1 << 20)
        self.assertIn("output:stdout_truncated", receipt.security_errors)
        self.executor.destroy(workspace)

    def test_disk_fill_is_bounded_by_file_size_limit(self):
        try:
            import resource as _resource
            if not hasattr(_resource, "RLIMIT_FSIZE"):
                raise ImportError
        except ImportError:
            self.skipTest("RLIMIT_FSIZE is unavailable on this platform")
        workspace = self.executor.prepare(self.base)
        receipt = self.executor.run(
            workspace,
            self.spec("open('big.bin','wb').write(b'0' * 64_000_000)",
                      limits=fast_limits(disk_bytes=8 << 20)),
        )
        self.assertNotEqual(receipt.exit_status, 0)
        self.assertLessEqual((workspace.path / "big.bin").stat().st_size, 8 << 20)
        self.executor.destroy(workspace)

    def test_aggregate_disk_budget_is_audited(self):
        workspace = self.executor.prepare(self.base)
        code = ("for i in range(3): open(f'f{i}.bin','wb').write(b'0' * (6 << 20))")
        receipt = self.executor.run(
            workspace, self.spec(code, limits=fast_limits(disk_bytes=8 << 20))
        )
        # Each file fits the per-file cap; the aggregate exceeds the budget.
        self.assertIn("fs:disk_budget_exceeded", receipt.security_errors)
        self.executor.destroy(workspace)

    def test_fork_attempt_is_bounded(self):
        if not hasattr(os, "fork"):
            self.skipTest("os.fork is unavailable on this platform")
        workspace = self.executor.prepare(self.base)
        code = (
            "import os\n"
            "n = 0\n"
            "try:\n"
            "    while n < 300:\n"
            "        if os.fork() == 0: os._exit(0)\n"
            "        n += 1\n"
            "except OSError:\n"
            "    print('fork blocked at', n)\n"
            "print('done', n)\n"
        )
        receipt = self.executor.run(
            workspace, self.spec(code, limits=fast_limits(process_count=16, wall_seconds=15))
        )
        out, _ = self.executor.output(receipt.execution_id)
        self.assertIn(b"done", out)
        self.assertNotEqual(receipt.exit_status, -1)
        self.assertEqual(self.executor._live, {})
        self.executor.destroy(workspace)

    def test_host_environment_does_not_leak_into_workspace(self):
        os.environ["SIS_TEST_SECRET_SENTINEL"] = "should-not-leak"
        try:
            workspace = self.executor.prepare(self.base)
            receipt = self.executor.run(
                workspace, self.spec("import os; print(os.environ.get('SIS_TEST_SECRET_SENTINEL'))")
            )
            out, _ = self.executor.output(receipt.execution_id)
            self.assertEqual(out.strip(), b"None")
            self.executor.destroy(workspace)
        finally:
            del os.environ["SIS_TEST_SECRET_SENTINEL"]

    def test_workspace_writes_do_not_touch_the_base_tree(self):
        workspace = self.executor.prepare(self.base)
        before = tree_digest(self.base)
        self.executor.run(workspace, self.spec("open('new.txt','w').write('x'); open('README.txt','w').write('dirty')"))
        self.assertEqual(tree_digest(self.base), before)
        self.executor.destroy(workspace)

    def test_symlinked_base_tree_is_rejected(self):
        if not POSIX:
            self.skipTest("symlink fixture requires POSIX")
        with tempfile.TemporaryDirectory() as temp:
            sneaky = Path(temp) / "sneaky"
            sneaky.mkdir()
            (sneaky / "real.txt").write_text("x")
            (sneaky / "escape").symlink_to("/etc/hosts")
            with self.assertRaises(RunnerError):
                self.executor.prepare(sneaky)

    def test_external_symlink_created_during_run_is_detected(self):
        if not POSIX:
            self.skipTest("symlink fixture requires POSIX")
        workspace = self.executor.prepare(self.base)
        receipt = self.executor.run(workspace, self.spec("import os; os.symlink('/etc/hosts','escape')"))
        self.assertIn("fs:external_symlink", receipt.security_errors)
        self.executor.destroy(workspace)

    def test_terminate_all_kills_live_workers(self):
        workspace = self.executor.prepare(self.base)
        receipt_holder = {}

        def run():
            receipt_holder["r"] = self.executor.run(
                workspace, self.spec("import time; time.sleep(30)", limits=fast_limits(wall_seconds=60))
            )

        import threading

        thread = threading.Thread(target=run)
        thread.start()
        import time

        for _ in range(100):
            if self.executor._live:
                break
            time.sleep(0.02)
        self.executor.terminate_all()
        thread.join(timeout=15)
        self.assertFalse(thread.is_alive())
        self.assertTrue(receipt_holder["r"].exit_status != 0)
        self.executor.destroy(workspace)

    def test_unresolvable_and_missing_command_fails_closed(self):
        workspace = self.executor.prepare(self.base)
        with self.assertRaises(RunnerError):
            self.executor.run(workspace, CommandSpec(argv=("definitely-not-a-real-binary-xyz",)))
        self.executor.destroy(workspace)

    def test_receipt_fields_round_trip_through_contract(self):
        workspace = self.executor.prepare(self.base)
        receipt = self.executor.run(workspace, self.spec("print('ok')"))
        parsed = ExecutionReceiptV1.from_json(receipt.canonical_bytes())
        self.assertEqual(parsed.digest, receipt.digest)
        self.executor.destroy(workspace)


class SeatbeltTests(RunnerFixture):
    def test_seatbelt_denies_network_when_available(self):
        executor = LocalSubprocessExecutor(Path(self.temp.name) / "exec-sb")
        workspace = executor.prepare(self.base)
        code = "import socket; socket.create_connection(('93.184.216.34', 80), 2)"
        receipt = executor.run(workspace, CommandSpec(argv=(PY, "-c", code), limits=fast_limits(wall_seconds=10)))
        _, err = executor.output(receipt.execution_id)
        if executor.network_isolation == "seatbelt_denied":
            self.assertNotEqual(receipt.exit_status, 0)
            self.assertIn(b"Operation not permitted", err)
            self.assertIn("network:seatbelt_denied", receipt.security_errors)
        else:
            self.assertIn("network:not_enforced", receipt.security_errors)
        executor.destroy(workspace)

    def test_seatbelt_denies_file_writes_outside_workspace(self):
        executor = LocalSubprocessExecutor(Path(self.temp.name) / "exec-sb2")
        workspace = executor.prepare(self.base)
        outside = Path(self.temp.name) / "escape-target.txt"
        code = f"open({str(outside)!r}, 'w').write('x')"
        receipt = executor.run(workspace, CommandSpec(argv=(PY, "-c", code), limits=fast_limits()))
        if executor.network_isolation == "seatbelt_denied":
            self.assertNotEqual(receipt.exit_status, 0)
            self.assertFalse(outside.exists())
        executor.destroy(workspace)


if __name__ == "__main__":
    unittest.main()
