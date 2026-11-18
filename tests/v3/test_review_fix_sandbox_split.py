"""Split-custody proxy: library shadowing and object-returning calls.

The local split backend needs seatbelt (macOS), so these tests run the
real bootstrap and worker sources directly over a socketpair. They check
the proxy's behaviour, not the read denial.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from sis.v3.runner import stage_private_material
from sis.v3.split_harness import (
    SPLIT_BOOTSTRAP_NAME,
    SplitClient,
    SplitRef,
    split_bootstrap_argv,
    split_pytest_argv,
    worker_argv,
)

PY = sys.executable


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()

    def run_split(self, tests: dict[str, bytes]) -> subprocess.CompletedProcess:
        material = stage_private_material(
            self.root, tests, private_mode=True, split_bootstrap=True)
        self.addCleanup(shutil.rmtree, material, True)
        parent, child = socket.socketpair()
        worker = subprocess.Popen(
            [PY, *worker_argv(("--fd", str(child.fileno())),
                              str(self.workspace))],
            cwd=str(self.workspace), pass_fds=(child.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        try:
            argv = (PY, "-m", "pytest", "-q", *(
                str(material / name) for name in tests))
            argv = split_pytest_argv(argv, private_dir=str(material))
            argv = split_bootstrap_argv(
                argv, bootstrap_path=str(material / SPLIT_BOOTSTRAP_NAME),
                transport=("--fd", str(parent.fileno())),
                workspace=str(self.workspace))
            return subprocess.run(
                argv, cwd=str(self.workspace), pass_fds=(parent.fileno(),),
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
        finally:
            parent.close()
            worker.kill()
            worker.wait(timeout=10)

    def test_workspace_cannot_shadow_libraries_the_tests_import(self):
        marker = self.root / "SHADOWED"
        for name in ("decimal", "statistics", "json", "pytest_shadow_probe"):
            (self.workspace / f"{name}.py").write_text(
                f"open({str(marker)!r}, 'a').write({name!r})\n"
                "def mean(values):\n    return 42\n"
                "class Decimal:\n    def __init__(self, v):\n        pass\n"
                "    def __eq__(self, other):\n        return True\n")
        (self.workspace / "calc.py").write_text(
            "def add(a, b):\n    return a + b\n")
        result = self.run_split({"test_hidden.py": (
            b"import calc\n"
            b"def test_add():\n"
            b"    import decimal, statistics\n"
            b"    assert type(decimal.Decimal('1')).__module__ == 'decimal'\n"
            b"    assert decimal.Decimal('1') != decimal.Decimal('2')\n"
            b"    assert statistics.mean([1, 3]) == 2\n"
            b"    assert calc.add(2, 3) == 5\n")})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_object_returning_calls_return_the_result(self):
        (self.workspace / "shapes.py").write_text(
            "class Box:\n"
            "    def __init__(self, n):\n"
            "        self.n = n\n"
            "    def area(self):\n"
            "        return self.n * self.n\n"
            "    def grow(self, by):\n"
            "        return Box(self.n + by)\n"
            "CALLS = []\n"
            "def make(n):\n"
            "    CALLS.append(n)\n"
            "    return Box(n)\n"
            "def area_of(box):\n"
            "    return box.area()\n"
            "def calls():\n"
            "    return list(CALLS)\n")
        result = self.run_split({"test_hidden.py": (
            b"import shapes\n"
            b"def test_objects():\n"
            b"    box = shapes.make(3)\n"
            b"    assert box.n == 3\n"
            b"    assert box.area() == 9\n"
            b"    assert box.grow(1).area() == 16\n"
            b"    assert shapes.area_of(box) == 9\n"
            b"    other = shapes.make(5)\n"
            b"    assert box.area() == 9 and other.area() == 25\n"
            b"    assert shapes.calls() == [3, 5]\n")})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class HostSplitClientTests(unittest.TestCase):
    def test_host_client_refers_to_results_by_handle(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        workspace = Path(temp.name)
        (workspace / "counter.py").write_text(
            "class C:\n"
            "    def __init__(self):\n        self.v = 0\n"
            "    def inc(self):\n        self.v += 1\n        return self.v\n"
            "MADE = []\n"
            "def new():\n    MADE.append(1)\n    return C()\n"
            "def made():\n    return len(MADE)\n")
        parent, child = socket.socketpair()
        worker = subprocess.Popen(
            [PY, *worker_argv(("--fd", str(child.fileno())), str(workspace))],
            cwd=str(workspace), pass_fds=(child.fileno(),))
        child.close()
        client = SplitClient(parent)
        try:
            client.ping()
            counter = client.call(["counter", "new"], (), {})
            self.assertIsInstance(counter, SplitRef)
            self.assertEqual(counter.inc(), 1)
            self.assertEqual(counter.inc(), 2)
            self.assertEqual(client.call(["counter", "made"], (), {}), 1)
        finally:
            client.close()
            worker.kill()
            worker.wait(timeout=10)


if __name__ == "__main__":
    unittest.main()
