"""Split-custody proxy: the data codec and the protocols a test suite uses.

The pilot graded correct upstream fixes under split custody and saw them
fail on the harness, not on the code: ``set`` values did not cross, and a
``Ref`` supported no ``len``/``in``/``iter``/``==``. These tests run the
real bootstrap and worker sources over a socketpair (the local split
backend needs seatbelt), so they check the proxy's behaviour, not the read
denial.
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
    MAX_ITEMS,
    SPLIT_BOOTSTRAP_NAME,
    SplitClient,
    SplitProtocolError,
    _decode,
    split_bootstrap_argv,
    split_pytest_argv,
    worker_argv,
)

PY = sys.executable


class SplitHarness(unittest.TestCase):
    """Run hidden tests against a workspace through the real split sources."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir()

    def write(self, relative: str, text: str) -> None:
        path = self.workspace / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def run_split(self, tests: dict[str, str]) -> subprocess.CompletedProcess:
        material = stage_private_material(
            self.root, {name: text.encode() for name, text in tests.items()},
            private_mode=True, split_bootstrap=True)
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
                str(material / name) for name in tests
                if Path(name).name.startswith("test_")))
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

    def assertPasses(self, tests: dict[str, str]) -> None:
        result = self.run_split(tests)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def host_client(self) -> SplitClient:
        parent, child = socket.socketpair()
        worker = subprocess.Popen(
            [PY, *worker_argv(("--fd", str(child.fileno())),
                              str(self.workspace))],
            cwd=str(self.workspace), pass_fds=(child.fileno(),),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        child.close()
        client = SplitClient(parent)

        def stop():
            client.close()
            worker.kill()
            worker.wait(timeout=10)

        self.addCleanup(stop)
        client.ping()
        return client


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitCodecTests(SplitHarness):
    def test_sets_cross_as_data(self):
        # inflection: [(w,) for w in inflection.UNCOUNTABLES], a set.
        self.write("words.py", (
            "UNCOUNTABLES = {'equipment', 'information', 'rice'}\n"
            "FROZEN = frozenset({1, 2, (3, 4)})\n"
            "NESTED = {frozenset({1}), frozenset({2, 3})}\n"
            "def echo(value):\n"
            "    return value\n"
            "def kinds(value):\n"
            "    return sorted(type(item).__name__ for item in value)\n"))
        self.assertPasses({"test_hidden.py": (
            "import words\n"
            "def test_sets():\n"
            "    pairs = [(w,) for w in words.UNCOUNTABLES]\n"
            "    assert sorted(pairs) == [('equipment',), ('information',),"
            " ('rice',)]\n"
            "    assert isinstance(words.UNCOUNTABLES, set)\n"
            "    assert words.FROZEN == frozenset({1, 2, (3, 4)})\n"
            "    assert isinstance(words.FROZEN, frozenset)\n"
            "    assert frozenset({2, 3}) in words.NESTED\n"
            "    assert words.echo({1, 'a'}) == {1, 'a'}\n"
            "    assert words.echo(frozenset({1})) == frozenset({1})\n"
            "    assert words.kinds({1, 'a', (2,)}) == ['int', 'str', 'tuple']\n"
        )})

    def test_mappings_with_non_text_keys_cross_as_data(self):
        self.write("table.py", (
            "CODES = {1: 'one', (2, 'b'): [2], None: {'x': 1}}\n"
            "def invert(mapping):\n"
            "    return {value: key for key, value in mapping.items()}\n"))
        self.assertPasses({"test_hidden.py": (
            "import table\n"
            "def test_maps():\n"
            "    assert table.CODES == {1: 'one', (2, 'b'): [2],"
            " None: {'x': 1}}\n"
            "    assert table.invert({1: 'a', 2: 'b'}) == {'a': 1, 'b': 2}\n"
        )})

    def test_unhashable_or_unbounded_sets_stay_in_the_worker(self):
        # A set whose element does not decode to something hashable (an
        # object, which would come back as a handle) is not data.
        self.write("bags.py", (
            "class Thing:\n"
            "    pass\n"
            f"BIG = set(range({MAX_ITEMS + 1}))\n"
            "MIXED = {1, Thing()}\n"))
        self.assertPasses({"test_hidden.py": (
            "import bags\n"
            "def test_refs():\n"
            "    assert not isinstance(bags.BIG, set)\n"
            "    assert not isinstance(bags.MIXED, set)\n"
        )})

    def test_host_client_decodes_sets_and_maps(self):
        self.write("data.py", (
            "S = {1, 2}\n"
            "F = frozenset({'a'})\n"
            "M = {1: 'x', (1, 2): 'y'}\n"
            "def echo(value):\n"
            "    return value\n"))
        client = self.host_client()
        self.assertEqual(client.get(["data", "S"]), {1, 2})
        self.assertEqual(client.get(["data", "F"]), frozenset({"a"}))
        self.assertEqual(client.get(["data", "M"]), {1: "x", (1, 2): "y"})
        self.assertEqual(
            client.call(["data", "echo"], ({3: {4}},), {}), {3: {4}})
        self.assertEqual(
            client.call(["data", "echo"], (frozenset({5}),), {}),
            frozenset({5}))

    def test_host_decoder_rejects_unhashable_set_elements(self):
        payload = {"t": "set", "v": [{"t": "list", "v": []}]}
        with self.assertRaisesRegex(SplitProtocolError, "unhashable"):
            _decode(payload)
        payload = {"t": "map", "v": [[{"t": "dict", "v": []},
                                      {"t": "none"}]]}
        with self.assertRaisesRegex(SplitProtocolError, "unhashable"):
            _decode(payload)
        payload = {"t": "set", "v": [{"t": "none"}] * (MAX_ITEMS + 1)}
        with self.assertRaisesRegex(SplitProtocolError, "out of bounds"):
            _decode(payload)


if __name__ == "__main__":
    unittest.main()
