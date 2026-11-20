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
    RemoteError,
    SplitClient,
    SplitProtocolError,
    SplitRef,
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

    #: A lower live-handle cap for the worker, for tests only: the real
    #: worker source with its ``MAX_HANDLES`` line rewritten.
    max_handles: int | None = None

    def worker_command(self, child: socket.socket) -> list[str]:
        argv = worker_argv(("--fd", str(child.fileno())), str(self.workspace))
        if self.max_handles is not None:
            line = "MAX_HANDLES = 100000\n"
            assert argv[2].count(line) == 1, "worker cap line moved"
            argv[2] = argv[2].replace(
                line, f"MAX_HANDLES = {int(self.max_handles)}\n")
        return [PY, *argv]

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
            self.worker_command(child), cwd=str(self.workspace),
            pass_fds=(child.fileno(),),
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
            # A relative PYTHONPATH (``src``) would resolve against the
            # workspace cwd and put submitted code on the evaluator's path.
            env = {**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"}
            if env.get("PYTHONPATH"):
                env["PYTHONPATH"] = os.pathsep.join(
                    os.path.abspath(entry)
                    for entry in env["PYTHONPATH"].split(os.pathsep) if entry)
            return subprocess.run(
                argv, cwd=str(self.workspace), pass_fds=(parent.fileno(),),
                capture_output=True, text=True, timeout=120, env=env)
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
            self.worker_command(child), cwd=str(self.workspace),
            pass_fds=(child.fileno(),),
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
            # A module-level set is submission state: it stays in the
            # worker (see SplitStateTests) and is no local set.
            "    assert not isinstance(words.UNCOUNTABLES, set)\n"
            "    assert words.UNCOUNTABLES == {'equipment', 'information',"
            " 'rice'}\n"
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
        # Call results, so the encoder decides (a module-level set is
        # state and a handle whatever its contents).
        self.write("bags.py", (
            "class Thing:\n"
            "    pass\n"
            "def big():\n"
            f"    return set(range({MAX_ITEMS + 1}))\n"
            "def mixed():\n"
            "    return {1, Thing()}\n"
            "def nested():\n"
            "    return frozenset({(1, Thing())})\n"
            "def small():\n"
            "    return {1, (2, 'a')}\n"))
        self.assertPasses({"test_hidden.py": (
            "import bags\n"
            "def test_refs():\n"
            "    assert not isinstance(bags.big(), set)\n"
            f"    assert len(bags.big()) == {MAX_ITEMS + 1}\n"
            "    assert not isinstance(bags.mixed(), set)\n"
            "    assert len(bags.mixed()) == 2\n"
            "    assert not isinstance(bags.nested(), frozenset)\n"
            "    assert type(bags.small()) is set\n"
            "    assert bags.small() == {1, (2, 'a')}\n"
        )})

    def test_results_too_large_for_a_frame_stay_in_the_worker(self):
        # Within the item and depth bounds but over the frame bound: the
        # result must come back as a handle, from the one call already
        # made, never end the run as a lost worker.
        self.write("large.py", (
            "CALLS = []\n"
            "BIG = 'b' * 1100000\n"
            "def pair():\n"
            "    CALLS.append(1)\n"
            "    return frozenset({'x' * 600000, 'y' * 600000})\n"
            "def small():\n"
            "    return frozenset({'x', 'y'})\n"
            "def fail():\n"
            "    raise ValueError('z' * 1100000)\n"))
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import large\n"
            "def test_large():\n"
            "    value = large.pair()\n"
            "    assert not isinstance(value, frozenset)\n"
            "    assert len(value) == 2 and len(large.CALLS) == 1\n"
            "    assert sorted(len(item) for item in value) == [600000] * 2\n"
            "    assert large.small() == frozenset({'x', 'y'})\n"
            "    assert isinstance(large.small(), frozenset)\n"
            "    assert not isinstance(large.BIG, str)\n"
            "    assert len(large.BIG) == 1100000\n"
            "    with pytest.raises(ValueError):\n"
            "        large.fail()\n"
        )})
        client = self.host_client()
        self.assertIsInstance(client.call(["large", "pair"], (), {}),
                              SplitRef)
        self.assertEqual(client.call(["large", "small"], (), {}),
                         frozenset({"x", "y"}))

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


STATE_MODULE = """
import collections

UNCOUNTABLES = {'equipment', 'rice'}
PLURALS = [('ox', 'oxen')]
TABLE = {'a': [1], 'b': {'c': 2}}
QUEUE = collections.deque([1])
BUFFER = bytearray(b'ab')
NAME = 'fixed'
PAIR = ([1], 2)
FROZEN = frozenset({1})


def singularize(word):
    return word if word in UNCOUNTABLES else word.rstrip('s')


def plural_count():
    return len(PLURALS)


def fresh():
    return [1, 2]


def internal():
    return PLURALS


def reset():
    global PLURALS
    PLURALS = []


class Box:
    def __init__(self):
        self.items = []
    def size(self):
        return len(self.items)
"""


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitStateTests(SplitHarness):
    """Module and object state read by a test is the worker's own object."""

    def setUp(self):
        super().setUp()
        self.write("state.py", STATE_MODULE)

    def test_mutating_a_module_set_reaches_the_submission(self):
        # inflection's hidden test, verbatim in shape.
        self.assertPasses({"test_hidden.py": (
            "import state\n"
            "from state import UNCOUNTABLES\n"
            "def test_uncountable():\n"
            "    assert state.singularize('ors') == 'or'\n"
            "    state.UNCOUNTABLES.add('ors')\n"
            "    try:\n"
            "        assert 'ors' == state.singularize('ors')\n"
            "        assert 'ors' in UNCOUNTABLES\n"
            "    finally:\n"
            "        state.UNCOUNTABLES.remove('ors')\n"
            "    assert state.singularize('ors') == 'or'\n"
            "    assert 'ors' not in state.UNCOUNTABLES\n"
        )})

    def test_container_handles_behave_like_the_container(self):
        self.assertPasses({"test_hidden.py": (
            "import state\n"
            "def test_protocols():\n"
            "    words = state.UNCOUNTABLES\n"
            "    assert words == {'equipment', 'rice'}\n"
            "    assert {'equipment', 'rice'} == words\n"
            "    assert words != {'rice'} and {'rice'} != words\n"
            "    assert sorted(words) == ['equipment', 'rice']\n"
            "    assert len(words) == 2 and 'rice' in words\n"
            "    assert sorted(x for x in words) == ['equipment', 'rice']\n"
            "    assert words | {'z'} == {'equipment', 'rice', 'z'}\n"
            "    assert {'z'} | words == {'equipment', 'rice', 'z'}\n"
            "    assert list(state.PLURALS) == [('ox', 'oxen')]\n"
            "    assert state.PLURALS[0] == ('ox', 'oxen')\n"
            "    assert state.PLURALS[:1] == [('ox', 'oxen')]\n"
            "    table = state.TABLE\n"
            "    assert table['a'] == [1] and table == {'a': [1],"
            " 'b': {'c': 2}}\n"
            "    assert sorted(table) == ['a', 'b']\n"
            "    assert dict(table.items()) == {'a': [1], 'b': {'c': 2}}\n"
            "    table['z'] = 0\n"
            "    del table['z']\n"
            "    assert 'z' not in state.TABLE\n"
            "    assert state.QUEUE == state.QUEUE and len(state.QUEUE) == 1\n"
            "    assert bytes(state.BUFFER) == b'ab'\n"
        )})

    def test_mutations_through_any_read_reach_the_worker(self):
        self.assertPasses({"test_hidden.py": (
            "import copy\n"
            "import state\n"
            "def test_mutations():\n"
            "    state.PLURALS.append(('mouse', 'mice'))\n"
            "    assert state.plural_count() == 2\n"
            "    state.PLURALS.extend([('a', 'b')])\n"
            "    state.PLURALS[2] = ('c', 'd')\n"
            "    assert state.PLURALS[-1] == ('c', 'd')\n"
            "    del state.PLURALS[2]\n"
            "    plurals = state.PLURALS\n"
            "    plurals += [('e', 'f')]\n"
            "    assert state.plural_count() == 3\n"
            "    plurals.pop()\n"
            "    assert state.plural_count() == 2\n"
            # An item read is state too: nested containers stay remote.
            "    state.TABLE['a'].append(2)\n"
            "    state.TABLE['b']['d'] = 3\n"
            "    assert state.TABLE == {'a': [1, 2], 'b': {'c': 2, 'd': 3}}\n"
            "    state.TABLE.update({'x': 1})\n"
            "    assert state.TABLE.pop('x') == 1\n"
            "    state.QUEUE.appendleft(0)\n"
            "    assert list(state.QUEUE) == [0, 1]\n"
            "    state.BUFFER.extend(b'c')\n"
            "    assert bytes(state.BUFFER) == b'abc'\n"
            # Object attributes are state as well.
            "    box = state.Box()\n"
            "    box.items.append(1)\n"
            "    assert box.size() == 1\n"
            # copy() is a snapshot the worker makes and sends as data.
            "    snapshot = copy.copy(state.PLURALS)\n"
            "    deep = copy.deepcopy(state.TABLE)\n"
            "    assert isinstance(snapshot, list) and isinstance(deep, dict)\n"
            "    state.PLURALS.clear()\n"
            "    assert len(snapshot) == 2 and state.plural_count() == 0\n"
            "    assert deep['a'] == [1, 2]\n"
        )})

    def test_a_handle_is_the_object_not_the_name(self):
        # Rebinding the module name leaves an earlier read on the old
        # object, as in one process.
        self.assertPasses({"test_hidden.py": (
            "import state\n"
            "def test_identity():\n"
            "    old = state.PLURALS\n"
            "    state.reset()\n"
            "    assert old == [('ox', 'oxen')] and state.PLURALS == []\n"
            "    assert state.plural_count() == 0\n"
        )})

    def test_immutable_values_and_call_results_cross_as_data(self):
        self.assertPasses({"test_hidden.py": (
            "import state\n"
            "def test_data():\n"
            "    assert type(state.NAME) is str\n"
            "    assert type(state.FROZEN) is frozenset\n"
            # A tuple is immutable: it and what it holds are copies.
            "    assert type(state.PAIR) is tuple\n"
            "    assert type(state.PAIR[0]) is list\n"
            # Call results are copies, including internal state a function
            # returns: a fresh list is by far the common case.
            "    assert type(state.fresh()) is list\n"
            "    leaked = state.internal()\n"
            "    assert type(leaked) is list\n"
            "    leaked.append('local')\n"
            "    assert state.plural_count() == 1\n"
        )})

    def test_threads_in_the_test_do_not_interleave_requests(self):
        # jmespath's cache-eviction test calls the submission from 32
        # threads. Each request must get its own answer, not another
        # thread's: frames on the one socket are serialized.
        self.assertPasses({"test_hidden.py": (
            "from concurrent.futures import ThreadPoolExecutor\n"
            "import state\n"
            "def check(index):\n"
            "    for _ in range(200):\n"
            "        word = 'w%d' % index\n"
            "        assert state.singularize(word + 's') == word\n"
            "        assert state.NAME == 'fixed'\n"
            "    return index\n"
            "def test_threads():\n"
            "    with ThreadPoolExecutor(max_workers=8) as pool:\n"
            "        assert list(pool.map(check, range(16))) =="
            " list(range(16))\n"
        )})

    def test_repeated_reads_share_one_handle(self):
        client = self.host_client()
        first = client.get(["state", "PLURALS"])
        self.assertIsInstance(first, SplitRef)
        for _ in range(50):
            again = client.get(["state", "PLURALS"])
            self.assertEqual(again._path, first._path)
        first.append(("a", "b"))
        self.assertEqual(client.call(["state", "plural_count"], (), {}), 2)
        self.assertEqual(client.get(["state", "NAME"]), "fixed")
        self.assertEqual(client.call(["state", "fresh"], (), {}), [1, 2])
        self.assertIsInstance(client.call(["state", "fresh"], (), {}), list)


HANDLE_CAP = 48
HANDLE_MODULE = """
LIST = []


class Box:
    def __init__(self, n):
        self.n = n
        self.items = [n]
    def get(self):
        return self


class Failure(Exception):
    def __init__(self, n):
        super().__init__(n)
        self.n = n


def make(n):
    return Box(n)


def fail(n):
    raise Failure(n)


def size():
    return len(LIST)
"""


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitHandleTests(SplitHarness):
    """Handles are released when the evaluator's last reference goes.

    jmespath's thread test makes 32 x 4096 calls; with handles never
    released, the worker's handle table filled up and the run failed on
    the harness. The worker here runs with a cap of HANDLE_CAP live
    handles, and every test makes several times that many.
    """

    max_handles = HANDLE_CAP

    def setUp(self):
        super().setUp()
        self.write("handles.py", HANDLE_MODULE)

    def test_short_lived_handles_are_released(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import handles\n"
            f"ROUNDS = 3 * {HANDLE_CAP}\n"
            "def test_calls():\n"
            "    kept = handles.make(-1)\n"
            "    for i in range(ROUNDS):\n"
            "        assert handles.make(i).n == i\n"
            "        assert handles.make(i).get().items == [i]\n"
            "        assert list(iter(handles.make(i).items)) == [i]\n"
            "    assert kept.n == -1 and kept.get().n == -1\n"
            "def test_exceptions():\n"
            "    for i in range(ROUNDS):\n"
            "        with pytest.raises(handles.Failure) as info:\n"
            "            handles.fail(i)\n"
            "        assert info.value.n == i\n"
            "        assert not hasattr(handles.make(i), 'missing')\n"
            "def test_threads():\n"
            "    from concurrent.futures import ThreadPoolExecutor\n"
            "    def work(index):\n"
            "        for i in range(ROUNDS):\n"
            "            assert handles.make(i).get().n == i\n"
            "        return index\n"
            "    with ThreadPoolExecutor(max_workers=8) as pool:\n"
            "        assert list(pool.map(work, range(8))) == list(range(8))\n"
        )})

    def test_a_shared_handle_survives_until_its_last_ref(self):
        self.assertPasses({"test_hidden.py": (
            "import gc\n"
            "import handles\n"
            f"ROUNDS = 3 * {HANDLE_CAP}\n"
            "def churn():\n"
            "    for i in range(ROUNDS):\n"
            "        assert handles.make(i).n == i\n"
            "    gc.collect()\n"
            "def test_shared():\n"
            "    first = handles.LIST\n"
            "    second = handles.LIST\n"
            "    assert first._path == second._path\n"
            "    del first\n"
            "    churn()\n"
            "    second.append(1)\n"
            "    assert handles.size() == 1 and len(second) == 1\n"
            "    box = handles.make(7)\n"
            "    items, method = box.items, box.get\n"
            "    del box\n"
            "    churn()\n"
            # An attribute path or a mutable read off a handle keeps the
            # handle it starts from.
            "    assert method().n == 7\n"
            "    items.append(8)\n"
            "    assert items == [7, 8]\n"
            "    for _ in range(ROUNDS):\n"
            "        again = handles.LIST\n"
            "        assert len(again) == 1\n"
            "    assert len(second) == 1\n"
        )})

    def release(self, client, entries, op="release"):
        response = client.request({"op": op, "release": entries})
        self.assertTrue(response.get("ok"), response)

    def test_the_worker_counts_hand_outs_before_dropping(self):
        client = self.host_client()
        first = client.get(["handles", "LIST"])
        second = client.get(["handles", "LIST"])
        handle = first._path[0]
        self.assertEqual(second._path, [handle])
        self.release(client, [[handle, 1]])
        self.assertEqual(len(first), 0)
        # Piggy-backed on an ordinary request, applied before it.
        response = client.request({"op": "dunder", "path": [handle],
                                   "name": "__len__", "args": [],
                                   "release": [[handle, 1]]})
        self.assertFalse(response.get("ok"))
        self.assertEqual(response["error"]["type"], "KeyError")
        # The object itself is untouched; a new read is a new handle.
        third = client.get(["handles", "LIST"])
        self.assertNotEqual(third._path, [handle])
        self.assertEqual(len(third), 0)

    def test_malformed_releases_never_hurt_the_worker(self):
        client = self.host_client()
        kept = client.call(["handles", "make"], (5,), {})
        handle = kept._path[0]
        for entries in (
                None, "x", 7, {"#1": 1}, [None], ["#1"], [[handle]],
                [[handle, 1, 2]], [[handle, True]], [[handle, 0]],
                [[handle, -3]], [[handle, 1.0]], [[handle, "1"]],
                [[1, 1]], [["handles", 1]], [["handles.LIST", 5]],
                [["#999999", 1]], [["#0", 1]], [[[handle], 1]],
                [[{"t": "none"}, 1]], [["#1" * 9, 10 ** 30]],
                [["#", 1]] * 20000):
            self.release(client, entries)
            self.release(client, entries, op="ping")
        client.ping()
        self.assertEqual(client.get([handle, "n"]), 5)
        self.assertEqual(client.call(["handles", "size"], (), {}), 0)
        # Releasing it twice is the same as once.
        self.release(client, [[handle, 1], [handle, 1]])
        self.release(client, [[handle, 1]])
        response = client.request({"op": "get", "path": [handle, "n"]})
        self.assertEqual(response["error"]["type"], "KeyError")
        client.ping()

    def test_the_cap_still_bounds_live_handles(self):
        client = self.host_client()
        held = [client.call(["handles", "make"], (i,), {})
                for i in range(HANDLE_CAP)]
        with self.assertRaises(RemoteError):
            client.call(["handles", "make"], (0,), {})
        self.release(client, [[held[0]._path[0], 1]])
        self.assertEqual(client.call(["handles", "make"], (9,), {}).n, 9)


PROTOCOL_MODULE = """
import functools

__version__ = "1.2"
__all__ = ["Bag", "make_bag"]
LOG = []


class Bag:
    def __init__(self, *items):
        self.items = list(items)
    def __len__(self):
        return len(self.items)
    def __contains__(self, item):
        return item in self.items
    def __getitem__(self, index):
        return self.items[index]
    def __setitem__(self, index, value):
        self.items[index] = value
    def __delitem__(self, index):
        del self.items[index]
    def __iter__(self):
        return iter(self.items)
    def __reversed__(self):
        return reversed(self.items)
    def __repr__(self):
        return "Bag(%r)" % (self.items,)
    def __str__(self):
        return "bag of %d" % len(self.items)


class Node:
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return "Node(%s)" % self.name


def make_bag(*items):
    return Bag(*items)


def nodes(*names):
    return Bag(*[Node(name) for name in names])


def count(limit):
    for value in range(limit):
        yield value


@functools.total_ordering
class Version:
    def __init__(self, major, minor=0):
        self.key = (major, minor)
    def __eq__(self, other):
        if isinstance(other, int):
            return self.key == (other, 0)
        if isinstance(other, Version):
            return self.key == other.key
        return NotImplemented
    def __lt__(self, other):
        if isinstance(other, int):
            other = Version(other)
        return self.key < other.key
    def __hash__(self):
        return hash(self.key)
    def __format__(self, spec):
        return format("%d.%d" % self.key, spec)
    def __bool__(self):
        return self.key != (0, 0)
    def __int__(self):
        return self.key[0]
    def __index__(self):
        return self.key[0]


class Money:
    def __init__(self, cents):
        self.cents = cents
    def __add__(self, other):
        other = other.cents if isinstance(other, Money) else other
        return Money(self.cents + other)
    __radd__ = __add__
    def __sub__(self, other):
        return Money(self.cents - other)
    def __rsub__(self, other):
        return Money(other - self.cents)
    def __mul__(self, factor):
        return Money(self.cents * factor)
    def __neg__(self):
        return Money(-self.cents)
    def __abs__(self):
        return Money(abs(self.cents))
    def __float__(self):
        return self.cents / 100
    def __round__(self, digits=None):
        return round(self.cents / 100, digits)
    def __eq__(self, other):
        return isinstance(other, Money) and other.cents == self.cents
    def __hash__(self):
        return hash(self.cents)


class Resource:
    def __init__(self, suppress=False):
        self.suppress = suppress
    def __enter__(self):
        LOG.append("enter")
        return self
    def __exit__(self, kind, value, traceback):
        LOG.append("exit:%s" % (None if kind is None
                                else "%s:%s" % (kind.__name__, value)))
        return self.suppress
    def use(self):
        LOG.append("use")


class Shape:
    pass


class Square(Shape):
    pass


class Other:
    pass


def log():
    return list(LOG)
"""


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitProtocolTests(SplitHarness):
    def setUp(self):
        super().setUp()
        self.write("shop.py", PROTOCOL_MODULE)

    def test_container_protocols(self):
        self.assertPasses({"test_hidden.py": (
            "import shop\n"
            "def test_container():\n"
            "    bag = shop.make_bag(1, 2, 3)\n"
            "    assert len(bag) == 3\n"
            "    assert 2 in bag and 9 not in bag\n"
            "    assert bag[0] == 1 and bag[-1] == 3\n"
            "    assert bag[1:] == [2, 3]\n"
            "    bag[0] = 10\n"
            "    del bag[1]\n"
            "    assert bag.items == [10, 3]\n"
            "    assert list(bag) == [10, 3]\n"
            "    assert [item * 2 for item in bag] == [20, 6]\n"
            "    assert list(reversed(bag)) == [3, 10]\n"
            "    assert str(bag) == 'bag of 2'\n"
            "    assert repr(bag) == 'Bag([10, 3])'\n"
            "    assert bool(bag) and not shop.make_bag()\n"
        )})

    def test_iteration_streams_through_handles(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import shop\n"
            "def test_stream():\n"
            "    counter = shop.count(3)\n"
            "    assert next(counter) == 0\n"
            "    assert list(counter) == [1, 2]\n"
            "    with pytest.raises(StopIteration):\n"
            "        next(counter)\n"
            "    names = [repr(node) for node in shop.nodes('a', 'b')]\n"
            "    assert names == ['Node(a)', 'Node(b)']\n"
            "    assert [node.name for node in shop.nodes('x')] == ['x']\n"
            "    assert 4 in shop.count(5)\n"
            "    assert sum(shop.count(4)) == 6\n"
        )})

    def test_comparisons_work_in_both_directions(self):
        self.assertPasses({"test_hidden.py": (
            "import shop\n"
            "def test_compare():\n"
            "    one, two = shop.Version(1), shop.Version(1, 5)\n"
            "    assert one < two and two > one and one <= one\n"
            "    assert one == shop.Version(1) and one != two\n"
            "    assert one == 1 and 1 == one\n"
            "    assert 0 < one and 2 > two and one < 2\n"
            "    assert one != object()\n"
            "    assert sorted([two, one])[0] == one\n"
            "    assert hash(one) == hash(shop.Version(1))\n"
            "    assert {one: 'x'}[shop.Version(1)] == 'x'\n"
            "    assert f'{two}' == '1.5' and f'{two:>5}' == '  1.5'\n"
            "    assert int(two) == 1 and [10, 20][one] == 20\n"
            "    assert not shop.Version(0)\n"
        )})

    def test_arithmetic_on_returned_objects(self):
        self.assertPasses({"test_hidden.py": (
            "import shop\n"
            "def test_money():\n"
            "    a = shop.Money(150)\n"
            "    assert (a + 50).cents == 200\n"
            "    assert (50 + a).cents == 200\n"
            "    assert (a + shop.Money(1)).cents == 151\n"
            "    assert (200 - a).cents == 50 and (a - 50).cents == 100\n"
            "    assert (a * 2).cents == 300\n"
            "    assert (-a).cents == -150 and abs(-a).cents == 150\n"
            "    assert sum([a, shop.Money(10)]).cents == 160\n"
            "    assert float(a) == 1.5 and round(a) == 2\n"
            "    a += 5\n"
            "    assert a.cents == 155\n"
        )})

    def test_context_managers(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import shop\n"
            "def test_with():\n"
            "    with shop.Resource() as resource:\n"
            "        resource.use()\n"
            "    with pytest.raises(KeyError):\n"
            "        with shop.Resource():\n"
            "            raise KeyError('k')\n"
            "    with shop.Resource(suppress=True):\n"
            "        raise ValueError('quiet')\n"
            "    assert shop.log() == ['enter', 'use', 'exit:None', 'enter',\n"
            "                          \"exit:KeyError:'k'\", 'enter',\n"
            "                          'exit:ValueError:quiet']\n"
        )})

    def test_enter_state_and_modular_pow(self):
        self.write("more.py", (
            "class Recorder:\n"
            "    def __init__(self):\n"
            "        self.log = []\n"
            "    def __enter__(self):\n"
            "        return self.log\n"
            "    def __exit__(self, *exc):\n"
            "        self.closed = list(self.log)\n"
            "        return False\n"
            "class Number:\n"
            "    def __init__(self, value):\n"
            "        self.value = value\n"
            "    def __pow__(self, exponent, modulus=None):\n"
            "        return pow(self.value, exponent, modulus)\n"))
        self.assertPasses({"test_hidden.py": (
            "import more\n"
            "def test_enter_and_pow():\n"
            # ``with x as y`` binds what __enter__ returned: the worker's
            # own list, so __exit__ sees the body's changes.
            "    recorder = more.Recorder()\n"
            "    with recorder as log:\n"
            "        log.append(1)\n"
            "    assert recorder.closed == [1]\n"
            "    assert pow(more.Number(3), 3, 5) == 2\n"
            "    assert more.Number(3) ** 2 == 9\n"
        )})
        client = self.host_client()
        number = client.call(["more", "Number"], (3,), {})
        self.assertEqual(pow(number, 3, 5), 2)

    def test_isinstance_and_issubclass_ask_the_worker(self):
        self.assertPasses({"test_hidden.py": (
            "import shop\n"
            "def test_types():\n"
            "    square = shop.Square()\n"
            "    assert isinstance(square, shop.Shape)\n"
            "    assert isinstance(square, (shop.Other, shop.Square))\n"
            "    assert not isinstance(square, shop.Other)\n"
            "    assert not isinstance(3, shop.Shape)\n"
            "    assert not isinstance(object(), shop.Shape)\n"
            "    assert issubclass(shop.Square, shop.Shape)\n"
            "    assert not issubclass(shop.Other, shop.Shape)\n"
        )})

    def test_attribute_assignment_and_readable_metadata(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import shop\n"
            "from shop import *\n"
            "def test_attributes():\n"
            "    node = shop.Node('a')\n"
            "    node.name = 'b'\n"
            "    assert node.name == 'b'\n"
            "    node.extra = [1]\n"
            "    del node.extra\n"
            "    with pytest.raises(AttributeError):\n"
            "        node.extra\n"
            "    assert shop.make_bag.__name__ == 'make_bag'\n"
            "    assert shop.Node.__qualname__ == 'Node'\n"
            "    assert shop.__version__ == '1.2'\n"
            "    assert make_bag(1).items == [1]\n"
            "    with pytest.raises(AttributeError):\n"
            "        node.__dict__\n"
            "    with pytest.raises(AttributeError):\n"
            "        node.__class__ = object\n"
        )})

    def test_the_worker_refuses_protocols_outside_its_table(self):
        client = self.host_client()
        bag = client.call(["shop", "make_bag"], (1,), {})
        for name in ("__reduce__", "__reduce_ex__", "__getattribute__",
                     "__class__", "__init_subclass__", "__del__",
                     "__getstate__", "__dict__", "__init__", "__call__"):
            response = client.request({"op": "dunder", "path": bag._path,
                                       "name": name, "args": []})
            self.assertFalse(response.get("ok"), name)
            self.assertIn("not forwarded", response["error"]["message"])
            with self.assertRaises(SplitProtocolError):
                client.dunder(bag._path, name, ())
        for attribute in ("__class__", "__dict__", "__globals__",
                          "__reduce__"):
            response = client.request(
                {"op": "get", "path": ["shop", "make_bag", attribute]})
            self.assertFalse(response.get("ok"), attribute)
            self.assertEqual(response["error"]["type"], "AttributeError")
        response = client.request(
            {"op": "dunder", "path": bag._path, "name": "__setattr__",
             "args": [{"t": "str", "v": "__class__"}, {"t": "none"}]})
        self.assertFalse(response.get("ok"))

    def test_host_client_forwards_the_same_protocols(self):
        client = self.host_client()
        bag = client.call(["shop", "make_bag"], (1, 2), {})
        self.assertIsInstance(bag, SplitRef)
        self.assertEqual(len(bag), 2)
        self.assertIn(2, bag)
        self.assertEqual(list(bag), [1, 2])
        self.assertEqual(bag[0], 1)
        version = client.call(["shop", "Version"], (1,), {})
        self.assertTrue(version == 1 and 1 == version)
        self.assertLess(0, version)
        self.assertNotEqual(version, object())
        self.assertEqual(str(bag), "bag of 2")

    def test_host_client_keeps_a_generator_return_value(self):
        self.write("gens.py", (
            "def counted():\n"
            "    yield 1\n"
            "    return 7\n"
            "def plain():\n"
            "    yield 1\n"
            "def texted():\n"
            "    yield 1\n"
            "    return '7'\n"))
        client = self.host_client()
        for name, expected in (("counted", 7), ("plain", None),
                               ("texted", "7")):
            generator = client.call(["gens", name], (), {})
            self.assertEqual(next(generator), 1)
            with self.assertRaises(StopIteration) as info:
                next(generator)
            self.assertEqual(info.exception.value, expected, name)
            self.assertIs(type(info.exception.value), type(expected))


ERRORS_MODULE = """
class BaseError(Exception):
    default_code = 500


class NotFound(BaseError, KeyError):
    def __init__(self, key, code=404):
        super().__init__(key)
        self.key = key
        self.code = code
    def __str__(self):
        return "missing %s (%d)" % (self.key, self.code)


class Fatal(BaseException):
    pass


class Mixin:
    pass


class Mixed(Mixin, ValueError):
    pass
"""

PACKAGE_INIT = """
import json

from .errors import BaseError, NotFound, Fatal, Mixed

SEEN = []


def find(key):
    raise NotFound(key)


def fail_base():
    raise BaseError("base " + "x" * 600)


def fatal():
    raise Fatal("stop")


def mixed():
    raise Mixed("mixed")


def parse(text):
    return json.loads(text)


def missing(key):
    return {}[key]


def no_file(path):
    open(path)


def make_error():
    return NotFound("made", 1)


def inspect(error):
    return [type(error).__name__, error.code]


def clean():
    try:
        raise KeyError("inner")
    except KeyError:
        return "handled"
"""


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitExceptionTests(SplitHarness):
    def setUp(self):
        super().setUp()
        self.write("pkg/__init__.py", PACKAGE_INIT)
        self.write("pkg/errors.py", ERRORS_MODULE)

    def test_pytest_raises_matches_submission_exceptions(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import pkg\n"
            "from pkg import errors\n"
            "def test_raises():\n"
            "    with pytest.raises(pkg.NotFound, match=r'missing k \\(404\\)')"
            " as info:\n"
            "        pkg.find('k')\n"
            "    assert info.value.code == 404 and info.value.key == 'k'\n"
            "    assert isinstance(info.value, KeyError)\n"
            "    assert isinstance(info.value, pkg.BaseError)\n"
            "    assert type(info.value) is errors.NotFound\n"
            "    assert pkg.NotFound is errors.NotFound\n"
            "    assert issubclass(pkg.NotFound, pkg.BaseError)\n"
            "    assert pkg.NotFound.__name__ == 'NotFound'\n"
            "    assert pkg.BaseError.default_code == 500\n"
            "    with pytest.raises(pkg.BaseError, match='x' * 600):\n"
            "        pkg.fail_base()\n"
            "    try:\n"
            "        pkg.find('j')\n"
            "    except pkg.BaseError as exc:\n"
            "        assert pkg.inspect(exc) == ['NotFound', 404]\n"
            "    else:\n"
            "        raise AssertionError('not raised')\n"
            "    with pytest.raises(ValueError):\n"
            "        pkg.mixed()\n"
            "    with pytest.raises(pkg.Mixed):\n"
            "        pkg.mixed()\n"
            "    assert pkg.clean() == 'handled'\n"
        )})

    def test_builtin_and_trusted_exceptions_keep_their_type(self):
        self.assertPasses({"test_hidden.py": (
            "import json\n"
            "import pytest\n"
            "import pkg\n"
            "def test_builtins():\n"
            "    with pytest.raises(KeyError, match=\"'gone'\") as info:\n"
            "        pkg.missing('gone')\n"
            "    assert type(info.value) is KeyError\n"
            "    assert info.value.args == ('gone',)\n"
            "    with pytest.raises(FileNotFoundError, match='nowhere'):\n"
            "        pkg.no_file('/nowhere/at/all')\n"
            "    with pytest.raises(json.JSONDecodeError):\n"
            "        pkg.parse('{')\n"
        )})

    def test_isinstance_of_a_returned_exception_asks_the_worker(self):
        self.assertPasses({"test_hidden.py": (
            "import pkg\n"
            "def test_instance():\n"
            "    made = pkg.make_error()\n"
            "    assert isinstance(made, pkg.NotFound)\n"
            "    assert isinstance(made, pkg.BaseError)\n"
            "    assert not isinstance(made, pkg.Mixed)\n"
            "    assert made.code == 1\n"
        )})

    def test_base_exceptions_arrive_as_ordinary_exceptions(self):
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import pkg\n"
            "def test_fatal():\n"
            "    with pytest.raises(pkg.Fatal) as info:\n"
            "        pkg.fatal()\n"
            "    assert isinstance(info.value, Exception)\n"
            "    assert issubclass(pkg.Fatal, Exception)\n"
        )})

    def test_a_forging_worker_cannot_raise_base_exceptions(self):
        # The submission runs in the worker and can rewrite what the
        # worker reports. Whatever it claims, the evaluator only ever
        # raises ordinary Exception subclasses and builds no class it
        # was not asked to stand in for.
        self.write("evil.py", (
            "import sys\n"
            "_main = sys.modules['__main__']\n"
            "_original = _main.describe_error\n"
            "_annotate = _main.annotate\n"
            "B = {'module': 'builtins', 'qualname': 'BaseException',"
            " 'bases': []}\n"
            "FORGED = {\n"
            "    'kbd': [{'module': 'builtins', 'qualname':"
            " 'KeyboardInterrupt', 'bases': [1]}, B],\n"
            "    'exit': [{'module': 'builtins', 'qualname': 'SystemExit',"
            " 'bases': [1]}, B],\n"
            "    'derived': [{'module': 'evil', 'qualname': 'Evil',"
            " 'bases': [1]}, {'module': 'builtins', 'qualname':"
            " 'KeyboardInterrupt', 'bases': [2]}, B],\n"
            "    'cycle': [{'module': 'evil', 'qualname': 'Loop',"
            " 'bases': [0]}],\n"
            "    'garbage': 'nonsense',\n"
            "    'gen': [{'module': 'builtins', 'qualname': 'GeneratorExit',"
            " 'bases': []}],\n"
            "}\n"
            "def forged(exc):\n"
            "    error = _original(exc)\n"
            "    kind = str(exc)\n"
            "    if kind in FORGED:\n"
            "        error['classes'] = FORGED[kind]\n"
            "        error['type'] = 'KeyboardInterrupt'\n"
            "        error['args'] = {'t': 'bogus'}\n"
            "    return error\n"
            "def annotate(ref, value):\n"
            "    ref = _annotate(ref, value)\n"
            "    if getattr(value, 'claim', False):\n"
            "        ref['exc'] = FORGED['kbd']\n"
            "    return ref\n"
            "_main.describe_error = forged\n"
            "_main.annotate = annotate\n"
            "class Claimed:\n"
            "    claim = True\n"
            "def boom(kind):\n"
            "    raise ValueError(kind)\n"))
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import evil\n"
            "@pytest.mark.parametrize('kind', ['kbd', 'exit', 'derived',"
            " 'cycle', 'garbage', 'gen'])\n"
            "def test_forged(kind):\n"
            "    with pytest.raises(Exception) as info:\n"
            "        evil.boom(kind)\n"
            "    assert isinstance(info.value, Exception)\n"
            "def test_claimed_class_is_not_a_base_exception():\n"
            "    claimed = evil.Claimed\n"
            "    assert not isinstance(claimed, type)\n"
        )})

    def test_a_worker_name_never_selects_a_non_stdlib_class(self):
        # A private helper the test imported defines an exception with
        # evaluator-side hooks. A worker naming that class (or deriving
        # from it by name) must get an inert stand-in: the hooks never
        # run with worker-chosen arguments, here or as a stand-in base.
        marker = self.root / "EVALUATOR_HOOK_RAN"
        self.write("claims.py", (
            "class Hooked(Exception):\n"
            "    pass\n"
            "Hooked.__module__ = 'hooked_helper'\n"
            "class Child(Hooked):\n"
            "    pass\n"
            "Child.__module__ = 'claims'\n"
            "def hooked():\n"
            "    raise Hooked('chosen by the worker')\n"
            "def child():\n"
            "    raise Child('derived')\n"
            "def decode():\n"
            "    import json\n"
            "    json.loads('{')\n"))
        self.assertPasses({
            "hooked_helper.py": (
                f"MARK = {str(marker)!r}\n"
                "class Meta(type):\n"
                "    def __call__(cls, *args):\n"
                "        open(MARK, 'a').write('meta')\n"
                "        return super().__call__(*args)\n"
                "class Hooked(Exception, metaclass=Meta):\n"
                "    def __init__(self, *args):\n"
                "        open(MARK, 'a').write('init')\n"
                "        super().__init__(*args)\n"
                "    def __init_subclass__(cls, **kwargs):\n"
                "        open(MARK, 'a').write('subclass')\n"),
            "test_hidden.py": (
                "import json\n"
                "import pytest\n"
                "import hooked_helper\n"
                "import claims\n"
                "def test_inert():\n"
                "    with pytest.raises(Exception, match='chosen') as info:\n"
                "        claims.hooked()\n"
                "    assert not isinstance(info.value, hooked_helper.Hooked)\n"
                "    assert type(info.value).__qualname__ == 'Hooked'\n"
                "    with pytest.raises(Exception, match='derived') as info:\n"
                "        claims.child()\n"
                "    assert not isinstance(info.value, hooked_helper.Hooked)\n"
                "    assert isinstance(info.value, type(\n"
                "        pytest.raises(Exception, claims.hooked).value))\n"
                # The standard library still resolves to its own class.
                "    with pytest.raises(json.JSONDecodeError):\n"
                "        claims.decode()\n"
            ),
        })
        self.assertFalse(marker.exists())

    def test_a_cached_stand_in_gains_the_path_read_later(self):
        # A factory-made class has no importable qualified name, so the
        # stand-in built when it is first raised has no path. Reading the
        # alias later supplies one; the same class keeps working.
        self.write("made.py", (
            "def factory():\n"
            "    class Error(Exception):\n"
            "        code = 5\n"
            "    return Error\n"
            "Error = factory()\n"
            "def boom():\n"
            "    raise Error('made')\n"
            "def is_error(cls):\n"
            "    return cls is Error\n"))
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "import made\n"
            "def test_alias_after_raise():\n"
            "    with pytest.raises(Exception, match='made') as info:\n"
            "        made.boom()\n"
            "    cls = made.Error\n"
            "    assert type(info.value) is cls\n"
            "    assert cls.code == 5\n"
            "    assert made.is_error(cls)\n"
        )})

    def test_threads_share_one_stand_in_per_class(self):
        # Exception classes are rebuilt outside the request lock; two
        # threads missing the cache at once must still end up with one
        # class, or a later raise fails to match the other's.
        self.write("many.py", (
            "NAMES = ['E%d' % index for index in range(40)]\n"
            "for _name in NAMES:\n"
            "    globals()[_name] = type(_name, (Exception,), {})\n"
            "def boom(index):\n"
            "    raise globals()['E%d' % index](index)\n"))
        self.assertPasses({"test_hidden.py": (
            "import threading\n"
            "import time\n"
            "import many\n"
            # White-box: widen the window between the cache miss and the
            # publication, by slowing the bootstrap's stand-in metaclass.
            "BOOT = type(many.NAMES).__getattr__.__globals__\n"
            "class Slow(BOOT['RemoteExceptionMeta']):\n"
            "    def __new__(mcls, *args):\n"
            "        time.sleep(0.002)\n"
            "        return super().__new__(mcls, *args)\n"
            "def test_one_class(monkeypatch):\n"
            "    monkeypatch.setitem(BOOT, 'RemoteExceptionMeta', Slow)\n"
            "    seen = {}\n"
            "    barrier = threading.Barrier(8)\n"
            "    def work():\n"
            "        barrier.wait()\n"
            "        for index in range(40):\n"
            "            try:\n"
            "                many.boom(index)\n"
            "            except Exception as exc:\n"
            "                seen.setdefault(index, set()).add(type(exc))\n"
            "    threads = [threading.Thread(target=work) for _ in range(8)]\n"
            "    for thread in threads:\n"
            "        thread.start()\n"
            "    for thread in threads:\n"
            "        thread.join()\n"
            "    assert len(seen) == 40\n"
            "    assert all(len(kinds) == 1 for kinds in seen.values())\n"
        )})

    SKIPPING = (
        "import unittest\n"
        "class Mine(unittest.SkipTest):\n"
        "    pass\n"
        "def plain():\n"
        "    raise unittest.SkipTest('not graded')\n"
        "def derived():\n"
        "    raise Mine('not graded')\n"
        "SkipAlias = unittest.SkipTest\n")

    def test_a_submission_cannot_turn_a_failure_into_a_skip(self):
        # pytest reports unittest.SkipTest raised anywhere in a test as a
        # skip, and an all-skipped run exits 0. Neither SkipTest nor a
        # subclass may cross as the evaluator's own class.
        self.write("skipper.py", self.SKIPPING)
        result = self.run_split({"test_hidden.py": (
            "import unittest\n"
            "import pytest\n"
            "import skipper\n"
            "@pytest.mark.parametrize('name', ['plain', 'derived'])\n"
            "def test_answer(name):\n"
            "    assert getattr(skipper, name)() == 42\n"
        )})
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("2 failed", result.stdout)
        self.assertNotIn("skipped", result.stdout)

    def test_skip_exceptions_cross_as_ordinary_errors(self):
        self.write("skipper.py", self.SKIPPING)
        self.assertPasses({"test_hidden.py": (
            "import unittest\n"
            "import pytest\n"
            "import skipper\n"
            "@pytest.mark.parametrize('name', ['plain', 'derived'])\n"
            "def test_raises_but_not_as_skip(name):\n"
            "    with pytest.raises(Exception) as info:\n"
            "        getattr(skipper, name)()\n"
            "    assert not isinstance(info.value, unittest.SkipTest)\n"
            "    assert 'not graded' in str(info.value)\n"
            "def test_alias_is_not_the_evaluator_class():\n"
            "    assert skipper.SkipAlias is not unittest.SkipTest\n"
        )})


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitSourceLayoutTests(SplitHarness):
    def test_src_layout_packages_are_importable(self):
        # cachetools keeps its package under src/; every task failed with
        # "No module named 'cachetools'".
        self.write("src/cachekit/__init__.py", (
            "from .keys import hashkey\n"
            "class Cache(dict):\n"
            "    pass\n"))
        self.write("src/cachekit/keys.py",
                   "def hashkey(*args):\n    return tuple(args)\n")
        self.write("setup.py", "raise SystemExit('never imported')\n")
        self.assertPasses({"test_hidden.py": (
            "import cachekit\n"
            "from cachekit.keys import hashkey\n"
            "def test_src():\n"
            "    assert cachekit.hashkey(1, 2) == (1, 2)\n"
            "    assert hashkey('a') == ('a',)\n"
            "    assert len(cachekit.Cache(a=1)) == 1\n"
        )})

    def test_the_workspace_root_shadows_src_as_in_the_worker(self):
        self.write("where.py", "WHERE = 'root'\n")
        self.write("src/where.py", "WHERE = 'src'\n")
        self.write("data/README", "not a package\n")
        self.write("src/data/__init__.py", "WHERE = 'src package'\n")
        self.assertPasses({"test_hidden.py": (
            "import where, data\n"
            "def test_order():\n"
            "    assert where.WHERE == 'root'\n"
            # A namespace directory at the root does not hide a regular
            # package under src/, as in the worker's import system.
            "    assert data.WHERE == 'src package'\n"
        )})

    def test_a_namespace_package_spans_the_root_and_src(self):
        # No acme/__init__.py: the worker's acme is a namespace package
        # over <ws>/acme and <ws>/src/acme, in that order, and the
        # evaluator must find its submodules in both.
        self.write("acme/rootmod.py", "WHERE = 'root'\n")
        self.write("acme/both.py", "WHERE = 'root'\n")
        self.write("src/acme/both.py", "WHERE = 'src'\n")
        self.write("src/acme/srcmod.py", "WHERE = 'src'\n")
        # A regular package still wins over a namespace directory, and
        # its own directory is then the only place its submodules live.
        self.write("acme/sub/stray.py", "WHERE = 'root namespace'\n")
        self.write("src/acme/sub/__init__.py", "WHERE = 'src package'\n")
        self.write("src/acme/sub/inner.py", "WHERE = 'src inner'\n")
        self.write("acme/deep/ns/one.py", "WHERE = 'root deep'\n")
        self.write("src/acme/deep/ns/two.py", "WHERE = 'src deep'\n")
        self.assertPasses({"test_hidden.py": (
            "import importlib\n"
            "import pytest\n"
            "import acme.rootmod\n"
            "import acme.srcmod\n"
            "import acme.both\n"
            "from acme import sub\n"
            "from acme.sub import inner\n"
            "from acme.deep.ns import one, two\n"
            "def test_namespace():\n"
            "    assert acme.rootmod.WHERE == 'root'\n"
            "    assert acme.srcmod.WHERE == 'src'\n"
            "    assert acme.both.WHERE == 'root'\n"
            "    assert sub.WHERE == 'src package'\n"
            "    assert inner.WHERE == 'src inner'\n"
            "    assert (one.WHERE, two.WHERE) == ('root deep', 'src deep')\n"
            "    with pytest.raises(ImportError):\n"
            "        importlib.import_module('acme.sub.stray')\n"
        )})

    def test_a_src_package_is_not_a_source_root(self):
        self.write("src/__init__.py", "")
        self.write("src/thing.py", "VALUE = 3\n")
        self.assertPasses({"test_hidden.py": (
            "import pytest\n"
            "from src import thing\n"
            "def test_package():\n"
            "    assert thing.VALUE == 3\n"
            "    with pytest.raises(ImportError):\n"
            "        import thing as missing  # noqa: F401\n"
        )})

    def test_src_cannot_shadow_trusted_modules(self):
        marker = self.root / "SHADOWED"
        for name in ("decimal", "helper", "pytest", "sitecustomize"):
            self.write(f"src/{name}.py", (
                f"open({str(marker)!r}, 'a').write({name!r})\n"
                "WHO = 'workspace'\n"))
        self.assertPasses({
            "helper.py": "WHO = 'private'\n",
            "test_hidden.py": (
                "import decimal\n"
                "import helper\n"
                "def test_trusted():\n"
                "    assert helper.WHO == 'private'\n"
                "    assert type(decimal.Decimal(1)).__module__ == 'decimal'\n"
            ),
        })
        self.assertFalse(marker.exists())

    def test_the_workspace_is_never_on_the_evaluator_import_path(self):
        # Standard-library names the run has not imported yet when the
        # test starts: a workspace copy on the evaluator's sys.path (as
        # '', '.', the cwd or the workspace itself) would be executed by
        # the import below, in the process that holds the tests.
        marker = self.root / "WORKSPACE_STDLIB_RAN"
        names = ("colorsys", "wave", "fractions", "graphlib")
        for name in names:
            for relative in (f"{name}.py", f"src/{name}.py"):
                self.write(relative, (
                    f"open({str(marker)!r}, 'a').write({relative!r})\n"
                    "WHO = 'workspace'\n"))
        self.write("pkg/__init__.py", "def f():\n    return 1\n")
        self.assertPasses({"test_hidden.py": (
            "import os\n"
            "import sys\n"
            f"WORKSPACE = os.path.realpath({str(self.workspace)!r})\n"
            "def inside(entry):\n"
            "    path = os.path.realpath(entry)\n"
            "    return path == WORKSPACE or path.startswith("
            "os.path.join(WORKSPACE, ''))\n"
            "def test_stdlib_resolves_outside_the_workspace():\n"
            "    assert '' not in sys.path\n"
            "    assert [entry for entry in sys.path\n"
            "            if isinstance(entry, str) and inside(entry)] == []\n"
            + "".join(f"    import {name}\n" for name in names)
            + "".join(
                f"    assert not hasattr({name}, 'WHO')\n"
                f"    assert not inside({name}.__file__)\n" for name in names)
            + "    import pkg\n"
            "    assert type(pkg).__name__ == 'ProxyModule'\n"
            "    assert pkg.f() == 1\n"
            "    assert [entry for entry in sys.path\n"
            "            if isinstance(entry, str) and inside(entry)] == []\n"
        )})
        self.assertFalse(marker.exists())


@unittest.skipUnless(os.name == "posix", "socketpair transport")
class SplitSupportFileTests(SplitHarness):
    """conftest.py, package __init__.py and helpers beside the test.

    cachetools' tests do ``from . import CacheTestMixin`` and jmespath's
    ``from tests import unittest``. The importer registers those files as
    further private material at their repository paths; the evaluator
    must import them from there, never the workspace's copies.
    """

    def setUp(self):
        super().setUp()
        self.marker = self.root / "WORKSPACE_TEST_CODE_RAN"
        self.write("cachekit.py", (
            "class Cache:\n"
            "    def __init__(self, maxsize):\n"
            "        self.maxsize = maxsize\n"))
        # The submission's own copies of the test package: never run by
        # the evaluator, whatever they contain.
        poison = (f"open({str(self.marker)!r}, 'a').write(__name__)\n"
                  "WHO = 'workspace'\n"
                  "class CacheTestMixin:\n"
                  "    pass\n")
        for name in ("tests/__init__.py", "tests/helpers.py",
                     "tests/conftest.py", "conftest.py", "helpers.py",
                     "sibling.py"):
            self.write(name, poison)

    def test_a_test_package_imports_its_private_helpers(self):
        self.assertPasses({
            "conftest.py": (
                "import pytest\n"
                "@pytest.fixture\n"
                "def root_value():\n"
                "    return 'root conftest'\n"),
            "tests/__init__.py": (
                "import cachekit\n"
                "WHO = 'private'\n"
                "class CacheTestMixin:\n"
                "    def test_maxsize(self):\n"
                "        assert self.Cache(maxsize=3).maxsize == 3\n"),
            "tests/conftest.py": (
                "import pytest\n"
                "@pytest.fixture\n"
                "def private_value():\n"
                "    return 'tests conftest'\n"),
            "tests/helpers.py": "WHO = 'private helper'\n",
            "tests/test_cache.py": (
                "import unittest\n"
                "import cachekit\n"
                "from . import CacheTestMixin, WHO\n"
                "from .helpers import WHO as HELPER\n"
                "from tests import helpers\n"
                "class CacheTest(unittest.TestCase, CacheTestMixin):\n"
                "    Cache = cachekit.Cache\n"
                "def test_sources(root_value, private_value):\n"
                "    assert WHO == 'private' and HELPER == 'private helper'\n"
                "    assert helpers.WHO == 'private helper'\n"
                "    assert root_value == 'root conftest'\n"
                "    assert private_value == 'tests conftest'\n"
                "    assert __name__ == 'tests.test_cache'\n"),
        })
        self.assertFalse(self.marker.exists())

    def test_a_plain_test_directory_imports_its_private_siblings(self):
        # Not a package: pytest puts the test's own directory on sys.path
        # while it collects, after the bootstrap started.
        self.assertPasses({
            "tests/sibling.py": "WHO = 'private sibling'\n",
            "tests/test_plain.py": (
                "import sibling\n"
                "import cachekit\n"
                "def test_sibling():\n"
                "    assert sibling.WHO == 'private sibling'\n"
                "    assert cachekit.Cache(2).maxsize == 2\n"),
        })
        self.assertFalse(self.marker.exists())

    def test_the_workspace_on_the_evaluator_path_is_still_not_trusted(self):
        # Trust follows sys.path as it changes, so an entry naming the
        # workspace (directly, through ``.``, or through a link) must
        # never make a workspace module evaluator material.
        link = self.root / "link"
        link.symlink_to(self.workspace)
        self.assertPasses({"test_path.py": (
            "import sys\n"
            f"sys.path[:0] = [{str(link)!r}, {str(self.workspace)!r}, '.']\n"
            "import helpers\n"
            "def test_proxied():\n"
            # The worker imports it (and so writes the marker); the
            # evaluator only holds the proxy.
            "    assert type(helpers).__name__ == 'ProxyModule'\n"
            "    assert helpers.WHO == 'workspace'\n")})

    def test_a_trusted_name_loads_from_the_trusted_path_only(self):
        # The workspace first on sys.path, and names it shares with the
        # evaluator: a private helper and standard-library modules the
        # run has not imported yet. Only the evaluator's copies may load,
        # through the finder and through any later lookup on sys.path.
        shadow = self.root / "WORKSPACE_SHADOW_RAN"
        for name in ("shared", "netrc", "tabnanny", "pyclbr"):
            self.write(f"{name}.py", (
                f"open({str(shadow)!r}, 'a').write({name!r})\n"
                "WHO = 'workspace'\n"))
        self.write("only_here.py", "WHO = 'workspace only'\n")
        self.assertPasses({
            "tests/shared.py": "WHO = 'private'\n",
            "tests/test_shadow.py": (
                "import importlib.machinery\n"
                "import os\n"
                "import sys\n"
                f"WORKSPACE = os.path.realpath({str(self.workspace)!r})\n"
                "sys.path[:0] = [WORKSPACE, '.', '']\n"
                "import shared\n"
                "import netrc, tabnanny, pyclbr\n"
                "import only_here\n"
                "def outside(module):\n"
                "    return not os.path.realpath(module.__file__).startswith("
                "WORKSPACE + os.sep)\n"
                "def test_trusted_copies():\n"
                "    assert shared.WHO == 'private' and outside(shared)\n"
                "    for module in (netrc, tabnanny, pyclbr):\n"
                "        assert not hasattr(module, 'WHO') and outside(module)\n"
                "    assert type(only_here).__name__ == 'ProxyModule'\n"
                "    assert only_here.WHO == 'workspace only'\n"
                "def test_no_later_lookup_sees_the_workspace():\n"
                "    for name in ('shared', 'netrc', 'only_here'):\n"
                "        spec = importlib.machinery.PathFinder.find_spec(\n"
                "            name, sys.path)\n"
                "        assert spec is None or not os.path.realpath(\n"
                "            spec.origin).startswith(WORKSPACE + os.sep), name\n"),
        })
        self.assertFalse(shadow.exists())

    def test_data_files_are_read_beside_the_private_test(self):
        # jmespath: tests/compliance/*.json through dirname(__file__).
        # They are staged at their repository paths in the private
        # directory; the workspace's copies are never what the test reads.
        self.write("tests/compliance/basic.json", "[[1, 1]]")
        self.write("tests/compliance/extra.json", "[[0, 1]]")
        self.assertPasses({
            "tests/__init__.py": "",
            "tests/compliance/basic.json": "[[2, 2]]",
            "tests/test_compliance.py": (
                "import glob\n"
                "import json\n"
                "import os\n"
                "import cachekit\n"
                "HERE = os.path.dirname(os.path.abspath(__file__))\n"
                "CASES = os.path.join(HERE, 'compliance')\n"
                "def test_cases():\n"
                "    names = glob.glob(os.path.join(CASES, '*.json'))\n"
                "    assert [os.path.basename(n) for n in names] =="
                " ['basic.json']\n"
                "    for size, expected in json.load(open(names[0])):\n"
                "        assert cachekit.Cache(size).maxsize == expected\n"),
        })
        self.assertFalse(self.marker.exists())

    def test_without_support_files_the_workspace_package_stays_proxied(self):
        # A test package the evaluator did not register is the
        # submission's: it is reached through the proxy, in the worker.
        result = self.run_split({"test_alone.py": (
            "import tests\n"
            "def test_proxied():\n"
            "    assert type(tests).__name__ == 'ProxyModule'\n"
            "    assert tests.WHO == 'workspace'\n")})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
