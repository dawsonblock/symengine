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


if __name__ == "__main__":
    unittest.main()
