"""Process-split custody for evaluator-private acceptance material.

The Gate 2 repair moved registered acceptance files out of the graded
workspace, but the test runner and the submitted code still shared one
process and one OS principal: a submission could read the tests it was
graded against. This module removes that read path.

The acceptance runner (pytest) never imports submitted code. A meta-path
finder replaces every top-level module the workspace provides with a proxy
whose attribute reads and calls are marshalled over a Unix socket to a
worker process. The worker runs under a separate principal and cannot read
the private directory, so a submission that enumerates that directory from
inside the worker is denied by the kernel rather than by a Python check.

The boundary is factual, and the receipt says which one held:

* ``split:custody:seatbelt_read_denied`` — local backend. The worker is a
  separate process confined by seatbelt with
  ``(deny file-read* (subpath <private>))``. It shares the user's UID, so
  the file-read denial is the boundary.
* ``split:custody:separate_uid`` — Docker backend. The worker runs under a
  second numeric UID through ``docker exec --user`` and the private
  directory is mode 0700 owned by the evaluator UID.

Only top-level modules are proxied, and never one the evaluator's own
environment provides (standard library, installed packages, modules
beside the tests): a workspace cannot shadow a library the tests import,
nor the test's own package (``from tests import helpers``). "Beside the
tests" is read from ``sys.path`` at each import, without any entry in
the workspace, because pytest adds the test's root directory in the
private material only while it collects. A trusted name is imported
from the spec found on that filtered path, by the finder itself, and a
path-entry hook makes every ``sys.path`` entry in the workspace find
nothing: whatever puts the workspace on ``sys.path``, no later finder
(pytest's assertion rewriter included) loads a workspace file in the
evaluator. A standard-library name the evaluator lacks is missing, never
the workspace's.
They are found in the workspace root and, for a src-layout project, in
``<workspace>/src`` (unless ``src`` is itself a package), in that order
in both processes, with namespace packages spanning both.

What crosses the socket. The codec is JSON over a closed type set:
submission-produced bytes are never unpickled or evaluated in the
evaluator process, and no class object or callable crosses except as a
handle.

* Data: ``None``, ``bool``, ``int``, ``float``, ``str``, ``bytes``, and
  ``list``, ``tuple``, ``set``, ``frozenset`` and ``dict`` of data
  (mapping keys and set elements must decode to something hashable),
  bounded by ``MAX_ITEMS`` per container, ``MAX_DEPTH`` nesting and
  ``MAX_FRAME_BYTES`` per frame. Call arguments may also be slices.
* Anything else stays in the worker. An attribute read refers to it by
  path, a call or protocol result by handle (``Ref``/``SplitRef``).
* Submission state stays in the worker. A read of a *mutable* container
  (``list``, ``dict``, ``set``, ``bytearray``, ``deque`` and their
  subclasses) is a handle to the worker's own object, never a copy:
  an attribute read of a module or object (``pkg.REGISTRY``,
  ``obj.items``), an item read with a non-slice key (``pkg.TABLE["a"]``),
  an in-place operator that returns its operand (``ref += [x]``) and
  what ``__enter__`` returns (``with ref as log``).
  ``pkg.UNCOUNTABLES.add(x)`` therefore changes the set the submission
  reads, and ``len``/``in``/iteration/``==``/indexing on the handle go
  through the ``dunder`` op. One handle per object, so ``old =
  pkg.LIST; pkg.reset()`` keeps ``old`` on the old list, as in one
  process. Immutable values (``str``, numbers, ``bytes``, ``tuple``,
  ``frozenset``, ``None``) still cross as data, and so do call results,
  slices and iteration items: a function returning a fresh list is the
  common case, and a test expects ``type(f()) is list``. A function
  that returns its module's internal list hands back a copy.
  ``copy.copy``/``copy.deepcopy`` of a handle copy in the worker, so a
  copied container arrives as data.
* Protocols on a handle go through one ``dunder`` op whose names come
  from a fixed table in the worker: ``len``, ``in``, item get/set/delete,
  iteration, ``reversed``, ``bool``/``str``/``repr``/``hash``/``format``,
  ``int``/``float``/``index``/``round``, comparisons, arithmetic
  (plain, reflected and in-place, and three-argument ``pow``), unary
  operators, ``with`` blocks, ``copy.copy``/``copy.deepcopy``,
  ``isinstance``/``issubclass`` against a worker class, and attribute
  assignment and deletion. The worker refuses every other name, and no
  attribute path may name a dunder outside ``__name__``,
  ``__qualname__``, ``__version__`` and ``__all__``. Iteration streams:
  the iterator stays in the worker and each ``next`` is one round trip
  ending in ``StopIteration``. Operators answer ``NotImplemented`` for a
  local operand with no wire form, so comparisons with plain data work
  in both directions.
* Exceptions cross as data, never as classes. The worker reports the
  class chain (module and qualified name of each MRO entry, with base
  indices), a bounded message and, when they encode, the exception's
  args, which the evaluator uses to build the local exception. Each
  chain entry maps to a builtin exception, to one of a fixed set of
  reviewed standard-library exceptions (``REVIEWED_STDLIB_EXCEPTIONS``,
  recorded by identity when the bootstrap starts, before any test code
  runs, and looked up by the reported name without walking anything),
  or to a local stand-in class cached by (module, qualname). Every other
  class, including those of installed packages, of the tests' own
  helpers, and aliases or spoofs of standard-library names, gets a
  stand-in: the worker chooses the name and the arguments, so no hook of
  theirs runs for it. A worker
  exception class read through the proxy is that same stand-in, so
  ``pytest.raises(pkg.Error)`` and ``except pkg.Base`` match what the
  worker raises. Every stand-in derives from ``Exception``: the
  evaluator never raises ``BaseException``, ``SystemExit`` or
  ``KeyboardInterrupt`` for the worker, whatever the worker reports.
  Nor does a name resolve to a class of the test runner's own modules
  (``unittest``, ``pytest``, ``pluggy``, ``doctest``), and no
  ``unittest.SkipTest`` (or subclass) crosses: pytest reads that as a
  skip wherever it is raised, so a submission could otherwise turn a
  failing hidden test into an all-skipped run that exits 0. The
  raised object stays in the worker; the local exception carries its
  message and reads further attributes through its handle.

Known limits, each because it would need code or class objects to cross:

* ``type(obj)`` of a worker object is ``Ref``; ``obj.__class__``,
  ``__dict__``, ``vars()``, ``dir()``, pickling and ``copy`` are not
  forwarded. A test cannot subclass a worker class, and a non-exception
  worker class is a handle, not a type (``isinstance`` still works).
* Local callables, classes and arbitrary objects cannot be passed to the
  submission (callbacks, ``key=`` functions, test-defined subclasses).
* Call results are copied: mutating a list a function returned does not
  change the worker's, even when the function returned its internal
  state. A handle to a container is not an instance of it
  (``isinstance(pkg.REGISTRY, set)`` is false), and a mutable container
  nested in an immutable one (``pkg.PAIR[0]`` of a tuple) is a copy.
  ``monkeypatch.setattr(pkg, ...)`` changes only the local proxy.
* Stand-ins collapse worker classes with the same module and qualified
  name. An exception the test constructs itself is local: it is not a
  call argument, and reaches a worker ``__exit__`` only as a builtin
  name and its args. A builtin raised in the worker is
  rebuilt from its args, or from its message when the args do not
  reproduce it (``OSError.filename``); ``__cause__`` and the worker
  traceback do not cross. A stand-in based on a builtin or
  standard-library class runs that class's own ``__init_subclass__``
  and metaclass, which are evaluator-environment code, never submission
  code. An exception of a test helper or installed package raised in
  the worker is a stand-in, not that class (``pytest.raises`` of it
  does not match).
* No async protocols, and every protocol call is one round trip.
  ``MAX_HANDLES`` bounds the worker's *live* handles. The bootstrap
  releases a handle when its last local holder (``Ref``, exception or
  stand-in class) is collected: each handle has one lease, which counts
  how often the worker handed it out, and its finalizer queues
  ``[handle, count]`` for the next request to carry (``"release"``). The
  worker drops a handle once every hand-out is released and ignores any
  malformed, unknown or non-``#n`` entry. A handle a test keeps alive
  stays held, as does one behind a cached stand-in class or an object
  the collector has not reached yet, and the host-side
  :class:`SplitClient` releases nothing. Requests from several test
  threads are serialized and the worker serves one at a time, so a race
  a test provokes with threads (jmespath's cache-eviction test) is not
  reproduced in the submission.
* Only files the evaluator registered are private material. The study
  importer registers, beside the test and at their repository paths, its
  ``conftest.py`` files, the ``__init__.py`` of each package up to its
  test root, the helper modules it imports from its own test package and
  the data files it names by a string-literal path (a file, or a test
  subdirectory such as jmespath's ``tests/compliance``), all from the
  fix commit (see docs/v3/SECURITY_BOUNDARIES_V3_3.md). They run, or are
  read, in the evaluator like the test. A data file the test finds only
  by listing its own directory, never by name, is not registered, nor is
  a data directory over ``MAX_SUPPORT_FILES``. A test that imports its
  helper through the source package (``calc2.tests.helper``) gets the
  workspace's copy through the proxy.

The host-side :class:`SplitClient` forwards the same data and protocols
but maps worker exceptions only to builtins (else :class:`RemoteError`).
"""
from __future__ import annotations

import base64
import builtins
import json
import re
import socket
import threading
from pathlib import PurePath
from typing import Any, Mapping

MAX_FRAME_BYTES = 1 << 20
MAX_DEPTH = 32
MAX_ITEMS = 10_000

SPLIT_BOOTSTRAP_NAME = "_sis_split_bootstrap.py"
SPLIT_SOCKET_NAME = "split.sock"
#: Evaluator-owned pytest configuration staged beside the material. Split
#: custody pins pytest to it, so a workspace ``pytest.ini`` cannot inject a
#: plugin into the process that holds the tests.
SPLIT_INI_NAME = "pytest.ini"
SPLIT_INI_SOURCE = b"[pytest]\n"
#: Exit statuses the bootstrap uses for a harness failure. They are never a
#: test result; the executors map them to ``sandbox:`` markers.
SPLIT_LOST_EXIT = 75
SPLIT_UNAVAILABLE_EXIT = 76

PYTHON_COMMAND = re.compile(
    r"^python(?:\d+(?:\.\d+)?)?(?:\.exe)?$", re.IGNORECASE)

#: Security-error markers. ``sandbox:`` markers classify as a sandbox
#: failure, never as a pass.
MARKER_SPLIT = "evaluation:process_split"
MARKER_SEATBELT = "split:custody:seatbelt_read_denied"
MARKER_SEPARATE_UID = "split:custody:separate_uid"
MARKER_WORKER_LOST = "sandbox:split_worker_lost"
MARKER_UNAVAILABLE = "sandbox:split_custody_unavailable"


def is_python_command(argv: tuple[str, ...] | list[str]) -> bool:
    """True when ``argv[0]`` names a Python interpreter."""
    return bool(argv) and bool(
        PYTHON_COMMAND.fullmatch(PurePath(argv[0]).name))


def split_failure_marker(exit_status: int | None) -> str | None:
    """Map a bootstrap harness-failure exit status to its receipt marker."""
    if exit_status == SPLIT_LOST_EXIT:
        return MARKER_WORKER_LOST
    if exit_status == SPLIT_UNAVAILABLE_EXIT:
        return MARKER_UNAVAILABLE
    return None


class SplitProtocolError(RuntimeError):
    """A split request or response violated the closed wire protocol."""


class SplitArgumentError(SplitProtocolError):
    """A local value has no form on the wire."""


class RemoteError(RuntimeError):
    """A worker raised an exception that has no safe local counterpart."""


def _decode(payload: Any, depth: int = 0) -> Any:
    if depth > MAX_DEPTH:
        raise SplitProtocolError("payload nesting exceeds the bound")
    if not isinstance(payload, dict):
        raise SplitProtocolError("payload must be an object")
    kind = payload.get("t")
    if kind == "none":
        return None
    if kind == "bool":
        return bool(payload.get("v"))
    if kind == "int":
        value = payload.get("v")
        if type(value) is not int:
            raise SplitProtocolError("int payload must be an integer")
        return value
    if kind == "float":
        value = payload.get("v")
        if type(value) not in (int, float):
            raise SplitProtocolError("float payload must be a number")
        return float(value)
    if kind == "str":
        value = payload.get("v")
        if not isinstance(value, str):
            raise SplitProtocolError("str payload must be text")
        return value
    if kind == "bytes":
        value = payload.get("v")
        if not isinstance(value, str):
            raise SplitProtocolError("bytes payload must be text")
        return base64.b64decode(value.encode("ascii"), validate=True)
    if kind in ("list", "tuple"):
        items = payload.get("v")
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise SplitProtocolError("sequence payload is out of bounds")
        decoded = [_decode(item, depth + 1) for item in items]
        return decoded if kind == "list" else tuple(decoded)
    if kind in ("set", "frozenset"):
        items = payload.get("v")
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise SplitProtocolError("set payload is out of bounds")
        decoded = [_decode(item, depth + 1) for item in items]
        try:
            return set(decoded) if kind == "set" else frozenset(decoded)
        except TypeError as exc:
            raise SplitProtocolError(
                "set payload has an unhashable element") from exc
    if kind == "map":
        items = payload.get("v")
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise SplitProtocolError("mapping payload is out of bounds")
        mapping = {}
        for item in items:
            if not isinstance(item, list) or len(item) != 2:
                raise SplitProtocolError("mapping entries must be pairs")
            key = _decode(item[0], depth + 1)
            value = _decode(item[1], depth + 1)
            try:
                mapping[key] = value
            except TypeError as exc:
                raise SplitProtocolError(
                    "mapping payload has an unhashable key") from exc
        return mapping
    if kind == "dict":
        items = payload.get("v")
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise SplitProtocolError("mapping payload is out of bounds")
        result = {}
        for item in items:
            if (not isinstance(item, list) or len(item) != 2
                    or not isinstance(item[0], str)):
                raise SplitProtocolError("mapping entries must be pairs")
            result[item[0]] = _decode(item[1], depth + 1)
        return result
    raise SplitProtocolError(f"unknown payload type: {kind!r}")


#: Builtin exceptions recorded at import, so a later ``builtins.X = Y``
#: cannot choose what a worker-reported name builds on the host.
_HOST_BUILTIN_EXCEPTIONS = {
    name: value for name, value in vars(builtins).items()
    if isinstance(value, type) and issubclass(value, Exception)}


def _raise_remote(error: Any) -> None:
    if not isinstance(error, dict):
        raise RemoteError("worker reported an untyped failure")
    name = error.get("type")
    message = error.get("message")
    if not isinstance(message, str):
        message = ""
    if isinstance(name, str):
        candidate = _HOST_BUILTIN_EXCEPTIONS.get(name)
        # Only ordinary exceptions cross the boundary: a worker must not be
        # able to raise SystemExit or KeyboardInterrupt in the evaluator.
        if (isinstance(candidate, type)
                and issubclass(candidate, Exception)):
            if candidate is StopIteration:
                # A generator's return value keeps its type
                # (``StopIteration.value``), and none stays None.
                args = error.get("args")
                try:
                    decoded = _decode(args) if args is not None else None
                except (SplitProtocolError, ValueError):
                    decoded = None
                if isinstance(decoded, tuple):
                    raise StopIteration(*decoded)
            raise candidate(message)
    raise RemoteError(f"{name}: {message}")


class SplitRef:
    """A reference to an object that stayed in the worker process."""

    __slots__ = ("_client", "_path")

    def __init__(self, client: "SplitClient", path: list[str]) -> None:
        self._client = client
        self._path = list(path)

    def __getattr__(self, name: str) -> Any:
        if _is_dunder(name) and name not in READABLE_DUNDERS:
            raise AttributeError(name)
        return self._client.get(self._path + [name])

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._client.call(self._path, args, kwargs)

    def __iter__(self) -> "SplitRef":
        # Iteration streams through a worker-held iterator; see Ref.
        iterator = self._client.dunder(self._path, "__iter__", ())
        if not isinstance(iterator, SplitRef):
            raise SplitProtocolError("iterator did not stay in the worker")
        return iterator

    def __setitem__(self, key: Any, value: Any) -> None:
        self._client.dunder(self._path, "__setitem__", (key, value))

    def __round__(self, ndigits: int | None = None) -> Any:
        return self._client.dunder(
            self._path, "__round__", () if ndigits is None else (ndigits,))

    def __instancecheck__(self, instance: Any) -> bool:
        try:
            return bool(self._client.dunder(
                self._path, "__instancecheck__", (instance,)))
        except SplitArgumentError:
            return False

    def __subclasscheck__(self, subclass: Any) -> bool:
        try:
            return bool(self._client.dunder(
                self._path, "__subclasscheck__", (subclass,)))
        except SplitArgumentError:
            return False

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        payload = None
        if exc is not None:
            name = type(exc).__name__
            if getattr(builtins, name, None) is not type(exc):
                name = "Exception"
            payload = (name, tuple(exc.args))
            try:
                _host_encode(payload)
            except SplitArgumentError:
                payload = (name, (str(exc),))
        return bool(self._client.dunder(self._path, "__exit__", (payload,)))

    def __copy__(self) -> Any:
        return self._client.dunder(self._path, "__copy__", ())

    def __deepcopy__(self, memo: Any) -> Any:
        return self._client.dunder(self._path, "__deepcopy__", ())


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def _host_protocol(name: str, operator: bool):
    def method(self: SplitRef, *args: Any) -> Any:
        try:
            return self._client.dunder(self._path, name, args)
        except SplitArgumentError:
            if operator:
                return NotImplemented
            raise
    method.__name__ = method.__qualname__ = name
    return method


#: Dunder attributes a caller may read from a worker object: metadata,
#: never a way into the object model. The worker holds the same set.
READABLE_DUNDERS = frozenset({"__name__", "__qualname__", "__version__",
                              "__all__"})
_ARITHMETIC = ("add", "sub", "mul", "truediv", "floordiv", "mod", "pow",
               "matmul", "and", "or", "xor", "lshift", "rshift")
#: Protocols forwarded through the worker's ``dunder`` op, which refuses
#: any name outside its own fixed table. Operators answer NotImplemented
#: for an operand with no wire form, so Python tries the reflected method.
FORWARDED_PROTOCOLS = frozenset({
    "__len__", "__contains__", "__getitem__", "__delitem__", "__next__",
    "__reversed__", "__bool__", "__str__", "__repr__", "__hash__",
    "__int__", "__float__", "__index__", "__neg__", "__pos__", "__abs__",
    "__invert__", "__format__", "__enter__",
})
FORWARDED_OPERATORS = frozenset(
    {"__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
     "__divmod__", "__rdivmod__"}
    | {f"__{item}__" for item in _ARITHMETIC}
    | {f"__r{item}__" for item in _ARITHMETIC}
    | {f"__i{item}__" for item in _ARITHMETIC})
for _name in FORWARDED_PROTOCOLS:
    setattr(SplitRef, _name, _host_protocol(_name, False))
for _name in FORWARDED_OPERATORS:
    setattr(SplitRef, _name, _host_protocol(_name, True))
del _name


class SplitClient:
    """Evaluator-side half of the split protocol."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._stream = sock.makefile("rwb")
        # One request and its response at a time, whatever the caller's
        # threads do.
        self._lock = threading.Lock()

    def close(self) -> None:
        for resource in (self._stream, self._sock):
            try:
                resource.close()
            except OSError:
                pass

    def request(self, payload: Mapping[str, Any]) -> dict:
        data = json.dumps(dict(payload)).encode("utf-8")
        if len(data) > MAX_FRAME_BYTES:
            raise SplitProtocolError("request frame exceeds the bound")
        try:
            with self._lock:
                self._stream.write(data + b"\n")
                self._stream.flush()
                line = self._stream.readline(MAX_FRAME_BYTES + 1)
        except OSError as exc:
            raise SplitProtocolError(f"worker_transport_failed:{exc}") from exc
        if not line:
            raise SplitProtocolError("worker_closed")
        if len(line) > MAX_FRAME_BYTES:
            raise SplitProtocolError("response frame exceeds the bound")
        try:
            response = json.loads(line)
        except ValueError as exc:
            raise SplitProtocolError("response is not JSON") from exc
        if not isinstance(response, dict):
            raise SplitProtocolError("response must be an object")
        return response

    def ping(self) -> None:
        response = self.request({"op": "ping"})
        if not response.get("ok"):
            _raise_remote(response.get("error"))

    def get(self, path: list[str]) -> Any:
        response = self.request({"op": "get", "path": list(path)})
        if not response.get("ok"):
            _raise_remote(response.get("error"))
        value = response.get("value")
        if isinstance(value, dict) and value.get("t") == "ref":
            if value.get("handle") is not None:
                # A mutable container: the worker's own object.
                return SplitRef(self, [_handle(value)])
            return SplitRef(self, path)
        return _decode(value)

    def call(self, path: list[str], args, kwargs) -> Any:
        response = self.request({
            "op": "call",
            "path": list(path),
            "args": [_host_encode(item) for item in args],
            "kwargs": {key: _host_encode(item) for key, item in kwargs.items()},
        })
        return self._result(response)

    def dunder(self, path: list[str], name: str, args) -> Any:
        """Apply one allow-listed protocol to a worker object."""
        if name not in FORWARDED_PROTOCOLS | FORWARDED_OPERATORS | {
                "__iter__", "__setitem__", "__round__", "__instancecheck__",
                "__subclasscheck__", "__exit__", "__copy__", "__deepcopy__"}:
            raise SplitProtocolError(f"protocol is not forwarded: {name}")
        response = self.request({
            "op": "dunder", "path": list(path), "name": name,
            "args": [_host_encode(item) for item in args],
        })
        return self._result(response)

    def _result(self, response: dict) -> Any:
        if not response.get("ok"):
            _raise_remote(response.get("error"))
        value = response.get("value")
        if isinstance(value, dict) and value.get("t") == "ref":
            # The result stayed in the worker; refer to it by its handle,
            # never by the callable's path (that would re-call it).
            return SplitRef(self, [_handle(value)])
        return _decode(value)


def _handle(value: Mapping[str, Any]) -> str:
    handle = value.get("handle")
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise SplitProtocolError("call result reference has no handle")
    return handle


_HANDLE = re.compile(r"^#[0-9]{1,9}$")


def _host_encode(value: Any, depth: int = 0) -> dict:
    """Encode evaluator-supplied call arguments for the worker."""
    if depth > MAX_DEPTH:
        raise SplitArgumentError("argument nesting exceeds the bound")
    if value is None:
        return {"t": "none"}
    if isinstance(value, SplitRef):
        return {"t": "handle", "v": list(value._path)}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, float):
        return {"t": "float", "v": value}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (bytes, bytearray)):
        return {"t": "bytes",
                "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("argument sequence exceeds the bound")
        return {"t": "list" if isinstance(value, list) else "tuple",
                "v": [_host_encode(item, depth + 1) for item in value]}
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("argument set exceeds the bound")
        return {"t": "frozenset" if isinstance(value, frozenset) else "set",
                "v": [_host_encode(item, depth + 1) for item in value]}
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("argument mapping exceeds the bound")
        if all(isinstance(key, str) for key in value):
            return {"t": "dict",
                    "v": [[key, _host_encode(item, depth + 1)]
                          for key, item in value.items()]}
        return {"t": "map",
                "v": [[_host_encode(key, depth + 1),
                       _host_encode(item, depth + 1)]
                      for key, item in value.items()]}
    if isinstance(value, slice):
        return {"t": "slice",
                "v": [_host_encode(value.start, depth + 1),
                      _host_encode(value.stop, depth + 1),
                      _host_encode(value.step, depth + 1)]}
    raise SplitArgumentError(
        f"argument type is not transferable: {type(value).__name__}")


#: Runs as the restricted principal. It imports submitted code, so it must
#: never hold the private material directory on its readable path.
WORKER_SOURCE = r'''"""SIS split-custody worker (restricted principal)."""
import base64
import collections
import copy
import importlib
import json
import operator
import os
import socket
import sys

MAX_DEPTH = 32
MAX_ITEMS = 10000
# The bound on *live* handles: those handed out and not released yet.
MAX_HANDLES = 100000
# Handle ids are never reused, and the evaluator accepts at most nine
# digits; past that the worker keeps nothing more.
MAX_HANDLE_ID = 999999999
MAX_CLASSES = 64
MAX_MESSAGE = 8192
# The evaluator's bound on one response line, newline included.
MAX_FRAME = 1 << 20
# A response may carry, under this key, how to answer instead when its
# serialized form would exceed MAX_FRAME (a handle, not a copy). It never
# crosses the socket.
LARGE = "_sis_large"
# Call results that cannot cross the socket stay here; the evaluator
# refers to them by handle ("#<n>"), never by the callable's path.
HANDLES = {}
# How many times each live handle was handed to the evaluator and not
# released yet. A release names a handle and a count; the handle is
# dropped when its count reaches zero.
COUNTS = {}
NEXT_HANDLE = [0]
# Mutable containers. Read as an attribute or an item they stay here and
# the evaluator gets a handle, so ``pkg.REGISTRY.add(x)`` changes the
# submission's own set instead of a copy. One handle per object, by id
# (HANDLES keeps the object alive while the handle lives, and a released
# handle's entry goes with it, so a reused id never names it).
MUTABLE = (list, dict, set, bytearray, collections.deque)
SHARED = {}
# Dunder attributes the evaluator may read: plain metadata, never a way to
# reach the object model (no __class__, __dict__, __reduce__, ...).
READABLE_DUNDERS = frozenset({"__name__", "__qualname__", "__version__",
                              "__all__"})
HASHABLE_KINDS = frozenset({"none", "bool", "int", "float", "str", "bytes"})


class NotEncodable(Exception):
    pass


def decode(payload):
    kind = payload.get("t")
    if kind == "none":
        return None
    if kind == "handle":
        return resolve(payload.get("v"))
    if kind == "bool":
        return bool(payload.get("v"))
    if kind == "int":
        return int(payload.get("v"))
    if kind == "float":
        return float(payload.get("v"))
    if kind == "str":
        return payload.get("v")
    if kind == "bytes":
        return base64.b64decode(payload.get("v").encode("ascii"), validate=True)
    if kind in ("list", "tuple"):
        items = [decode(item) for item in payload.get("v") or []]
        return items if kind == "list" else tuple(items)
    if kind in ("set", "frozenset"):
        items = [decode(item) for item in payload.get("v") or []]
        return set(items) if kind == "set" else frozenset(items)
    if kind == "dict":
        return {item[0]: decode(item[1]) for item in payload.get("v") or []}
    if kind == "map":
        return {decode(item[0]): decode(item[1])
                for item in payload.get("v") or []}
    if kind == "slice":
        start, stop, step = [decode(item) for item in payload.get("v")]
        return slice(start, stop, step)
    raise ValueError("unknown payload type: %r" % (kind,))


def hashable(payload):
    # The evaluator rebuilds set elements and mapping keys from their
    # encoding, so the encoding itself must decode to something hashable.
    kind = payload.get("t")
    if kind in HASHABLE_KINDS:
        return True
    if kind in ("tuple", "frozenset"):
        return all(hashable(item) for item in payload.get("v"))
    return False


def encode(value, depth=0):
    if depth > MAX_DEPTH:
        raise NotEncodable("depth")
    if value is None:
        return {"t": "none"}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, float):
        return {"t": "float", "v": value}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (bytes, bytearray)):
        return {"t": "bytes",
                "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise NotEncodable("sequence")
        return {"t": "list" if isinstance(value, list) else "tuple",
                "v": [encode(item, depth + 1) for item in value]}
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_ITEMS:
            raise NotEncodable("set")
        items = [encode(item, depth + 1) for item in value]
        if not all(hashable(item) for item in items):
            raise NotEncodable("unhashable")
        return {"t": "frozenset" if isinstance(value, frozenset) else "set",
                "v": items}
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise NotEncodable("mapping")
        if all(isinstance(key, str) for key in value):
            return {"t": "dict",
                    "v": [[key, encode(item, depth + 1)]
                          for key, item in value.items()]}
        items = []
        for key, item in value.items():
            encoded = encode(key, depth + 1)
            if not hashable(encoded):
                raise NotEncodable("key")
            items.append([encoded, encode(item, depth + 1)])
        return {"t": "map", "v": items}
    raise NotEncodable("object")


def is_dunder(name):
    return name.startswith("__") and name.endswith("__")


def check_path(path):
    if (not isinstance(path, list) or not path
            or not all(isinstance(part, str) for part in path)):
        raise ValueError("invalid path")
    for part in path[1:]:
        if is_dunder(part) and part not in READABLE_DUNDERS:
            raise AttributeError(part)


def resolve(path):
    check_path(path)
    if path[0].startswith("#"):
        obj = HANDLES[path[0]]
    else:
        obj = importlib.import_module(path[0])
    for name in path[1:]:
        obj = getattr(obj, name)
    return obj


def keep(value):
    if len(HANDLES) >= MAX_HANDLES or NEXT_HANDLE[0] >= MAX_HANDLE_ID:
        raise NotEncodable("handles")
    NEXT_HANDLE[0] += 1
    handle = "#%d" % (NEXT_HANDLE[0],)
    HANDLES[handle] = value
    COUNTS[handle] = 1
    return {"t": "ref", "handle": handle}


def share(value):
    handle = SHARED.get(id(value))
    if handle is not None and HANDLES.get(handle) is value:
        # Handed out once more: one more release before it is dropped.
        COUNTS[handle] += 1
        return {"t": "ref", "handle": handle}
    ref = keep(value)
    SHARED[id(value)] = ref["handle"]
    return ref


def release(entries):
    """Drop handles the evaluator no longer refers to.

    ``entries`` is a list of ``[handle, count]`` pairs: every local
    reference to ``handle`` is gone, and the evaluator had received it
    ``count`` times. A handle is dropped when all its hand-outs are
    released. Anything malformed, unknown, already released or not a
    ``#n`` handle (an attribute path) is ignored: a release never fails
    and never names a module.
    """
    if not isinstance(entries, list):
        return
    for entry in entries[:MAX_ITEMS]:
        if not isinstance(entry, list) or len(entry) != 2:
            continue
        handle, count = entry
        if (not isinstance(handle, str) or type(count) is not int
                or count < 1):
            continue
        held = COUNTS.get(handle)
        if held is None:
            continue
        if count < held:
            COUNTS[handle] = held - count
            continue
        del COUNTS[handle]
        value = HANDLES.pop(handle, None)
        if SHARED.get(id(value)) == handle:
            del SHARED[id(value)]
        del value


def state(value):
    """A read of submission state: a mutable container stays here."""
    if isinstance(value, MUTABLE):
        return {"ok": True, "value": share(value)}
    return result(value)


def describe(cls):
    """The class chain of an exception class, for evaluator stand-ins.

    Each entry names one class of the MRO (``object`` excluded) by module
    and qualified name, and lists its direct bases as indices into the
    chain. Only names cross; the evaluator never receives the class.
    """
    chain = [item for item in cls.__mro__ if item is not object]
    chain = chain[:MAX_CLASSES]
    index = {id(item): position for position, item in enumerate(chain)}
    return [{"module": str(getattr(item, "__module__", "") or ""),
             "qualname": str(getattr(item, "__qualname__", item.__name__)),
             "bases": [index[id(base)] for base in item.__bases__
                       if id(base) in index]}
            for item in chain]


def annotate(ref, value):
    # An exception class stays in the worker like any other class, but the
    # evaluator needs its name chain to stand in for it locally, so that
    # pytest.raises(pkg.Error) and except pkg.Error match what is raised.
    if isinstance(value, type) and issubclass(value, BaseException):
        try:
            ref["exc"] = describe(value)
        except Exception:
            pass
    return ref


def result(value, force_ref=False):
    if not force_ref:
        try:
            return {"ok": True, "value": encode(value),
                    LARGE: lambda: result(value, force_ref=True)}
        except NotEncodable:
            pass
    return {"ok": True, "value": annotate(keep(value), value)}


def reflected(function):
    return lambda obj, other: function(other, obj)


# The dunder protocols the evaluator may forward. Each entry maps a
# protocol name to the builtin or operator that implements it, so the
# worker applies Python's own semantics (reflected operands, NotImplemented
# fallback, __len__ for truth). Nothing outside this table is reachable.
UNARY = {
    "__len__": len, "__bool__": bool, "__str__": str, "__repr__": repr,
    "__hash__": hash, "__int__": int, "__float__": float,
    "__index__": operator.index, "__iter__": iter, "__next__": next,
    "__reversed__": reversed, "__neg__": operator.neg,
    "__pos__": operator.pos, "__abs__": abs, "__invert__": operator.invert,
    "__enter__": lambda obj: type(obj).__enter__(obj),
    "__copy__": copy.copy, "__deepcopy__": copy.deepcopy,
}
BINARY = {
    "__contains__": lambda obj, item: item in obj,
    "__getitem__": operator.getitem, "__delitem__": operator.delitem,
    "__format__": format,
    "__instancecheck__": lambda obj, item: isinstance(item, obj),
    "__subclasscheck__": lambda obj, item: issubclass(item, obj),
    "__eq__": operator.eq, "__ne__": operator.ne, "__lt__": operator.lt,
    "__le__": operator.le, "__gt__": operator.gt, "__ge__": operator.ge,
}
ARITHMETIC = {
    "add": operator.add, "sub": operator.sub, "mul": operator.mul,
    "truediv": operator.truediv, "floordiv": operator.floordiv,
    "mod": operator.mod, "pow": operator.pow, "matmul": operator.matmul,
    "and": operator.and_, "or": operator.or_, "xor": operator.xor,
    "lshift": operator.lshift, "rshift": operator.rshift,
}
for _name, _function in ARITHMETIC.items():
    BINARY["__%s__" % _name] = _function
    BINARY["__r%s__" % _name] = reflected(_function)
    BINARY["__i%s__" % _name] = getattr(operator, "i" + _name)
BINARY["__divmod__"] = divmod
BINARY["__rdivmod__"] = reflected(divmod)
SPECIAL = frozenset({"__setitem__", "__setattr__", "__delattr__",
                     "__exit__", "__round__"})
DUNDERS = frozenset(UNARY) | frozenset(BINARY) | SPECIAL
INPLACE = frozenset("__i%s__" % _name for _name in ARITHMETIC)


def exit_value(arg):
    # The evaluator names the exception that left a ``with`` block: the
    # worker-side original when it came from here, else a builtin by name.
    if arg is None or isinstance(arg, BaseException):
        return arg
    name, args = arg
    import builtins
    candidate = getattr(builtins, str(name), None)
    if not (isinstance(candidate, type) and issubclass(candidate, Exception)):
        candidate = Exception
    try:
        return candidate(*args)
    except Exception:
        return Exception(*args)


def dunder(obj, name, args):
    if name == "__enter__" and not args:
        # ``with x as y`` binds what __enter__ returned: state, so a
        # mutable result is the worker's own object, as an item read is.
        return state(UNARY[name](obj))
    if name in UNARY and not args:
        return result(UNARY[name](obj), force_ref=name == "__iter__")
    if name == "__pow__" and len(args) == 2:
        # Three-argument pow(x, exponent, modulus).
        return result(pow(obj, args[0], args[1]))
    if name in BINARY and len(args) == 1:
        value = BINARY[name](obj, args[0])
        if name in INPLACE and value is obj:
            # ``ref += [x]`` rebinds the evaluator's name to the result:
            # it must stay the worker's object, not become a copy.
            return state(value)
        if name == "__getitem__" and not isinstance(args[0], slice):
            # An item read is state, like an attribute read; a slice is a
            # new object and crosses as data.
            return state(value)
        return result(value)
    if name == "__setitem__" and len(args) == 2:
        obj[args[0]] = args[1]
        return result(None)
    if name in ("__setattr__", "__delattr__") and args:
        attribute = args[0]
        if not isinstance(attribute, str) or is_dunder(attribute):
            raise AttributeError(str(attribute))
        if name == "__setattr__" and len(args) == 2:
            setattr(obj, attribute, args[1])
            return result(None)
        if name == "__delattr__" and len(args) == 1:
            delattr(obj, attribute)
            return result(None)
    if name == "__exit__" and len(args) == 1:
        error = exit_value(args[0])
        if error is None:
            outcome = type(obj).__exit__(obj, None, None, None)
        else:
            outcome = type(obj).__exit__(
                obj, type(error), error, error.__traceback__)
        return result(bool(outcome))
    if name == "__round__" and len(args) <= 1:
        return result(round(obj, *args))
    raise TypeError("wrong arguments for " + name)


def handle(request):
    op = request.get("op")
    if op == "ping":
        return {"ok": True, "value": {"t": "str", "v": "ready"}}
    if op == "release":
        # The releases rode on the request itself (see main).
        return {"ok": True, "value": {"t": "none"}}
    path = request.get("path")
    if (not isinstance(path, list) or not path
            or not all(isinstance(part, str) for part in path)):
        return {"ok": False,
                "error": {"type": "SplitProtocolError",
                          "message": "invalid path"}}
    if op == "get":
        obj = resolve(path)
        if isinstance(obj, MUTABLE):
            return state(obj)
        by_path = {"ok": True, "value": annotate({"t": "ref"}, obj)}
        try:
            return {"ok": True, "value": encode(obj), LARGE: lambda: by_path}
        except NotEncodable:
            return by_path
    if op == "call":
        obj = resolve(path)
        if not callable(obj):
            return {"ok": False,
                    "error": {"type": "TypeError",
                              "message": "not callable"}}
        args = [decode(item) for item in request.get("args") or []]
        kwargs = {key: decode(item)
                  for key, item in (request.get("kwargs") or {}).items()}
        return result(obj(*args, **kwargs))
    if op == "dunder":
        name = request.get("name")
        if name not in DUNDERS:
            return {"ok": False,
                    "error": {"type": "SplitProtocolError",
                              "message": "protocol is not forwarded"}}
        obj = resolve(path)
        args = [decode(item) for item in request.get("args") or []]
        return dunder(obj, name, args)
    return {"ok": False,
            "error": {"type": "SplitProtocolError", "message": "unknown op"}}


def describe_error(exc):
    try:
        message = str(exc)
    except BaseException:
        message = "<unprintable %s>" % (type(exc).__name__,)
    error = {"type": type(exc).__name__, "message": message[:MAX_MESSAGE]}
    try:
        error["classes"] = describe(type(exc))
    except Exception:
        pass
    try:
        error["args"] = encode(tuple(exc.args))
    except Exception:
        pass
    if not isinstance(exc, (StopIteration, StopAsyncIteration)):
        # The raised object stays here; the evaluator reads its attributes
        # (``excinfo.value.code``) through this handle.
        try:
            error["handle"] = keep(exc)["handle"]
        except Exception:
            pass
    return error


def serialized(response):
    """The response as one frame, or None when it cannot be one.

    None when it exceeds the frame bound, or when JSON cannot write it at
    all (an int past the interpreter's int-to-str digit limit, which the
    wire encoder accepts).
    """
    try:
        data = json.dumps(response).encode("utf-8")
    except Exception:
        return None
    return data if len(data) < MAX_FRAME else None


def handed_out(response):
    """The handles a response hands to the evaluator."""
    for entry in (response.get("value"), response.get("error")):
        if isinstance(entry, dict) and isinstance(entry.get("handle"), str):
            yield entry["handle"]


def frame(response):
    """The serialized response, within the evaluator's frame bound.

    A data result that cannot be one frame (within the item and depth
    bounds, a frozenset of two long strings say, or of an int JSON cannot
    write) is answered with what its ``LARGE`` entry gives instead: a
    handle to the value already computed, never a second call. An error
    drops its encoded args, and anything still too large is refused as a
    protocol error, releasing the handle it would have handed out.
    """
    large = response.pop(LARGE, None)
    data = serialized(response)
    if data is not None:
        return data
    if large is not None:
        try:
            response = large()
        except BaseException as exc:
            response = {"ok": False, "error": describe_error(exc)}
        response.pop(LARGE, None)
    error = response.get("error")
    if isinstance(error, dict):
        error.pop("args", None)
    data = serialized(response)
    if data is not None:
        return data
    # The evaluator never sees this response, so it can never release the
    # handle it names: drop that hand-out here.
    release([[handle, 1] for handle in handed_out(response)])
    return json.dumps({"ok": False, "error": {
        "type": "SplitProtocolError",
        "message": "response exceeds the frame bound"}}).encode("utf-8")


def source_root(workspace):
    """``<workspace>/src`` for a src-layout project, else None.

    A directory named ``src`` that is itself a package (``src/__init__.py``)
    is imported as ``src``, not searched. The workspace root stays first on
    the path, so a top-level module there shadows one of the same name
    under ``src``; the evaluator's finder applies the same order.
    """
    candidate = os.path.join(workspace, "src")
    if (os.path.isdir(candidate)
            and not os.path.exists(os.path.join(candidate, "__init__.py"))):
        return candidate
    return None


def main():
    mode, target, workspace = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.path.insert(0, workspace)
    source = source_root(workspace)
    if source is not None:
        sys.path.insert(1, source)
    listener = None
    if mode == "--fd":
        sock = socket.socket(fileno=int(target))
        stream = sock.makefile("rwb")
    else:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(target)
        os.chmod(target, 0o666)
        listener.listen(1)
        conn, _ = listener.accept()
        stream = conn.makefile("rwb")
    while True:
        line = stream.readline()
        if not line:
            return 0
        try:
            request = json.loads(line)
            if isinstance(request, dict) and "release" in request:
                # Releases ride on any request and apply before it. They
                # come from the evaluator; a malformed one changes nothing
                # and never fails the request it came with.
                try:
                    release(request["release"])
                except Exception:
                    pass
            response = handle(request)
        except BaseException as exc:
            response = {"ok": False, "error": describe_error(exc)}
        stream.write(frame(response) + b"\n")
        stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
'''


#: Runs as the evaluator principal. It imports the trusted runner and the
#: acceptance tests, and reaches submitted code only through the proxy.
SPLIT_BOOTSTRAP_SOURCE = r'''"""SIS split-custody bootstrap (evaluator-owned, read-only)."""
import builtins
import collections
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import runpy
import socket
import sys
import threading
import types
import warnings
import weakref

warnings.filterwarnings(
    "ignore", message=r".*found in sys\.modules.*", category=RuntimeWarning)

MAX_FRAME = 1 << 20
MAX_DEPTH = 32
MAX_ITEMS = 10000
SPLIT_LOST_EXIT = 75
SPLIT_UNAVAILABLE_EXIT = 76
RESERVED = frozenset({
    "pytest", "_pytest", "pluggy", "py", "iniconfig", "sis", "setuptools",
    "pkg_resources", "sitecustomize", "usercustomize",
})
# Dunder attributes a test may read from a submitted object: metadata,
# never a way into the object model. The worker holds the same set.
READABLE_DUNDERS = frozenset({"__name__", "__qualname__", "__version__",
                              "__all__"})
MAX_CLASSES = 64
MAX_STAND_INS = 4096
# The test runner's own modules. Their exception classes steer the run
# itself (unittest.SkipTest becomes a skip wherever it is raised, and an
# all-skipped run exits 0), so a worker name never resolves to one.
RUNNER_MODULES = ("unittest", "pytest", "_pytest", "pluggy", "doctest")
# Local stand-ins for worker exception classes, by (module, qualname).
STAND_INS = {}
STAND_IN_LOCK = threading.RLock()

mode, target, workspace = sys.argv[1], sys.argv[2], sys.argv[3]
command = sys.argv[4:]
if not command:
    raise SystemExit(64)


def fail(code, reason):
    # A harness failure must never be recorded as a test result. The
    # executor maps these statuses to a ``sandbox:`` marker, so the run is
    # an error about the harness, not a verdict about the submission.
    sys.stderr.write(reason + "\n")
    sys.stderr.flush()
    os._exit(code)


try:
    if mode == "--fd":
        sock = socket.socket(fileno=int(target))
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(target)
    stream = sock.makefile("rwb")
except OSError as exc:
    fail(SPLIT_UNAVAILABLE_EXIT,
         "evaluation_split_worker_unavailable: %s" % (exc,))


# One request and its response at a time. A test that calls the
# submission from several threads (a ThreadPoolExecutor) would otherwise
# interleave frames on the one socket and read another thread's answer.
REQUEST_LOCK = threading.Lock()

# Handle release. Every handle the worker hands out is held here by one
# Lease, shared by every Ref (and stand-in exception or class) that
# refers to it, and the lease counts how many times the worker handed the
# handle out. When the last local reference goes, the lease's finalizer
# queues ``(handle, count)``; the next request carries the queue to the
# worker, which drops the handle once every hand-out is released. A
# handle the worker hands out again after its lease died gets a new
# lease with its own count, so a queued release never drops a handle a
# live Ref still uses. The finalizer only appends to a deque: no lock, no
# socket I/O, safe whenever the collector runs it (inside REQUEST_LOCK,
# in another thread, at shutdown).
RELEASE_BATCH = 1024
PENDING = collections.deque()
LEASES = weakref.WeakValueDictionary()
LEASE_LOCK = threading.Lock()


class Lease:
    __slots__ = ("handle", "count", "__weakref__")


def lease_for(handle):
    """The live lease for a handle the worker just handed out, counted."""
    with LEASE_LOCK:
        held = LEASES.get(handle)
        if held is None:
            held = Lease()
            held.handle = handle
            # The count cell outlives the lease, so the finalizer (which
            # must not refer to the lease) reads its final value.
            held.count = [0]
            finalizer = weakref.finalize(
                held, PENDING.append, (handle, held.count))
            finalizer.atexit = False
            LEASES[handle] = held
        held.count[0] += 1
        return held


def drain_releases():
    """Up to RELEASE_BATCH queued releases, as ``[handle, count]`` pairs.

    Called under REQUEST_LOCK only, so it is the one consumer of PENDING.
    """
    counts = {}
    while PENDING and len(counts) < RELEASE_BATCH:
        handle, cell = PENDING.popleft()
        counts[handle] = counts.get(handle, 0) + cell[0]
    return [[handle, count] for handle, count in counts.items() if count]


def exchange(payload):
    stream.write(json.dumps(payload).encode("utf-8") + b"\n")
    stream.flush()
    return stream.readline(MAX_FRAME + 1)


def request(payload):
    try:
        with REQUEST_LOCK:
            while len(PENDING) > RELEASE_BATCH:
                # A long queue goes ahead in release-only requests, so no
                # frame grows with it.
                exchange({"op": "release", "release": drain_releases()})
            released = drain_releases()
            if released:
                payload = dict(payload, release=released)
            line = exchange(payload)
    except OSError:
        fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
    if not line or len(line) > MAX_FRAME:
        fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
    try:
        response = json.loads(line)
    except ValueError:
        fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
    if not isinstance(response, dict):
        fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
    return response


# A worker that never serves is a harness failure, not a test result.
if not request({"op": "ping"}).get("ok"):
    fail(SPLIT_UNAVAILABLE_EXIT, "evaluation_split_worker_unavailable")


def decode(payload, depth=0):
    if depth > MAX_DEPTH:
        raise ValueError("payload nesting exceeds the bound")
    kind = payload.get("t")
    if kind == "none":
        return None
    if kind == "bool":
        return bool(payload.get("v"))
    if kind == "int":
        return int(payload.get("v"))
    if kind == "float":
        return float(payload.get("v"))
    if kind == "str":
        return payload.get("v")
    if kind == "bytes":
        import base64
        return base64.b64decode(payload.get("v").encode("ascii"), validate=True)
    if kind in ("list", "tuple", "set", "frozenset", "dict", "map"):
        items = payload.get("v") or []
        if not isinstance(items, list) or len(items) > MAX_ITEMS:
            raise ValueError("composite payload is out of bounds")
    if kind in ("list", "tuple"):
        items = [decode(item, depth + 1) for item in items]
        return items if kind == "list" else tuple(items)
    if kind in ("set", "frozenset"):
        items = [decode(item, depth + 1) for item in items]
        try:
            return set(items) if kind == "set" else frozenset(items)
        except TypeError:
            raise ValueError("set payload has an unhashable element")
    if kind == "dict":
        return {item[0]: decode(item[1], depth + 1) for item in items}
    if kind == "map":
        result = {}
        for item in items:
            key = decode(item[0], depth + 1)
            value = decode(item[1], depth + 1)
            try:
                result[key] = value
            except TypeError:
                raise ValueError("mapping payload has an unhashable key")
        return result
    raise ValueError("unknown payload type: %r" % (kind,))


class RemoteExceptionMeta(type):
    """Metaclass of the local stand-ins for worker exception classes.

    A stand-in is built here from the names the worker reports; it holds
    no worker code and always derives from ``Exception``. Reading a class
    attribute the stand-in lacks asks the worker, and isinstance() of a
    Ref asks the worker; a local instance is checked locally.
    """

    def __getattr__(cls, name):
        path = cls.__dict__.get("_sis_path")
        if path is None or is_dunder(name) or name.startswith("_sis_"):
            raise AttributeError(name)
        return fetch(list(path) + [name], cls.__dict__.get("_sis_lease"))

    def __instancecheck__(cls, instance):
        path = cls.__dict__.get("_sis_path")
        if path is not None and isinstance(instance, Ref):
            return bool(forward(path, "__instancecheck__", [encode(instance)]))
        return type.__instancecheck__(cls, instance)


def stand_in_str(self):
    # str() of the worker's exception, so pytest.raises(match=...) sees
    # the message the submission produced.
    message = self.__dict__.get("_sis_message")
    if message is not None:
        return message
    for klass in type(self).__mro__:
        if "_sis_remote" not in klass.__dict__ and "__str__" in klass.__dict__:
            return klass.__dict__["__str__"](self)
    return BaseException.__str__(self)


def stand_in_getattr(self, name):
    # ``excinfo.value.code``: attributes of the raised object stay in the
    # worker and are read through its handle.
    handle = self.__dict__.get("_sis_handle")
    if handle is None or is_dunder(name) or name.startswith("_sis_"):
        raise AttributeError(name)
    return fetch([handle, name], self.__dict__.get("_sis_lease"))


def class_entries(classes):
    """Validate a worker-reported class chain; None when malformed."""
    if (not isinstance(classes, list) or not classes
            or len(classes) > MAX_CLASSES):
        return None
    entries = []
    for position, entry in enumerate(classes):
        if not isinstance(entry, dict):
            return None
        module, qualname = entry.get("module"), entry.get("qualname")
        bases = entry.get("bases")
        if (not isinstance(module, str) or not isinstance(qualname, str)
                or not qualname or len(module) > 512 or len(qualname) > 512):
            return None
        # Bases come later in an MRO; requiring it rules out cycles.
        if not isinstance(bases, list) or not all(
                type(base) is int and position < base < len(classes)
                for base in bases):
            return None
        entries.append((module, qualname, bases))
    return entries


#: Reviewed standard-library exception classes a worker may name. Each is
#: imported and recorded by identity when the bootstrap starts, before any
#: test, conftest or helper code runs, so later changes to these modules
#: (``json.Hooked = Helper``, a replaced attribute) cannot add to the table.
REVIEWED_STDLIB_EXCEPTIONS = (
    ("argparse", ("ArgumentError", "ArgumentTypeError")),
    ("binascii", ("Error", "Incomplete")),
    ("configparser", ("Error", "NoSectionError", "DuplicateSectionError",
                      "DuplicateOptionError", "NoOptionError",
                      "InterpolationError", "InterpolationMissingOptionError",
                      "InterpolationSyntaxError", "InterpolationDepthError",
                      "ParsingError", "MissingSectionHeaderError")),
    ("copy", ("Error",)),
    ("csv", ("Error",)),
    ("decimal", ("DecimalException", "InvalidOperation", "DivisionByZero",
                 "Inexact", "Rounded", "Subnormal", "Overflow", "Underflow",
                 "Clamped", "FloatOperation", "ConversionSyntax",
                 "DivisionImpossible", "DivisionUndefined",
                 "InvalidContext")),
    ("email.errors", ("MessageError", "MessageParseError", "HeaderParseError",
                      "BoundaryError", "MultipartConversionError")),
    ("getopt", ("GetoptError",)),
    ("gzip", ("BadGzipFile",)),
    ("http.client", ("HTTPException", "IncompleteRead", "InvalidURL",
                     "RemoteDisconnected", "BadStatusLine")),
    ("ipaddress", ("AddressValueError", "NetmaskValueError")),
    ("json", ("JSONDecodeError",)),
    ("locale", ("Error",)),
    ("lzma", ("LZMAError",)),
    ("pickle", ("PickleError", "PicklingError", "UnpicklingError")),
    ("queue", ("Empty", "Full")),
    ("re", ("error", "PatternError")),
    ("shutil", ("Error", "SameFileError")),
    ("socket", ("herror", "gaierror")),
    ("sqlite3", ("Error", "Warning", "DatabaseError", "IntegrityError",
                 "OperationalError", "ProgrammingError", "InterfaceError",
                 "DataError", "NotSupportedError", "InternalError")),
    ("statistics", ("StatisticsError",)),
    ("struct", ("error",)),
    ("subprocess", ("SubprocessError", "CalledProcessError",
                    "TimeoutExpired")),
    ("tarfile", ("TarError", "ReadError", "CompressionError",
                 "StreamError", "ExtractError", "HeaderError")),
    ("tomllib", ("TOMLDecodeError",)),
    ("urllib.error", ("URLError", "HTTPError", "ContentTooShortError")),
    ("xml.etree.ElementTree", ("ParseError",)),
    ("zipfile", ("BadZipFile", "LargeZipFile")),
    ("zlib", ("error",)),
)

TYPE_MODULE = type.__dict__["__module__"]
TYPE_QUALNAME = type.__dict__["__qualname__"]


def _reviewed_classes():
    """(module, qualname) -> class for the builtin and reviewed exceptions.

    Keyed by the class's own defining module and qualified name (what the
    worker reports for the same class), recorded by identity at startup.
    """
    table = {}

    def record(cls):
        if not (issubclass(type(cls), type) and issubclass(cls, Exception)):
            return
        key = (TYPE_MODULE.__get__(cls, type), TYPE_QUALNAME.__get__(cls, type))
        if key[0].split(".")[0] in RUNNER_MODULES:
            return
        table.setdefault(key, cls)

    for value in list(vars(builtins).values()):
        record(value)
    for module_name, names in REVIEWED_STDLIB_EXCEPTIONS:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        namespace = vars(module)
        for name in names:
            value = namespace.get(name)
            if value is not None:
                record(value)
    return table


REVIEWED_CLASSES = _reviewed_classes()


def trusted_class(module, qualname):
    """The evaluator's own class for a worker-reported name, or None.

    Only builtin exceptions and the reviewed standard-library exceptions
    qualify, looked up by the reported (module, qualname) in a table of
    identities recorded at startup. Nothing is walked, nothing is imported
    and no attribute or class hook runs. Every other name, including a
    class of an installed package, a test helper, or an alias or spoof of
    a standard-library name, gets an inert stand-in.
    """
    if not (isinstance(module, str) and isinstance(qualname, str)):
        return None
    return REVIEWED_CLASSES.get((module, qualname))


def stand_in(module, qualname, bases, path, lease=None):
    key = (module, qualname)
    # Built and published under one lock: test threads rebuild classes
    # after the request lock, and two that miss the cache together must
    # still get one class, or a later raise would not match the other's.
    with STAND_IN_LOCK:
        cls = STAND_INS.get(key)
        if cls is not None:
            if path is not None and cls.__dict__.get("_sis_path") is None:
                # First raised under a name with no import path (a
                # factory's ``<locals>`` class), now read by its alias:
                # the same class gains the path, and keeps its identity.
                type.__setattr__(cls, "_sis_path", list(path))
                type.__setattr__(cls, "_sis_lease", lease)
            return cls
        if len(STAND_INS) >= MAX_STAND_INS:
            return None
        parts = qualname.split(".")
        if (path is None and module
                and all(part.isidentifier() for part in parts)):
            path, lease = [module, *parts], None
        # A cached stand-in keeps the handle its path names.
        namespace = {"__module__": module, "__qualname__": qualname,
                     "__doc__": None, "_sis_remote": key, "_sis_path": path,
                     "_sis_lease": lease,
                     "__str__": stand_in_str,
                     "__getattr__": stand_in_getattr}
        for candidate in (bases, (Exception,)):
            try:
                cls = RemoteExceptionMeta(
                    parts[-1], candidate, dict(namespace))
            except (TypeError, ValueError):
                continue
            # Only ordinary exceptions exist on this side: never a
            # BaseException a test cannot catch, SystemExit or
            # KeyboardInterrupt.
            if issubclass(cls, Exception):
                STAND_INS[key] = cls
                return cls
        return None


def exception_class(classes, path=None, lease=None):
    """The local class for a worker exception class chain, or None.

    Each class of the chain resolves to the evaluator's own builtin or
    already-imported class of that name, else to a cached stand-in keyed
    by (module, qualname) whose bases are the resolved bases. So
    ``pkg.CustomError`` read through the proxy and a ``CustomError`` the
    worker raises are the same local class, and ``except pkg.Base`` also
    catches a worker ``CustomError(Base)``. Bases that are not ordinary
    exceptions on this side (``BaseException``, ``KeyboardInterrupt``)
    are dropped; a class left with none derives from ``Exception``.
    """
    entries = class_entries(classes)
    if entries is None:
        return None
    built = [None] * len(entries)
    for position in range(len(entries) - 1, -1, -1):
        module, qualname, bases = entries[position]
        trusted = trusted_class(module, qualname)
        if trusted is not None or module == "builtins":
            built[position] = trusted
            continue
        local = []
        for base in bases:
            if built[base] is not None and built[base] not in local:
                local.append(built[base])
        # Drop a base another base already derives from, as an MRO would.
        local = [base for base in local if not any(
            other is not base and issubclass(other, base) for other in local)]
        built[position] = stand_in(
            module, qualname, tuple(local) or (Exception,),
            path if position == 0 else None,
            lease if position == 0 else None)
    if controls_the_run(built[0]):
        return None
    return built[0]


def controls_the_run(cls):
    """True for a class the test runner treats as a verdict, not an error."""
    if not isinstance(cls, type):
        return False
    unittest_module = sys.modules.get("unittest")
    skip = getattr(unittest_module, "SkipTest", None)
    return isinstance(skip, type) and issubclass(cls, skip)


def instantiate(cls, args, message):
    """Build the local exception without running worker code."""
    try:
        exc = cls(*args)
        if (isinstance(type(exc), RemoteExceptionMeta)
                or str(exc) == message):
            return exc
    except Exception:
        pass
    # A builtin whose str() does not follow from its args alone
    # (OSError's filename): keep the worker's message instead.
    for attempt in ((message,), ()):
        try:
            return cls(*attempt)
        except Exception:
            continue
    # A class whose __init__ wants other arguments (json.JSONDecodeError):
    # allocate it without __init__ and keep the worker's args.
    try:
        exc = cls.__new__(cls)
        exc.args = tuple(args)
        return exc
    except Exception:
        return None


def raise_remote(error):
    if not isinstance(error, dict):
        error = {}
    # The raised object's handle is counted first, so it is released with
    # the local exception, or right away when none is built.
    handle = error.get("handle")
    held = None
    if (isinstance(handle, str) and handle.startswith("#")
            and handle[1:].isdigit() and len(handle) <= 10):
        held = lease_for(handle)
    name = error.get("type")
    name = name if isinstance(name, str) else "RemoteError"
    message = error.get("message")
    message = message if isinstance(message, str) else ""
    try:
        cls = exception_class(error.get("classes"))
    except Exception:
        cls = None
    if cls is None:
        # The builtin identities recorded at startup, never the live
        # builtins namespace: a helper may have assigned builtins.X later.
        cls = REVIEWED_CLASSES.get(("builtins", name))
    # Only ordinary exceptions cross the boundary: a worker must not be
    # able to raise SystemExit or KeyboardInterrupt in the evaluator, nor
    # an exception the runner reads as a skip.
    if (cls is None or not issubclass(cls, Exception)
            or controls_the_run(cls)):
        raise RuntimeError("%s: %s" % (name, message))
    args = (message,)
    payload = error.get("args")
    if isinstance(payload, dict) and payload.get("t") == "tuple":
        try:
            args = decode(payload)
        except Exception:
            pass
    exc = instantiate(cls, args, message)
    if exc is None or not isinstance(exc, Exception):
        raise RuntimeError("%s: %s" % (name, message))
    if held is not None:
        exc._sis_handle = handle
        exc._sis_lease = held
    if isinstance(type(exc), RemoteExceptionMeta):
        exc._sis_message = message
    try:
        raise exc
    finally:
        # The traceback keeps this frame: without this, exc -> traceback
        # -> frame -> exc is a cycle, and the handle waits for the cycle
        # collector instead of going with the exception.
        exc = held = None


class SplitArgumentError(TypeError):
    """A local value that has no form on the wire."""


def is_dunder(name):
    return name.startswith("__") and name.endswith("__")


def result_value(value, path=None, lease=None):
    """Decode a response value; an object that stayed remote is a Ref.

    ``path`` names an attribute read, which the worker resolves again on
    use; ``lease`` is the lease of the handle that path starts from, kept
    by the result so the handle outlives it. A call or protocol result
    has no path: the worker keeps it and the evaluator refers to it by
    handle, never by the callable's path (that would re-call it on every
    access).
    """
    if value.get("t") != "ref":
        return decode(value)
    if path is None or value.get("handle") is not None:
        # A mutable container read as an attribute comes back by handle:
        # the worker's own object, whatever the path names later.
        handle = value.get("handle")
        if (not isinstance(handle, str) or not handle.startswith("#")
                or not handle[1:].isdigit() or len(handle) > 10):
            fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
        path = [handle]
        lease = lease_for(handle)
    if value.get("exc") is not None:
        # A worker exception class: a local stand-in, so that
        # pytest.raises(pkg.Error) and ``except pkg.Error`` work.
        cls = exception_class(value.get("exc"), path, lease)
        if cls is not None:
            return cls
    return Ref(path, lease)


def fetch(path, lease=None):
    response = request({"op": "get", "path": list(path)})
    if not response.get("ok"):
        raise_remote(response.get("error"))
    return result_value(response.get("value") or {}, list(path), lease)


def forward(path, name, payload):
    # One allow-listed protocol call; the worker refuses any other name.
    response = request({"op": "dunder", "path": list(path), "name": name,
                        "args": payload})
    if not response.get("ok"):
        raise_remote(response.get("error"))
    return result_value(response.get("value") or {})


class Ref:
    """An object that stays in the worker, reached by path or handle.

    Attribute reads and calls cross the socket. So do the protocols in
    PROTOCOLS and OPERATORS below, through the worker's single ``dunder``
    op; nothing else does (no ``__getattribute__``, ``__reduce__``,
    ``__class__`` or ``__dict__``). ``type(ref)`` is always ``Ref``.
    """

    __slots__ = ("_path", "_lease")

    def __init__(self, path, lease=None):
        object.__setattr__(self, "_path", list(path))
        # The lease of the handle the path starts from: the worker keeps
        # that handle at least as long as this Ref lives.
        object.__setattr__(self, "_lease", lease)

    def __getattr__(self, name):
        # Read the attribute in the worker: a plain value (``box.n``)
        # comes back as data, anything else stays a reference.
        if is_dunder(name) and name not in READABLE_DUNDERS:
            raise AttributeError(name)
        return fetch(self._path + [name], self._lease)

    def __setattr__(self, name, value):
        if is_dunder(name) or name in ("_path", "_lease"):
            raise AttributeError(name)
        forward(self._path, "__setattr__", [encode(name), encode(value)])

    def __delattr__(self, name):
        if is_dunder(name) or name in ("_path", "_lease"):
            raise AttributeError(name)
        forward(self._path, "__delattr__", [encode(name)])

    def __call__(self, *args, **kwargs):
        response = request({"op": "call", "path": self._path,
                            "args": [encode(item) for item in args],
                            "kwargs": {key: encode(item)
                                       for key, item in kwargs.items()}})
        if not response.get("ok"):
            raise_remote(response.get("error"))
        return result_value(response.get("value") or {})

    def __iter__(self):
        # Iteration streams: the worker keeps the iterator and each
        # ``next`` is one round trip, ending with StopIteration.
        iterator = forward(self._path, "__iter__", [])
        if not isinstance(iterator, Ref):
            raise TypeError("split iterator did not stay in the worker")
        return iterator

    def __setitem__(self, key, value):
        forward(self._path, "__setitem__", [encode(key), encode(value)])

    def __round__(self, ndigits=None):
        return forward(self._path, "__round__",
                       [] if ndigits is None else [encode(ndigits)])

    def __instancecheck__(self, instance):
        # isinstance(obj, pkg.Class): the worker answers for its classes.
        try:
            payload = [encode(instance)]
        except SplitArgumentError:
            return False
        return bool(forward(self._path, "__instancecheck__", payload))

    def __subclasscheck__(self, subclass):
        try:
            payload = [encode(subclass)]
        except SplitArgumentError:
            return False
        return bool(forward(self._path, "__subclasscheck__", payload))

    def __exit__(self, exc_type, exc, traceback):
        return bool(forward(self._path, "__exit__", [exit_payload(exc)]))

    def __copy__(self):
        # The worker copies its object: a container comes back as data,
        # anything else as a handle to the worker-side copy.
        return forward(self._path, "__copy__", [])

    def __deepcopy__(self, memo):
        return forward(self._path, "__deepcopy__", [])


def exit_payload(exc):
    """Name the exception leaving a ``with`` block for the worker."""
    if exc is None:
        return encode(None)
    if getattr(exc, "__dict__", {}).get("_sis_handle"):
        # Raised by the worker: hand it back its own exception object.
        return encode(exc)
    name = type(exc).__name__
    if getattr(builtins, name, None) is not type(exc):
        name = "Exception"
    try:
        return encode((name, tuple(exc.args)))
    except SplitArgumentError:
        return encode((name, (str(exc),)))


def protocol(name, operator):
    def method(self, *args):
        try:
            payload = [encode(item) for item in args]
        except SplitArgumentError:
            # An operand with no wire form: let Python try the reflected
            # method of the other operand, as for any foreign type.
            if operator:
                return NotImplemented
            raise
        return forward(self._path, name, payload)
    method.__name__ = method.__qualname__ = name
    return method


# The protocols forwarded on Ref. The worker holds the same fixed table;
# a name outside it is refused there as well.
PROTOCOLS = frozenset({
    "__len__", "__contains__", "__getitem__", "__delitem__", "__next__",
    "__reversed__", "__bool__", "__str__", "__repr__", "__hash__",
    "__int__", "__float__", "__index__", "__neg__", "__pos__", "__abs__",
    "__invert__", "__format__", "__enter__",
})
ARITHMETIC = ("add", "sub", "mul", "truediv", "floordiv", "mod", "pow",
              "matmul", "and", "or", "xor", "lshift", "rshift")
OPERATORS = frozenset(
    {"__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__",
     "__divmod__", "__rdivmod__"}
    | {"__%s__" % item for item in ARITHMETIC}
    | {"__r%s__" % item for item in ARITHMETIC}
    | {"__i%s__" % item for item in ARITHMETIC})
for _name in PROTOCOLS:
    setattr(Ref, _name, protocol(_name, False))
for _name in OPERATORS:
    setattr(Ref, _name, protocol(_name, True))


def encode(value, depth=0):
    if depth > 32:
        raise SplitArgumentError("split argument nesting exceeds the bound")
    if value is None:
        return {"t": "none"}
    if isinstance(value, Ref):
        return {"t": "handle", "v": list(value._path)}
    if isinstance(value, RemoteExceptionMeta) and value.__dict__.get(
            "_sis_path"):
        # A stand-in class names the worker class it stands for.
        return {"t": "handle", "v": list(value.__dict__["_sis_path"])}
    if isinstance(value, BaseException) and getattr(
            value, "__dict__", {}).get("_sis_handle"):
        # An exception the worker raised refers to the worker's object.
        return {"t": "handle", "v": [value.__dict__["_sis_handle"]]}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, float):
        return {"t": "float", "v": value}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, (bytes, bytearray)):
        import base64
        return {"t": "bytes",
                "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("split argument sequence exceeds the bound")
        return {"t": "list" if isinstance(value, list) else "tuple",
                "v": [encode(item, depth + 1) for item in value]}
    if isinstance(value, (set, frozenset)):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("split argument set exceeds the bound")
        return {"t": "frozenset" if isinstance(value, frozenset) else "set",
                "v": [encode(item, depth + 1) for item in value]}
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise SplitArgumentError("split argument mapping exceeds the bound")
        if all(isinstance(key, str) for key in value):
            return {"t": "dict",
                    "v": [[key, encode(item, depth + 1)]
                          for key, item in value.items()]}
        return {"t": "map",
                "v": [[encode(key, depth + 1), encode(item, depth + 1)]
                      for key, item in value.items()]}
    if isinstance(value, slice):
        return {"t": "slice",
                "v": [encode(value.start, depth + 1),
                      encode(value.stop, depth + 1),
                      encode(value.step, depth + 1)]}
    raise SplitArgumentError("split argument type is not transferable: %s"
                             % type(value).__name__)


class ProxyModule(types.ModuleType):
    def __getattr__(self, name):
        if is_dunder(name) and name not in READABLE_DUNDERS:
            raise AttributeError(name)
        return fetch([self.__name__, name])


class WorkspaceLoader(importlib.abc.Loader):
    def __init__(self, fullname, is_package):
        self._fullname = fullname
        self._is_package = is_package

    def create_module(self, spec):
        module = ProxyModule(self._fullname)
        module.__spec__ = spec
        return module

    def exec_module(self, module):
        return None

    def is_package(self, fullname):
        return self._is_package


def source_root(workspace):
    # Mirrors the worker: ``<workspace>/src`` for a src-layout project,
    # unless ``src`` is itself a package.
    candidate = os.path.join(workspace, "src")
    if (os.path.isdir(candidate)
            and not os.path.exists(os.path.join(candidate, "__init__.py"))):
        return candidate
    return None


# Where workspace top-level modules are looked up, in the worker's order:
# the workspace root first, so it shadows a same-named module under src/.
WORKSPACE_SEARCH = [workspace] + [
    entry for entry in (source_root(workspace),) if entry is not None]
# The directories each proxied workspace package spans: the __path__ the
# worker's import system gives it. A regular package has its own
# directory; a namespace package every portion, in search order (one
# under the workspace root and one under src/, say).
PACKAGE_PATHS = {}
_workspace_real = os.path.realpath(workspace)
_workspace_prefix = os.path.join(_workspace_real, "")
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset(
    sys.builtin_module_names)


def in_workspace(entry):
    """True when a path entry resolves to the workspace or inside it."""
    try:
        # Resolved, so no link (or ``.``, the workspace cwd) leads in.
        path = os.path.realpath(entry or os.getcwd())
    except Exception:
        return True
    return path == _workspace_real or path.startswith(_workspace_prefix)


class WorkspaceEntry:
    """The path-entry finder of a ``sys.path`` entry in the workspace.

    It finds nothing. Whatever puts the workspace on ``sys.path`` (a test,
    a ``.pth`` file, ``''`` for the cwd), no lookup on that path in the
    evaluator (the standard PathFinder, pytest's assertion-rewriting hook,
    any later finder) can load a module from it. Workspace modules are
    reached only through :class:`WorkspaceFinder`, which proxies them.
    """

    def find_spec(self, fullname, target=None):
        return None

    def invalidate_caches(self):
        return None


def workspace_entry_hook(entry):
    if isinstance(entry, str) and in_workspace(entry):
        return WorkspaceEntry()
    raise ImportError("not a workspace path entry")


def trusted_path():
    """The evaluator's own import path: ``sys.path`` without the workspace.

    Read at each lookup, not once: pytest puts the test's root directory
    in the private material on ``sys.path`` while it collects (a test
    package's parent, or the directory of a test that is not in a
    package), and a helper module there is evaluator material. Nothing
    in or under the workspace is ever trusted.
    """
    return [entry for entry in sys.path
            if isinstance(entry, str) and entry and not in_workspace(entry)]


def trusted_spec(name):
    """The evaluator's own spec for top-level ``name``, or None.

    The standard library, builtins, installed packages and modules beside
    the acceptance tests (the registered test, its ``conftest.py``,
    package ``__init__.py`` and helper modules) always resolve from the
    evaluator's environment. A workspace must never shadow a library the
    tests import later (``numpy``, ``decimal``, ``hypothesis``) or the
    test's own package (``from tests import helpers``): the test would
    then run code or compare against values the submission controls.
    The spec found on :func:`trusted_path` is the one the import uses,
    not a probe a later finder could answer differently.
    """
    return importlib.machinery.PathFinder.find_spec(name, trusted_path())


#: How a workspace directory is searched: the import system's own file
#: loaders, applied directly (PathFinder cannot see workspace entries).
FILE_LOADERS = importlib._bootstrap_external._get_supported_file_loaders()


def workspace_lookup(fullname, locations):
    """Where the worker's import system finds ``fullname`` in ``locations``.

    As PathFinder does over the same ordered locations: the first module
    or regular package wins, and namespace-package directories otherwise
    all become portions of one package. Nothing is loaded; the spec only
    says what the worker will import.
    """
    portions = []
    for entry in locations:
        try:
            spec = importlib.machinery.FileFinder(
                entry, *FILE_LOADERS).find_spec(fullname)
        except Exception:
            continue
        if spec is None:
            continue
        if spec.loader is not None:
            return spec
        portions.extend(entry for entry in spec.submodule_search_locations
                        or () if isinstance(entry, str))
    if not portions:
        return None
    spec = importlib.machinery.ModuleSpec(fullname, None, is_package=True)
    spec.submodule_search_locations = portions
    return spec


class WorkspaceFinder(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        parts = fullname.split(".")
        root = parts[0]
        if root in RESERVED:
            return None
        if root in sys.modules:
            if not isinstance(sys.modules[root], ProxyModule):
                return None
        elif len(parts) > 1:
            # A submodule of something the evaluator already resolved.
            return None
        elif (importlib.machinery.BuiltinImporter.find_spec(root) is not None
              or importlib.machinery.FrozenImporter.find_spec(root)
              is not None):
            # Compiled into the interpreter: never on any path.
            return None
        else:
            try:
                trusted = trusted_spec(root)
                failed = False
            except Exception:
                trusted, failed = None, True
            if trusted is not None:
                return trusted
            if root in STDLIB or failed:
                # The standard library never comes from the workspace.
                raise ModuleNotFoundError(
                    "No module named %r" % (root,), name=root)
        if len(parts) == 1:
            search = WORKSPACE_SEARCH
        else:
            search = PACKAGE_PATHS.get(fullname.rpartition(".")[0])
            if not search:
                return None
        spec = workspace_lookup(fullname, list(search))
        if spec is None:
            return None
        # Workspace packages are proxied too, so a submission laid out as
        # a package keeps its submodules; the proxy never holds their code.
        is_package = spec.submodule_search_locations is not None
        if is_package:
            PACKAGE_PATHS[fullname] = [
                entry for entry in spec.submodule_search_locations
                if isinstance(entry, str)]
        module_spec = importlib.util.spec_from_loader(
            fullname, WorkspaceLoader(fullname, is_package),
            origin=spec.origin)
        if is_package:
            module_spec.submodule_search_locations = []
        return module_spec


def blind_workspace_entries():
    """Make every ``sys.path`` entry in the workspace find nothing."""
    sys.path_hooks.insert(0, workspace_entry_hook)
    for entry in list(sys.path_importer_cache):
        if isinstance(entry, str) and in_workspace(entry):
            sys.path_importer_cache.pop(entry, None)


blind_workspace_entries()


def block_missing_runner():
    class BlockPytest:
        def find_spec(self, name, path=None, target=None):
            if (name == "pytest" or name.startswith("pytest.")
                    or name == "_pytest" or name.startswith("_pytest.")):
                raise ModuleNotFoundError(
                    "evaluation_runner_unavailable: pytest")
            return None
    sys.meta_path.insert(0, BlockPytest())


def preload_pytest():
    try:
        importlib.import_module("pytest")
    except ImportError:
        block_missing_runner()


if command[0] == "-m":
    if len(command) < 2:
        raise SystemExit(64)
    module = command[1]
    try:
        importlib.import_module(module)
    except ImportError:
        sys.stderr.write("evaluation_runner_unavailable: " + module + "\n")
        raise SystemExit(70)
    sys.meta_path.insert(0, WorkspaceFinder())
    sys.argv = [module, *command[2:]]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
elif command[0] == "-c":
    if len(command) < 2:
        raise SystemExit(64)
    preload_pytest()
    sys.meta_path.insert(0, WorkspaceFinder())
    sys.argv = ["-c", *command[2:]]
    exec(compile(command[1], "<string>", "exec"), {"__name__": "__main__"})
else:
    preload_pytest()
    sys.meta_path.insert(0, WorkspaceFinder())
    sys.argv = command
    runpy.run_path(command[0], run_name="__main__")
'''


def worker_argv(transport: tuple[str, str], workspace: str) -> list[str]:
    """Argv for the restricted worker process."""
    mode, target = transport
    # -I: the worker starts inside the workspace, and its own imports
    # (json, socket, ...) must resolve from the standard library. The
    # workspace is added to sys.path only after they are loaded.
    return ["-I", "-c", WORKER_SOURCE, mode, target, workspace]


def split_bootstrap_argv(
    argv: tuple[str, ...] | list[str], *,
    bootstrap_path: str,
    transport: tuple[str, str],
    workspace: str,
) -> tuple[str, ...]:
    """Route a Python acceptance command through the split bootstrap.

    ``argv`` must already name private files by their staged path (see
    :func:`sis.v3.runner.private_command_spec` with ``bootstrap=False``).
    The proxy is a Python harness, so a command that is not a Python
    interpreter is refused rather than silently mangled: a shell or test
    binary handed the bootstrap would fail as if the submission had.
    """
    mode, target = transport
    items = tuple(argv)
    if not items:
        raise SplitProtocolError("acceptance argv is empty")
    if not is_python_command(items):
        raise SplitProtocolError(
            "split custody requires a Python acceptance command")
    return (items[0], bootstrap_path, mode, target, workspace, *items[1:])


def split_pytest_argv(
    argv: tuple[str, ...] | list[str], *, private_dir: str,
) -> tuple[str, ...]:
    """Pin pytest to evaluator-owned configuration for split custody.

    Without this, pytest would read ``pytest.ini``, ``pyproject.toml`` and
    ``conftest.py`` from the graded workspace: a submission could add
    ``addopts = -p submission_plugin`` and have that plugin imported into
    the process that holds the tests. ``-c`` and ``--confcutdir`` keep
    configuration and conftest discovery inside the private directory.
    ``-c`` also makes it pytest's rootdir: support files staged at their
    repository paths (``tests/__init__.py``, ``tests/conftest.py``) put
    the test in its package (``tests.test_x``), with the private
    directory, never the workspace, on ``sys.path``.
    """
    items = tuple(argv)
    if len(items) >= 3 and items[1] == "-m" and items[2] == "pytest":
        return items + (
            "-c", private_dir.rstrip("/") + "/" + SPLIT_INI_NAME,
            "--confcutdir", private_dir,
            "-p", "no:cacheprovider",
        )
    return items
