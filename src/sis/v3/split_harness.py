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
beside the tests): a workspace cannot shadow a library the tests import.
Only primitives, callables and composites of primitives cross the
socket; any other call result stays in the worker and is referred to by
a handle. The codec is JSON over a closed
type set: submission-produced bytes are never unpickled in the evaluator
process.
"""
from __future__ import annotations

import base64
import builtins
import json
import re
import socket
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


def _raise_remote(error: Any) -> None:
    if not isinstance(error, dict):
        raise RemoteError("worker reported an untyped failure")
    name = error.get("type")
    message = error.get("message")
    if not isinstance(message, str):
        message = ""
    if isinstance(name, str):
        candidate = getattr(builtins, name, None)
        # Only ordinary exceptions cross the boundary: a worker must not be
        # able to raise SystemExit or KeyboardInterrupt in the evaluator.
        if (isinstance(candidate, type)
                and issubclass(candidate, Exception)):
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
                "__subclasscheck__", "__exit__"}:
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
import importlib
import json
import operator
import os
import socket
import sys

MAX_DEPTH = 32
MAX_ITEMS = 10000
MAX_HANDLES = 100000
MAX_CLASSES = 64
MAX_MESSAGE = 8192
# Call results that cannot cross the socket stay here; the evaluator
# refers to them by handle ("#<n>"), never by the callable's path.
HANDLES = {}
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
    if len(HANDLES) >= MAX_HANDLES:
        raise NotEncodable("handles")
    handle = "#%d" % (len(HANDLES) + 1,)
    HANDLES[handle] = value
    return {"t": "ref", "handle": handle}


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
            return {"ok": True, "value": encode(value)}
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
    if name in UNARY and not args:
        return result(UNARY[name](obj), force_ref=name == "__iter__")
    if name in BINARY and len(args) == 1:
        return result(BINARY[name](obj, args[0]))
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
    path = request.get("path")
    if (not isinstance(path, list) or not path
            or not all(isinstance(part, str) for part in path)):
        return {"ok": False,
                "error": {"type": "SplitProtocolError",
                          "message": "invalid path"}}
    if op == "get":
        obj = resolve(path)
        try:
            return {"ok": True, "value": encode(obj)}
        except NotEncodable:
            return {"ok": True, "value": annotate({"t": "ref"}, obj)}
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
            response = handle(request)
        except BaseException as exc:
            response = {"ok": False, "error": describe_error(exc)}
        stream.write(json.dumps(response).encode("utf-8") + b"\n")
        stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
'''


#: Runs as the evaluator principal. It imports the trusted runner and the
#: acceptance tests, and reaches submitted code only through the proxy.
SPLIT_BOOTSTRAP_SOURCE = r'''"""SIS split-custody bootstrap (evaluator-owned, read-only)."""
import builtins
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import json
import os
import runpy
import socket
import sys
import types
import warnings

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
# Local stand-ins for worker exception classes, by (module, qualname).
STAND_INS = {}

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


def request(payload):
    try:
        stream.write(json.dumps(payload).encode("utf-8") + b"\n")
        stream.flush()
        line = stream.readline(MAX_FRAME + 1)
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
        return fetch(list(path) + [name])

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
    return fetch([handle, name])


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


def trusted_class(module, qualname):
    """An Exception class the evaluator already has under this name.

    Builtins, and classes of modules the evaluator itself imported (never
    a proxied workspace module). The lookup is static: nothing is
    imported and no attribute hook runs.
    """
    if module == "builtins":
        candidate = vars(builtins).get(qualname)
    else:
        loaded = sys.modules.get(module)
        root = sys.modules.get(module.split(".")[0])
        if (loaded is None or isinstance(loaded, ProxyModule)
                or isinstance(root, ProxyModule)):
            return None
        candidate = loaded
        for part in qualname.split("."):
            namespace = getattr(candidate, "__dict__", None)
            if not isinstance(namespace, (dict, types.MappingProxyType)):
                return None
            candidate = namespace.get(part)
    if isinstance(candidate, type) and issubclass(candidate, Exception):
        return candidate
    return None


def stand_in(module, qualname, bases, path):
    key = (module, qualname)
    cls = STAND_INS.get(key)
    if cls is not None or len(STAND_INS) >= MAX_STAND_INS:
        return cls
    parts = qualname.split(".")
    if path is None and module and all(part.isidentifier() for part in parts):
        path = [module, *parts]
    namespace = {"__module__": module, "__qualname__": qualname,
                 "__doc__": None, "_sis_remote": key, "_sis_path": path,
                 "__str__": stand_in_str, "__getattr__": stand_in_getattr}
    for candidate in (bases, (Exception,)):
        try:
            cls = RemoteExceptionMeta(parts[-1], candidate, dict(namespace))
        except (TypeError, ValueError):
            continue
        # Only ordinary exceptions exist on this side: never a
        # BaseException a test cannot catch, SystemExit or
        # KeyboardInterrupt.
        if issubclass(cls, Exception):
            STAND_INS[key] = cls
            return cls
    return None


def exception_class(classes, path=None):
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
            path if position == 0 else None)
    return built[0]


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
    name = error.get("type")
    name = name if isinstance(name, str) else "RemoteError"
    message = error.get("message")
    message = message if isinstance(message, str) else ""
    try:
        cls = exception_class(error.get("classes"))
    except Exception:
        cls = None
    if cls is None:
        candidate = vars(builtins).get(name)
        if isinstance(candidate, type) and issubclass(candidate, Exception):
            cls = candidate
    # Only ordinary exceptions cross the boundary: a worker must not be
    # able to raise SystemExit or KeyboardInterrupt in the evaluator.
    if cls is None or not issubclass(cls, Exception):
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
    handle = error.get("handle")
    if (isinstance(handle, str) and handle.startswith("#")
            and handle[1:].isdigit() and len(handle) <= 10):
        exc._sis_handle = handle
    if isinstance(type(exc), RemoteExceptionMeta):
        exc._sis_message = message
    raise exc


class SplitArgumentError(TypeError):
    """A local value that has no form on the wire."""


def is_dunder(name):
    return name.startswith("__") and name.endswith("__")


def result_value(value, path=None):
    """Decode a response value; an object that stayed remote is a Ref.

    ``path`` names an attribute read, which the worker resolves again on
    use. A call or protocol result has no path: the worker keeps it and
    the evaluator refers to it by handle, never by the callable's path
    (that would re-call it on every access).
    """
    if value.get("t") != "ref":
        return decode(value)
    if path is None:
        handle = value.get("handle")
        if (not isinstance(handle, str) or not handle.startswith("#")
                or not handle[1:].isdigit() or len(handle) > 10):
            fail(SPLIT_LOST_EXIT, "evaluation_split_worker_lost")
        path = [handle]
    if value.get("exc") is not None:
        # A worker exception class: a local stand-in, so that
        # pytest.raises(pkg.Error) and ``except pkg.Error`` work.
        cls = exception_class(value.get("exc"), path)
        if cls is not None:
            return cls
    return Ref(path)


def fetch(path):
    response = request({"op": "get", "path": list(path)})
    if not response.get("ok"):
        raise_remote(response.get("error"))
    return result_value(response.get("value") or {}, list(path))


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

    __slots__ = ("_path",)

    def __init__(self, path):
        object.__setattr__(self, "_path", list(path))

    def __getattr__(self, name):
        # Read the attribute in the worker: a plain value (``box.n``)
        # comes back as data, anything else stays a reference.
        if is_dunder(name) and name not in READABLE_DUNDERS:
            raise AttributeError(name)
        return fetch(self._path + [name])

    def __setattr__(self, name, value):
        if is_dunder(name) or name == "_path":
            raise AttributeError(name)
        forward(self._path, "__setattr__", [encode(name), encode(value)])

    def __delattr__(self, name):
        if is_dunder(name) or name == "_path":
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
# The workspace directory a proxied top-level module was found in.
WORKSPACE_ROOTS = {}
_untrusted = {os.path.abspath(entry) for entry in WORKSPACE_SEARCH}
TRUSTED_PATH = [entry for entry in sys.path
                if entry and os.path.abspath(entry) not in _untrusted]
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | frozenset(
    sys.builtin_module_names)


def trusted_module(name):
    """True when the evaluator's own environment provides ``name``.

    The standard library, builtins, installed packages and modules beside
    the acceptance tests always resolve from the evaluator's environment.
    A workspace must never shadow a library the tests import later
    (``numpy``, ``decimal``, ``hypothesis``): the test would then compare
    against values the submission computed in its own process.
    """
    if name in STDLIB:
        return True
    try:
        return importlib.machinery.PathFinder.find_spec(
            name, TRUSTED_PATH) is not None
    except Exception:
        return True


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
        elif trusted_module(root):
            return None
        if len(parts) == 1:
            bases = WORKSPACE_SEARCH
        else:
            bases = [WORKSPACE_ROOTS.get(root, workspace)]
        found = []
        for base in bases:
            search = [os.path.join(base, *parts[:-1])]
            try:
                candidate = importlib.machinery.PathFinder.find_spec(
                    fullname, search)
            except Exception:
                return None
            if candidate is not None:
                found.append((candidate.origin is None, base, candidate))
        if not found:
            return None
        # As the worker's import system does: a regular module or package
        # anywhere on the path wins over a namespace-package directory.
        _namespace, base, spec = min(found, key=lambda item: item[0])
        if len(parts) == 1:
            WORKSPACE_ROOTS[root] = base
        # Workspace packages are proxied too, so a submission laid out as
        # a package keeps its submodules; the proxy never holds their code.
        is_package = spec.submodule_search_locations is not None
        module_spec = importlib.util.spec_from_loader(
            fullname, WorkspaceLoader(fullname, is_package),
            origin=spec.origin)
        if is_package:
            module_spec.submodule_search_locations = []
        return module_spec


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
    """
    items = tuple(argv)
    if len(items) >= 3 and items[1] == "-m" and items[2] == "pytest":
        return items + (
            "-c", private_dir.rstrip("/") + "/" + SPLIT_INI_NAME,
            "--confcutdir", private_dir,
            "-p", "no:cacheprovider",
        )
    return items
