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

Only top-level modules are proxied, and only primitives, callables and
composites of primitives cross the socket. The codec is JSON over a closed
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

    def __getattr__(self, name: str) -> "SplitRef":
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return SplitRef(self._client, self._path + [name])

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self._client.call(self._path, args, kwargs)

    def __repr__(self) -> str:
        return f"<split-ref {'.'.join(self._path)}>"


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
        if not response.get("ok"):
            _raise_remote(response.get("error"))
        value = response.get("value")
        if isinstance(value, dict) and value.get("t") == "ref":
            return SplitRef(self, path)
        return _decode(value)


def _host_encode(value: Any, depth: int = 0) -> dict:
    """Encode evaluator-supplied call arguments for the worker."""
    if depth > MAX_DEPTH:
        raise SplitProtocolError("argument nesting exceeds the bound")
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
            raise SplitProtocolError("argument sequence exceeds the bound")
        return {"t": "list" if isinstance(value, list) else "tuple",
                "v": [_host_encode(item, depth + 1) for item in value]}
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise SplitProtocolError("argument mapping exceeds the bound")
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise SplitProtocolError("argument mapping keys must be text")
            items.append([key, _host_encode(item, depth + 1)])
        return {"t": "dict", "v": items}
    raise SplitProtocolError(
        f"argument type is not transferable: {type(value).__name__}")


#: Runs as the restricted principal. It imports submitted code, so it must
#: never hold the private material directory on its readable path.
WORKER_SOURCE = r'''"""SIS split-custody worker (restricted principal)."""
import base64
import importlib
import json
import os
import socket
import sys

MAX_DEPTH = 32
MAX_ITEMS = 10000


class NotEncodable(Exception):
    pass


def decode(payload):
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
        return base64.b64decode(payload.get("v").encode("ascii"), validate=True)
    if kind in ("list", "tuple"):
        items = [decode(item) for item in payload.get("v") or []]
        return items if kind == "list" else tuple(items)
    if kind == "dict":
        return {item[0]: decode(item[1]) for item in payload.get("v") or []}
    raise ValueError("unknown payload type: %r" % (kind,))


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
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise NotEncodable("mapping")
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotEncodable("key")
            items.append([key, encode(item, depth + 1)])
        return {"t": "dict", "v": items}
    raise NotEncodable("object")


def resolve(path):
    obj = importlib.import_module(path[0])
    for name in path[1:]:
        obj = getattr(obj, name)
    return obj


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
            return {"ok": True, "value": {"t": "ref"}}
    if op == "call":
        obj = resolve(path)
        if not callable(obj):
            return {"ok": False,
                    "error": {"type": "TypeError",
                              "message": "not callable"}}
        args = [decode(item) for item in request.get("args") or []]
        kwargs = {key: decode(item)
                  for key, item in (request.get("kwargs") or {}).items()}
        result = obj(*args, **kwargs)
        try:
            return {"ok": True, "value": encode(result)}
        except NotEncodable:
            return {"ok": True, "value": {"t": "ref"}}
    return {"ok": False,
            "error": {"type": "SplitProtocolError", "message": "unknown op"}}


def main():
    mode, target, workspace = sys.argv[1], sys.argv[2], sys.argv[3]
    sys.path.insert(0, workspace)
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
            response = {"ok": False,
                        "error": {"type": type(exc).__name__,
                                  "message": str(exc)[:400]}}
        stream.write(json.dumps(response).encode("utf-8") + b"\n")
        stream.flush()


if __name__ == "__main__":
    raise SystemExit(main())
'''


#: Runs as the evaluator principal. It imports the trusted runner and the
#: acceptance tests, and reaches submitted code only through the proxy.
SPLIT_BOOTSTRAP_SOURCE = r'''"""SIS split-custody bootstrap (evaluator-owned, read-only)."""
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
    if kind in ("list", "tuple"):
        items = [decode(item, depth + 1) for item in payload.get("v") or []]
        return items if kind == "list" else tuple(items)
    if kind == "dict":
        return {item[0]: decode(item[1], depth + 1)
                for item in payload.get("v") or []}
    raise ValueError("unknown payload type: %r" % (kind,))


def raise_remote(error):
    name = (error or {}).get("type")
    message = (error or {}).get("message") or ""
    candidate = getattr(__builtins__, name, None) if isinstance(
        __builtins__, types.ModuleType) else None
    if candidate is None:
        import builtins
        candidate = getattr(builtins, name, None)
    # Only ordinary exceptions cross the boundary: a worker must not be
    # able to raise SystemExit or KeyboardInterrupt in the evaluator.
    if isinstance(candidate, type) and issubclass(candidate, Exception):
        raise candidate(message)
    raise RuntimeError("%s: %s" % (name, message))


class Ref:
    __slots__ = ("_path",)

    def __init__(self, path):
        self._path = list(path)

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return Ref(self._path + [name])

    def __call__(self, *args, **kwargs):
        response = request({"op": "call", "path": self._path,
                            "args": [encode(item) for item in args],
                            "kwargs": {key: encode(item)
                                       for key, item in kwargs.items()}})
        if not response.get("ok"):
            raise_remote(response.get("error"))
        value = response.get("value") or {}
        if value.get("t") == "ref":
            return Ref(self._path)
        return decode(value)

    def __repr__(self):
        return "<split-ref %s>" % ".".join(self._path)


def encode(value, depth=0):
    if depth > 32:
        raise TypeError("split argument nesting exceeds the bound")
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
        import base64
        return {"t": "bytes",
                "v": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_ITEMS:
            raise TypeError("split argument sequence exceeds the bound")
        return {"t": "list" if isinstance(value, list) else "tuple",
                "v": [encode(item, depth + 1) for item in value]}
    if isinstance(value, dict):
        if len(value) > MAX_ITEMS:
            raise TypeError("split argument mapping exceeds the bound")
        items = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("split argument keys must be text")
            items.append([key, encode(item, depth + 1)])
        return {"t": "dict", "v": items}
    raise TypeError("split argument type is not transferable: %s"
                    % type(value).__name__)


class ProxyModule(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        response = request({"op": "get",
                            "path": [self.__name__, name]})
        if not response.get("ok"):
            raise_remote(response.get("error"))
        value = response.get("value") or {}
        if value.get("t") == "ref":
            return Ref([self.__name__, name])
        return decode(value)


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
        search = [workspace] if len(parts) == 1 else [
            os.path.join(workspace, *parts[:-1])]
        try:
            spec = importlib.machinery.PathFinder.find_spec(fullname, search)
        except Exception:
            return None
        if spec is None:
            return None
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
    return ["-c", WORKER_SOURCE, mode, target, workspace]


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
