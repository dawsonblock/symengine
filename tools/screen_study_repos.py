#!/usr/bin/env python3
"""Screen candidate study repositories for split-custody compatibility.

Choosing study repositories is slow: a correct upstream fix is often
rejected by ``tools/import_study_tasks.py --verify docker`` for a reason a
static scan can predict. This tool reads each repository's test files at
``HEAD`` (through hardened, read-only Git queries; nothing in the
repository is imported or executed) and reports, per repository:

- the layout (``flat`` or ``src``) and the package names under test;
- third-party imports of the tests (and fixtures such as ``mocker``) that
  the base evaluator image (``sis-evaluator:3.3.9``, pytest only) or the
  test-dependency variant (``sis-evaluator:3.3.9-testdeps``) lacks;
  imports guarded by ``try/except ImportError`` or ``importorskip`` are
  listed as optional;
- third-party modules the package itself imports at module level;
- patterns the split-custody proxy cannot support, where package code in
  the worker would have to call back into, or receive a class or
  callable from, the evaluator: a test-defined function, lambda, class
  or instance passed into the package (``key=``, ``callback=``, ...), a
  package decorator applied to a test-defined function
  (``@pkg.cached(...)``), a test class subclassing a package class,
  ``pickle``/``copy`` of a package object, and ``monkeypatch.setattr`` or
  ``mock.patch`` on the package;
- values the split codec cannot carry into the package (it carries
  ``None``, numbers, text, bytes, slices and containers of those): a
  ``range``, generator, iterator, compiled pattern, ``datetime``, path,
  ``StringIO``, ``functools.partial``, ``object()`` sentinel or builtin
  callable (``key=str``);
- what stays in the evaluator process: an expected ``SystemExit``,
  ``KeyboardInterrupt`` or package exception derived from them (they cross
  as ordinary errors), captured output (``capsys``, ``caplog``,
  ``redirect_stdout``), changed ``sys.argv``/``os.environ``/working
  directory, and temporary files (``tmp_path``, ``tempfile``) the worker
  UID cannot read;
- reads of data files beside the tests (the importer ships a hidden test
  with its Python support files only);
- Python 2-era and nose-era APIs that Python 3.12 or pytest 8 removed
  (``assertEquals``, ``assertRaisesRegexp``, nose ``setup``/``teardown``
  methods, ``yield`` tests).

A test module is *clean* when it shows no blocking signal, counting the
support modules it imports (``tests/__init__.py`` mixins, helpers), the
module level of the ``conftest.py`` files above it and the conftest
fixtures it requests. The same rules are applied to the first
``--candidates`` fix candidates the importer would grade (its own
``candidate_commits``/``describe_commit``), each on its fix commit's
version of its one test file. The verdict is coarse and per image:
``likely`` when at least 60% of those candidates are clean (of the test
modules at HEAD when fewer than three candidates exist), ``partial``
from 25%, ``unlikely`` below that, when the package itself imports a
module the image lacks, or when the image installs the repository's own
package (the grader would import that copy, never the submission).
**This is a heuristic, not a verdict on any
task**: only ``--verify docker`` grades a task.

``--sample N`` adds an empirical rate: the first N fix candidates are
graded with the importer's own ``import_repository`` under Docker split
custody (requires Docker and a digest-pinned ``--docker-image``).

Usage:
    PYTHONPATH=src python3 tools/screen_study_repos.py \\
        --repo /study/repos/inflection --repo /study/repos/cachetools \\
        -o /study/diag/screen.json
"""
from __future__ import annotations

import argparse
import ast
import builtins
import importlib.util
import json
import re
import sys
import tempfile
import warnings
from collections import Counter
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sis.v3 import gitquery  # noqa: E402

SCHEMA_VERSION = 1
HEURISTIC_NOTE = (
    "Static heuristic over test files (at HEAD and at the first fix "
    "commits); it predicts, it does not decide. Only "
    "tools/import_study_tasks.py --verify docker grades a task.")
LIKELY_AT = 0.6
PARTIAL_AT = 0.25
#: Modules the base evaluator image provides beyond the standard library.
BASE_IMAGE_MODULES = frozenset({
    "pytest", "_pytest", "pluggy", "iniconfig", "packaging", "pygments"})
#: Modules the ``-testdeps`` variant adds (docker/sandbox/
#: requirements-testdeps.lock), by import name.
TESTDEPS_MODULES = frozenset({
    "hypothesis", "pytest_mock", "pytest_timeout", "freezegun", "yaml",
    "toml", "dateutil", "six", "sortedcontainers"})
#: Fixtures that come from a plugin rather than an import.
PLUGIN_FIXTURES = {"mocker": "pytest_mock", "benchmark": "pytest_benchmark",
                   "freezer": "pytest_freezer"}
#: Python 3.12 still ships these; the host interpreter may not list them.
STDLIB_EXTRA = frozenset({
    "aifc", "audioop", "cgi", "cgitb", "chunk", "crypt", "imghdr",
    "lib2to3", "mailcap", "msilib", "nis", "nntplib", "ossaudiodev",
    "pipes", "sndhdr", "spwd", "sunau", "telnetlib", "uu", "xdrlib"})
#: Removed before or in Python 3.12: an import fails in the image.
STDLIB_REMOVED = frozenset({"imp", "distutils", "asynchat", "asyncore",
                            "smtpd"})
#: unittest aliases that Python 3.12 removed (or Python 2 only).
REMOVED_ASSERTS = frozenset({
    "assertEquals", "assertNotEquals", "assertAlmostEquals",
    "assertNotAlmostEquals", "assert_", "failUnless", "failIf",
    "failUnlessEqual", "failIfEqual", "failUnlessAlmostEqual",
    "failIfAlmostEqual", "failUnlessRaises", "assertRaisesRegexp",
    "assertRegexpMatches", "assertNotRegexpMatches",
    "assertDictContainsSubset", "assertItemsEqual"})
NOSE_HOOKS = frozenset({"setup", "teardown"})
SKIP_DIRS = frozenset({"docs", "doc", "examples", "example", "bench",
                       "benchmarks", "scripts", "tools", "extra", "build",
                       "dist", "site-packages", "venv", ".venv"})
NOT_PACKAGES = frozenset({"setup", "conftest", "noxfile", "tasks",
                          "fabfile", "conf", "runtests", "run_tests"})
CONFIG_SUFFIXES = (".cfg", ".ini", ".toml", ".md", ".rst", ".txt.in",
                   ".pyc", ".pyi", ".typed")
CONFIG_NAMES = frozenset({".coveragerc", ".gitignore", "requirements.txt",
                          "README", "README.md", "README.rst", ".flake8",
                          "__pycache__", "py.typed"})
BLOCKING = ("missing_test_dependency", "callable_into_package",
            "non_data_argument", "package_decorator_on_test_function",
            "subclass_of_package_class", "pickle_or_copy_of_package_object",
            "patches_package", "base_exception_expected",
            "captures_package_output", "evaluator_process_state",
            "evaluator_temp_files", "reads_data_files",
            "removed_python_api", "nose_style_test", "unparseable",
            "package_shadowed_by_image")
#: Call results that the split codec cannot carry into the worker (it
#: carries None, bool, int, float, str, bytes, slices, and lists, tuples,
#: sets and mappings of those; anything else needs a callback).
NON_DATA_CALLS = frozenset({
    "iter", "range", "map", "filter", "zip", "reversed", "enumerate",
    "object", "complex", "memoryview", "open", "re.compile",
    "functools.partial", "collections.deque", "operator.itemgetter",
    "operator.attrgetter", "operator.methodcaller"})
NON_DATA_PREFIXES = ("datetime.", "decimal.", "fractions.", "pathlib.",
                     "uuid.", "ipaddress.", "io.", "itertools.", "array.",
                     "threading.", "weakref.")
#: Builtin classes and functions passed as values (``key=str``).
BUILTIN_CALLABLES = frozenset(
    name for name, value in vars(builtins).items()
    if callable(value) and not name.startswith("_"))
#: Exceptions the split bootstrap never raises in the evaluator: a worker
#: SystemExit or KeyboardInterrupt crosses as an ordinary error.
BASE_EXCEPTIONS = frozenset({"SystemExit", "KeyboardInterrupt",
                             "GeneratorExit", "BaseException"})
#: Fixtures that capture this process's output; the package writes in the
#: worker process.
CAPTURE_FIXTURES = frozenset({"capsys", "capfd", "capsysbinary",
                              "capfdbinary", "caplog"})
#: Fixtures and calls that create files only the evaluator UID can read
#: (pytest's base temp directory and ``tempfile`` results are private).
TEMP_FIXTURES = frozenset({"tmp_path", "tmpdir", "tmp_path_factory",
                           "tmpdir_factory"})
#: Changes to process state that stay in the evaluator process.
PROCESS_STATE_CALLS = frozenset({
    "monkeypatch.setenv", "monkeypatch.delenv", "monkeypatch.chdir",
    "monkeypatch.syspath_prepend", "os.chdir", "os.putenv", "os.unsetenv",
    "time.tzset", "locale.setlocale", "os.environ.update",
    "os.environ.pop", "os.environ.setdefault", "os.environ.clear",
    "os.umask"})
_IDENTIFIER = re.compile(r"[^A-Za-z0-9_.:@-]+")


class ScreenError(RuntimeError):
    """A repository cannot be screened."""


# ---- repository reading --------------------------------------------------- #
def is_test_path(path: str) -> bool:
    """A Python test module by the usual pytest conventions.

    The same rule as ``is_test_path`` in ``tools/import_study_tasks.py``
    (a unit test keeps the two in step), so the screen looks at the files
    the importer would take a hidden test from.
    """
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return False
    name = pure.name
    return (name.startswith("test_") or name.endswith("_test.py")
            or any(part in ("test", "tests") for part in pure.parts[:-1]))


def _is_test_module(path: str) -> bool:
    """A module pytest collects tests from (not a helper or conftest)."""
    name = PurePosixPath(path).name
    return name.endswith(".py") and (
        name.startswith("test_") or name.endswith("_test.py"))


def _in_test_dir(path: str) -> bool:
    return any(part in ("test", "tests")
               for part in PurePosixPath(path).parts[:-1])


def tracked_files(root: Path, rev: str = "HEAD") -> list[str]:
    """Regular files committed at ``rev`` (symlinks, submodules excluded)."""
    listing = gitquery.raw_bytes(root, "ls-tree", "-r", "-z", rev)
    if listing is None:
        raise ScreenError(f"{rev} tree unreadable (is this a Git checkout"
                          " owned by the current user?)")
    paths = []
    for item in listing.split(b"\0"):
        header, _, name = item.partition(b"\t")
        if header.split(b" ")[0] in (b"100644", b"100755") and name:
            paths.append(name.decode("utf-8", "replace"))
    return sorted(paths)


def read_blob(root: Path, path: str, rev: str = "HEAD") -> bytes:
    data = gitquery.raw_bytes(root, "cat-file", "blob", f"{rev}:{path}")
    if data is None:
        raise ScreenError(f"blob unreadable: {rev}:{path}")
    return data


def package_layout(paths: list[str]) -> tuple[str, list[str]]:
    """``(layout, top-level import names of the code under test)``."""
    present = set(paths)

    def top_level(prefix: str) -> set[str]:
        names = set()
        for path in paths:
            if not path.startswith(prefix):
                continue
            parts = PurePosixPath(path[len(prefix):]).parts
            if not parts or parts[0] in SKIP_DIRS or parts[0].startswith("."):
                continue
            if len(parts) == 1 and parts[0].endswith(".py"):
                stem = parts[0][:-3]
                if (stem.isidentifier() and stem not in NOT_PACKAGES
                        and not is_test_path(parts[0])):
                    names.add(stem)
            elif (len(parts) >= 2 and parts[0].isidentifier()
                  and parts[0] not in ("test", "tests")
                  and f"{prefix}{parts[0]}/__init__.py" in present):
                names.add(parts[0])
        return names

    src = top_level("src/")
    if src:
        return "src", sorted(src)
    return "flat", sorted(top_level(""))


# ---- per-module analysis -------------------------------------------------- #
def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


_CONDITIONAL = re.compile(
    r"TYPE_CHECKING|version_info|sys\.platform|\bPY[23]\b|PYPY|"
    r"platform\.|os\.name")


def _import_lines(nodes) -> set[int]:
    return {item.lineno for child in nodes for item in ast.walk(child)
            if isinstance(item, (ast.Import, ast.ImportFrom))}


def _guarded_imports(tree: ast.AST) -> set[int]:
    """Line numbers of imports that need not succeed for the module to load.

    That is an import inside a ``try`` that catches ``ImportError`` (or
    in its handler, the fallback), under an ``if`` on the interpreter
    version, platform or ``TYPE_CHECKING``, or inside a function body
    (it runs, and can fail, only with that one test, which often skips
    itself first).
    """
    lines = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try):
            caught = set()
            for handler in node.handlers:
                if handler.type is None:
                    caught.add("*")
                for item in ast.walk(handler.type) if handler.type else ():
                    if isinstance(item, ast.Name):
                        caught.add(item.id)
            if caught & {"*", "ImportError", "ModuleNotFoundError",
                         "Exception"}:
                lines |= _import_lines(node.body)
                lines |= _import_lines(node.handlers)
        elif isinstance(node, ast.If) and _CONDITIONAL.search(
                ast.unparse(node.test)):
            lines |= _import_lines(node.body) | _import_lines(node.orelse)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lines |= _import_lines(node.body)
    return lines


def imported_modules(tree: ast.AST) -> list[tuple[str, bool, int]]:
    """``(top-level module, optional, line)`` of each absolute import."""
    guarded = _guarded_imports(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((alias.name.split(".")[0],
                              node.lineno in guarded, node.lineno))
        elif isinstance(node, ast.ImportFrom) and not node.level \
                and node.module:
            found.append((node.module.split(".")[0],
                          node.lineno in guarded, node.lineno))
        elif (isinstance(node, ast.Call)
              and _dotted(node.func) == "pytest.importorskip"
              and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)):
            found.append((node.args[0].value.split(".")[0], True,
                          node.lineno))
    return found


def _parse(source: bytes) -> ast.AST:
    # Old sources carry invalid escape sequences; that is not a signal.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return ast.parse(source)


def _yields(function: ast.AST) -> bool:
    """Whether ``function`` itself (not a nested def) is a generator."""
    stack = list(ast.iter_child_nodes(function))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            return True
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.Lambda, ast.ClassDef)):
            stack.extend(ast.iter_child_nodes(node))
    return False


def _is_stdlib(name: str) -> bool:
    return (name in sys.stdlib_module_names or name in STDLIB_EXTRA
            or name == "__future__")


class ModuleScan:
    """Signals of one Python file, from its AST alone."""

    def __init__(self, path: str, source: bytes, *, packages: set[str],
                 local_modules: set[str], package_attrs: set[str],
                 data_names: set[str],
                 base_exceptions: frozenset = frozenset()) -> None:
        self.path = path
        self.base_exceptions = BASE_EXCEPTIONS | base_exceptions
        self.signals: list[dict] = []
        self.imports: dict[str, bool] = {}
        self.import_lines: list[tuple[str, bool, int]] = []
        self.import_specs: list[tuple[int, str | None, list[str]]] = []
        self.fixtures: list[tuple[str, int, int, bool]] = []
        self.arg_names: set[str] = set()
        try:
            self.tree = _parse(source)
        except (SyntaxError, ValueError) as exc:
            self.tree = None
            self._hit("unparseable", getattr(exc, "lineno", 0) or 0,
                      type(exc).__name__)
            return
        self.packages = packages
        self.local_modules = local_modules
        self.package_attrs = package_attrs
        self.data_names = data_names
        self._collect_names()

    def _hit(self, kind: str, line: int, detail: str) -> None:
        self.signals.append({"kind": kind, "path": self.path, "line": line,
                             "detail": detail[:120]})

    # -- name tables ---------------------------------------------------- #
    def _collect_names(self) -> None:
        tree = self.tree
        self.pkg_names: set[str] = set()
        self.aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    bound = alias.asname or top
                    self.aliases[bound] = alias.name if alias.asname else top
                    if top in self.packages:
                        self.pkg_names.add(bound)
            elif isinstance(node, ast.ImportFrom) and node.module \
                    and not node.level:
                top = node.module.split(".")[0]
                for alias in node.names:
                    bound = alias.asname or alias.name
                    self.aliases[bound] = f"{node.module}.{alias.name}"
                    if top in self.packages:
                        self.pkg_names.add(bound)
        self.test_defined: set[str] = set()
        self.test_classes: set[str] = set()
        self.methods: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                self.test_defined.add(node.name)
            if isinstance(node, ast.ClassDef):
                self.test_classes.add(node.name)
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef,
                                         ast.AsyncFunctionDef)):
                        self.methods.add(item.name)
            if isinstance(node, ast.Assign) and isinstance(
                    node.value, ast.Lambda):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.test_defined.add(target.id)
        self.test_defined -= set(self.aliases)
        self.test_classes -= set(self.aliases)
        self.assigned: set[str] = set()
        self.non_data_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = (node.targets if isinstance(node, ast.Assign)
                           else [node.target])
                names = [target.id for target in targets
                         if isinstance(target, ast.Name)]
                self.assigned.update(names)
                if node.value is not None and self._non_data_value(
                        node.value):
                    self.non_data_names.update(names)
            elif isinstance(node, (ast.For, ast.comprehension)) and \
                    isinstance(node.target, ast.Name):
                self.assigned.add(node.target.id)
            elif isinstance(node, ast.arg):
                self.assigned.add(node.arg)
        # Names bound to package objects: flow-insensitive, to a fixpoint.
        for _ in range(4):
            before = len(self.pkg_names)
            for node in ast.walk(tree):
                targets, value = (), None
                if isinstance(node, ast.Assign):
                    targets, value = node.targets, node.value
                elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) \
                        and node.value is not None:
                    targets, value = (node.target,), node.value
                elif isinstance(node, (ast.With, ast.AsyncWith)):
                    for item in node.items:
                        if item.optional_vars is not None and self.rooted(
                                item.context_expr):
                            targets += (item.optional_vars,)
                    value = None
                    for target in targets:
                        if isinstance(target, ast.Name):
                            self.pkg_names.add(target.id)
                    continue
                if value is not None and self.rooted(value):
                    for target in targets:
                        if isinstance(target, ast.Name):
                            self.pkg_names.add(target.id)
                            self.test_defined.discard(target.id)
            if len(self.pkg_names) == before:
                break

    def rooted(self, node: ast.AST) -> bool:
        """Whether ``node`` evaluates to (or from) a package object."""
        while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call,
                                ast.Starred)):
            if (isinstance(node, ast.Attribute)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in ("self", "cls")
                    and node.attr in self.package_attrs):
                return True
            if isinstance(node, ast.Call):
                node = node.func
            else:
                node = node.value
        return isinstance(node, ast.Name) and node.id in self.pkg_names

    def class_attrs(self) -> set[str]:
        """Class-level attributes bound to package objects (``Cache = ...``)."""
        names = set()
        if self.tree is None:
            return names
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for item in node.body:
                if isinstance(item, ast.Assign) and self.rooted(item.value):
                    names.update(target.id for target in item.targets
                                 if isinstance(target, ast.Name))
        return names

    def _resolve(self, node: ast.AST) -> str:
        """The dotted name a callee or value spells, through import aliases."""
        dotted = _dotted(node) or ""
        if not dotted:
            return ""
        first, _, rest = dotted.partition(".")
        base = self.aliases.get(first, first)
        return base + ("." + rest if rest else "")

    def _non_data_value(self, node: ast.AST) -> str | None:
        """Describe ``node`` if the split codec cannot carry its value."""
        if isinstance(node, ast.GeneratorExp):
            return "generator"
        if isinstance(node, ast.Constant):
            return ("complex" if isinstance(node.value, complex) else
                    "Ellipsis" if node.value is Ellipsis else None)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for item in node.elts:
                found = self._non_data_value(item)
                if found:
                    return found
            return None
        if isinstance(node, ast.Dict):
            for item in [*node.keys, *node.values]:
                found = item is not None and self._non_data_value(item)
                if found:
                    return found
            return None
        if self.rooted(node):
            return None
        if isinstance(node, ast.Call):
            name = self._resolve(node.func)
            if name in NON_DATA_CALLS or name.startswith(NON_DATA_PREFIXES):
                return f"{name}(...)"
            return None
        if isinstance(node, ast.Name):
            if node.id in self.non_data_names:
                return node.id
            if (node.id in BUILTIN_CALLABLES and node.id not in self.assigned
                    and node.id not in self.aliases
                    and node.id not in self.test_defined):
                return node.id
            return None
        if isinstance(node, ast.Attribute):
            name = self._resolve(node)
            if name.startswith(NON_DATA_PREFIXES):
                return name
        return None

    def _test_object(self, node: ast.AST) -> str | None:
        """Describe ``node`` if it is a test-defined callable or object."""
        if isinstance(node, ast.Lambda):
            return "lambda"
        if isinstance(node, ast.Name) and node.id in self.test_defined:
            return node.id
        if (isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and node.value.id in ("self", "cls")
                and node.attr in self.methods):
            return f"{node.value.id}.{node.attr}"
        if isinstance(node, ast.Call):
            # An instance of a test-defined class (a callable object, a
            # key or a sentinel the package would call back into). The
            # result of a test helper function is not judged.
            if isinstance(node.func, ast.Name) \
                    and node.func.id in self.test_classes:
                return f"{node.func.id}()"
            if _dotted(node.func) in ("functools.partial", "partial"):
                for arg in node.args[:1]:
                    inner = self._test_object(arg)
                    if inner:
                        return f"partial({inner})"
        return None

    # -- signals -------------------------------------------------------- #
    def scan(self, *, test_module: bool) -> "ModuleScan":
        if self.tree is None:
            return self
        for name, optional, line in imported_modules(self.tree):
            if name in self.local_modules or name in self.packages:
                continue
            if name in STDLIB_REMOVED:
                self._hit("removed_python_api", line, f"import {name}")
                continue
            if _is_stdlib(name):
                continue
            self._import(name, optional, line)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                self.import_specs.extend(
                    (0, alias.name, []) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                self.import_specs.append(
                    (node.level, node.module,
                     [alias.name for alias in node.names]))
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                text = " ".join(ast.unparse(item)
                                for item in node.decorator_list)
                if "fixture" in text:
                    self.fixtures.append(
                        (node.name, node.lineno,
                         node.end_lineno or node.lineno,
                         "autouse=True" in text.replace(" ", "")))
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._function(node, test_module=test_module)
            elif isinstance(node, ast.ClassDef):
                self._class(node, test_module=test_module)
            elif isinstance(node, ast.Call):
                self._call(node)
            elif (isinstance(node, ast.Attribute)
                  and node.attr in REMOVED_ASSERTS
                  and isinstance(node.value, ast.Name)
                  and node.value.id in ("self", "cls", "unittest")):
                self._hit("removed_python_api", node.lineno,
                          f"{node.value.id}.{node.attr}")
            elif (isinstance(node, (ast.Assign, ast.AugAssign))
                  and self.pkg_names):
                targets = (node.targets if isinstance(node, ast.Assign)
                           else [node.target])
                for target in targets:
                    text = ast.unparse(target)
                    if re.match(r"(sys\.(argv|path|stdin|stdout|stderr)|"
                                r"os\.environ\[)", text):
                        self._hit("evaluator_process_state", node.lineno,
                                  f"{text} = ...")
            elif isinstance(node, ast.ExceptHandler) and node.type:
                names = [_dotted(item) or "" for item in (
                    node.type.elts if isinstance(node.type, ast.Tuple)
                    else [node.type])]
                hit = [name for name in names
                       if name.rsplit(".", 1)[-1] in self.base_exceptions
                       and name.rsplit(".", 1)[-1] != "BaseException"]
                if hit and self.pkg_names:
                    self._hit("base_exception_expected", node.lineno,
                              f"except {', '.join(hit)}")
            elif isinstance(node, ast.Name) and node.id == "__file__":
                self._file_relative = min(
                    node.lineno, getattr(self, "_file_relative", None)
                    or node.lineno)
            elif (isinstance(node, ast.Constant)
                  and isinstance(node.value, str) and self.data_names
                  and any(part in self.data_names
                          for part in re.split(r"[\\/]", node.value))):
                self._hit("reads_data_files", node.lineno,
                          f"names {node.value!r}")
        if getattr(self, "_file_relative", None) and self.data_names:
            self._hit("reads_data_files", self._file_relative,
                      "path relative to __file__ beside data files")
        return self

    def _import(self, name: str, optional: bool, line: int) -> None:
        self.imports[name] = self.imports.get(name, True) and optional
        self.import_lines.append((name, optional, line))

    def _function(self, node, *, test_module: bool) -> None:
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) \
                else decorator
            if self.rooted(target):
                self._hit("package_decorator_on_test_function",
                          node.lineno, f"@{ast.unparse(target)} on "
                                       f"{node.name}")
            dotted = _dotted(target) or ""
            if dotted.endswith("mark.timeout"):
                self._import("pytest_timeout", False, node.lineno)
        for arg in node.args.args + node.args.kwonlyargs:
            self.arg_names.add(arg.arg)
            module = PLUGIN_FIXTURES.get(arg.arg)
            if module:
                self._import(module, False, node.lineno)
            if arg.arg in CAPTURE_FIXTURES and self.pkg_names:
                self._hit("captures_package_output", node.lineno,
                          f"{node.name}({arg.arg})")
            if arg.arg in TEMP_FIXTURES and self.pkg_names:
                self._hit("evaluator_temp_files", node.lineno,
                          f"{node.name}({arg.arg})")
        if test_module and node.name.startswith("test") \
                and _yields(node):
            self._hit("nose_style_test", node.lineno,
                      f"yield test {node.name}")
        if test_module and node.name in NOSE_HOOKS \
                and node.col_offset == 0:
            self._hit("nose_style_test", node.lineno,
                      f"module-level {node.name}()")

    def _class(self, node: ast.ClassDef, *, test_module: bool) -> None:
        for base in node.bases:
            if self.rooted(base):
                self._hit("subclass_of_package_class", node.lineno,
                          f"class {node.name}({ast.unparse(base)})")
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) \
                else decorator
            if self.rooted(target):
                self._hit("package_decorator_on_test_function",
                          node.lineno, f"@{ast.unparse(target)} on "
                                       f"class {node.name}")
        if test_module:
            for item in node.body:
                if isinstance(item, ast.FunctionDef) \
                        and item.name in NOSE_HOOKS:
                    self._hit("nose_style_test", item.lineno,
                              f"{node.name}.{item.name}()")

    def _call(self, node: ast.Call) -> None:
        dotted = _dotted(node.func) or ""
        full = self._resolve(node.func)
        if self.pkg_names:
            self._state_call(node, dotted, full)
        if (dotted.endswith(("raises", "assertRaises", "assertRaisesRegex",
                             "assertRaisesRegexp")) and node.args):
            names = [_dotted(item) or "" for item in (
                node.args[0].elts if isinstance(node.args[0], ast.Tuple)
                else [node.args[0]])]
            hit = [name for name in names
                   if name.rsplit(".", 1)[-1] in self.base_exceptions]
            if hit:
                self._hit("base_exception_expected", node.lineno,
                          f"{dotted}({', '.join(hit)})")
        if full in ("pickle.dumps", "pickle.dump", "pickle.loads",
                    "copy.copy", "copy.deepcopy", "copy.replace"):
            if any(self.rooted(arg) for arg in node.args):
                self._hit("pickle_or_copy_of_package_object", node.lineno,
                          f"{full}({ast.unparse(node.args[0])[:60]})")
            return
        if dotted.endswith(".setattr") or dotted.endswith(".setitem") \
                or dotted.endswith(".delattr"):
            if dotted.split(".")[0] == "monkeypatch" and node.args:
                first = node.args[0]
                if self.rooted(first) or self._names_package(first):
                    self._hit("patches_package", node.lineno,
                              f"{dotted}({ast.unparse(first)[:60]}, ...)")
                return
        if full.startswith(("unittest.mock.patch", "mock.patch")) \
                or dotted in ("patch", "patch.object", "patch.dict"):
            first = node.args[0] if node.args else None
            if first is not None and (self.rooted(first)
                                      or self._names_package(first)):
                self._hit("patches_package", node.lineno,
                          f"{dotted}({ast.unparse(first)[:60]})")
            return
        if not self.rooted(node.func):
            return
        for value in [*node.args, *(item.value for item in node.keywords)]:
            keyword = next((item.arg for item in node.keywords
                            if item.value is value), None)
            what = self._test_object(value)
            if what is not None:
                label = f"{keyword}={what}" if keyword else what
                self._hit("callable_into_package", node.lineno,
                          f"{ast.unparse(node.func)[:50]}({label})")
                break
            what = self._non_data_value(value)
            if what is not None:
                label = f"{keyword}={what}" if keyword else what
                self._hit("non_data_argument", node.lineno,
                          f"{ast.unparse(node.func)[:50]}({label})")
                break

    def _state_call(self, node: ast.Call, dotted: str, full: str) -> None:
        """Output capture, process state and private temporary files."""
        if full in ("contextlib.redirect_stdout",
                    "contextlib.redirect_stderr"):
            self._hit("captures_package_output", node.lineno, full)
        elif full in PROCESS_STATE_CALLS or dotted in PROCESS_STATE_CALLS:
            self._hit("evaluator_process_state", node.lineno, dotted)
        elif dotted.endswith("setattr") and len(node.args) >= 2:
            target = " ".join(ast.unparse(item) for item in node.args[:2])
            if re.search(r"\bsys\b.*argv|sys\.argv|\bsys\b.*stdin", target):
                self._hit("evaluator_process_state", node.lineno,
                          f"{dotted}({target[:50]})")
        elif (full.startswith(("unittest.mock.patch", "mock.patch"))
              or dotted.startswith("patch")) and node.args:
            target = ast.unparse(node.args[0])
            if re.search(r"sys\.(argv|stdout|stderr|stdin)|os\.environ|"
                         r"^sys$", target.strip("'\"")):
                self._hit("evaluator_process_state", node.lineno,
                          f"{dotted}({target[:50]})")
        elif full.startswith("tempfile.") and full.rsplit(".", 1)[-1] in (
                "mkdtemp", "mkstemp", "NamedTemporaryFile",
                "TemporaryDirectory", "TemporaryFile",
                "SpooledTemporaryFile"):
            self._hit("evaluator_temp_files", node.lineno, full)

    def _names_package(self, node: ast.AST) -> bool:
        return (isinstance(node, ast.Constant) and isinstance(node.value, str)
                and node.value.split(".")[0] in self.packages)


# ---- repository screening ------------------------------------------------- #
def _data_names(paths: list[str]) -> set[str]:
    """Names of data files and data directories inside test directories."""
    names = set()
    for path in paths:
        pure = PurePosixPath(path)
        if not _in_test_dir(path) or pure.suffix == ".py":
            continue
        if pure.name in CONFIG_NAMES or pure.name.endswith(CONFIG_SUFFIXES):
            continue
        if "__pycache__" in pure.parts:
            continue
        names.add(pure.name)
        # Directories between the test directory and the file
        # (``tests/compliance/basic.json`` -> ``compliance``).
        last = max(index for index, part in enumerate(pure.parts[:-1])
                   if part in ("test", "tests"))
        names.update(pure.parts[last + 1:-1])
    return names


def _helper_paths(path: str, specs, helpers: set[str]) -> set[str]:
    """Support modules that the import statements of ``path`` name."""
    found = set()
    here = PurePosixPath(path).parent

    def add(stem: str, *, suffix_match: bool) -> None:
        for candidate in (stem + ".py", stem + "/__init__.py"):
            candidate = candidate.removeprefix("./")
            for helper in helpers:
                if helper == candidate or (
                        suffix_match and helper.endswith("/" + candidate)):
                    found.add(helper)

    for level, module, names in specs:
        if level:
            base = here
            for _ in range(level - 1):
                base = base.parent
            prefix = base.joinpath(*module.split(".")) if module else base
            add(prefix.as_posix(), suffix_match=False)
            for name in names:
                add(prefix.joinpath(name).as_posix(), suffix_match=False)
        elif module:
            parts = module.split(".")
            for depth in range(1, len(parts) + 1):
                add("/".join(parts[:depth]), suffix_match=True)
            for name in names:
                add("/".join([*parts, name]), suffix_match=True)
    return found


class TreeAnalysis:
    """Per-module blocking signals of the test files of one commit."""

    def __init__(self, root: Path, rev: str) -> None:
        paths = tracked_files(root, rev)
        self.layout, self.packages = package_layout(paths)
        self.python_tests = [path for path in paths if is_test_path(path)]
        sources = {path: read_blob(root, path, rev)
                   for path in self.python_tests}
        # Of the top-level modules, the code under test is what the tests
        # import (a root-level build script is not), when that is known.
        imported = set()
        for data in sources.values():
            try:
                imported |= {name for name, _, _ in
                             imported_modules(_parse(data))}
            except (SyntaxError, ValueError):
                continue
        if set(self.packages) & imported:
            self.packages = sorted(set(self.packages) & imported)
        package_set = set(self.packages)
        self.modules = [path for path in self.python_tests
                        if _is_test_module(path)]
        self.support = [path for path in self.python_tests
                        if path not in self.modules]
        local = {PurePosixPath(path).stem for path in self.python_tests}
        local |= {part for path in self.python_tests
                  for part in PurePosixPath(path).parts[:-1]}
        local |= {PurePosixPath(path).parts[0] for path in paths
                  if len(PurePosixPath(path).parts) > 1}
        local |= {PurePosixPath(path).stem for path in paths
                  if "/" not in path and path.endswith(".py")}
        self.data_names = _data_names(paths)

        self.runtime, base_exceptions = self._package_facts(
            root, rev, paths, package_set, local)

        def scanner(path, attrs):
            return ModuleScan(path, sources[path], packages=package_set,
                              local_modules=local, package_attrs=attrs,
                              data_names=self.data_names,
                              base_exceptions=base_exceptions)

        # Class attributes bound to package classes anywhere in the tests
        # (``Cache = cachetools.LRUCache``) make ``self.Cache``
        # package-rooted in the mixins that use it.
        attrs: set[str] = set()
        for path in self.python_tests:
            attrs |= scanner(path, set()).class_attrs()
        self.scans = {path: scanner(path, attrs).scan(
            test_module=path in self.modules) for path in self.python_tests}

    def _package_facts(self, root, rev, paths, package_set, local):
        """The package's module-level third-party imports, and its classes
        that derive from ``SystemExit``/``KeyboardInterrupt``/``BaseException``
        rather than ``Exception``."""
        runtime: Counter = Counter()
        bases: dict[str, set[str]] = {}
        for path in paths:
            pure = PurePosixPath(path)
            if pure.suffix != ".py" or is_test_path(path):
                continue
            parts = pure.parts[1:] if self.layout == "src" else pure.parts
            if not parts or parts[0].removesuffix(".py") not in package_set:
                continue
            try:
                tree = _parse(read_blob(root, path, rev))
            except (SyntaxError, ValueError):
                continue
            for name, optional, _ in imported_modules(tree):
                if (not optional and name not in package_set
                        and name not in local and not _is_stdlib(name)
                        and name not in STDLIB_REMOVED):
                    runtime[name] += 1
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases.setdefault(node.name, set()).update(
                        (_dotted(base) or "").rsplit(".", 1)[-1]
                        for base in node.bases)
        derived = set()
        while True:
            grown = {name for name, parents in bases.items()
                     if parents & (BASE_EXCEPTIONS | derived)} - derived
            if not grown:
                return runtime, frozenset(derived)
            derived |= grown

    def evidence(self, path: str) -> tuple[list[dict], dict[str, bool]]:
        """Signals and imports that decide whether ``path`` can be graded.

        A module carries its own signals, all of those of the support
        modules it imports (transitively), the module level of every
        ``conftest.py`` above it, and the conftest fixtures it requests
        or that are autouse.
        """
        scan = self.scans[path]
        signals = list(scan.signals)
        imports: dict[str, bool] = {}

        def merge(items) -> None:
            for name, optional in items:
                imports[name] = imports.get(name, True) and optional

        merge((name, optional) for name, optional, _ in scan.import_lines)
        helpers = {item for item in self.support
                   if PurePosixPath(item).name != "conftest.py"}
        queue, seen = [path], {path}
        while queue:
            current = queue.pop()
            for helper in _helper_paths(
                    current, self.scans[current].import_specs, helpers):
                if helper in seen:
                    continue
                seen.add(helper)
                queue.append(helper)
                signals.extend(self.scans[helper].signals)
                merge(self.scans[helper].imports.items())
        scope = PurePosixPath(path).parent
        wanted = scan.arg_names
        for helper in self.support:
            pure = PurePosixPath(helper)
            if pure.name != "conftest.py" or not (
                    pure.parent == scope or pure.parent in scope.parents):
                continue
            conftest = self.scans[helper]

            uses = any(autouse or name in wanted
                       for name, _, _, autouse in conftest.fixtures)

            def applies(line: int, conftest=conftest) -> bool:
                for name, first, last, autouse in conftest.fixtures:
                    if first <= line <= last:
                        return autouse or name in wanted
                return True

            # A data path computed at conftest module level matters only
            # to a module that requests one of its fixtures.
            signals.extend(
                item for item in conftest.signals
                if (uses if item["kind"] == "reads_data_files"
                    else applies(item["line"])))
            merge((name, optional) for name, optional, line
                  in conftest.import_lines if applies(line))
        return signals, imports

    def blocking(self, path: str, available: frozenset) -> set[str]:
        """Blocking signal kinds of ``path`` for an image's module set."""
        signals, imports = self.evidence(path)
        kinds = {item["kind"] for item in signals} & set(BLOCKING)
        if _missing(imports, available):
            kinds.add("missing_test_dependency")
        if any(name not in available for name in self.runtime):
            kinds.add("package_runtime_dependency")
        if set(self.packages) & available:
            # The image installs the repository's own package: the split
            # grader imports that copy (trusted_spec), never the submission.
            kinds.add("package_shadowed_by_image")
        return kinds


def _missing(imports: dict[str, bool], available: frozenset) -> list[str]:
    return sorted(name for name, optional in imports.items()
                  if not optional and name not in available)


PROFILES = {"base": BASE_IMAGE_MODULES,
            "testdeps": BASE_IMAGE_MODULES | TESTDEPS_MODULES}


def screen_repository(root: Path, *, candidates: int = 0,
                      max_scan: int = 500, importer=None) -> dict:
    """Static split-custody screen of one repository.

    The signals are read from the test files at HEAD. With ``candidates``
    and the importer, the first fix candidates the importer would try are
    screened too, each on its fix commit's version of its one test file,
    and the verdict rests on them.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise ScreenError("repository path is not a directory")
    head = gitquery.query(root, "rev-parse", "HEAD")
    if head is None:
        raise ScreenError("HEAD unreadable (is this a Git checkout owned by"
                          " the current user?)")
    tree = TreeAnalysis(root, "HEAD")
    modules = tree.modules
    images = {}
    for profile, available in PROFILES.items():
        clean = [path for path in modules
                 if not tree.blocking(path, available)]
        images[profile] = {
            "head_clean_test_modules": len(clean),
            "head_clean_fraction": round(
                len(clean) / len(modules), 3) if modules else 0.0,
            "package_runtime_missing": sorted(
                name for name in tree.runtime if name not in available),
            "package_shadowed": sorted(set(tree.packages) & available),
        }
    blocked_by: Counter = Counter()
    per_module = {}
    for path in modules:
        kinds = tree.blocking(path, BASE_IMAGE_MODULES)
        blocked_by.update(kinds)
        per_module[path] = sorted(kinds)
    all_signals = [item for scan in tree.scans.values()
                   for item in scan.signals]
    imports_all: dict[str, bool] = {}
    for scan in tree.scans.values():
        for name, optional in scan.imports.items():
            imports_all[name] = imports_all.get(name, True) and optional
    examples: dict[str, list[str]] = {}
    for item in all_signals:
        bucket = examples.setdefault(item["kind"], [])
        if len(bucket) < 3:
            bucket.append(f"{item['path']}:{item['line']} {item['detail']}")
    report = {
        "repository": root.name,
        "path": str(root),
        "head": head,
        "layout": tree.layout,
        "packages": tree.packages,
        "test_modules": len(modules),
        "support_modules": len(tree.support),
        "test_imports": {
            "third_party": sorted(name for name in imports_all
                                  if name not in BASE_IMAGE_MODULES),
            "missing_in_base_image": _missing(
                imports_all, PROFILES["base"]),
            "missing_in_testdeps_image": _missing(
                imports_all, PROFILES["testdeps"]),
            "optional": sorted(name for name, optional in imports_all.items()
                               if optional),
        },
        "package_runtime_imports": sorted(tree.runtime),
        "data_files_beside_tests": sorted(tree.data_names)[:20],
        "signal_counts": dict(sorted(Counter(
            item["kind"] for item in all_signals).items())),
        "modules_blocked_by": dict(sorted(blocked_by.items())),
        "module_blockers": per_module,
        "examples": examples,
        "fix_candidates": (
            _screen_candidates(root, importer, candidates, max_scan)
            if importer is not None and candidates > 0 else None),
        "images": images,
    }
    for profile in PROFILES:
        _decide(report, profile)
    report["verdict"] = images["base"]["verdict"]
    report["verdict_basis"] = images["base"]["verdict_basis"]
    report["reasons"] = images["base"]["reasons"]
    return report


def _screen_candidates(root: Path, importer, count: int,
                       max_scan: int) -> dict:
    """Screen the first fix candidates on their fix commits' test files."""
    rows = []
    trees: dict[str, TreeAnalysis] = {}
    for commit, test_path in fix_candidates(importer, root, count,
                                            max_scan=max_scan):
        analysis = trees.setdefault(commit, TreeAnalysis(root, commit))
        row = {"commit": commit[:12], "test_path": test_path}
        for profile, available in PROFILES.items():
            row[profile] = sorted(analysis.blocking(test_path, available))
        rows.append(row)
    return {"screened": len(rows), "rows": rows}


#: Fewer screened fix candidates than this and the verdict uses HEAD.
MIN_CANDIDATES = 3


def _decide(report: dict, profile: str) -> None:
    """Attach the coarse verdict and its reasons for one image profile."""
    image = report["images"][profile]
    total = report["test_modules"]
    runtime = image["package_runtime_missing"]
    candidates = report["fix_candidates"]
    reasons = []
    if candidates and candidates["screened"] >= MIN_CANDIDATES:
        screened = candidates["screened"]
        clean = sum(1 for row in candidates["rows"] if not row[profile])
        fraction = clean / screened
        basis = "fix_candidates"
        reasons.append(f"{clean}/{screened} fix candidates' test files"
                       " show no blocking signal")
        counts = Counter(kind for row in candidates["rows"]
                         for kind in row[profile])
        reasons += [f"{kind} in {count}/{screened} candidates"
                    for kind, count in counts.most_common()]
        reasons.append(f"HEAD: {image['head_clean_test_modules']}/{total}"
                       " test modules clean")
    else:
        fraction = image["head_clean_fraction"]
        basis = "head"
        if not total:
            reasons.append("no test modules at HEAD")
        else:
            reasons.append(f"{image['head_clean_test_modules']}/{total} test"
                           " modules at HEAD show no blocking signal")
        if profile == "base":
            reasons += [f"{kind} in {count}/{total} modules"
                        for kind, count in sorted(
                            report["modules_blocked_by"].items(),
                            key=lambda item: (-item[1], item[0]))]
    shadowed = image.get("package_shadowed") or []
    if shadowed:
        reasons.append("the image installs the repository's own package: "
                       + ", ".join(shadowed) + "; the grader would import"
                       " the installed copy, never the submission")
    if runtime:
        reasons.append("the package imports modules the image lacks: "
                       + ", ".join(runtime))
    missing = report["test_imports"][
        "missing_in_base_image" if profile == "base"
        else "missing_in_testdeps_image"]
    if missing:
        reasons.append("third-party test imports the image lacks: "
                       + ", ".join(missing))
    if not total or runtime or shadowed or fraction < PARTIAL_AT:
        verdict = "unlikely"
    elif fraction >= LIKELY_AT:
        verdict = "likely"
    else:
        verdict = "partial"
    image.update({"verdict": verdict, "verdict_basis": basis,
                  "clean_fraction": round(fraction, 3), "reasons": reasons})


# ---- optional empirical sample ------------------------------------------- #
def _load_importer():
    path = Path(__file__).resolve().parent / "import_study_tasks.py"
    spec = importlib.util.spec_from_file_location(
        "sis_tool_import_study_tasks", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fix_candidates(importer, root: Path, count: int, *,
                   max_scan: int) -> list[tuple[str, str]]:
    """``(commit, test path)`` of the first ``count`` commits the importer
    would grade, chosen by its own ``candidate_commits`` and
    ``describe_commit`` (the fix pattern, one test file, a source change).
    """
    pattern = re.compile(importer.DEFAULT_FIX_PATTERN)
    head = gitquery.query(root, "rev-parse", "HEAD")
    chosen = []
    for commit in importer.candidate_commits(root, max_scan=max_scan,
                                             explicit=None):
        if len(chosen) >= count:
            break
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                info = importer.describe_commit(
                    root, commit, fix_pattern=pattern)
        except Exception:  # noqa: BLE001 - not a candidate
            continue
        if gitquery.predicate(root, "merge-base", "--is-ancestor",
                              info["parent"], head):
            chosen.append((commit, info["test_path"]))
    return chosen


def sample_repository(root: Path, count: int, *, docker_image: str | None,
                      split_user: str | None, allow_unpinned: bool,
                      timeout: int, max_scan: int, importer=None,
                      executor_factory=None) -> dict:
    """Grade the first ``count`` fix candidates with the importer."""
    importer = importer or _load_importer()
    commits = [commit for commit, _ in fix_candidates(
        importer, root, count, max_scan=max_scan)]
    if not commits:
        return {"candidates": 0, "accepted": 0, "acceptance_rate": None,
                "rejected": []}
    repository_id = _IDENTIFIER.sub("-", root.name).strip("-") or "repo"
    with tempfile.TemporaryDirectory(prefix="sis-screen-") as temp:
        argv = ["--repo", str(root), "--repository-id", repository_id,
                "--partition", "holdout", "--hidden-dir",
                str(Path(temp) / "hidden"), "--verify", "docker",
                "--timeout", str(timeout), "--output",
                str(Path(temp) / "fragment.json"), "--commits", *commits]
        if docker_image:
            argv += ["--docker-image", docker_image]
        if split_user:
            argv += ["--docker-split-user", split_user]
        if allow_unpinned:
            argv.append("--allow-unpinned-image")
        args = importer.parser().parse_args(argv)
        fragment = importer.import_repository(
            args, executor_factory=executor_factory)
    accepted = [task["source"]["fix_commit"] for task in fragment["tasks"]]
    return {
        "candidates": len(commits),
        "accepted": len(accepted),
        "acceptance_rate": round(len(accepted) / len(commits), 3),
        "accepted_commits": accepted,
        "rejected": [{"commit": item["commit"][:12],
                      "reason": item["reason"][:200]}
                     for item in fragment["rejected"]],
    }


# ---- output ---------------------------------------------------------------- #
def table(reports: list[dict]) -> str:
    """A short fixed-width summary, one row per repository."""
    header = ("repository", "layout", "head", "cands", "base", "testdeps",
              "sample", "main blockers")
    rows = [header]
    for report in reports:
        if "error" in report:
            rows.append((report["repository"], "-", "-", "-", "error", "-",
                         "-", report["error"][:70]))
            continue
        base = report["images"]["base"]
        candidates = report.get("fix_candidates")
        if candidates and candidates["screened"]:
            clean = sum(1 for row in candidates["rows"] if not row["base"])
            cands = f"{clean}/{candidates['screened']}"
            counts = Counter(kind for row in candidates["rows"]
                             for kind in row["base"])
        else:
            cands = "-"
            counts = Counter(report["modules_blocked_by"])
        sample = report.get("sample")
        sample_text = ("-" if not sample else
                       f"{sample['accepted']}/{sample['candidates']}")
        top = ", ".join(f"{kind}({count})" for kind, count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0]))[:3])
        rows.append((
            report["repository"], report["layout"],
            f"{base['head_clean_test_modules']}/{report['test_modules']}",
            cands, base["verdict"], report["images"]["testdeps"]["verdict"],
            sample_text, top or "none"))
    widths = [max(len(row[index]) for row in rows)
              for index in range(len(header) - 1)]
    return "\n".join(
        "  ".join(cell.ljust(width) for cell, width in zip(row, widths))
        + "  " + row[-1] for row in rows)


LEGEND = ("head: clean test modules at HEAD; cands: clean fix candidates"
          " (each on its fix commit's test file); base/testdeps: verdict for"
          " sis-evaluator:3.3.9 and :3.3.9-testdeps; sample: accepted under"
          " --verify docker.")


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", action="append", required=True, type=Path,
                   help="repository checkout to screen (repeatable)")
    p.add_argument("--output", "-o", type=Path,
                   help="write the JSON report here")
    p.add_argument("--candidates", type=int, default=10, metavar="K",
                   help="statically screen the first K fix candidates on"
                        " their fix commits (0: HEAD only; default 10)")
    p.add_argument("--sample", type=int, default=0, metavar="N",
                   help="also grade the first N fix candidates per"
                        " repository with import_study_tasks --verify"
                        " docker")
    p.add_argument("--docker-image",
                   help="digest-pinned evaluator image for --sample")
    p.add_argument("--docker-split-user")
    p.add_argument("--allow-unpinned-image", action="store_true")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--max-scan", type=int, default=500)
    p.add_argument("--json", action="store_true",
                   help="print the JSON report instead of the table")
    return p


def main(argv=None, *, executor_factory=None) -> int:
    args = parser().parse_args(argv)
    if args.sample < 0 or args.candidates < 0:
        print("screen_study_repos: --sample and --candidates must be >= 0",
              file=sys.stderr)
        return 2
    importer = (_load_importer() if args.sample or args.candidates
                else None)
    reports = []
    for repo in args.repo:
        try:
            report = screen_repository(
                repo, candidates=args.candidates, max_scan=args.max_scan,
                importer=importer)
            if args.sample:
                report["sample"] = sample_repository(
                    Path(repo).resolve(), args.sample,
                    docker_image=args.docker_image,
                    split_user=args.docker_split_user,
                    allow_unpinned=args.allow_unpinned_image,
                    timeout=args.timeout, max_scan=args.max_scan,
                    importer=importer, executor_factory=executor_factory)
        except (ScreenError, OSError, ValueError) as exc:
            report = {"repository": Path(repo).name, "path": str(repo),
                      "error": str(exc)}
        reports.append(report)
    document = {
        "schema_version": SCHEMA_VERSION,
        "kind": "study_repository_screen",
        "heuristic": True,
        "note": HEURISTIC_NOTE,
        "thresholds": {"likely": LIKELY_AT, "partial": PARTIAL_AT,
                       "min_candidates": MIN_CANDIDATES},
        "repositories": reports,
    }
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    if args.json:
        sys.stdout.write(text)
    else:
        print(table(reports))
        print(f"\n{LEGEND}\nNote: {HEURISTIC_NOTE}")
    return 0 if all("error" not in report for report in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
