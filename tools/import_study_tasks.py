#!/usr/bin/env python3
"""Import efficacy-study tasks from the bug-fix history of a Git repository.

A task is a bug-fix commit ``F`` that changes Python source and exactly one
Python test file ``T``:

- the task starts from ``F``'s parent commit (its ``base_commit``; the
  agent sees that tree, without Git metadata);
- ``F``'s version of ``T`` is moved out of the tree into the hidden-test
  directory and becomes the task's evaluator-owned acceptance file
  (``hidden_tests_target`` keeps its original path);
- the files that test needs beside it are captured from ``F`` too and
  registered with it as further private files at their repository paths
  (``acceptance.support_files``: target, stored path and SHA-256 each):
  ``conftest.py`` of its directory and every directory above, the
  ``__init__.py`` of each test package up to its test root, and the
  helper modules it imports from its own test package. Only paths in a
  ``test``/``tests`` directory qualify as packages or helpers, so a
  source package is never captured;
- the prompt is ``F``'s commit message (subject and body), or the issue
  text supplied with ``--prompt-file``;
- with ``--verify`` the task is graded exactly as the study runner grades
  it (an :class:`~sis.v3.verifier.OutcomeVerifier` on the chosen
  executor): the base tree must **fail** the hidden test and ``F``'s tree
  must **pass** it. Tasks that do not are rejected with the reason.

The output is a spec fragment: one ``repositories`` entry and its
``tasks``, in the format ``tools/build_efficacy_manifest.py`` (holdout
repositories) and ``tools/build_guidance_bundle.py`` (induction
repositories) read. ``--merge-into SPEC`` adds them to an existing spec,
replacing that repository's earlier entry and tasks.

The repository path must be a full (non-shallow) clean clone with an
``origin``; its checkout (``HEAD``) is the repository's ``base_commit``
and every task commit must be an ancestor of it. Use the local executor
with ``--allow-shared-custody`` for development, or ``--verify docker``
for the split-custody grading the pilot uses. The evaluator image only
carries pytest: a repository whose tests need other packages fails
verification there and is rejected, not silently accepted.

Usage:
    PYTHONPATH=src python3 tools/import_study_tasks.py \\
        --repo /study/repos/pkg --repository-id pkg --partition holdout \\
        --hidden-dir /study/private/pkg --max-tasks 15 \\
        --verify docker --merge-into /study/spec.json -o /study/pkg.json
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import posixpath
import re
import secrets
import sys
import tempfile
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sis.v3 import gitquery  # noqa: E402
from sis.v3.contracts import TaskEnvelopeV1  # noqa: E402
from sis.v3.evaluation_runtime import EvaluationRuntimeProfile  # noqa: E402
from sis.v3.runner import (MAX_PRIVATE_FILE_BYTES,  # noqa: E402
                           MAX_PRIVATE_FILES, MAX_PRIVATE_TOTAL_BYTES,
                           ResourceLimits, repository_execution_digest,
                           tree_digest)
from sis.v3.study_runtime import (DEFAULT_SPLIT_USER,  # noqa: E402
                                  MAX_SUPPORT_FILES, StudyRuntimeError,
                                  build_study_executor, materialize_commit,
                                  support_target_allowed)
from sis.v3.verifier import OutcomeVerifier  # noqa: E402

HEX = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
SAFE_REL = re.compile(
    r"^(?!/)(?![A-Za-z]:)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/-]{1,512}$")
DEFAULT_FIX_PATTERN = (r"(?i)\b(fix(e[sd])?|bug|issue|regression|crash|"
                       r"error|incorrect|wrong|broken)\b")
MAX_PROMPT_CHARS = 16_000
PROMPT_SUFFIX = (
    "\n\nFix the problem described above in this repository. Change the"
    " source code, not the tests: an evaluator-owned test that you cannot"
    " see will check the fix. Do not delete or weaken existing tests.")


class ImportError_(RuntimeError):
    """A repository or commit cannot be imported."""


def _git(root: Path, *args: str) -> str | None:
    return gitquery.query(root, *args)


def is_test_path(path: str) -> bool:
    """A Python test module by the usual pytest conventions."""
    pure = PurePosixPath(path)
    if pure.suffix != ".py":
        return False
    name = pure.name
    return (name.startswith("test_") or name.endswith("_test.py")
            or any(part in ("test", "tests") for part in pure.parts[:-1]))


def _changes(root: Path, parent: str, commit: str) -> list[tuple[str, str]]:
    output = gitquery.raw_bytes(
        root, "diff-tree", "--no-commit-id", "--no-renames", "-r",
        "--name-status", "-z", parent, commit)
    if output is None:
        raise ImportError_("diff_unreadable")
    fields = [item.decode("utf-8", "replace")
              for item in output.split(b"\0") if item]
    return [(fields[index], fields[index + 1])
            for index in range(0, len(fields) - 1, 2)]


def _message(root: Path, commit: str) -> str:
    text = gitquery.raw(root, "log", "-1", "--format=%B", commit) or ""
    return text.strip()


def candidate_commits(root: Path, *, max_scan: int,
                      explicit: list[str] | None) -> list[str]:
    if explicit:
        resolved = []
        for item in explicit:
            commit = _git(root, "rev-parse", "--verify", f"{item}^{{commit}}")
            if commit is None or not HEX.match(commit):
                raise ImportError_(f"unknown commit: {item}")
            resolved.append(commit)
        return resolved
    output = _git(root, "log", "--no-merges", "--format=%H",
                  f"-n{max_scan}", "HEAD")
    if output is None:
        raise ImportError_("history_unreadable")
    return [line for line in output.splitlines() if HEX.match(line)]


def describe_commit(root: Path, commit: str, *, fix_pattern: re.Pattern
                    ) -> dict:
    """Classify one commit; raise ``ImportError_`` with the reason to skip."""
    parents = (_git(root, "rev-list", "--parents", "-n", "1", commit)
               or "").split()
    if len(parents) != 2:
        raise ImportError_("not_a_single_parent_commit")
    parent = parents[1]
    message = _message(root, commit)
    if not fix_pattern.search(message):
        raise ImportError_("message_is_not_a_fix")
    changes = _changes(root, parent, commit)
    tests = [(status, path) for status, path in changes if is_test_path(path)]
    sources = [(status, path) for status, path in changes
               if path.endswith(".py") and not is_test_path(path)]
    if len(tests) != 1:
        raise ImportError_(f"changes_{len(tests)}_test_files")
    status, test_path = tests[0]
    if status not in ("A", "M"):
        raise ImportError_("test_file_not_added_or_modified")
    if not sources:
        raise ImportError_("no_python_source_change")
    if not SAFE_REL.fullmatch(test_path):
        raise ImportError_("test_path_unsafe")
    payload = gitquery.raw_bytes(root, "cat-file", "blob",
                                 f"{commit}:{test_path}")
    if payload is None:
        raise ImportError_("test_blob_unreadable")
    notes: list = []
    support = support_files(root, commit, test_path, payload, notes)
    return {"commit": commit, "parent": parent, "message": message,
            "test_path": test_path, "test_bytes": payload,
            "support": support, "support_notes": notes,
            "source_files": sorted(path for _, path in sources)}


def _blob(root: Path, commit: str, path: str) -> bytes:
    payload = gitquery.raw_bytes(root, "cat-file", "blob", f"{commit}:{path}")
    if payload is None:
        raise ImportError_("support_blob_unreadable:" + path)
    return payload


def _imported_modules(source: bytes) -> list[tuple[int, list[str]]]:
    """``(level, dotted parts)`` of every module an import statement names.

    ``from .a import b`` names ``a`` and ``a.b`` (``b`` may be a
    submodule); ``from . import b`` names ``b``. Nothing is executed.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend((0, alias.name.split(".")) for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module.split(".") if node.module else []
            if base:
                names.append((node.level, base))
            names.extend((node.level, base + [alias.name])
                         for alias in node.names if alias.name != "*")
    return names


#: Calls whose consecutive string arguments form one path
#: (``os.path.join(HERE, 'data', 'x.json')``, ``Path('data', 'x.json')``).
_PATH_CALLS = frozenset({"join", "joinpath", "Path", "PurePath",
                         "PurePosixPath"})


def _string_paths(source: bytes) -> list[tuple[str, ...]]:
    """Path fragments a Python file names with string literals.

    Every string literal alone, and every run of two or more consecutive
    literals that a path join (:data:`_PATH_CALLS`) or the ``/`` operator
    combines: ``os.path.join(dirname(__file__), 'compliance')`` names
    ``compliance``, ``HERE / 'data' / 'x.json'`` names ``data/x.json``.
    Nothing is executed.
    """
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []

    def literal(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    def operands(node):
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return [*operands(node.left), node.right]
        return [node]

    found: set[tuple[str, ...]] = set()
    # A literal followed by another in one join is a path component
    # (``'fixtures'`` in ``HERE / 'fixtures' / 'one.txt'``), not a
    # reference to that directory as a whole.
    components: set[int] = set()

    def runs(nodes):
        run: list = []
        for node in [*nodes, None]:
            if node is not None and literal(node) is not None:
                run.append(node)
                continue
            if len(run) > 1:
                found.add(tuple(literal(item) for item in run))
                components.update(id(item) for item in run[:-1])
            run = []

    def division(node):
        return isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)

    nodes = list(ast.walk(tree))
    # Only a whole ``/`` chain names a path. Its inner chains (``HERE /
    # 'fixtures' / 'nested'`` in ``... / 'nested' / 'one.txt'``) are
    # prefixes of it, not references to those directories.
    inner = {id(node.left) for node in nodes
             if division(node) and division(node.left)}
    for node in nodes:
        if isinstance(node, ast.Call):
            function = node.func
            name = (function.attr if isinstance(function, ast.Attribute)
                    else getattr(function, "id", None))
            if name in _PATH_CALLS:
                runs(node.args)
        elif division(node) and id(node) not in inner:
            runs(operands(node))
    for node in nodes:
        value = literal(node)
        if value is not None and id(node) not in components:
            found.add((value,))
    return sorted(found)


def _relative_path(base: PurePosixPath, parts: tuple[str, ...]) -> str | None:
    """``parts`` joined under ``base``, normalized; None if it leaves it."""
    joined = "/".join(parts)
    if (not joined or len(joined) > 512 or "\0" in joined or "\\" in joined
            or joined.startswith("/") or ":" in joined):
        return None
    combined = posixpath.normpath(posixpath.join(base.as_posix(), joined))
    if combined in (".", "..") or combined.startswith("../"):
        return None
    return combined


def support_files(root: Path, commit: str, test_path: str,
                  test_bytes: bytes,
                  notes: list | None = None) -> dict[str, bytes]:
    """Files the hidden test needs beside it, read from the fix commit.

    The evaluator captures them at registration exactly like the test
    itself, never from a submission: the ``conftest.py`` of the test's
    directory and of every directory above it, the ``__init__.py`` of
    each package from the test's directory up to its test root, and the
    modules the test (or a helper it pulls in) imports from its own test
    package, by relative import (``from . import Mixin``, resolved
    against the importing file's own package, so a helper in
    ``tests/sub`` brings its ``.data``) or by the package's name
    (``from tests import helpers``). A test directory that
    is not a package contributes the sibling modules it imports by bare
    name. Only paths under a test directory (``test``/``tests``) qualify
    as packages or helpers, so a source package (``src/pkg/__init__.py``,
    or ``pkg.py`` beside a root-level test) is never captured: the
    submission's code is always the submission's.

    Data files are captured too (:func:`_data_files`): non-Python regular
    files under the test root that the test or a captured helper names
    by a string-literal path, and every such file of a test subdirectory
    it names (``os.path.join(HERE, 'compliance')`` and a ``glob``). A
    directory that would exceed :data:`MAX_SUPPORT_FILES` or the
    private-material bounds is captured not at all, never in part, and
    the reason is appended to ``notes``.
    """
    listing = gitquery.raw_bytes(root, "ls-tree", "-r", "-z", commit)
    if listing is None:
        raise ImportError_("tree_unreadable")
    paths = set()
    for item in listing.split(b"\0"):
        # "<mode> <type> <object>\t<path>": regular files only, so a
        # symbolic link or submodule is never captured as a helper.
        header, _, name = item.partition(b"\t")
        if header.split(b" ")[0] in (b"100644", b"100755") and name:
            paths.add(name.decode("utf-8", "replace"))
    test = PurePosixPath(test_path)

    def in_test_dir(path: str) -> bool:
        pure = PurePosixPath(path)
        return any(part in ("test", "tests") for part in pure.parts[:-1])

    found: dict[str, bytes] = {}

    def add(path: str) -> bool:
        if path == test_path or path not in paths:
            return False
        if path not in found:
            if len(found) >= MAX_SUPPORT_FILES:
                raise ImportError_("support_files_exceed_the_bound")
            if not SAFE_REL.fullmatch(path):
                raise ImportError_("support_path_unsafe")
            found[path] = _blob(root, commit, path)
        return True

    def package_chain(directory: PurePosixPath) -> list[PurePosixPath]:
        """The test packages from ``directory`` up, innermost first."""
        chain = []
        while (directory.parts
               and f"{directory.as_posix()}/__init__.py" in paths
               and in_test_dir(f"{directory.as_posix()}/__init__.py")):
            chain.append(directory)
            directory = directory.parent
        return chain

    packages = package_chain(test.parent)
    for package in packages:
        add(f"{package.as_posix()}/__init__.py")
    directory = packages[-1].parent if packages else test.parent
    # Where pytest's rootdir-relative import puts the test root on
    # sys.path: the first directory above the package chain.
    basedir = directory if packages else test.parent
    top = packages[-1].name if packages else None
    for ancestor in [*reversed(test.parents)]:
        prefix = "" if not ancestor.parts else ancestor.as_posix() + "/"
        add(prefix + "conftest.py")

    def module_file(base: PurePosixPath, parts: list[str]) -> str | None:
        """The module or package file ``parts`` names under ``base``."""
        if not parts or not all(part.isidentifier() for part in parts):
            return None
        stem = base.joinpath(*parts).as_posix()
        for candidate in (stem + ".py", stem + "/__init__.py"):
            if candidate in paths and in_test_dir(candidate):
                return candidate
        return None

    def resolve(origin: str, level: int, parts: list[str]) -> None:
        if level:
            # Against the importing file's own package chain: a helper in
            # a subpackage (tests/sub/helper.py) brings its ``.data``.
            package = PurePosixPath(origin).parent
            for _ in range(level - 1):
                package = package.parent
            if package not in package_chain(PurePosixPath(origin).parent):
                return
            base, names = package, parts
        elif top is not None and parts[0] == top:
            base, names = basedir, parts
        elif top is None and len(parts) >= 1:
            base, names = test.parent, parts
        else:
            return
        # Every package on the way is needed too (``tests.sub.helpers``).
        for depth in range(1, len(names) + 1):
            path = module_file(base, names[:depth])
            if path is None:
                return
            if add(path) and path not in seen:
                seen.add(path)
                queue.append(path)

    # The test, its package __init__ files and conftest files can each
    # import helpers; so can every helper found.
    queue = [test_path, *found]
    seen: set[str] = set(queue)
    while queue:
        origin = queue.pop()
        source = test_bytes if origin == test_path else found[origin]
        for level, parts in _imported_modules(source):
            resolve(origin, level, parts)
    test_root = packages[-1] if packages else test.parent
    _data_files(root, commit, test_path, test_bytes, found, paths,
                test_root=test_root, in_test_dir=in_test_dir,
                notes=notes if notes is not None else [])
    sizes = [len(test_bytes), *(len(data) for data in found.values())]
    if (len(sizes) > MAX_PRIVATE_FILES or max(sizes) > MAX_PRIVATE_FILE_BYTES
            or sum(sizes) > MAX_PRIVATE_TOTAL_BYTES):
        raise ImportError_("support_files_exceed_the_bound")
    return dict(sorted(found.items()))


def _data_files(root: Path, commit: str, test_path: str, test_bytes: bytes,
                found: dict[str, bytes], paths: set[str], *,
                test_root: PurePosixPath, in_test_dir, notes: list) -> None:
    """Add the data files the test reads beside itself to ``found``.

    jmespath's compliance tests load ``tests/compliance/*.json`` through
    ``os.path.dirname(__file__)``; without them the staged test fails
    even on the correct fix. A string literal (or a joined run of them)
    in the test or a captured ``.py`` helper is resolved against that
    file's directory and the test's. It names:

    - a data file: a regular file in the fix commit (``paths`` holds
      regular files only), not ``.py`` and no other code suffix, in a
      test directory under the test root;
    - a data directory: a test subdirectory strictly under the test
      root, not a package, whose data files (recursively) are captured
      all together or, when they would exceed :data:`MAX_SUPPORT_FILES`
      or a size bound, not at all, with a note saying why.

    Single files come first, then directories, each in path order, after
    every Python support file. A named file inside a named directory is
    captured with that directory, and a directory inside a refused one is
    refused too (``enclosing_directory_refused``), so no directory the
    test names is ever staged in part.
    """
    root_text = test_root.as_posix()
    prefix = "" if root_text == "." else root_text + "/"
    directories = {posixpath.dirname(path) for path in paths}
    for path in list(directories):
        while path:
            path = posixpath.dirname(path)
            directories.add(path)

    def eligible(path: str) -> bool:
        return (path.startswith(prefix) and in_test_dir(path)
                and not path.endswith(".py") and path != test_path)

    def total() -> int:
        return len(test_bytes) + sum(len(data) for data in found.values())

    sources = {test_path: test_bytes, **{
        path: data for path, data in found.items() if path.endswith(".py")}}
    files: set[str] = set()
    folders: set[str] = set()
    for origin, source in sources.items():
        bases = {PurePosixPath(origin).parent, PurePosixPath(test_path).parent}
        for parts in _string_paths(source):
            for base in bases:
                candidate = _relative_path(base, parts)
                if candidate is None:
                    continue
                if candidate in paths and eligible(candidate):
                    files.add(candidate)
                elif (candidate in directories and candidate.startswith(prefix)
                      and candidate != root_text
                      and in_test_dir(candidate + "/x")
                      and candidate + "/__init__.py" not in paths):
                    folders.add(candidate)

    def note(path: str, reason: str, **extra) -> None:
        notes.append({"path": path, "reason": reason, **extra})

    def grouped(path: str) -> bool:
        # A file inside a directory the test also names is captured with
        # that directory, all or none, never ahead of it.
        return any(path.startswith(folder + "/") for folder in folders)

    for path in sorted(files - set(found)):
        if grouped(path):
            continue
        if not SAFE_REL.fullmatch(path) or not support_target_allowed(path):
            note(path, "data_path_unsafe")
        elif len(found) >= MAX_SUPPORT_FILES:
            note(path, "support_files_cap")
        else:
            data = _blob(root, commit, path)
            if (len(data) > MAX_PRIVATE_FILE_BYTES
                    or total() + len(data) > MAX_PRIVATE_TOTAL_BYTES):
                note(path, "private_size_bound")
            else:
                found[path] = data
    refused: list[str] = []
    # In path order, so a directory comes before the directories in it.
    for folder in sorted(folders):
        if any(folder.startswith(other + "/") for other in refused):
            # Part of a directory refused as a whole: staging it would
            # leave a partial listing of that directory.
            note(folder, "enclosing_directory_refused")
            continue
        members = sorted(path for path in paths
                         if path.startswith(folder + "/") and eligible(path)
                         and support_target_allowed(path)
                         and path not in found)
        if not members:
            continue
        if any(not SAFE_REL.fullmatch(path) for path in members):
            note(folder, "data_path_unsafe")
            refused.append(folder)
            continue
        if len(found) + len(members) > MAX_SUPPORT_FILES:
            note(folder, "support_files_cap", files=len(members),
                 room=MAX_SUPPORT_FILES - len(found))
            refused.append(folder)
            continue
        payloads = {path: _blob(root, commit, path) for path in members}
        if (max(len(data) for data in payloads.values())
                > MAX_PRIVATE_FILE_BYTES
                or total() + sum(len(data) for data in payloads.values())
                > MAX_PRIVATE_TOTAL_BYTES):
            note(folder, "private_size_bound", files=len(members))
            refused.append(folder)
            continue
        found.update(payloads)


def private_files(info: dict) -> dict[str, bytes]:
    """The evaluator-private material of one task: test and support files."""
    return {info["test_path"]: info["test_bytes"], **info["support"]}


def make_prompt(message: str, prompt_text: str | None = None) -> str:
    body = (prompt_text or message).strip()
    if not body:
        raise ImportError_("empty_prompt")
    return body[:MAX_PROMPT_CHARS] + PROMPT_SUFFIX


class TaskVerifier:
    """Grade base and fix trees exactly as the study runner grades them."""

    def __init__(self, root: Path, *, executor: str,
                 allow_shared_custody: bool, wall_seconds: int,
                 docker_image: str | None, docker_split_user: str | None,
                 require_image_digest: bool, executor_factory=None) -> None:
        self.root = root
        protected = (root / "keys", root / "registry")
        if executor_factory is not None:
            backend = executor_factory(root / "exec", protected)
        else:
            backend = build_study_executor(
                executor, root / "exec", protected_paths=protected,
                image=docker_image if executor == "docker" else None,
                split_user=docker_split_user,
                require_image_digest=require_image_digest)
        profile = EvaluationRuntimeProfile(
            cpu_seconds=wall_seconds, wall_seconds=wall_seconds,
            process_count=None)
        self.custody = "shared" if allow_shared_custody else None
        self.verifier = OutcomeVerifier(
            executor=backend, key_dir=root / "keys",
            registry_dir=root / "registry",
            allow_shared_custody=allow_shared_custody,
            limits=ResourceLimits(
                wall_seconds=wall_seconds, cpu_seconds=wall_seconds,
                memory_bytes=profile.task_memory_bytes, process_count=None),
            runtime_profile=profile)

    def grade(self, task_id: str, *, base_commit: str, argv: list[str],
              files: dict[str, bytes], tree: Path) -> str:
        self.verifier.register_task(
            actor_role="evaluator", task_id=task_id,
            criterion_version="v1", argv=tuple(argv), files=files,
            base_commit=base_commit, custody=self.custody)
        envelope = TaskEnvelopeV1(
            schema_version=1, task_id=task_id,
            repo_snapshot_digest=tree_digest(tree, version=3),
            base_commit=base_commit,
            task_statement_digest=hashlib.sha256(task_id.encode()).hexdigest(),
            permitted_commands=("pytest",),
            isolation_profile="unverified_local",
            time_budget_seconds=900, token_budget=1, tool_budget=1,
            actor_id="importer", evaluator_task_ref=task_id)
        receipt = self.verifier.evaluate(
            actor_role="evaluator", task=envelope, submission_dir=tree,
            evaluation_nonce="import-" + secrets.token_hex(8))
        return receipt.outcome


def import_repository(args, *, executor_factory=None) -> dict:
    root = Path(args.repo).resolve()
    if not root.is_dir():
        raise ImportError_("repository path is not a directory")
    toplevel = _git(root, "rev-parse", "--show-toplevel")
    if toplevel is None or Path(toplevel).resolve() != root:
        raise ImportError_("repository path is not the root of a Git checkout")
    if _git(root, "rev-parse", "--is-shallow-repository") == "true":
        raise ImportError_("repository history is shallow; fetch it fully")
    if not IDENTIFIER.fullmatch(args.repository_id):
        raise ImportError_("repository_id is not a valid identifier")
    head = _git(root, "rev-parse", "HEAD")
    if head is None or not HEX.match(head):
        raise ImportError_("repository HEAD is unreadable")
    hidden_dir = Path(args.hidden_dir).resolve()
    if hidden_dir == root or root in hidden_dir.parents \
            or hidden_dir in root.parents:
        raise ImportError_("hidden-dir must be outside the repository")
    fix_pattern = re.compile(args.fix_pattern)
    prompts = {}
    if args.prompt_file is not None:
        document = json.loads(Path(args.prompt_file).read_text("utf-8"))
        if not isinstance(document, dict):
            raise ImportError_("prompt file must map commits to issue text")
        prompts = {str(key): str(value) for key, value in document.items()}
    python = args.python or (
        "python3" if args.verify == "docker" else sys.executable)
    tasks, rejected = [], []
    with tempfile.TemporaryDirectory(prefix="sis-import-") as temp:
        scratch = Path(temp)
        grader = None
        if args.verify != "none":
            grader = TaskVerifier(
                scratch / "verifier", executor=args.verify,
                allow_shared_custody=args.allow_shared_custody,
                wall_seconds=args.timeout,
                docker_image=args.docker_image,
                docker_split_user=args.docker_split_user,
                require_image_digest=not args.allow_unpinned_image,
                executor_factory=executor_factory)
        for commit in candidate_commits(
                root, max_scan=args.max_scan, explicit=args.commits):
            if args.max_tasks and len(tasks) >= args.max_tasks:
                break
            info = {}
            try:
                info = describe_commit(root, commit, fix_pattern=fix_pattern)
                if not gitquery.predicate(root, "merge-base", "--is-ancestor",
                                          info["parent"], head):
                    raise ImportError_("base_not_an_ancestor_of_HEAD")
                task_id = f"{args.repository_id}-{commit[:12]}"
                base_tree = scratch / f"{commit[:12]}-base"
                fix_tree = scratch / f"{commit[:12]}-fix"
                try:
                    materialize_commit(root, info["parent"], base_tree)
                    materialize_commit(root, commit, fix_tree)
                except StudyRuntimeError as exc:
                    raise ImportError_(f"tree_unusable:{exc}") from exc
                target = info["test_path"]
                argv = [python, "-m", "pytest", "-q", "-p", "no:cacheprovider",
                        target]
                files = private_files(info)
                verification = None
                if grader is not None:
                    base_outcome = grader.grade(
                        task_id + "-base", base_commit=info["parent"],
                        argv=argv, files=files, tree=base_tree)
                    fix_outcome = grader.grade(
                        task_id + "-fix", base_commit=info["parent"],
                        argv=argv, files=files, tree=fix_tree)
                    verification = {"base": base_outcome, "fix": fix_outcome}
                    if base_outcome != "fail":
                        raise ImportError_(f"base_does_not_fail:{base_outcome}")
                    if fix_outcome != "pass":
                        raise ImportError_(f"fix_does_not_pass:{fix_outcome}")
                hidden_file = hidden_dir / task_id / PurePosixPath(target).name
                hidden_file.parent.mkdir(parents=True, exist_ok=True)
                hidden_file.write_bytes(info["test_bytes"])
                support = []
                for relative, data in info["support"].items():
                    # Kept at its repository path under support/, inside
                    # the hidden-tests directory and so inside its digest.
                    stored = hidden_dir / task_id / "support" / relative
                    stored.parent.mkdir(parents=True, exist_ok=True)
                    stored.write_bytes(data)
                    support.append({
                        "target": relative, "path": str(stored),
                        "digest": hashlib.sha256(data).hexdigest()})
                task = {
                    "task_id": task_id,
                    "repository_id": args.repository_id,
                    "base_commit": info["parent"],
                    "prompt": make_prompt(info["message"],
                                          prompts.get(commit)),
                    "failure_class": args.failure_class,
                    "acceptance": {
                        "argv": argv,
                        "hidden_tests_path": str(hidden_file),
                        "hidden_tests_digest": hashlib.sha256(
                            info["test_bytes"]).hexdigest(),
                        "hidden_tests_target": target,
                        **({"support_files": support} if support else {}),
                    },
                    "source": {
                        "fix_commit": commit,
                        "test_path": target,
                        "source_files": info["source_files"],
                        "subject": info["message"].splitlines()[0][:200],
                        "base_tree_digest": tree_digest(base_tree, version=3),
                        "base_execution_digest":
                            repository_execution_digest(base_tree),
                        "verification": verification,
                        **({"support_notes": info["support_notes"]}
                           if info.get("support_notes") else {}),
                    },
                }
                tasks.append(task)
            except ImportError_ as exc:
                rejected.append({"commit": commit, "reason": str(exc),
                                 **({"support_notes": info["support_notes"]}
                                    if info.get("support_notes") else {})})
            except Exception as exc:  # noqa: BLE001 - recorded, not fatal
                rejected.append({"commit": commit,
                                 "reason": f"{type(exc).__name__}: {exc}"})
    repository = {
        "repository_id": args.repository_id,
        "path": str(root),
        "partition": args.partition,
    }
    if args.lineage_id:
        repository["lineage_id"] = args.lineage_id
    if args.partition == "holdout":
        repository["hidden_tests"] = {"path": str(hidden_dir)}
    if args.partition == "induction":
        repository["learning_split"] = args.learning_split
    return {
        "schema_version": 1,
        "kind": "study_task_import",
        "repository": repository,
        "repository_head": head,
        "verification_executor": args.verify,
        "tasks": tasks,
        "rejected": rejected,
    }


def merge_into(spec_path: Path, fragment: dict) -> dict:
    """Add the fragment's repository and tasks to a study or learning spec."""
    spec = json.loads(spec_path.read_text("utf-8"))
    if not isinstance(spec, dict):
        raise ImportError_("spec must be a JSON object")
    repository = dict(fragment["repository"])
    repository_id = repository["repository_id"]
    repositories = [item for item in spec.get("repositories", [])
                    if item.get("repository_id") != repository_id]
    repositories.append(repository)
    tasks = [item for item in spec.get("tasks", [])
             if item.get("repository_id") != repository_id]
    for task in fragment["tasks"]:
        tasks.append({key: value for key, value in task.items()
                      if key != "source"})
    spec["repositories"] = repositories
    spec["tasks"] = tasks
    temporary = spec_path.with_name(spec_path.name + ".tmp")
    temporary.write_text(json.dumps(spec, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    os.replace(temporary, spec_path)
    return spec


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", required=True, type=Path)
    p.add_argument("--repository-id", required=True)
    p.add_argument("--lineage-id")
    p.add_argument("--partition", choices=("holdout", "induction"),
                   required=True)
    p.add_argument("--learning-split", choices=("training", "qualification"),
                   default="training",
                   help="induction repositories only: which split of the"
                        " guidance-bundle build the repository belongs to")
    p.add_argument("--hidden-dir", required=True, type=Path,
                   help="directory outside the repository for the hidden"
                        " acceptance files (one subdirectory per task)")
    p.add_argument("--commits", nargs="*",
                   help="explicit fix commits (default: scan the history)")
    p.add_argument("--max-scan", type=int, default=500)
    p.add_argument("--max-tasks", type=int, default=0)
    p.add_argument("--fix-pattern", default=DEFAULT_FIX_PATTERN)
    p.add_argument("--prompt-file", type=Path,
                   help="JSON mapping fix commit -> issue text to use as the"
                        " prompt instead of the commit message")
    p.add_argument("--failure-class", default="bug_fix")
    p.add_argument("--python", default=None,
                   help="interpreter in acceptance argv (default: python3"
                        " for docker, this interpreter for local)")
    p.add_argument("--verify", choices=("none", "local", "docker"),
                   default="local")
    p.add_argument("--allow-shared-custody", action="store_true")
    p.add_argument("--docker-image")
    p.add_argument("--docker-split-user", default=DEFAULT_SPLIT_USER)
    p.add_argument("--allow-unpinned-image", action="store_true")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--merge-into", type=Path)
    p.add_argument("--output", "-o", type=Path, required=True)
    return p


def main(argv=None, *, executor_factory=None) -> int:
    args = parser().parse_args(argv)
    if args.verify == "docker" and args.allow_shared_custody:
        print("import_study_tasks: --verify docker grades under split"
              " custody; drop --allow-shared-custody", file=sys.stderr)
        return 2
    try:
        fragment = import_repository(args, executor_factory=executor_factory)
    except (ImportError_, OSError, ValueError) as exc:
        print(f"import_study_tasks: {exc}", file=sys.stderr)
        return 1
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fragment, indent=2, sort_keys=True)
                           + "\n", encoding="utf-8")
    if args.merge_into is not None and fragment["tasks"]:
        merge_into(args.merge_into, fragment)
    print(json.dumps({
        "repository_id": args.repository_id,
        "tasks": len(fragment["tasks"]),
        "rejected": len(fragment["rejected"]),
        "output": str(args.output),
        "merged_into": str(args.merge_into) if args.merge_into else None,
    }, indent=2))
    return 0 if fragment["tasks"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
