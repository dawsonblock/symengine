"""Runtime pieces shared by the efficacy-study tools.

- :func:`build_study_executor` chooses the evaluator backend for a study
  run: the local subprocess executor (development, shared custody on
  Linux) or :class:`~sis.v3.docker_sandbox.DockerSandboxExecutor` with a
  second container identity, which gives split custody on Linux.
- :func:`materialize_commit` writes the tree of one Git commit to a plain
  directory without running any repository-configured program, so a task
  can start from its own base commit inside a repository.
- :func:`hidden_tests_digest` fingerprints a hidden-test file or a
  directory of per-task hidden-test files.
- :class:`RunJournal` is the append-only, digest-chained record of every
  finished ``(task, arm)`` row that makes a study run resumable.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import stat
import subprocess
import threading
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath

from . import gitquery
from .contracts import ContractError, canonical_digest

#: The evaluator image recorded in docs/v3/SANDBOX_QUALIFICATION_GATE2.md.
#: Build it from docker/sandbox and pass ``--docker-image`` when the local
#: build resolves to a different digest.
DEFAULT_STUDY_IMAGE = (
    "sis-evaluator:3.3.9@sha256:"
    "5af4f6ceed7041f1665fdb077708c9b8fdd71cedf451e0adbfb0490e5e914466")
#: The second, non-root container identity that runs submitted code under
#: split custody. It must differ from the evaluator identity.
DEFAULT_SPLIT_USER = "65533:65533"
EXECUTOR_KINDS = ("local", "docker")

_HEX = frozenset("0123456789abcdef")
_MAX_TREE_ENTRIES = 200_000
_MAX_TREE_BYTES = 2 << 30


class StudyRuntimeError(RuntimeError):
    """A study runtime operation cannot be completed safely."""


# --------------------------------------------------------------------- #
# executors
# --------------------------------------------------------------------- #
def build_study_executor(
    kind: str,
    root: str | Path,
    *,
    protected_paths: Iterable[str | Path] = (),
    image: str | None = None,
    split_user: str | None = DEFAULT_SPLIT_USER,
    user: str | None = None,
    runtime: str | None = None,
    require_image_digest: bool = True,
    docker_factory: Callable | None = None,
):
    """Construct the evaluator executor for a study run.

    ``kind="local"`` is the development backend; on Linux it has no
    second principal, so private acceptance tests need shared custody.
    ``kind="docker"`` runs every evaluation in a bounded container; with a
    ``split_user`` the submission runs as a second container identity and
    the hidden tests stay with the evaluator identity (split custody).

    ``runtime`` (for example ``runsc``) is passed to the executor only if
    it accepts one; otherwise the request is refused instead of silently
    running under the default runtime. ``docker_factory`` replaces the
    executor class in tests.
    """
    if kind not in EXECUTOR_KINDS:
        raise ContractError("executor must be 'local' or 'docker'")
    root = Path(root)
    protected = tuple(Path(path) for path in protected_paths)
    if kind == "local":
        if runtime is not None or image is not None:
            raise ContractError(
                "docker image/runtime options require --executor docker")
        from .runner import LocalSubprocessExecutor
        return LocalSubprocessExecutor(root, protected_paths=protected)
    if docker_factory is None:
        from .docker_sandbox import DockerSandboxExecutor
        docker_factory = DockerSandboxExecutor
    kwargs = {
        "image": image or DEFAULT_STUDY_IMAGE,
        "require_image_digest": require_image_digest,
        "split_user": split_user,
    }
    if user is not None:
        kwargs["user"] = user
    if runtime is not None:
        try:
            parameters = inspect.signature(docker_factory).parameters
        except (TypeError, ValueError):
            parameters = {}
        if "runtime" not in parameters:
            raise ContractError("docker_runtime_unsupported_by_executor")
        kwargs["runtime"] = runtime
    executor = docker_factory(root, **kwargs)
    protect = getattr(executor, "protect", None)
    if callable(protect):
        for path in protected:
            protect(path)
    return executor


def executor_description(executor) -> dict:
    """Facts about the executor recorded in a study report."""
    return {
        "class": type(executor).__name__,
        "supports_split_custody": bool(
            getattr(executor, "supports_split_custody", False)),
        "split_user": getattr(executor, "split_user", None),
        "worker_identity": getattr(executor, "worker_identity", None),
        "image": getattr(executor, "_image", None),
        "runtime": getattr(executor, "_runtime", None),
    }


# --------------------------------------------------------------------- #
# commit trees
# --------------------------------------------------------------------- #
def _safe_relative(raw: bytes) -> PurePosixPath:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StudyRuntimeError("commit_path_not_utf8") from exc
    path = PurePosixPath(text)
    if (not text or path.is_absolute()
            or any(part in ("", ".", "..", ".git") for part in path.parts)
            or any(ord(ch) < 32 for ch in text)):
        raise StudyRuntimeError("commit_path_unsafe:" + text[:200])
    return path


def commit_exists(repository: str | Path, commit: str) -> bool:
    return gitquery.predicate(
        Path(repository), "cat-file", "-e", f"{commit}^{{commit}}")


def commit_is_ancestor(repository: str | Path, ancestor: str,
                       descendant: str) -> bool:
    return gitquery.predicate(
        Path(repository), "merge-base", "--is-ancestor", ancestor, descendant)


def materialize_commit(repository: str | Path, commit: str,
                       destination: str | Path) -> Path:
    """Write ``commit``'s tree to ``destination`` as plain files.

    Blobs are read with ``git cat-file --batch`` through the hardened
    :mod:`sis.v3.gitquery` settings, so no filter, hook, attribute or
    configured program runs. Only regular files (modes 100644/100755) are
    supported: a symlink or submodule in the tree is refused, because no
    executor evaluates a tree containing a link. ``destination`` must not
    exist; it is created with the files and their executable bits.
    """
    repository = Path(repository)
    destination = Path(destination)
    if not (isinstance(commit, str) and len(commit) in (40, 64)
            and set(commit) <= _HEX):
        raise StudyRuntimeError("commit_invalid")
    if destination.exists() or destination.is_symlink():
        raise StudyRuntimeError("destination_exists")
    if not commit_exists(repository, commit):
        raise StudyRuntimeError("commit_missing:" + commit)
    listing = gitquery.raw_bytes(
        repository, "ls-tree", "-r", "-z", "--full-tree", commit)
    if listing is None:
        raise StudyRuntimeError("commit_tree_unreadable:" + commit)
    entries: list[tuple[PurePosixPath, str, str]] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, separator, raw_path = record.partition(b"\t")
        fields = meta.split()
        if not separator or len(fields) != 3:
            raise StudyRuntimeError("commit_tree_malformed")
        mode, kind, oid = (field.decode("ascii") for field in fields)
        path = _safe_relative(raw_path)
        if mode == "120000":
            raise StudyRuntimeError("commit_tree_contains_symlink:" + str(path))
        if mode == "160000" or kind == "commit":
            raise StudyRuntimeError(
                "commit_tree_contains_submodule:" + str(path))
        if mode not in ("100644", "100755") or kind != "blob":
            raise StudyRuntimeError("commit_tree_unsupported_entry:" + str(path))
        entries.append((path, mode, oid))
        if len(entries) > _MAX_TREE_ENTRIES:
            raise StudyRuntimeError("commit_tree_too_large")
    destination.mkdir(parents=True)
    os.chmod(destination, 0o755)
    total = 0
    process = subprocess.Popen(
        ["git", "-C", str(repository), *gitquery._GLOBAL_OPTIONS,
         "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, env=gitquery.environment())
    try:
        assert process.stdin is not None and process.stdout is not None
        for path, mode, oid in entries:
            process.stdin.write(oid.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob" \
                    or header[0].decode("ascii") != oid:
                raise StudyRuntimeError("commit_blob_unreadable:" + str(path))
            size = int(header[2])
            total += size
            if total > _MAX_TREE_BYTES:
                raise StudyRuntimeError("commit_tree_too_large")
            data = process.stdout.read(size)
            process.stdout.read(1)  # the record's trailing newline
            if len(data) != size:
                raise StudyRuntimeError("commit_blob_truncated:" + str(path))
            target = destination.joinpath(*path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "xb") as handle:
                handle.write(data)
            os.chmod(target, 0o755 if mode == "100755" else 0o644)
        process.stdin.close()
        process.wait(timeout=60)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    for directory, dirnames, _ in os.walk(destination):
        for name in dirnames:
            os.chmod(os.path.join(directory, name), 0o755)
    return destination


# --------------------------------------------------------------------- #
# hidden tests
# --------------------------------------------------------------------- #
def hidden_tests_digest(path: str | Path) -> str:
    """SHA-256 of a hidden-test file, or the digest of a directory of them.

    A directory digest binds every regular file's relative path and
    SHA-256 (``hidden_tests_directory`` v1). Links and special files are
    refused.
    """
    path = Path(path)
    if path.is_symlink():
        raise StudyRuntimeError("hidden_tests_symlink")
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        raise StudyRuntimeError("hidden_tests_missing")
    files: dict[str, str] = {}
    for item in sorted(path.rglob("*")):
        relative = item.relative_to(path).as_posix()
        info = item.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise StudyRuntimeError("hidden_tests_special_file:" + relative)
        files[relative] = hashlib.sha256(item.read_bytes()).hexdigest()
    return canonical_digest("hidden_tests_directory", 1, {"files": files})


def hidden_test_belongs(task_file: str | Path, hidden_root: str | Path) -> bool:
    """Whether a task's hidden-test file is the repository's hidden tests."""
    task_file = Path(task_file).resolve()
    hidden_root = Path(hidden_root).resolve()
    if hidden_root.is_dir():
        return hidden_root in task_file.parents
    return task_file == hidden_root


# --------------------------------------------------------------------- #
# run journal
# --------------------------------------------------------------------- #
def _normalized(value):
    return json.loads(json.dumps(value, sort_keys=True),
                      parse_float=lambda item: f"float:{item}")


class RunJournal:
    """Append-only, digest-chained log of finished ``(task, arm)`` rows.

    The first line binds the run identity (manifest digest, protocol,
    guidance bundle, executor and arm design). Opening an existing journal
    with a different identity is refused, so a resume can never mix rows
    from two different studies. Each later line carries one arm row, its
    annotations (for example whether guidance was served and the serving
    decision), the previous entry digest and its own digest. Every line is
    flushed and fsynced before the next arm starts; a line cut short by a
    crash at the end of the file is discarded on reopen, anything else
    that does not verify is refused.

    The journal proves continuity, not authenticity: the caller must check
    that every journaled receipt digest resolves in the verifier that the
    resumed run uses.
    """

    KIND = "five_arm_run_journal"

    def __init__(self, path: str | Path, identity: Mapping) -> None:
        self.path = Path(path)
        self.identity = _normalized(dict(identity))
        self.identity_digest = canonical_digest(
            "five_arm_run_identity", 1, self.identity)
        self._lock = threading.Lock()
        self._rows: dict[tuple[str, str], dict] = {}
        self._annotations: dict[tuple[str, str], dict] = {}
        self._head: str | None = None
        self.resumed_rows = 0
        #: ``annotator(task_id, arm) -> dict`` adds caller facts to a row.
        self.annotator: Callable[[str, str], Mapping] | None = None
        if self.path.exists():
            self._load()
            self.resumed_rows = len(self._rows)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            header = {"kind": self.KIND, "schema_version": 1,
                      "identity": self.identity,
                      "identity_digest": self.identity_digest}
            self._head = self.identity_digest
            self._append(header)

    def _load(self) -> None:
        raw = self.path.read_bytes()
        lines = raw.split(b"\n")
        complete = raw.endswith(b"\n")
        if not complete:
            # A line cut short by a crash: drop it (its arm is re-run) and
            # rewrite the file without it.
            lines = lines[:-1]
        records = [line for line in lines if line]
        if not records:
            # Crashed before the header was complete: start over.
            self.path.unlink()
            self._head = self.identity_digest
            self._append({"kind": self.KIND, "schema_version": 1,
                          "identity": self.identity,
                          "identity_digest": self.identity_digest})
            return
        try:
            header = json.loads(records[0])
        except ValueError as exc:
            raise StudyRuntimeError("journal_header_invalid") from exc
        if (not isinstance(header, dict) or header.get("kind") != self.KIND
                or header.get("schema_version") != 1):
            raise StudyRuntimeError("journal_header_invalid")
        if header.get("identity_digest") != self.identity_digest:
            raise StudyRuntimeError("journal_identity_mismatch")
        head = self.identity_digest
        for line in records[1:]:
            try:
                entry = json.loads(line)
            except ValueError as exc:
                raise StudyRuntimeError("journal_entry_invalid") from exc
            body = {key: entry[key] for key in
                    ("task_id", "arm", "row", "annotations", "prior")
                    if key in entry}
            if (not isinstance(entry, dict) or entry.get("prior") != head
                    or entry.get("entry_digest") != canonical_digest(
                        "five_arm_run_journal_entry", 1, _normalized(body))):
                raise StudyRuntimeError("journal_chain_broken")
            key = (entry["task_id"], entry["arm"])
            row = entry["row"]
            if isinstance(row, dict) and not row.get("workspace_retained"):
                self._rows[key] = row
                self._annotations[key] = dict(entry.get("annotations") or {})
            head = entry["entry_digest"]
        self._head = head
        if not complete:
            tmp = self.path.with_name(self.path.name + ".repair")
            tmp.write_bytes(b"".join(line + b"\n" for line in records))
            os.replace(tmp, self.path)

    def _append(self, document: Mapping) -> None:
        data = json.dumps(document, sort_keys=True,
                          separators=(",", ":")).encode("utf-8") + b"\n"
        with open(self.path, "ab") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

    # ---- harness interface ------------------------------------------- #
    def completed(self, task_id: str, arm: str) -> dict | None:
        with self._lock:
            row = self._rows.get((task_id, arm))
            return dict(row) if row is not None else None

    def annotations(self, task_id: str, arm: str) -> dict:
        with self._lock:
            return dict(self._annotations.get((task_id, arm), {}))

    def record(self, task_id: str, arm: str, row: Mapping) -> None:
        annotations = dict(self.annotator(task_id, arm)) \
            if self.annotator is not None else {}
        with self._lock:
            body = {"task_id": task_id, "arm": arm,
                    "row": _normalized(dict(row)),
                    "annotations": _normalized(annotations),
                    "prior": self._head}
            digest = canonical_digest("five_arm_run_journal_entry", 1, body)
            self._append({**body, "entry_digest": digest})
            self._head = digest
            if not row.get("workspace_retained"):
                self._rows[(task_id, arm)] = dict(row)
                self._annotations[(task_id, arm)] = annotations

    def rows(self) -> dict[tuple[str, str], dict]:
        with self._lock:
            return {key: dict(value) for key, value in self._rows.items()}

    @property
    def head(self) -> str | None:
        return self._head


__all__ = ["DEFAULT_SPLIT_USER", "DEFAULT_STUDY_IMAGE", "EXECUTOR_KINDS",
           "RunJournal", "StudyRuntimeError", "build_study_executor",
           "commit_exists", "commit_is_ancestor", "executor_description",
           "hidden_test_belongs", "hidden_tests_digest", "materialize_commit"]
