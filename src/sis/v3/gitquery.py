"""Read-only Git queries that cannot execute repository-configured programs.

A manifest names a repository path that is not trusted yet: the point of
the check is to decide whether it can be trusted. Running ``git`` in that
checkout reads the checkout's own ``.git/config``, which can name a
program to run: ``core.fsmonitor`` is executed by ``git status``, and
``core.hooksPath`` can point at hooks such as ``post-index-change``.
Environment variables such as ``GIT_DIR`` can also redirect a query to a
different repository than the path being verified.

Every query here therefore:

- overrides ``core.fsmonitor`` and ``core.hooksPath`` on the command
  line, which has higher precedence than repository, global or included
  configuration;
- scrubs every inherited ``GIT_*`` variable and disables the system and
  global configuration files, so only the checkout's own repository
  configuration remains (``remote.origin.url`` is part of what the
  provenance check must read);
- runs without optional locks, so a query cannot rewrite the index and
  trigger a hook while answering;
- disables replace refs and grafts, so a checkout cannot make ``HEAD``
  read as a different tree or history than the commit it names;
- refuses every transport (``protocol.allow=never``), so no configured
  ``core.sshCommand``, remote helper or protocol handler can start.

Repository configuration can still name programs that some commands
run on file content: a ``.gitattributes`` ``filter=`` driver's
``clean``/``process`` command runs during ``git status`` and ``git
diff``, as do ``textconv`` and ``diff.external``. Those commands are
therefore never used here. :func:`worktree_matches_head` answers the
"is the checkout clean" question by comparing raw object ids from
``ls-tree``/``ls-files`` with hashes computed in Python, which runs no
repository-configured program. Content-converting attributes
(``eol``/``text``/``filter``) are not applied, so a checkout whose bytes
differ from the committed blobs reads as modified: conservative, never
a false "clean".

The queries stay read-only; this module never fetches, checks out or
writes.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

# Command-line configuration is applied to every invocation. Keep this a
# tuple so a caller cannot append after it by accident.
_GLOBAL_OPTIONS = (
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={os.devnull}",
    "-c", "protocol.allow=never",
)


def environment() -> dict[str, str]:
    """Return a Git environment with ambient redirection and hooks removed."""
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_PAGER": "cat",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_GRAFT_FILE": os.devnull,
        "LC_ALL": "C",
    })
    return env


def run(root: Path, *args: str, timeout: float = 30) -> subprocess.CompletedProcess:
    """Run one read-only Git query in ``root`` with the hardened settings."""
    return subprocess.run(
        ["git", "-C", str(root), *_GLOBAL_OPTIONS, *args],
        capture_output=True, text=True, timeout=timeout, check=False,
        env=environment())


def raw(root: Path, *args: str, timeout: float = 30) -> str | None:
    """Return stdout verbatim, or ``None`` when Git cannot answer.

    Porcelain output can begin with a significant space (an unstaged
    modification is ``" M path"``), so callers that parse it must not
    strip it.
    """
    try:
        completed = run(root, *args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def query(root: Path, *args: str, timeout: float = 30) -> str | None:
    """Return stripped stdout, or ``None`` when Git cannot answer."""
    output = raw(root, *args, timeout=timeout)
    return None if output is None else output.strip()


def predicate(root: Path, *args: str, timeout: float = 30) -> bool:
    """Return whether a read-only Git predicate exits zero."""
    try:
        completed = run(root, *args, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return False
    return completed.returncode == 0


def raw_bytes(root: Path, *args: str, timeout: float = 120) -> bytes | None:
    """Return stdout bytes verbatim, or ``None`` when Git cannot answer."""
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), *_GLOBAL_OPTIONS, *args],
            capture_output=True, timeout=timeout, check=False,
            env=environment())
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def _entries(output: bytes, *, tree: bool) -> dict[bytes, tuple[str, str]] | None:
    """Parse ``ls-tree -r -z`` or ``ls-files -s -z`` into path -> (mode, oid)."""
    entries: dict[bytes, tuple[str, str]] = {}
    for record in output.split(b"\0"):
        if not record:
            continue
        meta, separator, path = record.partition(b"\t")
        fields = meta.split()
        if not separator or len(fields) != 3:
            return None
        if tree:
            mode, _kind, oid = fields
        else:
            mode, oid, stage = fields
            if stage != b"0":
                return None  # an unmerged index is never clean
        entries[path] = (mode.decode("ascii"), oid.decode("ascii"))
    return entries


def _blob_id(algorithm: str, data: bytes) -> str:
    hasher = hashlib.new(algorithm)
    hasher.update(b"blob %d\0" % len(data))
    hasher.update(data)
    return hasher.hexdigest()


def worktree_matches_head(root: Path) -> bool | None:
    """Whether the checkout at ``root`` is exactly its ``HEAD`` commit.

    Clean means: the index matches ``HEAD`` entry for entry, every
    tracked file's bytes, symlink target and executable bit match the
    committed blob, and there are no untracked files outside the ignore
    rules — the same answer ``git status --porcelain --untracked-files=all``
    gives, without running filter, textconv or diff drivers the checkout
    configures. Returns ``None`` when Git cannot answer.
    """
    root = Path(root)
    algorithm = query(root, "rev-parse", "--show-object-format")
    if algorithm not in ("sha1", "sha256"):
        return None
    tree_output = raw_bytes(root, "ls-tree", "-r", "-z", "--full-tree", "HEAD")
    index_output = raw_bytes(root, "ls-files", "-s", "-z")
    others = raw_bytes(
        root, "ls-files", "-z", "--others", "--exclude-standard")
    if tree_output is None or index_output is None or others is None:
        return None
    tree = _entries(tree_output, tree=True)
    index = _entries(index_output, tree=False)
    if tree is None or index is None:
        return None
    if tree != index or others.strip(b"\0"):
        return False
    base = os.fsencode(root)
    for path, (mode, oid) in tree.items():
        full = os.path.join(base, path)
        try:
            info = os.lstat(full)
        except OSError:
            return False
        if mode == "160000":
            # A submodule is checked for presence only; its own checkout
            # is a separate repository.
            if not stat.S_ISDIR(info.st_mode):
                return False
            continue
        if mode == "120000":
            if not stat.S_ISLNK(info.st_mode):
                return False
            data = os.readlink(full)
        elif mode in ("100644", "100755"):
            if not stat.S_ISREG(info.st_mode):
                return False
            if bool(info.st_mode & stat.S_IXUSR) != (mode == "100755"):
                return False
            hasher = hashlib.new(algorithm)
            hasher.update(b"blob %d\0" % info.st_size)
            size = 0
            try:
                with open(full, "rb") as handle:
                    for chunk in iter(lambda: handle.read(1 << 16), b""):
                        hasher.update(chunk)
                        size += len(chunk)
            except OSError:
                return False
            if size != info.st_size or hasher.hexdigest() != oid:
                return False
            continue
        else:
            return False
        if _blob_id(algorithm, data) != oid:
            return False
    return True
