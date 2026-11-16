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
- runs without optional locks, so ``git status`` cannot rewrite the
  index and trigger a hook while answering.

The queries stay read-only; this module never fetches, checks out or
writes.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

# Command-line configuration is applied to every invocation. Keep this a
# tuple so a caller cannot append after it by accident.
_GLOBAL_OPTIONS = (
    "-c", "core.fsmonitor=false",
    "-c", f"core.hooksPath={os.devnull}",
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
