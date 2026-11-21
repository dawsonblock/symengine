"""Serialize tests that run as the real agent user, host-wide.

``AgentPrincipal.kill_all`` SIGKILLs every process of the agent user. Two
suites on one host that share ``SIS_TEST_AGENT_USER`` therefore kill each
other's helpers (seen as exit -9 in the timeout test). Every test that runs
anything as the real agent user holds :class:`AgentUserLock` while it does.

The lock is an exclusive ``flock`` on one file per user in the system temp
directory, mode 0o666 so root and a non-root runner share it. The kernel
drops it when the holder exits, however it exits. POSIX-only: without
``fcntl`` (Windows) this module still imports, and ``acquire`` refuses.
"""
from __future__ import annotations

import os
import tempfile

try:
    import fcntl
except ImportError:  # Windows: agent principals are POSIX-only.
    fcntl = None


def agent_user_lock_path(user: str) -> str:
    """The host-wide lock file for ``user``."""
    return os.path.join(tempfile.gettempdir(), f"sis-agent-user-{user}.lock")


def _open_shared(path: str) -> int:
    """Open the lock file, creating it with mode 0o666 if it is absent.

    An existing file is opened without ``O_CREAT``: with
    ``fs.protected_regular`` set, ``O_CREAT`` on another user's file in a
    sticky directory such as /tmp fails, even for root.
    """
    while True:
        try:
            return os.open(path, os.O_RDWR)
        except FileNotFoundError:
            pass
        except PermissionError:
            # Another user's file we may not write: flock needs only a
            # descriptor, and a read-only one will do.
            return os.open(path, os.O_RDONLY)
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o666)
        except FileExistsError:
            continue  # another process created it first; open that one
        try:
            # The umask narrowed the mode; the other users need it back.
            os.fchmod(fd, 0o666)
        except PermissionError:
            pass
        return fd


class AgentUserLock:
    """An exclusive, host-wide hold on one agent user."""

    def __init__(self, user: str) -> None:
        self.user = user
        self.path = agent_user_lock_path(user)
        self._fd: int | None = None

    def acquire(self) -> None:
        """Block until no other process on this host holds the user."""
        if fcntl is None:
            raise RuntimeError("the agent user lock is POSIX-only")
        if self._fd is not None:
            raise RuntimeError(f"the lock on {self.user} is already held")
        fd = _open_shared(self.path)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        """Drop the lock; closing the descriptor releases the flock."""
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)

    def __enter__(self) -> AgentUserLock:
        self.acquire()
        return self

    def __exit__(self, *exc_info) -> None:
        self.release()
