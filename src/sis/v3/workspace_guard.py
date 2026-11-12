"""Managed-workspace ownership guard (SIS v3.3.8, Phase 1).

A :class:`~sis.v3.runner.Workspace` handle is a capability, not a path.
Each backend records every workspace it creates in a private registry,
and execution or deletion resolves the handle's ID through that
registry. A caller-supplied path is accepted only when it is exactly the
registered canonical path; anything else is rejected before the backend
mounts, executes within, or deletes a directory.

The registry also serializes destruction against in-flight executions. A
workspace marked closing refuses new runs, live executions are terminated
by the backend first, and the directory is removed only after every
execution that already started has left its critical section. Repeated
destruction is a no-op: an unregistered ID never reaches a filesystem
operation.
"""
from __future__ import annotations

import os
import re
import secrets
import shutil
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

_WORKSPACE_ID = re.compile(r"^ws-[0-9a-f]{16}$")
_DESTROY_WAIT_SECONDS = 30.0


class WorkspaceOwnershipError(RuntimeError):
    """A workspace handle does not name a directory this executor owns."""


@dataclass(frozen=True)
class WorkspaceRecord:
    """Canonical registry entry for one managed workspace.

    ``path`` is the absolute lexical path the executor constructed;
    ``real_path`` is its symlink-resolved form at registration time. Both
    are re-checked on every use so a directory swapped for a symlink is
    rejected rather than followed.
    """

    workspace_id: str
    path: Path
    real_path: Path
    executor_identity: str
    before_tree_digest: str


def protected_overlap(
    path: str | Path, protected: Iterable[str | Path],
) -> Path | None:
    """Return the first protected path that contains, or lives in, ``path``.

    Overlap in either direction is a rejection: a source tree inside a
    key/registry directory would copy secrets into a workspace, and a
    protected directory inside a source tree would be copied verbatim.
    """
    real = Path(os.path.realpath(path))
    for candidate in protected:
        other = Path(os.path.realpath(candidate))
        if (real == other or real.is_relative_to(other)
                or other.is_relative_to(real)):
            return other
    return None


class ManagedWorkspaceRegistry:
    """Private, thread-safe registry of workspaces owned by one executor."""

    def __init__(
        self,
        root: str | Path,
        *,
        executor_identity: str,
        error: type[Exception] = WorkspaceOwnershipError,
    ) -> None:
        if not isinstance(executor_identity, str) or not executor_identity:
            raise error("executor_identity must be a non-empty string")
        self.root = Path(os.path.abspath(root))
        self.workspaces_root = self.root / "workspaces"
        self.workspaces_root.mkdir(parents=True, exist_ok=True)
        self._real_root = Path(os.path.realpath(self.workspaces_root))
        self.executor_identity = executor_identity
        self._error = error
        self._records: dict[str, WorkspaceRecord] = {}
        self._active: dict[str, int] = {}
        self._closing: set[str] = set()
        self._condition = threading.Condition(threading.RLock())

    # ---- creation ------------------------------------------------------- #
    def allocate(self) -> tuple[str, Path]:
        """Return a fresh ID and its path inside this executor's root."""
        workspace_id = "ws-" + secrets.token_hex(8)
        return workspace_id, self.workspaces_root / workspace_id

    def register(
        self, workspace_id: str, path: str | Path, *,
        before_tree_digest: str,
    ) -> WorkspaceRecord:
        """Record a workspace that this executor just created."""
        if (not isinstance(workspace_id, str)
                or not _WORKSPACE_ID.fullmatch(workspace_id)):
            raise self._error("workspace_id_malformed")
        path = Path(os.path.abspath(path))
        if path.parent != self.workspaces_root:
            raise self._error("workspace_path_outside_workspace_root")
        if path.is_symlink() or not path.is_dir():
            raise self._error("workspace_path_not_a_managed_directory")
        real = Path(os.path.realpath(path))
        if real != self._real_root / workspace_id:
            raise self._error("workspace_path_symlink_escape")
        record = WorkspaceRecord(
            workspace_id=workspace_id,
            path=path,
            real_path=real,
            executor_identity=self.executor_identity,
            before_tree_digest=str(before_tree_digest),
        )
        with self._condition:
            if workspace_id in self._records:
                raise self._error("workspace_id_already_registered")
            self._records[workspace_id] = record
        return record

    # ---- resolution ----------------------------------------------------- #
    def resolve(
        self, workspace_id: str, path: str | Path, *,
        executor_identity: str,
    ) -> WorkspaceRecord:
        """Resolve a handle to its registry record, or reject it."""
        with self._condition:
            return self._resolve_locked(workspace_id, path, executor_identity)

    def _resolve_locked(
        self, workspace_id: str, path: str | Path, executor_identity: str,
    ) -> WorkspaceRecord:
        record = self._records.get(workspace_id)
        if record is None:
            raise self._error("workspace_not_registered")
        if (not isinstance(executor_identity, str)
                or executor_identity != record.executor_identity
                or executor_identity != self.executor_identity):
            raise self._error("workspace_executor_identity_mismatch")
        if not isinstance(path, (str, os.PathLike)):
            raise self._error("workspace_path_substituted")
        if Path(os.path.abspath(path)) != record.path:
            raise self._error("workspace_path_substituted")
        self._verify_record(record)
        return record

    def _verify_record(self, record: WorkspaceRecord) -> None:
        if record.path.is_symlink():
            raise self._error("workspace_path_symlink_escape")
        real = Path(os.path.realpath(record.path))
        if (real != record.real_path or real == self._real_root
                or not real.is_relative_to(self._real_root)):
            raise self._error("workspace_path_symlink_escape")

    @contextmanager
    def execution(
        self, workspace_id: str, path: str | Path, *,
        executor_identity: str,
    ) -> Iterator[WorkspaceRecord]:
        """Mark one execution in flight so destruction cannot race it."""
        with self._condition:
            record = self._resolve_locked(
                workspace_id, path, executor_identity)
            if workspace_id in self._closing:
                raise self._error("workspace_is_closing")
            self._active[workspace_id] = self._active.get(workspace_id, 0) + 1
        try:
            yield record
        finally:
            with self._condition:
                remaining = self._active.get(workspace_id, 1) - 1
                if remaining > 0:
                    self._active[workspace_id] = remaining
                else:
                    self._active.pop(workspace_id, None)
                self._condition.notify_all()

    def is_closing(self, workspace_id: str) -> bool:
        with self._condition:
            return workspace_id in self._closing

    # ---- destruction ---------------------------------------------------- #
    def begin_destroy(
        self, workspace_id: str, path: str | Path, *,
        executor_identity: str,
    ) -> WorkspaceRecord | None:
        """Validate and mark a workspace closing; ``None`` if already gone.

        An unknown ID, including one from another executor, is a no-op:
        cleanup must never reach a path the registry did not create.
        """
        deadline = time.monotonic() + _DESTROY_WAIT_SECONDS
        with self._condition:
            while True:
                record = self._records.get(workspace_id)
                if record is None:
                    return None
                if (executor_identity != record.executor_identity
                        or executor_identity != self.executor_identity):
                    raise self._error("workspace_executor_identity_mismatch")
                if Path(os.path.abspath(path)) != record.path:
                    raise self._error("workspace_path_substituted")
                if workspace_id not in self._closing:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise self._error("workspace_busy")
                self._condition.wait(min(remaining, 1.0))
            self._closing.add(workspace_id)
        try:
            self._verify_record(record)
        except BaseException:
            self.abort_destroy(workspace_id)
            raise
        return record

    def wait_idle(self, workspace_id: str, *, timeout: float = 30.0) -> bool:
        """Wait until every execution that started has left its section."""
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._active.get(workspace_id, 0) > 0:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
        return True

    def remove(self, record: WorkspaceRecord) -> bool:
        """Delete the registered directory, never a substituted target."""
        path = record.path
        if path.is_symlink():
            try:
                path.unlink()
            except OSError:
                return False
            return True
        if not path.exists():
            return True
        real = Path(os.path.realpath(path))
        if (real != record.real_path or real == self._real_root
                or not real.is_relative_to(self._real_root)):
            return False
        shutil.rmtree(path, ignore_errors=True)
        return not path.exists()

    def finish_destroy(self, workspace_id: str) -> None:
        with self._condition:
            self._records.pop(workspace_id, None)
            self._closing.discard(workspace_id)
            self._condition.notify_all()

    def abort_destroy(self, workspace_id: str) -> None:
        with self._condition:
            self._closing.discard(workspace_id)
            self._condition.notify_all()


__all__ = [
    "ManagedWorkspaceRegistry",
    "WorkspaceOwnershipError",
    "WorkspaceRecord",
    "protected_overlap",
]
