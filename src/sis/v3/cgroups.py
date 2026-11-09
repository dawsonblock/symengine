"""Minimal cgroup v2 leaf controller for one worker execution (Phase 2.4).

``RLIMIT_NPROC`` is not enforced reliably for the user namespace's
mapped root, and ``RLIMIT_AS`` is a per-process address-space bound, not
an aggregate memory bound. A cgroup v2 leaf gives the worker hard
``pids.max`` and ``memory.max`` limits and a ``cgroup.kill`` that
terminates every process in the group, including descendants that
escape the parent's process group.

The controller operates on a caller-supplied root so it can be tested
against a fake hierarchy. Production uses ``/sys/fs/cgroup`` and fails
closed when cgroup v2 is unavailable or not writable.
"""
from __future__ import annotations

import secrets
from pathlib import Path


class CgroupUnavailable(RuntimeError):
    """The host cannot provide a writable cgroup v2 leaf."""


class CgroupV2Controller:
    """One disposable cgroup v2 leaf with pids/memory limits."""

    def __init__(self, root: str | Path = "/sys/fs/cgroup", *,
                 name: str | None = None) -> None:
        self.root = Path(root)
        if not (self.root / "cgroup.controllers").is_file():
            raise CgroupUnavailable("cgroup_v2_required")
        self.name = name or "sis-worker-" + secrets.token_hex(8)
        self.path = self.root / self.name
        self._created = False

    def create(self, *, pids_max: int | None = None,
               memory_max: int | None = None) -> "CgroupV2Controller":
        if self.path.exists():
            raise CgroupUnavailable("cgroup_name_conflict")
        try:
            self.path.mkdir()
            self._created = True
            self._ensure_controllers(pids_max, memory_max)
            if pids_max is not None:
                (self.path / "pids.max").write_text(str(pids_max))
            if memory_max is not None:
                (self.path / "memory.max").write_text(str(memory_max))
        except CgroupUnavailable:
            self.remove()
            raise
        except OSError as exc:
            self.remove()
            raise CgroupUnavailable(f"cgroup_setup_failed:{exc}") from exc
        return self

    def _ensure_controllers(self, pids_max: int | None,
                            memory_max: int | None) -> None:
        needed = []
        if pids_max is not None and not (self.path / "pids.max").exists():
            needed.append("pids")
        if memory_max is not None and not (self.path / "memory.max").exists():
            needed.append("memory")
        if not needed:
            return
        subtree = self.root / "cgroup.subtree_control"
        current = subtree.read_text().split()
        for controller in needed:
            if controller in current:
                continue
            with open(subtree, "a", encoding="ascii") as handle:
                handle.write("+" + controller + "\n")
        missing = [
            controller for controller in needed
            if not (self.path / f"{controller}.max").exists()]
        if missing:
            raise CgroupUnavailable(
                "cgroup_controller_unavailable:" + ",".join(missing))

    def attach(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0:
            raise ValueError("pid must be a positive integer")
        (self.path / "cgroup.procs").write_text(str(pid))

    def kill(self) -> None:
        kill = self.path / "cgroup.kill"
        if not kill.exists():
            return
        try:
            kill.write_text("1")
        except OSError:
            pass

    def remove(self) -> None:
        if not self._created:
            return
        try:
            self.path.rmdir()
            self._created = False
        except OSError:
            pass

    def __enter__(self) -> "CgroupV2Controller":
        return self

    def __exit__(self, *exc) -> bool:
        self.kill()
        self.remove()
        return False


__all__ = ["CgroupUnavailable", "CgroupV2Controller"]
