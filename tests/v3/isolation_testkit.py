"""Test doubles for the production isolation boundary (SIS v3.3.4, Phase 2).

``ScriptedExecutor`` implements the workspace lifecycle and returns
schema-valid execution receipts without claiming real containment. It is
how the verifier's attestation gate is tested without pretending the
local subprocess backend is qualified.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from sis.v3.contracts import ExecutionReceiptV1
from sis.v3.runner import (
    Workspace,
    command_spec_digest,
    tree_digest,
)

BOOTSTRAP_VERSION = b"8.4.2\n"
PYTEST_VERSION = b"pytest 8.4.2\n"


class ScriptedExecutor:
    """A receipt-producing executor with no real containment."""

    def __init__(self, root, *, worker_identity="worker-A",
                 exit_status=0, timeout=False, security_errors=(),
                 environment_digest="e" * 64):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.worker_identity = worker_identity
        self.exit_status = exit_status
        self.timeout = timeout
        self.security_errors = tuple(security_errors)
        self.environment_digest = environment_digest
        self._outputs: dict[str, tuple[bytes, bytes]] = {}
        self._counter = 0

    def prepare(self, base_dir, *, label="task"):
        self._counter += 1
        workspace_id = f"ws-{self._counter}"
        path = self.root / workspace_id
        shutil.copytree(Path(base_dir), path)
        return Workspace(
            workspace_id=workspace_id,
            path=path,
            before_tree_digest=tree_digest(Path(base_dir)),
            executor_identity=self.worker_identity,
        )

    def run(self, workspace, spec):
        self._counter += 1
        execution_id = f"exec-{self._counter}"
        stdout = b""
        exit_status = self.exit_status
        if any("import pytest; print" in arg for arg in spec.argv):
            stdout = BOOTSTRAP_VERSION
            exit_status = 0
        elif "-m" in spec.argv and "pytest" in spec.argv:
            stdout = PYTEST_VERSION
            exit_status = 0
        self._outputs[execution_id] = (stdout, b"")
        return ExecutionReceiptV1(
            schema_version=1,
            execution_id=execution_id,
            worker_identity=self.worker_identity,
            environment_digest=self.environment_digest,
            before_tree_digest=workspace.before_tree_digest,
            after_tree_digest=tree_digest(workspace.path),
            command_spec_digest=command_spec_digest(spec),
            exit_status=exit_status,
            stdout_digest=None,
            stderr_digest=None,
            resource_usage={"cpu_seconds": 0, "wall_seconds": 0},
            timeout=self.timeout,
            security_errors=self.security_errors,
        )

    def destroy(self, workspace):
        shutil.rmtree(workspace.path, ignore_errors=True)

    def terminate_all(self):
        pass

    def output(self, execution_id):
        return self._outputs.get(execution_id, (b"", b""))
