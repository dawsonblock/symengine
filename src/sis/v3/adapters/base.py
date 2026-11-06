"""Small observation-only interface shared by coding-agent adapters."""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from ..contracts import ObservationEventV1

SandboxChoice = Literal["read_only", "workspace_write"]


@runtime_checkable
class AgentAdapter(Protocol):
    """Observe agent sessions without assigning evaluator authority."""

    def start_task(
        self,
        prompt: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "read_only",
    ) -> AgentTurn: ...

    def resume_thread(
        self,
        thread_id: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "read_only",
    ) -> str: ...

    def stream_turn(self, thread_id: str, message: str) -> AgentTurn: ...

    def send_external_message(
        self,
        thread_id: str,
        content: str,
        *,
        tool_name: str = "sis_guidance",
        namespace: str = "sis",
    ) -> AgentTurn: ...

    def cancel(self, turn_id: str) -> object: ...

    def close(self) -> None: ...


@dataclass(frozen=True)
class AgentTurn:
    """A Codex turn handle and its one-shot normalized event stream."""

    thread_id: str
    turn_id: str
    events: Iterator[ObservationEventV1]

    def __iter__(self) -> Iterator[ObservationEventV1]:
        return iter(self.events)
