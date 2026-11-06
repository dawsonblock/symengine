"""Observation adapter for the Codex CLI ``codex exec --json`` interface.

The CLI is launched as a managed child process in a caller-prepared disposable
workspace with ``--ephemeral`` (no session persistence), a scrubbed
environment, a wall-clock deadline, and process-group cleanup. Each JSONL
event line is projected into a bounded structural summary — command text,
output text, file paths, diffs, and message content are never recorded.

The CLI's own sandbox flag (``read-only``/``workspace-write``) constrains the
agent's tool calls; it is not an evaluator security boundary and is recorded
as-is. ``danger-full-access`` is not offered.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import shutil
import signal
import subprocess
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import AgentTurn, SandboxChoice
from ..contracts import ContractError, ObservationEventV1, canonical_digest


_MAX_PROMPT_CHARS = 65_536
_MAX_LINE_BYTES = 1 << 20
_MAX_EVENT_LINES = 100_000
_MAX_STDERR_BYTES = 64 * 1_024
_DEFAULT_WALL_SECONDS = 900
_CLI_SANDBOXES = {"read_only": "read-only", "workspace_write": "workspace-write"}
_ITEM_TYPES = {
    "command_execution", "commandExecution",
    "file_change", "fileChange",
    "agent_message", "reasoning", "mcp_tool_call", "web_search", "todo_list",
    "error",
}
_TERMINAL_METHODS = {"turn.completed", "turn.failed", "error", "turn.cancelled"}


class CodexCliError(RuntimeError):
    """The Codex CLI could not be launched or produced unusable output."""


@dataclass(frozen=True)
class _ActiveProcess:
    proc: subprocess.Popen
    timed_out: list[bool]


class CodexCliAdapter:
    """Drive ``codex exec`` once per turn; events form one episode chain."""

    def __init__(
        self,
        *,
        codex_path: str | Path | None = None,
        wall_seconds: int = _DEFAULT_WALL_SECONDS,
        env_extra: Mapping[str, str] | None = None,
    ) -> None:
        binary = str(codex_path) if codex_path is not None else shutil.which("codex")
        if not binary:
            raise CodexCliError("codex CLI not found on PATH")
        resolved = Path(binary).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise CodexCliError("codex CLI is not an executable file")
        if type(wall_seconds) is not int or not 1 <= wall_seconds <= 86_400:
            raise ValueError("wall_seconds out of range")
        self._binary = str(resolved)
        self._wall_seconds = wall_seconds
        self._env_extra = dict(env_extra or {})
        self._active: dict[str, _ActiveProcess] = {}
        self._lock = threading.Lock()

    def start_task(
        self,
        prompt: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "read_only",
        thread_id: str | None = None,
    ) -> AgentTurn:
        """Launch ``codex exec`` and stream normalized observation events."""
        self._validate_prompt(prompt)
        root = self._workspace(workspace)
        if sandbox not in _CLI_SANDBOXES:
            raise ValueError("sandbox must be 'read_only' or 'workspace_write'")
        argv = [
            self._binary, "exec", "--json", "--ephemeral",
            "--skip-git-repo-check", "--ignore-user-config", "--ignore-rules",
            "--color", "never",
            "-s", _CLI_SANDBOXES[sandbox],
            "-C", str(root),
        ]
        if model is not None:
            self._validate_prompt(model, maximum=128)
            argv += ["-m", model]
        argv.append("--")
        argv.append(prompt)

        thread = thread_id or "clithr-" + secrets.token_hex(8)
        turn = "cliturn-" + secrets.token_hex(8)
        try:
            proc = subprocess.Popen(
                argv,
                cwd=str(root),
                env=self._environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            raise CodexCliError(f"failed to launch codex CLI: {exc}") from exc

        timed_out = [False]
        watchdog = threading.Timer(self._wall_seconds, self._expire, args=(proc, timed_out))
        watchdog.daemon = True
        watchdog.start()
        with self._lock:
            self._active[turn] = _ActiveProcess(proc, timed_out)
        return AgentTurn(
            thread_id=thread,
            turn_id=turn,
            events=self._observe(proc, watchdog, thread, turn, timed_out),
        )

    def resume_thread(self, thread_id: str, workspace: str | Path, **kwargs: Any) -> str:
        raise CodexCliError("thread resume is not supported by the exec JSONL interface")

    def stream_turn(self, thread_id: str, message: str) -> AgentTurn:
        raise CodexCliError("multi-turn streaming is not supported by codex exec; start a new task")

    def send_external_message(self, thread_id: str, content: str, **kwargs: Any) -> AgentTurn:
        raise CodexCliError("external messages are not supported by the exec JSONL interface")

    def cancel(self, turn_id: str) -> object:
        """Kill the process group of an active turn."""
        with self._lock:
            active = self._active.get(turn_id)
        if active is None:
            raise CodexCliError("turn is not active in this adapter")
        self._kill_group(active.proc)
        return {"cancelled": turn_id}

    def close(self) -> None:
        with self._lock:
            active = list(self._active.values())
            self._active.clear()
        for item in active:
            self._kill_group(item.proc)

    def __enter__(self) -> "CodexCliAdapter":
        return self

    def __exit__(self, _t, _e, _tb) -> None:
        self.close()

    def _observe(
        self,
        proc: subprocess.Popen,
        watchdog: threading.Timer,
        thread_id: str,
        turn_id: str,
        timed_out: list[bool],
    ) -> Iterator[ObservationEventV1]:
        prior: str | None = None
        seq = 0
        emitted: list[ObservationEventV1] = []

        def emit(method: str, summary: dict[str, Any], event_type: str,
                 *, actor: str = "agent", extra: Mapping[str, Any] | None = None) -> ObservationEventV1:
            nonlocal prior, seq
            payload: dict[str, Any] = {
                "source_sdk": "codex-cli",
                "sdk_method": method,
                "summary": summary,
                "raw_content_included": False,
            }
            if extra:
                payload.update(extra)
            event = self._make_event(thread_id, turn_id, seq, actor, event_type, payload, prior)
            prior = event.digest
            seq += 1
            emitted.append(event)
            return event

        assert proc.stdout is not None and proc.stderr is not None
        stderr_tail = bytearray()
        try:
            lines = 0
            while lines < _MAX_EVENT_LINES:
                raw = proc.stdout.readline()
                if not raw:
                    break
                lines += 1
                if len(raw) > _MAX_LINE_BYTES:
                    yield emit("sis/oversized_line", {"skipped_bytes": len(raw)}, "agent_event", actor="system")
                    continue
                try:
                    note = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(note, dict):
                    continue
                method, summary, event_type, extra = self._normalize(note)
                yield emit(method, summary, event_type, extra=extra)

            proc.wait(timeout=60)
            stderr_tail.extend(proc.stderr.read(_MAX_STDERR_BYTES + 1)[:_MAX_STDERR_BYTES])
            exit_status = proc.returncode if proc.returncode is not None else -1
            summary = {"cli_exit_status": exit_status}
            if timed_out[0]:
                summary["timed_out"] = True
            if stderr_tail:
                summary["stderr_bytes"] = len(stderr_tail)
            yield emit(
                "sis/process_exit", summary,
                "completion" if exit_status == 0 and not timed_out[0] else "agent_event",
                actor="system",
            )
        finally:
            watchdog.cancel()
            with self._lock:
                self._active.pop(turn_id, None)
            if proc.poll() is None:
                self._kill_group(proc)
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass

    def _normalize(self, note: dict[str, Any]) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
        method = note.get("type")
        method = method if isinstance(method, str) and len(method) <= 128 else "unknown"
        summary: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        for key in ("thread_id", "turn_id", "session_id"):
            value = note.get(key)
            if isinstance(value, str) and len(value) <= 128:
                extra["cli_" + key] = value
        item = note.get("item")
        item_type = item.get("type") if isinstance(item, dict) else None
        if isinstance(item_type, str) and item_type in _ITEM_TYPES:
            summary["item_type"] = item_type
            status = item.get("status")
            if isinstance(status, str) and len(status) <= 64:
                summary["item_status"] = status
            if item_type in {"command_execution", "commandExecution"}:
                code = item.get("exit_code")
                if type(code) is int and -255 <= code <= 255:
                    summary["exit_code"] = code
                output = item.get("aggregated_output") or item.get("output")
                if isinstance(output, str):
                    summary["output_chars"] = min(len(output), 2**31 - 1)
            elif item_type in {"file_change", "fileChange"}:
                changes = item.get("changes")
                if isinstance(changes, list):
                    summary["change_count"] = min(len(changes), 100_000)
            elif item_type == "agent_message":
                text = item.get("text")
                if isinstance(text, str):
                    summary["message_chars"] = min(len(text), 2**31 - 1)
        usage = note.get("usage")
        if isinstance(usage, dict):
            counts = {
                name: value for name, value in usage.items()
                if isinstance(name, str) and type(value) is int and 0 <= value <= 2**63 - 1
            }
            if counts:
                summary["token_usage"] = counts
        error = note.get("message") or note.get("error")
        if method in _TERMINAL_METHODS and isinstance(error, str):
            summary["error_chars"] = min(len(error), 2**31 - 1)

        if method == "item.completed" and item_type in {"command_execution", "commandExecution"}:
            event_type = "tool_result"
        elif method == "item.started" and item_type in {"command_execution", "commandExecution"}:
            event_type = "tool_request"
        elif method == "item.completed" and item_type in {"file_change", "fileChange"}:
            event_type = "edit"
        elif method == "turn.completed":
            event_type = "completion"
        else:
            event_type = "agent_event"
        return method, summary, event_type, extra

    @staticmethod
    def _make_event(
        thread_id: str, turn_id: str, seq: int, actor: str,
        event_type: str, payload: Mapping[str, Any], prior: str | None,
    ) -> ObservationEventV1:
        payload_digest = canonical_digest("event_payload", 1, payload)
        event_id = canonical_digest("codex_event_id", 1, {
            "thread_id_digest": hashlib.sha256(thread_id.encode()).hexdigest(),
            "turn_id_digest": hashlib.sha256(turn_id.encode()).hexdigest(),
            "sequence": seq,
            "payload_digest": payload_digest,
        })
        episode_id = "codex-episode-" + hashlib.sha256(thread_id.encode()).hexdigest()[:32]
        attempt_id = "codex-turn-" + hashlib.sha256(turn_id.encode()).hexdigest()[:32]
        return ObservationEventV1(
            schema_version=1,
            event_id=event_id,
            episode_id=episode_id,
            attempt_id=attempt_id,
            seq=seq,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            actor=actor,
            inputs_digest=None,
            outputs_digest=None,
            artifact_refs=(),
            prior_event_digest=prior,
            idempotency_key=event_id,
            payload_digest=payload_digest,
            payload=payload,
        )

    def _environment(self) -> dict[str, str]:
        env: dict[str, str] = {"NO_COLOR": "1", "TERM": "dumb"}
        for name in ("HOME", "PATH", "TMPDIR", "LANG", "CODEX_HOME", "SHELL"):
            value = os.environ.get(name)
            if value:
                env[name] = value
        env.setdefault("LANG", "en_US.UTF-8")
        env.update(self._env_extra)
        return env

    @staticmethod
    def _expire(proc: subprocess.Popen, timed_out: list[bool]) -> None:
        timed_out[0] = True
        CodexCliAdapter._kill_group(proc)

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except (ProcessLookupError, OSError):
                pass

    @staticmethod
    def _workspace(workspace: str | Path) -> Path:
        try:
            root = Path(workspace).expanduser().resolve(strict=True)
        except (OSError, TypeError, ValueError) as exc:
            raise ValueError("workspace must be an existing directory") from exc
        if not root.is_dir():
            raise ValueError("workspace must be an existing directory")
        return root

    @staticmethod
    def _validate_prompt(prompt: str, *, maximum: int = _MAX_PROMPT_CHARS) -> None:
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > maximum:
            raise ValueError(f"message must be nonempty text of at most {maximum} characters")
        if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in prompt):
            raise ValueError("message contains control characters")
