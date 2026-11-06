"""Optional adapter for the public OpenAI Codex Python SDK.

Codex event text, tool output, and file-change notifications are untrusted
observations. This module records only bounded structural summaries and never
creates evaluator receipts or claims that Codex's sandbox isolates hostile
repository code.
"""
from __future__ import annotations

import hashlib
import importlib
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any

from .base import AgentTurn, SandboxChoice
from ..contracts import ObservationEventV1, canonical_digest


_ALLOWED_SANDBOXES = frozenset({"read_only", "workspace_write"})
_MAX_PROMPT_CHARS = 65_536
_MAX_EXTERNAL_CHARS = 16_384
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
_SAFE_METHOD = re.compile(r"^[A-Za-z0-9_./:@-]{1,128}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9_.+-]{1,128}$")


class CodexAdapterError(RuntimeError):
    """The Codex adapter could not perform a requested operation."""


class CodexDependencyError(CodexAdapterError):
    """The optional openai-codex SDK is not installed."""


@dataclass(frozen=True)
class _ThreadState:
    thread: Any
    workspace: Path
    sandbox: str


class CodexAdapter:
    """Stream Codex's typed public events into SIS observation envelopes.

    The adapter defaults Codex to read-only access. Callers may opt into the
    SDK's workspace-write preset for an authorized coding task. Neither preset
    is treated as an evaluator security boundary.
    """

    def __init__(
        self,
        *,
        config: Any | None = None,
        sdk: Any | None = None,
        client: Any | None = None,
        sdk_version: str | None = None,
        require_authentication: bool = False,
    ) -> None:
        if sdk_version is not None and (
            not isinstance(sdk_version, str) or not _SAFE_VERSION.fullmatch(sdk_version)
        ):
            raise ValueError("sdk_version must be a bounded version identifier")
        if type(require_authentication) is not bool:
            raise ValueError("require_authentication must be Boolean")
        self._config = config
        self._sdk = sdk
        self._client = client
        self._owns_client = client is None
        self._sdk_version = sdk_version
        self._require_auth = require_authentication
        self._threads: dict[str, _ThreadState] = {}
        self._active_turns: dict[str, Any] = {}
        self._usage: dict[str, int] = {}
        self._tools: dict[str, int] = {}
        self._lock = RLock()

    def __enter__(self) -> "CodexAdapter":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        self.close()

    def start_task(
        self,
        prompt: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "read_only",
    ) -> AgentTurn:
        """Start a task and return its thread/turn IDs with the first event stream."""
        self._validate_prompt(prompt, maximum=_MAX_PROMPT_CHARS)
        root = self._workspace(workspace)
        sandbox_enum = self._sandbox(sandbox)
        kwargs: dict[str, Any] = {"cwd": str(root), "sandbox": sandbox_enum}
        if model is not None:
            kwargs["model"] = model
        thread = self._get_client().thread_start(**kwargs)
        thread_id = self._validate_thread_id(getattr(thread, "id", None))
        with self._lock:
            self._threads[thread_id] = _ThreadState(thread, root, sandbox)
        return self._start_stream(thread_id, prompt)

    def resume_thread(
        self,
        thread_id: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "read_only",
    ) -> str:
        """Resume a thread while explicitly binding it to a local workspace."""
        thread_id = self._validate_thread_id(thread_id)
        root = self._workspace(workspace)
        sandbox_enum = self._sandbox(sandbox)
        kwargs: dict[str, Any] = {"cwd": str(root), "sandbox": sandbox_enum}
        if model is not None:
            kwargs["model"] = model
        thread = self._get_client().thread_resume(thread_id, **kwargs)
        actual_id = self._validate_thread_id(getattr(thread, "id", None))
        if actual_id != thread_id:
            raise CodexAdapterError("Codex resumed a different thread than requested")
        with self._lock:
            self._threads[thread_id] = _ThreadState(thread, root, sandbox)
        return thread_id

    def stream_turn(self, thread_id: str, message: str) -> AgentTurn:
        """Run and observe one user-authorized text turn."""
        self._validate_prompt(message, maximum=_MAX_PROMPT_CHARS)
        return self._start_stream(thread_id, message)

    def send_external_message(
        self,
        thread_id: str,
        content: str,
        *,
        tool_name: str = "sis_guidance",
        namespace: str = "sis",
    ) -> AgentTurn:
        """Deliver bounded untrusted SIS/tool content at tool-level authority."""
        self._validate_prompt(content, maximum=_MAX_EXTERNAL_CHARS)
        if (
            not isinstance(tool_name, str)
            or not isinstance(namespace, str)
            or not _SAFE_COMPONENT.fullmatch(tool_name)
            or not _SAFE_COMPONENT.fullmatch(namespace)
        ):
            raise ValueError("tool_name and namespace must be bounded identifiers")
        sdk = self._get_sdk()
        if not callable(getattr(sdk, "ExternalMessage", None)):
            raise CodexAdapterError("installed SDK does not expose ExternalMessage")
        external_message = sdk.ExternalMessage(
            tool_name=tool_name,
            namespace=namespace,
            content=content,
        )
        return self._start_stream(thread_id, external_message, source="sis_external_message")

    def cancel(self, turn_id: str) -> object:
        """Request interruption of a currently streamed Codex turn."""
        turn_id = self._validate_thread_id(turn_id)
        with self._lock:
            handle = self._active_turns.get(turn_id)
        if handle is None:
            raise CodexAdapterError("turn is not active in this adapter")
        return handle.interrupt()

    def close(self) -> None:
        """Close an adapter-owned SDK process and discard transient handles."""
        with self._lock:
            client = self._client if self._owns_client else None
            self._client = None if self._owns_client else self._client
            self._threads.clear()
            self._active_turns.clear()
        if client is not None:
            client.close()

    def _start_stream(
        self, thread_id: str, message: Any, *, source: str | None = None
    ) -> AgentTurn:
        thread_id = self._validate_thread_id(thread_id)
        with self._lock:
            state = self._threads.get(thread_id)
        if state is None:
            raise CodexAdapterError("thread is not known to this adapter; resume it first")
        kwargs: dict[str, Any] = {
            "cwd": str(state.workspace),
            "sandbox": self._sandbox(state.sandbox),
        }
        if source is not None:
            kwargs["source"] = source
        handle = state.thread.turn(message, **kwargs)
        turn_id = self._validate_thread_id(getattr(handle, "id", None))
        with self._lock:
            if turn_id in self._active_turns:
                raise CodexAdapterError("Codex returned a duplicate active turn ID")
            self._active_turns[turn_id] = handle
        return AgentTurn(thread_id, turn_id, self._observe_stream(thread_id, turn_id, handle))

    def _observe_stream(
        self, thread_id: str, turn_id: str, handle: Any
    ) -> Iterator[ObservationEventV1]:
        previous_digest: str | None = None
        try:
            for sequence, notification in enumerate(handle.stream()):
                event = self._normalize_event(
                    thread_id=thread_id,
                    turn_id=turn_id,
                    sequence=sequence,
                    prior_digest=previous_digest,
                    notification=notification,
                )
                previous_digest = event.digest
                self._record_usage(thread_id, event)
                yield event
        finally:
            with self._lock:
                self._active_turns.pop(turn_id, None)

    def _record_usage(self, thread_id: str, event: ObservationEventV1) -> None:
        """Track runtime-derived usage from normalized event payloads."""
        summary = event.payload.get("summary") or {}
        usage = summary.get("token_usage") or {}
        total = (usage.get("total") or {}).get("total_tokens")
        with self._lock:
            if type(total) is int:
                self._usage[thread_id] = total
            if event.event_type == "tool_request":
                self._tools[thread_id] = self._tools.get(thread_id, 0) + 1

    def usage(self, thread_id: str) -> dict[str, int | None]:
        """Runtime-extracted usage for a thread: stream-derived, not self-reported.

        ``tokens`` is the last ``total_tokens`` the SDK reported on the
        stream (``None`` when the SDK never reported usage);
        ``tools`` counts ``tool_request`` events observed so far.
        """
        thread_id = self._validate_thread_id(thread_id)
        with self._lock:
            return {
                "tokens": self._usage.get(thread_id),
                "tools": self._tools.get(thread_id, 0),
            }

    def _normalize_event(
        self,
        *,
        thread_id: str,
        turn_id: str,
        sequence: int,
        prior_digest: str | None,
        notification: Any,
    ) -> ObservationEventV1:
        method = getattr(notification, "method", "unknown")
        if not isinstance(method, str) or not _SAFE_METHOD.fullmatch(method):
            method = "unknown"
        payload_obj = getattr(notification, "payload", None)
        summary = self._safe_summary(payload_obj)
        payload: Mapping[str, Any] = {
            "source_sdk": "openai-codex-python",
            "source_sdk_version": self._source_sdk_version(),
            "sdk_method": method,
            "summary": summary,
            "raw_content_included": False,
        }
        payload_digest = canonical_digest("event_payload", 1, payload)
        event_type = self._event_type(method, summary.get("item_type"))
        event_id = canonical_digest("codex_event_id", 1, {
            "thread_id_digest": hashlib.sha256(thread_id.encode("utf-8")).hexdigest(),
            "turn_id_digest": hashlib.sha256(turn_id.encode("utf-8")).hexdigest(),
            "sequence": sequence,
            "payload_digest": payload_digest,
        })
        episode_id = "codex-episode-" + hashlib.sha256(thread_id.encode("utf-8")).hexdigest()[:32]
        attempt_id = "codex-turn-" + hashlib.sha256(turn_id.encode("utf-8")).hexdigest()[:32]
        return ObservationEventV1(
            schema_version=1,
            event_id=event_id,
            episode_id=episode_id,
            attempt_id=attempt_id,
            seq=sequence,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z"),
            actor="agent",
            inputs_digest=None,
            outputs_digest=None,
            artifact_refs=(),
            prior_event_digest=prior_digest,
            idempotency_key=event_id,
            payload_digest=payload_digest,
            payload=payload,
        )

    def _safe_summary(self, payload: Any) -> dict[str, Any]:
        """Project only bounded structural fields; omit all content and paths."""
        summary: dict[str, Any] = {"payload_type": type(payload).__name__[:128]}
        item = getattr(payload, "item", None)
        item_type = self._safe_string(getattr(item, "type", None)) if item is not None else None
        if item_type:
            summary["item_type"] = item_type
        if item_type == "commandExecution":
            exit_code = getattr(item, "exit_code", None)
            if type(exit_code) is int and -255 <= exit_code <= 255:
                summary["exit_code"] = exit_code
            status = self._safe_string(getattr(item, "status", None))
            if status:
                summary["item_status"] = status
        elif item_type == "fileChange":
            changes = getattr(item, "changes", None)
            if isinstance(changes, (tuple, list)):
                summary["change_count"] = min(len(changes), 100_000)
            status = self._safe_string(getattr(item, "status", None))
            if status:
                summary["item_status"] = status

        turn = getattr(payload, "turn", None)
        if turn is not None:
            status = self._safe_string(getattr(turn, "status", None))
            if status:
                summary["turn_status"] = status
        delta = getattr(payload, "delta", None)
        if isinstance(delta, str):
            summary["delta_chars"] = min(len(delta), 2**31 - 1)
        output = getattr(payload, "output", None)
        if isinstance(output, str):
            summary["output_chars"] = min(len(output), 2**31 - 1)
        diff = getattr(payload, "diff", None)
        if isinstance(diff, str):
            summary["diff_chars"] = min(len(diff), 2**31 - 1)
        stdin = getattr(payload, "stdin", None)
        if isinstance(stdin, str):
            summary["terminal_interaction"] = True
            summary["stdin_chars"] = min(len(stdin), 2**31 - 1)
        token_usage = getattr(payload, "token_usage", None)
        if token_usage is not None:
            usage_summary = {}
            for group_name in ("last", "total"):
                group = getattr(token_usage, group_name, None)
                if group is None:
                    continue
                counts = {}
                for field_name in (
                    "input_tokens", "output_tokens", "reasoning_output_tokens", "total_tokens",
                    "cached_input_tokens", "cache_write_input_tokens",
                ):
                    count = getattr(group, field_name, None)
                    if type(count) is int and 0 <= count <= 2**63 - 1:
                        counts[field_name] = count
                if counts:
                    usage_summary[group_name] = counts
            if usage_summary:
                summary["token_usage"] = usage_summary
        return summary

    @staticmethod
    def _event_type(method: str, item_type: str | None) -> str:
        if method == "turn/completed":
            return "completion"
        if method == "item/started" and item_type == "commandExecution":
            return "tool_request"
        if method == "item/completed" and item_type == "commandExecution":
            return "tool_result"
        if method == "item/completed" and item_type == "fileChange":
            return "edit"
        if method == "commandExecution/outputDelta":
            return "tool_result"
        if method == "fileChange/outputDelta":
            return "edit"
        return "agent_event"

    def _get_client(self) -> Any:
        if self._client is None:
            sdk = self._get_sdk()
            self._client = sdk.Codex() if self._config is None else sdk.Codex(config=self._config)
            self._owns_client = True
            if self._require_auth:
                self._require_authenticated(self._client)
        elif self._require_auth:
            self._require_authenticated(self._client)
        return self._client

    @staticmethod
    def _require_authenticated(client: Any) -> None:
        """Fail closed unless the SDK client provably holds a session.

        ``require_authentication`` means "the runtime is authenticated or
        nothing runs" — a missing, falsy, or unverifiable auth probe is a
        refusal, never a silent degradation to an anonymous runtime.
        """
        for probe in ("authenticated", "is_authenticated", "auth_status"):
            candidate = getattr(client, probe, None)
            if candidate is None:
                continue
            try:
                result = candidate() if callable(candidate) else candidate
            except Exception as exc:
                raise CodexAdapterError(
                    f"authentication probe failed: {type(exc).__name__}") from exc
            if not result:
                raise CodexAdapterError("authentication_failed")
            return
        authenticate = getattr(client, "authenticate", None)
        if callable(authenticate):
            try:
                if not authenticate():
                    raise CodexAdapterError("authentication_failed")
            except CodexAdapterError:
                raise
            except Exception as exc:
                raise CodexAdapterError(
                    f"authentication_failed: {type(exc).__name__}") from exc
            return
        raise CodexAdapterError(
            "authentication_unverifiable: SDK exposes no auth probe")

    def _get_sdk(self) -> Any:
        if self._sdk is None:
            try:
                self._sdk = importlib.import_module("openai_codex")
            except ModuleNotFoundError as exc:
                if exc.name == "openai_codex":
                    raise CodexDependencyError(
                        "Codex support is optional; install SIS with `pip install '.[codex]'`."
                    ) from exc
                raise
        if not hasattr(self._sdk, "Codex") or not hasattr(self._sdk, "Sandbox"):
            raise CodexAdapterError("installed SDK does not expose the required Codex API")
        if self._sdk_version is None:
            version = getattr(self._sdk, "__version__", "unknown")
            self._sdk_version = version if isinstance(version, str) and _SAFE_VERSION.fullmatch(version) else "unknown"
        return self._sdk

    def _source_sdk_version(self) -> str:
        self._get_sdk()
        return self._sdk_version or "unknown"

    def _sandbox(self, name: str) -> Any:
        if not isinstance(name, str) or name not in _ALLOWED_SANDBOXES:
            raise ValueError("sandbox must be 'read_only' or 'workspace_write'")
        sdk = self._get_sdk()
        try:
            return sdk.Sandbox.__members__[name]
        except (AttributeError, KeyError) as exc:
            raise CodexAdapterError("installed SDK is missing a supported sandbox preset") from exc

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
    def _validate_prompt(prompt: str, *, maximum: int) -> None:
        if not isinstance(prompt, str) or not prompt.strip() or len(prompt) > maximum:
            raise ValueError(f"message must be nonempty text of at most {maximum} characters")
        if any(ord(character) < 32 and character not in "\n\r\t" for character in prompt):
            raise ValueError("message contains control characters")

    @staticmethod
    def _validate_thread_id(thread_id: Any) -> str:
        if not isinstance(thread_id, str) or not _SAFE_COMPONENT.fullmatch(thread_id):
            raise ValueError("Codex thread/turn ID is malformed")
        return thread_id

    @staticmethod
    def _safe_string(value: Any) -> str | None:
        if isinstance(value, str):
            result = value
        else:
            result = getattr(value, "value", None)
        if isinstance(result, str) and _SAFE_COMPONENT.fullmatch(result):
            return result
        return None
