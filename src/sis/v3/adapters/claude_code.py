"""Observation adapter for Claude Code's headless ``claude -p`` interface.

Claude Code runs once per turn in a caller-prepared disposable workspace,
in print mode with ``--output-format stream-json --verbose`` (one JSON
object per line), no session persistence, a scrubbed environment, a
wall-clock watchdog and process-group cleanup. :func:`claude_code_argv`
is the single place the command line is built; change it there and the
pinned CLI version in the manifest together.

Each stream line is projected into a bounded structural summary. Message
text, tool inputs, tool output and file contents are never recorded: a
summary carries counts, tool *names*, token usage and terminal status.

Token usage
    Claude Code emits one ``assistant`` line per content block, and every
    line of one API message repeats that message's ``usage``. The adapter
    keeps the largest usage seen per message id and emits only the
    increase as ``summary["token_usage_delta"]``, so summing deltas never
    double-counts. The final ``result`` line carries the cumulative
    ``usage`` for the run as ``summary["token_usage"]``. The budget total
    is ``input_tokens + output_tokens``; cache reads and cache creation are
    reported separately and are not part of that total.

Tool calls
    Every distinct ``tool_use`` block (by id, subagent calls included) is
    counted once, in ``summary["new_tool_uses"]`` with its tool name.

Permission mode
    ``acceptEdits`` by default, with ``--allowed-tools`` naming the tools a
    coding task needs. Nothing can prompt in print mode; a tool outside
    the allowed set is denied. Like the Codex CLI's sandbox flag, this
    constrains the agent's tool calls and is not an evaluator security
    boundary.
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
from collections.abc import Iterator, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import AgentTurn, SandboxChoice
from ..contracts import ObservationEventV1, canonical_digest

_MAX_PROMPT_CHARS = 65_536
_MAX_LINE_BYTES = 4 << 20
_MAX_EVENT_LINES = 200_000
_MAX_STDERR_BYTES = 64 * 1_024
_MAX_TRACKED_IDS = 100_000
_DEFAULT_WALL_SECONDS = 900
_MAX_INT = 2**63 - 1
#: Usage counters recorded from the stream; anything else is ignored.
USAGE_FIELDS = ("input_tokens", "output_tokens",
                "cache_creation_input_tokens", "cache_read_input_tokens")
#: Tools a coding task needs, allowed without a prompt. Names must exist in
#: the pinned CLI version (2.1.x exposes Bash, Read, Edit, Write,
#: NotebookEdit; search runs through Bash).
DEFAULT_ALLOWED_TOOLS = ("Bash", "Read", "Edit", "Write", "NotebookEdit")
#: Denied outright: a study task must be solved from the workspace alone.
DEFAULT_DISALLOWED_TOOLS = ("WebFetch", "WebSearch")
EDIT_TOOLS = frozenset({"Edit", "MultiEdit", "Write", "NotebookEdit"})
PERMISSION_MODES = ("acceptEdits", "bypassPermissions", "dontAsk")
# The environment is rebuilt from this allowlist: credentials and the
# network settings the CLI needs to reach its API, and nothing that would
# make a nested run inherit the parent's session.
_ENV_ALLOWLIST = (
    "HOME", "PATH", "TMPDIR", "LANG", "SHELL", "USER", "LOGNAME",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CONFIG_DIR",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    "AWS_REGION", "AWS_PROFILE", "CLOUD_ML_REGION",
    "ANTHROPIC_VERTEX_PROJECT_ID",
    "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    "https_proxy", "http_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
)


class ClaudeCodeError(RuntimeError):
    """Claude Code could not be launched or produced unusable output."""


def claude_code_argv(
    binary: str,
    prompt: str,
    *,
    model: str | None = None,
    permission_mode: str = "acceptEdits",
    allowed_tools: Sequence[str] = DEFAULT_ALLOWED_TOOLS,
    max_budget_usd: str | None = None,
) -> list[str]:
    """The exact Claude Code command line SIS runs for one turn.

    - ``-p`` print (headless) mode; the prompt is the final argument,
      after ``--`` so a prompt beginning with ``-`` is not an option.
    - ``--output-format stream-json --verbose``: one JSON event per line
      (``system``/``assistant``/``user``/``result``); ``--verbose`` is
      required for stream-json in print mode.
    - ``--no-session-persistence``: nothing is written for ``--resume``.
    - ``--safe-mode``: user CLAUDE.md, skills, plugins, hooks, MCP servers
      and custom agents are off, so the operator's personal configuration
      cannot differ between arms or leak into the study. The task
      repository is the agent's only context besides the prompt.
    - ``--strict-mcp-config`` with no ``--mcp-config``: no MCP servers.
    - ``--disable-slash-commands``: no skills or custom commands.
    - ``--permission-mode`` and ``--allowed-tools``: see the module
      docstring; ``--permission-prompts none`` denies anything that would
      otherwise wait for an answer; ``--disallowed-tools`` denies web
      access (``DEFAULT_DISALLOWED_TOOLS``).
    - ``--model`` when the manifest pins one; ``--max-budget-usd`` as a
      provider-side backstop (the SIS token budget is enforced live).

    The working directory is the workspace (set by the caller), so no
    ``--add-dir`` is passed.
    """
    if permission_mode not in PERMISSION_MODES:
        raise ValueError("permission_mode must be one of "
                         + ", ".join(PERMISSION_MODES))
    tools = [str(name) for name in allowed_tools]
    if not tools or any(not name or not name.replace("_", "").isalnum()
                        for name in tools):
        raise ValueError("allowed_tools must be plain tool names")
    argv = [
        binary, "-p",
        "--output-format", "stream-json", "--verbose",
        "--no-session-persistence",
        "--safe-mode",
        "--strict-mcp-config",
        "--disable-slash-commands",
        "--permission-mode", permission_mode,
        "--permission-prompts", "none",
        "--allowed-tools", ",".join(tools),
        "--disallowed-tools", ",".join(DEFAULT_DISALLOWED_TOOLS),
    ]
    if model is not None:
        argv += ["--model", model]
    if max_budget_usd is not None:
        argv += ["--max-budget-usd", max_budget_usd]
    argv += ["--", prompt]
    return argv


def _bounded_int(value) -> int | None:
    return value if type(value) is int and 0 <= value <= _MAX_INT else None


def usage_counts(usage) -> dict[str, int]:
    """The recognised integer usage counters of one usage record."""
    if not isinstance(usage, Mapping):
        return {}
    counts = {}
    for name in USAGE_FIELDS:
        value = _bounded_int(usage.get(name))
        if value is not None:
            counts[name] = value
    return counts


class ClaudeCodeAdapter:
    """Drive ``claude -p`` once per turn; events form one episode chain."""

    def __init__(
        self,
        *,
        claude_path: str | Path | None = None,
        wall_seconds: int = _DEFAULT_WALL_SECONDS,
        env_extra: Mapping[str, str] | None = None,
        permission_mode: str = "acceptEdits",
        allowed_tools: Sequence[str] = DEFAULT_ALLOWED_TOOLS,
    ) -> None:
        binary = (str(claude_path) if claude_path is not None
                  else shutil.which("claude"))
        if not binary:
            raise ClaudeCodeError("claude CLI not found on PATH")
        resolved = Path(binary).resolve()
        if not resolved.is_file() or not os.access(resolved, os.X_OK):
            raise ClaudeCodeError("claude CLI is not an executable file")
        if type(wall_seconds) is not int or not 1 <= wall_seconds <= 86_400:
            raise ValueError("wall_seconds out of range")
        # Validate once; claude_code_argv re-validates per turn.
        claude_code_argv(str(resolved), "x", permission_mode=permission_mode,
                         allowed_tools=allowed_tools)
        self._binary = str(resolved)
        self._wall_seconds = wall_seconds
        self._env_extra = dict(env_extra or {})
        self._permission_mode = permission_mode
        self._allowed_tools = tuple(allowed_tools)
        self._active: dict[str, subprocess.Popen] = {}
        self._lock = threading.Lock()

    @property
    def binary(self) -> str:
        return self._binary

    def start_task(
        self,
        prompt: str,
        workspace: str | Path,
        *,
        model: str | None = None,
        sandbox: SandboxChoice = "workspace_write",
        thread_id: str | None = None,
    ) -> AgentTurn:
        """Launch ``claude -p`` and stream normalized observation events.

        ``sandbox="read_only"`` drops the edit tools and ``Bash`` from the
        allowed set; ``workspace_write`` uses the configured set.
        """
        self._validate_prompt(prompt)
        root = self._workspace(workspace)
        if sandbox not in ("read_only", "workspace_write"):
            raise ValueError("sandbox must be 'read_only' or 'workspace_write'")
        tools = self._allowed_tools
        if sandbox == "read_only":
            tools = tuple(name for name in tools
                          if name not in EDIT_TOOLS and name != "Bash")
        if model is not None:
            self._validate_prompt(model, maximum=128)
        argv = claude_code_argv(
            self._binary, prompt, model=model,
            permission_mode=self._permission_mode, allowed_tools=tools)
        thread = thread_id or "ccthr-" + secrets.token_hex(8)
        turn = "ccturn-" + secrets.token_hex(8)
        try:
            proc = subprocess.Popen(
                argv, cwd=str(root), env=self._environment(),
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, start_new_session=True)
        except OSError as exc:
            raise ClaudeCodeError(f"failed to launch claude CLI: {exc}") from exc
        timed_out = [False]
        watchdog = threading.Timer(
            self._wall_seconds, self._expire, args=(proc, timed_out))
        watchdog.daemon = True
        watchdog.start()
        with self._lock:
            self._active[turn] = proc
        return AgentTurn(thread_id=thread, turn_id=turn,
                         events=self._observe(proc, watchdog, thread, turn,
                                              timed_out))

    def resume_thread(self, thread_id: str, workspace: str | Path,
                      **kwargs: Any) -> str:
        raise ClaudeCodeError("session resume is disabled: SIS runs Claude"
                              " Code without session persistence")

    def stream_turn(self, thread_id: str, message: str) -> AgentTurn:
        raise ClaudeCodeError("multi-turn streaming is not supported; start"
                              " a new task")

    def send_external_message(self, thread_id: str, content: str,
                              **kwargs: Any) -> AgentTurn:
        raise ClaudeCodeError("external messages are not supported by print"
                              " mode")

    def cancel(self, turn_id: str) -> object:
        """Kill the process group of an active turn."""
        with self._lock:
            proc = self._active.get(turn_id)
        if proc is None:
            raise ClaudeCodeError("turn is not active in this adapter")
        self._kill_group(proc)
        return {"cancelled": turn_id}

    def close(self) -> None:
        with self._lock:
            active = list(self._active.values())
            self._active.clear()
        for proc in active:
            self._kill_group(proc)

    def __enter__(self) -> "ClaudeCodeAdapter":
        return self

    def __exit__(self, _t, _e, _tb) -> None:
        self.close()

    # ---- stream ------------------------------------------------------- #
    def _observe(self, proc, watchdog, thread_id, turn_id, timed_out
                 ) -> Iterator[ObservationEventV1]:
        prior: str | None = None
        seq = 0
        state = _StreamState()

        def emit(method, summary, event_type, *, actor="agent", extra=None):
            nonlocal prior, seq
            payload: dict[str, Any] = {
                "source_sdk": "claude-code",
                "sdk_method": method,
                "summary": summary,
                "raw_content_included": False,
            }
            if extra:
                payload.update(extra)
            event = self._make_event(thread_id, turn_id, seq, actor,
                                     event_type, payload, prior)
            prior = event.digest
            seq += 1
            return event

        assert proc.stdout is not None and proc.stderr is not None
        stderr_tail = bytearray()

        def drain_stderr() -> None:
            while True:
                try:
                    chunk = proc.stderr.read(8192)
                except (OSError, ValueError):
                    return
                if not chunk:
                    return
                room = _MAX_STDERR_BYTES - len(stderr_tail)
                if room > 0:
                    stderr_tail.extend(chunk[:room])

        stderr_thread = threading.Thread(target=drain_stderr, daemon=True)
        stderr_thread.start()
        try:
            lines = 0
            while lines < _MAX_EVENT_LINES:
                raw, skipped = self._read_bounded_line(proc.stdout)
                if raw is None and not skipped:
                    break
                lines += 1
                if raw is None:
                    yield emit("sis/oversized_line",
                               {"skipped_bytes": min(skipped, _MAX_INT)},
                               "agent_event", actor="system")
                    continue
                try:
                    note = json.loads(raw)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                if not isinstance(note, dict):
                    continue
                method, summary, event_type, extra = state.normalize(note)
                yield emit(method, summary, event_type, extra=extra)
            try:
                proc.wait(timeout=60)
            except subprocess.TimeoutExpired:
                self._kill_group(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            stderr_thread.join(timeout=5)
            exit_status = proc.returncode if proc.returncode is not None else -1
            summary = {"cli_exit_status": exit_status}
            if timed_out[0]:
                summary["timed_out"] = True
            if stderr_tail:
                summary["stderr_bytes"] = len(stderr_tail)
            yield emit("sis/process_exit", summary,
                       "completion" if exit_status == 0 and not timed_out[0]
                       else "agent_event", actor="system")
        finally:
            watchdog.cancel()
            with self._lock:
                self._active.pop(turn_id, None)
            # The CLI can exit while commands it started keep running in
            # its process group; always kill the group.
            self._kill_group(proc)
            stderr_thread.join(timeout=5)
            for stream in (proc.stdout, proc.stderr):
                try:
                    stream.close()
                except OSError:
                    pass

    @staticmethod
    def _read_bounded_line(stream) -> tuple[bytes | None, int]:
        raw = stream.readline(_MAX_LINE_BYTES + 1)
        if not raw:
            return None, 0
        if len(raw) <= _MAX_LINE_BYTES:
            return raw, 0
        skipped = len(raw)
        while not raw.endswith(b"\n"):
            raw = stream.readline(_MAX_LINE_BYTES + 1)
            if not raw:
                break
            skipped += len(raw)
        return None, skipped

    @staticmethod
    def _make_event(thread_id, turn_id, seq, actor, event_type, payload,
                    prior) -> ObservationEventV1:
        payload_digest = canonical_digest("event_payload", 1, payload)
        event_id = canonical_digest("claude_code_event_id", 1, {
            "thread_id_digest": hashlib.sha256(thread_id.encode()).hexdigest(),
            "turn_id_digest": hashlib.sha256(turn_id.encode()).hexdigest(),
            "sequence": seq,
            "payload_digest": payload_digest,
        })
        return ObservationEventV1(
            schema_version=1,
            event_id=event_id,
            episode_id="claude-episode-"
            + hashlib.sha256(thread_id.encode()).hexdigest()[:32],
            attempt_id="claude-turn-"
            + hashlib.sha256(turn_id.encode()).hexdigest()[:32],
            seq=seq,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc).isoformat(
                timespec="microseconds").replace("+00:00", "Z"),
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
        env: dict[str, str] = {
            "NO_COLOR": "1", "TERM": "dumb",
            # No update checks, telemetry or error reporting mid-study.
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
        }
        for name in _ENV_ALLOWLIST:
            value = os.environ.get(name)
            if value:
                env[name] = value
        env.setdefault("LANG", "en_US.UTF-8")
        env.update(self._env_extra)
        return env

    @staticmethod
    def _expire(proc: subprocess.Popen, timed_out: list[bool]) -> None:
        timed_out[0] = True
        ClaudeCodeAdapter._kill_group(proc)

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        killpg = getattr(os, "killpg", None)
        if killpg is not None:
            try:
                killpg(proc.pid, getattr(signal, "SIGKILL", signal.SIGTERM))
                return
            except (ProcessLookupError, PermissionError, OSError,
                    AttributeError):
                pass
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
        if not isinstance(prompt, str) or not prompt.strip() \
                or len(prompt) > maximum:
            raise ValueError(
                f"message must be nonempty text of at most {maximum} characters")
        if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in prompt):
            raise ValueError("message contains control characters")


class _StreamState:
    """Per-turn de-duplication of message usage and tool-use ids."""

    def __init__(self) -> None:
        self.usage_by_message: dict[str, dict[str, int]] = {}
        self.tool_ids: set[str] = set()

    def normalize(self, note: Mapping[str, Any]
                  ) -> tuple[str, dict[str, Any], str, dict[str, Any]]:
        kind = note.get("type")
        kind = kind if isinstance(kind, str) and len(kind) <= 64 else "unknown"
        subtype = note.get("subtype")
        method = kind
        if isinstance(subtype, str) and 0 < len(subtype) <= 64:
            method = f"{kind}.{subtype}"
        summary: dict[str, Any] = {}
        extra: dict[str, Any] = {}
        session = note.get("session_id")
        if isinstance(session, str) and len(session) <= 128:
            extra["cli_session_id"] = session
        event_type = "agent_event"
        if kind == "assistant":
            event_type = self._assistant(note, summary)
        elif kind == "user":
            event_type = self._user(note, summary)
        elif kind == "result":
            event_type = self._result(note, summary)
        elif kind == "system" and subtype == "init":
            model = note.get("model")
            if isinstance(model, str) and len(model) <= 128:
                summary["model"] = model
            tools = note.get("tools")
            if isinstance(tools, list):
                summary["tool_count"] = min(len(tools), 100_000)
        return method, summary, event_type, extra

    def _assistant(self, note, summary) -> str:
        message = note.get("message")
        message = message if isinstance(message, Mapping) else {}
        message_id = message.get("id")
        counts = usage_counts(message.get("usage"))
        if counts and isinstance(message_id, str) and message_id:
            key = hashlib.sha256(message_id.encode()).hexdigest()
            previous = self.usage_by_message.get(key)
            if previous is None and len(self.usage_by_message) >= _MAX_TRACKED_IDS:
                previous = {}
            current = dict(previous or {})
            delta = {}
            for name, value in counts.items():
                grown = value - current.get(name, 0)
                if grown > 0:
                    delta[name] = grown
                    current[name] = value
            if len(self.usage_by_message) < _MAX_TRACKED_IDS or key in \
                    self.usage_by_message:
                self.usage_by_message[key] = current
            if delta:
                summary["token_usage_delta"] = delta
        elif counts:
            # A usage record without a message id cannot be de-duplicated;
            # report it as a delta (Claude Code always sets an id).
            summary["token_usage_delta"] = counts
        new_tools: list[str] = []
        text_chars = 0
        content = message.get("content")
        if isinstance(content, list):
            for block in content[:10_000]:
                if not isinstance(block, Mapping):
                    continue
                if block.get("type") == "tool_use":
                    tool_id = block.get("id")
                    name = block.get("name")
                    name = name if isinstance(name, str) and len(name) <= 128 \
                        else "unknown"
                    if isinstance(tool_id, str) and tool_id:
                        if tool_id in self.tool_ids:
                            continue
                        if len(self.tool_ids) < _MAX_TRACKED_IDS:
                            self.tool_ids.add(tool_id)
                    new_tools.append(name)
                elif block.get("type") == "text":
                    text = block.get("text")
                    if isinstance(text, str):
                        text_chars += len(text)
        if new_tools:
            summary["new_tool_uses"] = new_tools
        if text_chars:
            summary["message_chars"] = min(text_chars, 2**31 - 1)
        if note.get("parent_tool_use_id"):
            summary["subagent"] = True
        if new_tools:
            return "edit" if any(name in EDIT_TOOLS for name in new_tools) \
                else "tool_request"
        return "agent_event"

    @staticmethod
    def _user(note, summary) -> str:
        message = note.get("message")
        content = message.get("content") if isinstance(message, Mapping) else None
        results = errors = 0
        if isinstance(content, list):
            for block in content[:10_000]:
                if isinstance(block, Mapping) and \
                        block.get("type") == "tool_result":
                    results += 1
                    errors += block.get("is_error") is True
        if results:
            summary["tool_results"] = results
            if errors:
                summary["tool_errors"] = errors
            return "tool_result"
        return "agent_event"

    @staticmethod
    def _result(note, summary) -> str:
        counts = usage_counts(note.get("usage"))
        if counts:
            summary["token_usage"] = counts
        is_error = note.get("is_error")
        summary["is_error"] = is_error is True
        for name in ("num_turns", "duration_ms", "duration_api_ms"):
            value = _bounded_int(note.get(name))
            if value is not None:
                summary[name] = value
        cost = note.get("total_cost_usd")
        if type(cost) in (int, float) and 0 <= cost < 1e9:
            # Canonical payloads carry integers only.
            summary["cost_usd_micros"] = int(round(cost * 1_000_000))
        result = note.get("result")
        if isinstance(result, str):
            summary["result_chars"] = min(len(result), 2**31 - 1)
        return "agent_event" if is_error is True else "completion"


__all__ = ["ClaudeCodeAdapter", "ClaudeCodeError", "DEFAULT_ALLOWED_TOOLS",
           "DEFAULT_DISALLOWED_TOOLS",
           "EDIT_TOOLS", "PERMISSION_MODES", "USAGE_FIELDS",
           "claude_code_argv", "usage_counts"]
