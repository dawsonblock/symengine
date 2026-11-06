from __future__ import annotations

import tempfile
import unittest
from enum import Enum
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from sis.v3.adapters import (
    AgentAdapter,
    AgentTurn,
    CodexAdapter,
    CodexAdapterError,
    CodexDependencyError,
)


class FakeSandbox(Enum):
    read_only = "read-only"
    workspace_write = "workspace-write"


class FakeExternalMessage:
    def __init__(self, *, tool_name, namespace, content):
        self.tool_name = tool_name
        self.namespace = namespace
        self.content = content


class FakeSdk:
    __version__ = "9.8.7-test"
    Sandbox = FakeSandbox
    ExternalMessage = FakeExternalMessage

    def __init__(self, client):
        self.client = client

    def Codex(self, **_kwargs):
        return self.client


class FakeTurn:
    def __init__(self, turn_id, events=()):
        self.id = turn_id
        self.events = list(events)
        self.interrupted = False

    def stream(self):
        yield from self.events

    def interrupt(self):
        self.interrupted = True
        return "interrupt-requested"


class FakeThread:
    def __init__(self, thread_id="thr-1", event_sets=None):
        self.id = thread_id
        self.event_sets = list(event_sets or [])
        self.calls = []
        self.handles = []

    def turn(self, message, **kwargs):
        self.calls.append((message, kwargs))
        events = self.event_sets.pop(0) if self.event_sets else []
        handle = FakeTurn(f"turn-{len(self.handles) + 1}", events)
        self.handles.append(handle)
        return handle


class FakeCodex:
    def __init__(self, thread=None):
        self.thread = thread or FakeThread()
        self.start_calls = []
        self.resume_calls = []
        self.closed = False

    def thread_start(self, **kwargs):
        self.start_calls.append(kwargs)
        return self.thread

    def thread_resume(self, thread_id, **kwargs):
        self.resume_calls.append((thread_id, kwargs))
        return self.thread

    def close(self):
        self.closed = True


def notification(method, payload):
    return SimpleNamespace(method=method, payload=payload)


class CodexAdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.thread = FakeThread(event_sets=[[
            notification("item/started", SimpleNamespace(item=SimpleNamespace(
                type="commandExecution", command="secret command", status="inProgress"
            ))),
            notification("item/completed", SimpleNamespace(item=SimpleNamespace(
                type="commandExecution", command="secret command", exit_code=0,
                status="completed", aggregated_output="private tool output"
            ))),
            notification("item/completed", SimpleNamespace(item=SimpleNamespace(
                type="fileChange", changes=[{"path": "/private/path"}], status="applied"
            ))),
            notification("item/agentMessage/delta", SimpleNamespace(delta="private assistant text")),
            notification("item/commandExecution/terminalInteraction", SimpleNamespace(
                stdin="private terminal input"
            )),
            notification("thread/tokenUsage/updated", SimpleNamespace(token_usage=SimpleNamespace(
                last=SimpleNamespace(input_tokens=12, output_tokens=4, total_tokens=16),
                total=SimpleNamespace(input_tokens=120, output_tokens=40, total_tokens=160),
            ))),
            notification("turn/completed", SimpleNamespace(turn=SimpleNamespace(status="completed"))),
        ]])
        self.client = FakeCodex(self.thread)
        self.sdk = FakeSdk(self.client)
        self.adapter = CodexAdapter(sdk=self.sdk, client=self.client)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_start_task_uses_typed_sdk_and_emits_bounded_observations(self):
        self.assertIsInstance(self.adapter, AgentAdapter)
        session = self.adapter.start_task(
            "Fix the bug", self.workspace, model="codex-test", sandbox="workspace_write"
        )
        self.assertIsInstance(session, AgentTurn)
        self.assertEqual(session.thread_id, "thr-1")
        self.assertEqual(session.turn_id, "turn-1")
        self.assertEqual(self.client.start_calls[0]["cwd"], str(self.workspace.resolve()))
        self.assertIs(self.client.start_calls[0]["sandbox"], FakeSandbox.workspace_write)
        self.assertEqual(self.client.start_calls[0]["model"], "codex-test")

        events = list(session.events)
        self.assertEqual(
            [event.event_type for event in events],
            ["tool_request", "tool_result", "edit", "agent_event", "agent_event", "agent_event", "completion"],
        )
        self.assertEqual([event.seq for event in events], list(range(7)))
        self.assertIsNone(events[0].prior_event_digest)
        self.assertEqual(events[1].prior_event_digest, events[0].digest)
        self.assertEqual(events[2].prior_event_digest, events[1].digest)
        self.assertEqual(events[0].payload["source_sdk_version"], "9.8.7-test")
        self.assertEqual(events[1].payload["summary"]["exit_code"], 0)
        self.assertEqual(events[2].payload["summary"]["change_count"], 1)
        self.assertEqual(events[3].payload["summary"]["delta_chars"], len("private assistant text"))
        self.assertEqual(events[4].payload["summary"]["stdin_chars"], len("private terminal input"))
        self.assertEqual(events[5].payload["summary"]["token_usage"]["total"]["total_tokens"], 160)
        serialized = str([event.to_dict() for event in events])
        self.assertNotIn("secret command", serialized)
        self.assertNotIn("private tool output", serialized)
        self.assertNotIn("private assistant text", serialized)
        self.assertNotIn("private terminal input", serialized)
        self.assertNotIn("/private/path", serialized)
        self.assertTrue(all(event.payload["raw_content_included"] is False for event in events))

    def test_cancel_interrupts_an_active_turn_and_unknown_turn_fails_closed(self):
        session = self.adapter.start_task("Run task", self.workspace)
        handle = self.thread.handles[0]
        self.assertEqual(self.adapter.cancel(session.turn_id), "interrupt-requested")
        self.assertTrue(handle.interrupted)
        with self.assertRaises(CodexAdapterError):
            self.adapter.cancel("turn-unknown")
        list(session.events)

    def test_external_message_keeps_tool_level_provenance(self):
        session = self.adapter.start_task("Run task", self.workspace)
        external_events = self.adapter.send_external_message(
            session.thread_id,
            "Untrusted advice: inspect the failure first.",
            tool_name="sis_guidance",
            namespace="sis",
        )
        message, kwargs = self.thread.calls[-1]
        self.assertIsInstance(message, FakeExternalMessage)
        self.assertEqual(message.tool_name, "sis_guidance")
        self.assertEqual(message.namespace, "sis")
        self.assertEqual(kwargs["source"], "sis_external_message")
        list(session.events)
        self.assertIsInstance(external_events, AgentTurn)
        self.assertEqual(external_events.thread_id, session.thread_id)
        list(external_events)

    def test_resume_binds_the_requested_workspace_and_rejects_changed_identity(self):
        resumed_id = self.adapter.resume_thread("thr-1", self.workspace)
        self.assertEqual(resumed_id, "thr-1")
        thread_id, kwargs = self.client.resume_calls[-1]
        self.assertEqual(thread_id, "thr-1")
        self.assertEqual(kwargs["cwd"], str(self.workspace.resolve()))
        self.assertIs(kwargs["sandbox"], FakeSandbox.read_only)

        self.client.thread_resume = lambda *_args, **_kwargs: FakeThread("thr-other")
        with self.assertRaises(CodexAdapterError):
            self.adapter.resume_thread("thr-1", self.workspace)

    def test_rejects_unbounded_prompts_paths_and_full_access(self):
        with self.assertRaises(ValueError):
            self.adapter.start_task("", self.workspace)
        with self.assertRaises(ValueError):
            self.adapter.start_task("x" * 65_537, self.workspace)
        with self.assertRaises(ValueError):
            self.adapter.start_task("task", self.workspace / "missing")
        with self.assertRaises(ValueError):
            self.adapter.start_task("task", self.workspace, sandbox="full_access")
        with self.assertRaises(ValueError):
            CodexAdapter(sdk_version="x" * 129)

    def test_external_message_bounds_and_identifiers_are_checked(self):
        session = self.adapter.start_task("task", self.workspace)
        with self.assertRaises(ValueError):
            self.adapter.send_external_message(session.thread_id, "x" * 16_385)
        with self.assertRaises(ValueError):
            self.adapter.send_external_message(session.thread_id, "advice", tool_name="bad name")
        with self.assertRaises(ValueError):
            self.adapter.send_external_message(session.thread_id, "advice", namespace=None)

    def test_missing_optional_sdk_has_actionable_error(self):
        adapter = CodexAdapter()
        with patch(
            "sis.v3.adapters.codex.importlib.import_module",
            side_effect=ModuleNotFoundError("not installed", name="openai_codex"),
        ):
            with self.assertRaisesRegex(CodexDependencyError, r"\[codex\]"):
                adapter.start_task("task", self.workspace)

    def test_adapter_closes_owned_client_but_not_injected_client(self):
        self.adapter.close()
        self.assertFalse(self.client.closed)

        owned_client = FakeCodex()
        owned_adapter = CodexAdapter(sdk=FakeSdk(owned_client))
        owned_adapter.start_task("Run task", self.workspace)
        owned_adapter.close()
        self.assertTrue(owned_client.closed)


if __name__ == "__main__":
    unittest.main()
