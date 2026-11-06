"""Deterministic episode projections with a redaction boundary (SIS3-122).

``project_episode`` replays a stored event log into a stable structural
summary — attempts, tool calls, edits, failure signatures, completion —
suitable for mining and audit. ``agent_view`` produces the agent-facing
projection: the same shape minus evaluator-actor payloads and artifact
contents, which never leave the evidence boundary. Artifact digests may be
referenced; artifact bytes require ``artifact:read`` permission through the
store, not this module.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from .contracts import ObservationEventV1
from .episode_store import EpisodeStore

_EVALUATOR_ACTORS = {"evaluator"}


@dataclass(frozen=True)
class AttemptSummary:
    attempt_id: str
    event_count: int
    first_seq: int
    last_seq: int


@dataclass(frozen=True)
class EpisodeProjection:
    episode_id: str
    event_count: int
    head_digest: str | None
    attempts: tuple[AttemptSummary, ...]
    tool_calls: tuple[Mapping, ...]
    edits: tuple[Mapping, ...]
    test_results: tuple[Mapping, ...]
    failure_signatures: tuple[str, ...]
    artifact_refs: tuple[str, ...]
    completed: bool
    chain_ok: bool


def project_episode(store: EpisodeStore, episode_id: str) -> EpisodeProjection:
    """Replay the episode into a deterministic structural projection."""
    events = store.events(episode_id)
    attempts: dict[str, dict] = {}
    tool_calls: list[Mapping] = []
    edits: list[Mapping] = []
    test_results: list[Mapping] = []
    artifact_refs: list[str] = []
    failures: set[str] = set()

    for event in events:
        bucket = attempts.setdefault(
            event.attempt_id, {"count": 0, "first": event.seq, "last": event.seq}
        )
        bucket["count"] += 1
        bucket["last"] = event.seq
        summary = event.payload.get("summary")
        if event.event_type in {"tool_request", "tool_result"} and isinstance(summary, Mapping):
            tool_calls.append({
                "seq": event.seq,
                "sdk_method": event.payload.get("sdk_method"),
                **{k: summary[k] for k in ("item_type", "exit_code", "item_status") if k in summary},
            })
            code = summary.get("exit_code")
            if type(code) is int and code != 0:
                failures.add(f"{summary.get('item_type', 'unknown')}:exit_{code}")
        elif event.event_type == "edit":
            edits.append({
                "seq": event.seq,
                **(summary if isinstance(summary, Mapping) else {}),
            })
        elif event.event_type == "test_result":
            test_results.append({"seq": event.seq, "actor": event.actor,
                                 **(summary if isinstance(summary, Mapping) else {})})
        artifact_refs.extend(ref for ref in event.artifact_refs if ref not in artifact_refs)

    report = store.verify_episode(episode_id)
    return EpisodeProjection(
        episode_id=episode_id,
        event_count=len(events),
        head_digest=report["head_digest"],
        attempts=tuple(sorted(
            (AttemptSummary(a, b["count"], b["first"], b["last"]) for a, b in attempts.items()),
            key=lambda a: a.first_seq,
        )),
        tool_calls=tuple(tool_calls),
        edits=tuple(edits),
        test_results=tuple(test_results),
        failure_signatures=tuple(sorted(failures)),
        artifact_refs=tuple(artifact_refs),
        completed=any(e.event_type == "completion" for e in events),
        chain_ok=bool(report["ok"]),
    )


def agent_view(projection: EpisodeProjection) -> dict:
    """Redact evaluator-held detail for agent-facing use.

    Returns only digests and structural counts — no artifact bytes, no
    evaluator-authored payload content, no test internals.
    """
    return {
        "schema_version": 1,
        "episode_id": projection.episode_id,
        "event_count": projection.event_count,
        "head_digest": projection.head_digest,
        "attempts": [a.__dict__ for a in projection.attempts],
        "tool_call_count": len(projection.tool_calls),
        "edit_count": len(projection.edits),
        "failure_signatures": list(projection.failure_signatures),
        "artifact_digests": list(projection.artifact_refs),
        "completed": projection.completed,
        "chain_ok": projection.chain_ok,
        "redaction": "evaluator payloads and artifact bytes excluded",
    }
