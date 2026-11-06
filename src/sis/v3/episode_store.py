"""Append-only episode event and content-addressed artifact store (SIS3-005).

Events are canonical ``ObservationEventV1`` records appended as single JSONL
lines and chained through ``prior_event_digest``. Appends are idempotent on
``event_id`` and ``idempotency_key``; conflicting reuse, sequence gaps, chain
breaks, and references to missing artifacts are rejected. A trailing partial
line left by a crash is truncated on the next append; earlier bytes are never
rewritten. ``verify_episode`` replays the file and reports any tampering.

Artifacts live under ``artifacts/<digest[:2]>/<digest>`` and are written
atomically; reading always re-checks the content digest.

Append-only here means this implementation never modifies earlier bytes and
detects their corruption — it is code discipline over a writable filesystem,
not WORM custody. Durability claims against a writer with store access require
OS-enforced object immutability or an external anchor; ``anchor_head`` exports
ledger heads for that purpose.
"""
from __future__ import annotations

import hashlib
import os
import re
import tempfile
import threading
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .contracts import ContractError, ObservationEventV1, canonical_json

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None

MAX_ARTIFACT_BYTES = 16 << 20
MAX_EPISODE_EVENTS = 100_000
_EPISODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class EpisodeStoreError(RuntimeError):
    """The store cannot complete an operation."""


class ConflictError(EpisodeStoreError):
    """An event conflicts with already-persisted episode state."""


class IntegrityError(EpisodeStoreError):
    """Persisted bytes do not match their claimed identity."""


@dataclass
class _Index:
    size: int
    count: int
    last_digest: str | None
    ids: dict[str, str]
    keys: dict[str, str]


class EpisodeStore:
    """Filesystem-backed append-only store rooted at a private directory."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        (self.root / "artifacts").mkdir(parents=True, exist_ok=True)
        (self.root / "episodes").mkdir(exist_ok=True)
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._indexes: dict[str, _Index] = {}

    def put_artifact(self, data: bytes) -> str:
        """Store bytes under their SHA-256 digest; return the digest."""
        if not isinstance(data, bytes) or len(data) > MAX_ARTIFACT_BYTES:
            raise ContractError(f"artifact must be at most {MAX_ARTIFACT_BYTES} bytes")
        digest = hashlib.sha256(data).hexdigest()
        directory = self.root / "artifacts" / digest[:2]
        directory.mkdir(exist_ok=True)
        target = directory / digest
        if not target.exists():
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp, target)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        return digest

    def has_artifact(self, digest: str) -> bool:
        return (self.root / "artifacts" / digest[:2] / digest).is_file()

    def read_artifact(self, digest: str) -> bytes:
        """Return artifact bytes after re-verifying the content digest."""
        if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
            raise ContractError("artifact reference must be a lowercase SHA-256 digest")
        path = self.root / "artifacts" / digest[:2] / digest
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise IntegrityError("artifact_missing") from exc
        if hashlib.sha256(data).hexdigest() != digest:
            raise IntegrityError("artifact_digest_mismatch")
        return data

    def append_event(self, event: ObservationEventV1 | Mapping) -> ObservationEventV1:
        """Append one chained event; retries on a stable event are idempotent."""
        if not isinstance(event, ObservationEventV1):
            event = ObservationEventV1.from_dict(event)
        path = self._episode_path(event.episode_id)
        with self._episode_lock(event.episode_id):
            guard = self._file_lock(event.episode_id)
            try:
                self._repair_tail(event.episode_id)
                index = self._index(event.episode_id)
                if index.count >= MAX_EPISODE_EVENTS:
                    raise ConflictError("episode_event_bound_reached")
                if event.event_id in index.ids:
                    if index.ids[event.event_id] == event.digest:
                        return self._find_event(path, event.event_id)
                    raise ConflictError("event_id_reused_with_different_content")
                if event.idempotency_key in index.keys:
                    if index.keys[event.idempotency_key] == event.digest:
                        return self._find_event(path, event.event_id)
                    raise ConflictError("idempotency_key_reused_with_different_content")
                if event.seq != index.count:
                    raise ConflictError("sequence_conflict")
                if event.prior_event_digest != index.last_digest:
                    raise ConflictError("chain_conflict")
                for ref in event.artifact_refs:
                    if not self.has_artifact(ref):
                        raise ConflictError("missing_artifact_ref")
                line = event.canonical_bytes() + b"\n"
                with open(path, "ab") as handle:
                    handle.write(line)
                    handle.flush()
                    os.fsync(handle.fileno())
                index.ids[event.event_id] = event.digest
                index.keys[event.idempotency_key] = event.digest
                index.last_digest = event.digest
                index.count += 1
                index.size += len(line)
                return event
            finally:
                guard.close()

    def events(self, episode_id: str) -> list[ObservationEventV1]:
        """Replay the episode in stored order."""
        path = self._episode_path(episode_id)
        if not path.exists():
            raise EpisodeStoreError("unknown_episode")
        result = []
        with open(path, "rb") as handle:
            for line in handle:
                result.append(ObservationEventV1.from_json(line.rstrip(b"\n")))
        return result

    def iter_events(self, episode_id: str) -> Iterator[ObservationEventV1]:
        yield from self.events(episode_id)

    def episode_ids(self) -> list[str]:
        base = self.root / "episodes"
        return sorted(
            path.stem for path in base.glob("*.jsonl") if _EPISODE_ID.fullmatch(path.stem)
        )

    def head_digest(self, episode_id: str) -> str | None:
        events = self.events(episode_id)
        return events[-1].digest if events else None

    def verify_episode(self, episode_id: str) -> dict:
        """Replay and check sequence, chain, uniqueness, and artifact presence."""
        problems: list[str] = []
        try:
            raw_lines = (self._episode_path(episode_id)).read_bytes().splitlines()
        except OSError:
            return {"episode_id": episode_id, "ok": False, "events": 0,
                    "head_digest": None, "problems": ["unknown_episode"]}
        seen_ids: set[str] = set()
        seen_keys: set[str] = set()
        prior: str | None = None
        for position, line in enumerate(raw_lines):
            try:
                event = ObservationEventV1.from_json(line)
            except ContractError:
                problems.append(f"undecodable_event_at_{position}")
                continue
            if event.seq != position:
                problems.append(f"sequence_conflict_at_{position}")
            if event.prior_event_digest != prior:
                problems.append(f"chain_conflict_at_{position}")
            if event.event_id in seen_ids:
                problems.append(f"event_id_reused_at_{position}")
            if event.idempotency_key in seen_keys:
                problems.append(f"idempotency_key_reused_at_{position}")
            seen_ids.add(event.event_id)
            seen_keys.add(event.idempotency_key)
            for ref in event.artifact_refs:
                if not self.has_artifact(ref):
                    problems.append(f"missing_artifact_ref_at_{position}")
            prior = event.digest
        return {
            "episode_id": episode_id,
            "ok": not problems,
            "events": len(raw_lines),
            "head_digest": prior,
            "problems": problems,
        }

    def anchor_head(self, episode_id: str, anchor_dir: str | Path) -> dict:
        """Export a ledger head to a caller-supplied, separately controlled dir.

        The anchor document is canonical JSON identifying the episode, event
        count, head digest, and export timestamp; custody of ``anchor_dir`` is
        the caller's responsibility.
        """
        report = self.verify_episode(episode_id)
        if not report["ok"]:
            raise IntegrityError("cannot anchor a corrupt episode")
        document = {
            "schema_version": 1,
            "episode_id": episode_id,
            "event_count": report["events"],
            "head_digest": report["head_digest"],
            "anchored_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
        target_dir = Path(anchor_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        payload = canonical_json(document)
        fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, target_dir / f"{episode_id}.head.json")
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return document

    def _episode_path(self, episode_id: str) -> Path:
        if not isinstance(episode_id, str) or not _EPISODE_ID.fullmatch(episode_id):
            raise ContractError("episode_id is not a valid identifier")
        return self.root / "episodes" / f"{episode_id}.jsonl"

    def _episode_lock(self, episode_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(episode_id, threading.Lock())

    def _file_lock(self, episode_id: str):
        """Best-effort cross-process lock; degrades to in-process only."""
        path = self.root / "episodes" / f"{episode_id}.lock"
        handle = open(path, "ab")
        if fcntl is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def _find_event(self, path: Path, event_id: str) -> ObservationEventV1:
        with open(path, "rb") as handle:
            for line in handle:
                if f'"event_id":"{event_id}"'.encode("utf-8") in line:
                    event = ObservationEventV1.from_json(line.rstrip(b"\n"))
                    if event.event_id == event_id:
                        return event
        raise IntegrityError("indexed event is missing from the log")

    def _index(self, episode_id: str) -> _Index:
        path = self._episode_path(episode_id)
        size = path.stat().st_size if path.exists() else 0
        cached = self._indexes.get(episode_id)
        if cached is not None and cached.size == size:
            return cached
        index = _Index(size=0, count=0, last_digest=None, ids={}, keys={})
        if path.exists():
            with open(path, "rb") as handle:
                for raw in handle:
                    line = raw.rstrip(b"\n")
                    if not line:
                        continue
                    try:
                        event = ObservationEventV1.from_json(line)
                    except ContractError as exc:
                        raise IntegrityError("stored event is undecodable") from exc
                    index.ids[event.event_id] = event.digest
                    index.keys[event.idempotency_key] = event.digest
                    index.last_digest = event.digest
                    index.count += 1
        index.size = size
        self._indexes[episode_id] = index
        return index

    def _repair_tail(self, episode_id: str) -> int:
        """Truncate a trailing partial line left by an interrupted append."""
        path = self._episode_path(episode_id)
        if not path.exists():
            return 0
        size = path.stat().st_size
        if size == 0:
            return 0
        with open(path, "rb+") as handle:
            handle.seek(size - 1)
            if handle.read(1) == b"\n":
                return 0
            handle.seek(0)
            data = handle.read()
            cut = data.rfind(b"\n")
            keep = cut + 1 if cut >= 0 else 0
            dropped = size - keep
            handle.seek(keep)
            handle.truncate()
            handle.flush()
            os.fsync(handle.fileno())
        self._indexes.pop(episode_id, None)
        return dropped
