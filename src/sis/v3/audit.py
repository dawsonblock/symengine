"""External anchor chain for episode ledger heads.

``AnchorChain`` keeps a hash-chained JSONL log in a directory the caller
controls separately from the episode store — the trust model only holds if
that directory has independent custody (different filesystem, object store,
or signed timestamping). ``anchor_episode`` records the verified head;
``verify_all`` replays each anchored episode and reports divergence between
the anchored head and the current store state, distinguishing a legitimate
append (episode grew) from corruption (chain or digest failure).
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .contracts import ContractError, canonical_json, loads_json
from .episode_store import EpisodeStore


class AnchorError(RuntimeError):
    """An anchor operation failed or the anchor log is corrupt."""


@dataclass(frozen=True)
class Divergence:
    episode_id: str
    kind: str  # "grew_after_anchor" | "corrupt" | "missing"
    anchored_head: str | None
    current_head: str | None


class AnchorChain:
    """Append-only anchor log at ``<dir>/anchors.jsonl``."""

    def __init__(self, anchor_dir: str | Path) -> None:
        self.anchor_dir = Path(anchor_dir)
        self.anchor_dir.mkdir(parents=True, exist_ok=True)
        self._log = self.anchor_dir / "anchors.jsonl"
        self._prior: str | None = None
        self._entries: list[dict] = []
        self._load()

    def anchor_episode(self, store: EpisodeStore, episode_id: str) -> dict:
        """Verify then anchor the current head of one episode."""
        report = store.verify_episode(episode_id)
        if not report["ok"]:
            raise AnchorError(f"cannot anchor corrupt episode: {report['problems']}")
        entry = {
            "schema_version": 1,
            "seq": len(self._entries),
            "episode_id": episode_id,
            "event_count": report["events"],
            "head_digest": report["head_digest"],
            "anchored_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "prior_anchor_digest": self._prior,
        }
        line = canonical_json(entry)
        with open(self._log, "ab") as handle:
            handle.write(line + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        self._prior = hashlib.sha256(line).hexdigest()
        self._entries.append({**entry, "anchor_digest": self._prior})
        return self._entries[-1]

    def verify_all(self, store: EpisodeStore) -> dict:
        """Compare every anchored head with the episode store's live state."""
        divergences: list[Divergence] = []
        latest: dict[str, dict] = {}
        for entry in self._entries:
            latest[entry["episode_id"]] = entry
        for episode_id, entry in sorted(latest.items()):
            report = store.verify_episode(episode_id)
            if not report["ok"]:
                kind = "missing" if "unknown_episode" in report["problems"] else "corrupt"
                divergences.append(Divergence(episode_id, kind, entry["head_digest"], report["head_digest"]))
            elif report["head_digest"] != entry["head_digest"]:
                divergences.append(Divergence(episode_id, "grew_after_anchor", entry["head_digest"], report["head_digest"]))
        return {
            "ok": not divergences,
            "anchored_episodes": len(latest),
            "divergences": [d.__dict__ for d in divergences],
        }

    def entries(self) -> list[dict]:
        return list(self._entries)

    def _load(self) -> None:
        if not self._log.exists():
            return
        with open(self._log, "rb") as handle:
            for position, raw in enumerate(handle):
                line = raw.rstrip(b"\n")
                try:
                    entry = loads_json(line)
                except ContractError as exc:
                    raise AnchorError(f"anchor log line {position} is corrupt") from exc
                required = {"schema_version", "seq", "episode_id", "event_count",
                            "head_digest", "anchored_at", "prior_anchor_digest"}
                if set(entry) != required or entry["seq"] != position:
                    raise AnchorError(f"anchor log line {position} has an unexpected shape")
                if entry["prior_anchor_digest"] != self._prior:
                    raise AnchorError(f"anchor log line {position} breaks the chain")
                self._prior = hashlib.sha256(line).hexdigest()
                self._entries.append({**entry, "anchor_digest": self._prior})
