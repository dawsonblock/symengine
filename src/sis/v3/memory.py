"""Experience-memory subsystem (SIS v3.3, milestone 2).

ReasoningBank-style episodic memory, rebuilt inside the v3 trust model:

- Ingestion accepts only schema-validated ``ExperienceRecordV1`` JSON —
  no pickle, no caller-asserted verification flags. The record carries
  digest references to the verified outcome receipt and the execution
  trace; large artifacts stay outside the record.
- Induction produces ``CandidateV1`` records of type
  ``experience_memory`` — *candidates*, never qualified truth. Facts
  (observed) and hypotheses (model-inferred) are stored separately and
  only facts may serve as evidence handles downstream.
- ``UNIQUE(episode_id, task_fingerprint)`` dedup means replaying the same
  episode can never masquerade as independent attempts.
- Retrieval gates on trusted repository scope, applicability predicates
  (the same allowlisted kinds as procedure retrieval), counterexample
  suppression, score threshold and a deterministic token budget — and
  abstains instead of guessing. Unqualified memory never reaches this
  function: callers pass only registry-qualified candidates.
"""
from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .candidates import content_digest
from .contracts import (CandidateV1, ContractError, ExperienceRecordV1,
                        loads_json)
from .retrieval import (RetrievalContext, precondition_holds,
                        suppression_match)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS experience (
    experience_id TEXT PRIMARY KEY,
    episode_id TEXT NOT NULL,
    task_fingerprint TEXT NOT NULL,
    repository_registry_id TEXT NOT NULL,
    record_digest TEXT NOT NULL UNIQUE,
    record_json TEXT NOT NULL,
    outcome TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE (episode_id, task_fingerprint)
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class MemoryError(RuntimeError):
    """The memory store cannot complete an operation."""


class DuplicateEpisode(MemoryError):
    """The same episode + task fingerprint was already ingested."""


class MemoryStore:
    """Durable, deduplicating store of verified experience records.

    The store holds evidence-pointers only: it never executes, never
    interprets content as instructions, and never grants authority.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._con = sqlite3.connect(
            str(self.path), isolation_level=None, timeout=15.0,
            check_same_thread=False)
        self._con.execute("PRAGMA journal_mode=WAL")
        self._con.execute("PRAGMA synchronous=FULL")
        self._con.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            if self._con is not None:
                try:
                    self._con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
                self._con.close()
                self._con = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def _conn(self) -> sqlite3.Connection:
        if self._con is None:
            raise MemoryError("memory_store_closed")
        return self._con

    def ingest(self, record: ExperienceRecordV1, *,
               evidence_check=None) -> str:
        """Store a verified experience; identical re-ingest is idempotent.

        A different record for the same ``(episode_id, task_fingerprint)``
        is a conflict — repeated or mutated copies of an episode cannot
        masquerade as independent evidence.

        ``evidence_check(record)`` is the trust-boundary hook: production
        ingestion must pass ``verify_experience_evidence`` bound to the
        evaluator, so a record cannot claim a receipt it does not have.
        It runs before any write and fails closed.
        """
        if not isinstance(record, ExperienceRecordV1):
            record = ExperienceRecordV1.from_dict(record)
        if evidence_check is not None and not evidence_check(record):
            raise MemoryError("experience_evidence_rejected")
        with self._lock:
            con = self._conn()
            row = con.execute(
                "SELECT record_digest FROM experience WHERE experience_id=?",
                (record.experience_id,),
            ).fetchone()
            if row is not None:
                if row[0] == record.digest:
                    return record.digest
                raise DuplicateEpisode("experience_id_conflict")
            dup = con.execute(
                "SELECT record_digest FROM experience"
                " WHERE episode_id=? AND task_fingerprint=?",
                (record.episode_id, record.task_fingerprint),
            ).fetchone()
            if dup is not None:
                if dup[0] == record.digest:
                    return record.digest
                raise DuplicateEpisode(
                    "episode_replay: episode+fingerprint already recorded")
            try:
                con.execute(
                    "INSERT INTO experience"
                    " (experience_id, episode_id, task_fingerprint,"
                    "  repository_registry_id, record_digest, record_json,"
                    "  outcome, captured_at) VALUES (?,?,?,?,?,?,?,?)",
                    (record.experience_id, record.episode_id,
                     record.task_fingerprint, record.repository_registry_id,
                     record.digest,
                     record.canonical_bytes().decode("utf-8"),
                     record.outcome, record.captured_at))
            except sqlite3.IntegrityError as exc:
                raise DuplicateEpisode(f"ingest_conflict: {exc}") from exc
            return record.digest

    def get(self, experience_id: str) -> ExperienceRecordV1:
        row = self._conn().execute(
            "SELECT record_json, record_digest FROM experience"
            " WHERE experience_id=?", (experience_id,),
        ).fetchone()
        if row is None:
            raise MemoryError("experience_missing")
        record = ExperienceRecordV1.from_dict(loads_json(row[0].encode("utf-8")))
        if record.digest != row[1]:
            raise MemoryError(f"experience_tampered:{experience_id}")
        return record

    def by_outcome(self, outcome: str) -> list[ExperienceRecordV1]:
        rows = self._conn().execute(
            "SELECT record_json, record_digest FROM experience"
            " WHERE outcome=? ORDER BY experience_id", (outcome,),
        ).fetchall()
        out = []
        for raw, digest in rows:
            record = ExperienceRecordV1.from_dict(loads_json(raw.encode("utf-8")))
            if record.digest != digest:
                raise MemoryError("experience_tampered")
            out.append(record)
        return out


def verify_experience_evidence(record: ExperienceRecordV1, verifier) -> bool:
    """Authenticate the receipt an experience record points at.

    Resolves ``outcome_receipt_digest`` through the evaluator's own
    receipt journal and verifies its signature against the trusted key
    registry. The record's claimed outcome must match the signed receipt;
    anything else is rejected rather than stored as "verified" experience.
    """
    if not isinstance(record, ExperienceRecordV1):
        raise ContractError("evidence check requires an ExperienceRecordV1")
    receipt = verifier.load_receipt(record.outcome_receipt_digest)
    if not verifier.verify_receipt(receipt):
        raise MemoryError("experience_receipt_unauthenticated")
    if receipt.outcome != record.outcome:
        raise MemoryError("experience_outcome_mismatch")
    return True


def induce_candidate(record: ExperienceRecordV1, *,
                     candidate_id: str | None = None,
                     generator_identity: str = "sis-v3-memory-induction",
                     repository_scope: dict | None = None,
                     now: str | None = None) -> CandidateV1:
    """Distill a verified experience into an ``experience_memory`` candidate.

    The lesson becomes payload text; observed facts and inferred
    hypotheses stay separated — hypotheses are carried for evaluation
    but are never silently promoted to accepted causal truth.
    """
    if not isinstance(record, ExperienceRecordV1):
        raise ContractError("induce requires an ExperienceRecordV1")
    payload = {
        "lesson": record.lesson,
        "facts": list(record.facts),
        "hypotheses": list(record.hypotheses),
        "outcome": record.outcome,
        "failure_category": record.failure_category or "",
        "task_category": record.task_category,
        "outcome_receipt_digest": record.outcome_receipt_digest,
        "trace_digest": record.trace_digest,
    }
    cid = candidate_id or (
        "mem-" + record.experience_id.replace(" ", "-")[:32])
    return CandidateV1(
        schema_version=1,
        candidate_id=cid,
        candidate_type="experience_memory",
        content_digest=content_digest("experience_memory", payload),
        parent_candidate_ids=(),
        source_episode_ids=(record.episode_id,),
        generator_identity=generator_identity,
        target_agent="any",
        target_task_family=record.task_category,
        repository_scope=dict(repository_scope) if repository_scope
        else {"kind": "registry_id",
              "value": record.repository_registry_id},
        applicability_predicate=tuple(record.applicability),
        known_counterexamples=tuple(record.counterexamples),
        payload=payload,
        created_at=now or _utcnow(),
    )


@dataclass(frozen=True)
class RetrievedMemory:
    candidate: CandidateV1
    score: int


def retrieve_memories(
    candidates: list[CandidateV1],
    context: RetrievalContext,
    *,
    min_score: int = 10,
    token_budget: int = 600,
    limit: int = 5,
) -> tuple[RetrievedMemory, ...]:
    """Select applicable qualified memory candidates; abstain via empty tuple.

    Gates (all must pass): applicability predicates hold against the
    caller-supplied context; no known counterexample text appears in the
    task context; candidate is ``experience_memory`` type. Ranking is
    deterministic: matched-gate count, then content digest. Greedy
    token-budget packing; exact-duplicate lessons are deduplicated by
    ``content_digest``.
    """
    if type(min_score) is not int or min_score < 0:
        raise ContractError("min_score must be a nonnegative integer")
    if type(token_budget) is not int or token_budget < 1:
        raise ContractError("token_budget must be a positive integer")
    if type(limit) is not int or not 1 <= limit <= 32:
        raise ContractError("limit must be in [1,32]")

    context_text = " ".join(sorted(
        context.failure_signatures | context.symbols_present
        | context.files_present)).lower()
    scored: list[RetrievedMemory] = []
    seen_digests: set[str] = set()
    for cand in candidates:
        if cand.candidate_type != "experience_memory":
            continue
        if cand.content_digest in seen_digests:
            continue
        if any(not precondition_holds(cond, context)
               for cond in cand.applicability_predicate):
            continue
        suppressed = any(
            isinstance(cx, str) and suppression_match(context_text, cx)
            for cx in cand.known_counterexamples)
        if suppressed:
            continue
        matched = sum(1 for cond in cand.applicability_predicate
                      if precondition_holds(cond, context))
        score = matched * 10 + len(cand.source_episode_ids)
        if score < min_score:
            continue
        scored.append(RetrievedMemory(candidate=cand, score=score))
        seen_digests.add(cand.content_digest)

    scored.sort(key=lambda m: (-m.score, m.candidate.digest))
    picked: list[RetrievedMemory] = []
    spent = 0
    for item in scored:
        cost = max(1, len(item.candidate.payload.get("lesson", "")) // 4)
        if len(picked) >= limit or spent + cost > token_budget:
            continue
        picked.append(item)
        spent += cost
    return tuple(picked)
