"""Observe–learn–verify–reuse composition (v3.1-alpha, PR-08).

Single audited entry point: verified capture → evidence-bound induction
→ candidate ProcedureRecordV1 → store intake. Every stage's bindings are
enforced here — no caller-supplied digests, no status writes. Records
land as ``candidate`` revision 1; promotion remains the signed-decision
path in ``PromotionController`` and serving stays behind
``StrictGuidanceGateway``. This module cannot qualify anything.
"""
from __future__ import annotations

from typing import Callable, Mapping, Sequence

from ..contracts import ProcedureRecordV1, SourceChangeV1
from ..procedures import ProcedureStore
from .records import strategy_to_record, structure_to_record
from .strategies import EpisodeEvidence, induce_strategies
from .symbolic import induce_from_source_change


def observe_structural_proposal(
    change: SourceChangeV1,
    file_contents: Mapping[str, tuple[bytes | None, bytes | None]],
    *, semantic_contract_digest: str,
    independently_verified_receipt_digest: str,
    store: ProcedureStore,
    language: str = "python",
) -> str | None:
    """Capture-bound induction → candidate record → intake.

    Returns the committed candidate revision digest, or ``None`` when no
    supported structural change was found. Raises on any evidence-binding
    violation. The record is admitted as ``candidate`` — never qualified.
    """
    induced = induce_from_source_change(
        change, file_contents,
        semantic_contract_digest=semantic_contract_digest,
        independently_verified_receipt_digest=independently_verified_receipt_digest)
    if induced is None:
        return None
    record = structure_to_record(induced, language=language)
    return store.add(record)


def observe_strategy_proposals(
    episodes: Sequence[EpisodeEvidence], *, language: str,
    store: ProcedureStore,
    receipt_resolver: Callable[[str], Mapping | None],
    min_successes: int = 2, min_distinct_repositories: int = 2,
) -> tuple[str, ...]:
    """Receipt-resolved strategy induction → candidate records → intake.

    ``receipt_resolver`` is mandatory here: the pipeline never accepts
    caller-asserted verification alone.
    """
    candidates = induce_strategies(
        episodes, min_successes=min_successes,
        min_distinct_repositories=min_distinct_repositories,
        receipt_resolver=receipt_resolver)
    return tuple(store.add(strategy_to_record(c, language=language))
                 for c in candidates)
