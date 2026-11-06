"""Counterexample index: corpus-level negative-transfer memory (SIS3-141).

Procedures carry ``counterexample_refs`` (receipts where the approach failed)
and ``contraindications`` (context facts where it must not fire). The index
surfaces both across the whole catalog so promotion gates and retrieval can
answer "has this approach demonstrably hurt a similar context?" — not just
"does this record forbid this context?".
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .contracts import ProcedureRecordV1
from .procedures import ProcedureStore
from .retrieval import RetrievalContext, precondition_holds


@dataclass(frozen=True)
class NegativeEvidence:
    procedure_id: str
    kind: str  # "counterexample_receipt" | "contraindication"
    detail: str


class CounterexampleIndex:
    """Cross-catalog view of negative evidence."""

    def __init__(self, store: ProcedureStore) -> None:
        self._store = store

    def negatives_for(self, context: RetrievalContext) -> list[NegativeEvidence]:
        """All negative evidence whose context overlaps the request."""
        hits: list[NegativeEvidence] = []
        for record in self._store.all_latest():
            if record.counterexample_refs:
                hits.append(NegativeEvidence(
                    procedure_id=record.procedure_id,
                    kind="counterexample_receipt",
                    detail=f"{len(record.counterexample_refs)} verified counterexample(s) on record",
                ))
            for condition in record.contraindications:
                try:
                    if precondition_holds(condition, context):
                        hits.append(NegativeEvidence(
                            procedure_id=record.procedure_id,
                            kind="contraindication",
                            detail=f"contraindication matched: {condition.get('kind')}={condition.get('value')}",
                        ))
                except Exception:
                    continue
        return hits

    def blocked(self, context: RetrievalContext) -> bool:
        """True when live negative evidence overlaps the request context."""
        return any(
            n.kind == "contraindication" for n in self.negatives_for(context)
        )
