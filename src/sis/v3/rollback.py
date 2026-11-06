"""Checkpoints and governed rollback of the qualified catalog head.

A checkpoint is a plain export of the current qualified head plus the
decision-log head; restoring one does not rewrite history — it issues new
signed ``suspended`` decisions for every qualified record absent from the
checkpoint, so the qualified head returns to the earlier set while the audit
trail remains append-only.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from .promotion import PromotionController, PromotionRejected


@dataclass(frozen=True)
class QualifiedCheckpoint:
    qualified_head: str
    qualified_digests: frozenset[str]
    decision_head: str | None
    taken_at: str


def checkpoint(controller: PromotionController) -> QualifiedCheckpoint:
    """Snapshot the current qualified set and decision-log head."""
    report = controller.verify()
    return QualifiedCheckpoint(
        qualified_head=controller.qualified_head(),
        qualified_digests=frozenset(
            record.digest for record in controller.store.by_status("qualified")
        ),
        decision_head=report["head"],
        taken_at=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
    )


def restore(
    controller: PromotionController,
    target: QualifiedCheckpoint,
    *,
    actor_role: str,
    actor_identity: str,
    operator_token: str,
    evaluator_signer: Callable[[bytes], tuple[str, str]] | None = None,
) -> list[str]:
    """Suspend qualified records absent from ``target``; returns decision ids.

    Restoring requires the same authority as any other transition. Records in
    the target set stay qualified; everything qualified since is suspended,
    moving the qualified head back toward ``target.qualified_head``.
    """
    decisions = []
    for record in controller.store.by_status("qualified"):
        if record.digest in target.qualified_digests:
            continue
        decision = controller.transition(
            record.procedure_id,
            "suspended",
            actor_role=actor_role,
            actor_identity=actor_identity,
            operator_token=operator_token,
            evaluator_signer=None,
            rollback_ref=target.qualified_head,
        )
        decisions.append(decision.decision_id)
    if controller.store.by_status("qualified") and controller.qualified_head() != target.qualified_head:
        remaining = {
            r.digest for r in controller.store.by_status("qualified")
        }
        if remaining - target.qualified_digests:
            raise PromotionRejected(
                "rollback_incomplete",
                "checkpoint cannot be reached without requalifying records",
            )
    return decisions
