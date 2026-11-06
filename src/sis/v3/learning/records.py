"""Convert learned evidence into immutable *candidate* ProcedureRecordV1.

No operation in this module is capable of qualifying, persisting a qualified
revision, or causing source edits. Qualification remains external.
"""
from __future__ import annotations

from ..contracts import ProcedureRecordV1
from .strategies import StrategyCandidate
from .symbolic import StructuralChange


def strategy_to_record(candidate: StrategyCandidate, *, language: str,
                       toolchain: str = "") -> ProcedureRecordV1:
    if candidate.status != "candidate" or not candidate.supporting_receipts:
        raise ValueError("unqualified_strategy_evidence")
    pre = [{"kind": "language_is", "value": language},
           {"kind": "failure_signature_is", "value": candidate.failure_signature}]
    if toolchain:
        pre.append({"kind": "toolchain_is", "value": toolchain})
    return ProcedureRecordV1(
        schema_version=1, procedure_id=candidate.candidate_id, revision=1,
        intent="Candidate diagnostic strategy for " + candidate.failure_signature,
        language=language, frameworks=(), task_signatures=(),
        failure_signatures=(candidate.failure_signature,),
        preconditions=tuple(pre), contraindications=(),
        steps=candidate.diagnostic_steps,
        required_verification=("Independently re-run task-owned acceptance tests.",
                               "Validate on a sealed repository-disjoint evaluation set."),
        counterexample_refs=candidate.negative_receipts,
        evidence_refs=candidate.supporting_receipts,
        outcome_distribution={"tasks": len(candidate.supporting_receipts)+len(candidate.negative_receipts),
                              "successes": len(candidate.supporting_receipts),
                              "failures": len(candidate.negative_receipts), "regressions": 0},
        status="candidate", expires_at=None)


def structure_to_record(change: StructuralChange, *, language: str = "python") -> ProcedureRecordV1:
    if change.status != "candidate":
        raise ValueError("structural_proposal_must_be_candidate")
    return ProcedureRecordV1(
        schema_version=1, procedure_id=change.candidate_id, revision=1,
        intent=f"Observed AST operator substitution: {change.old_operator} to {change.new_operator}; not proven correct outside its source task",
        language=language, frameworks=(), task_signatures=(), failure_signatures=(),
        preconditions=({"kind": "language_is", "value": language},),
        contraindications=(),
        steps=(f"Inspect whether the original operator {change.old_operator} violates the independent contract.",
               f"Consider candidate operator {change.new_operator} only if the contract and counterexamples support it."),
        required_verification=("Run independent semantic specification tests; structural equivalence alone is insufficient.",
                               "Validate on unseen codebases before promotion."),
        counterexample_refs=(), evidence_refs=(change.receipt_digest, change.contract_digest),
        outcome_distribution={"tasks": 1, "successes": 1, "failures": 0, "regressions": 0},
        status="candidate", expires_at=None)
