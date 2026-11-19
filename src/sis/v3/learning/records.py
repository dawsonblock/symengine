"""Convert learned evidence into immutable *candidate* ProcedureRecordV1.

No operation in this module is capable of qualifying, persisting a qualified
revision, or causing source edits. Qualification remains external.
"""
from __future__ import annotations

import hashlib

from ..contracts import ExperienceRecordV1, ExperienceRecordV2, ProcedureRecordV1
from .strategies import StrategyCandidate
from .symbolic import StructuralChange


def experience_to_record(record: ExperienceRecordV1 | ExperienceRecordV2, *,
                         failure_class: str) -> ProcedureRecordV1:
    """Convert one verified experience into a candidate procedure.

    The procedure is applicable to a *failure class*, not to the task that
    produced it: the originating task signature would make the lesson
    unreachable on any sibling task. The record must already name that
    class in ``failure_category``; this function will not relabel evidence.
    A class that is too broad remains a generalization risk the retrieval
    gates cannot detect.
    """
    if not isinstance(record, (ExperienceRecordV1, ExperienceRecordV2)):
        raise ValueError("experience_record_required")
    if record.outcome != "pass":
        raise ValueError("experience_not_verified_pass")
    if not isinstance(failure_class, str) or not failure_class.strip():
        raise ValueError("failure_class_required")
    if record.failure_category != failure_class:
        raise ValueError("failure_class_not_bound_to_record")
    language = next(
        (condition["value"] for condition in record.applicability
         if condition.get("kind") == "language_is"), "python")
    preconditions = [{"kind": "language_is", "value": language},
                     {"kind": "failure_signature_is", "value": failure_class}]
    for condition in record.applicability:
        if condition.get("kind") == "language_is":
            continue
        if condition.get("kind") == "failure_signature_is" and \
                condition.get("value") == failure_class:
            continue
        preconditions.append(dict(condition))
    procedure_id = "exp-" + record.experience_id
    if len(procedure_id) > 128:
        procedure_id = "exp-" + hashlib.sha256(
            record.experience_id.encode()).hexdigest()[:32]
    return ProcedureRecordV1(
        schema_version=1,
        procedure_id=procedure_id,
        revision=1,
        intent=record.lesson,
        language=language,
        frameworks=(), task_signatures=(),
        failure_signatures=(failure_class,),
        preconditions=tuple(preconditions),
        contraindications=(),
        steps=(record.lesson,),
        required_verification=(
            "Independently re-run task-owned acceptance tests.",
            "Validate on a sealed repository-disjoint evaluation set."),
        counterexample_refs=(),
        evidence_refs=(record.outcome_receipt_digest,),
        outcome_distribution={"tasks": 1, "successes": 1, "failures": 0,
                              "regressions": 0},
        status="candidate", expires_at=None)


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
