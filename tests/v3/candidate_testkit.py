"""Authenticated candidate fixtures: real receipts, evidence and decisions.

Nothing here sets a state column directly. Qualified/revoked state is
produced exactly the way the registry accepts it in production: a signed
evaluator receipt, a signed evidence binding naming the candidate, and a
signed operator decision for the exact edge.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from sis.v3 import signatures
from sis.v3.candidate_authority import (CandidateDecisionAuthority,
                                        CandidateEvidenceAuthority)
from sis.v3.candidates import CandidateRegistry
from sis.v3.contracts import OutcomeReceiptV1, canonical_json
from sis.v3.verifier import verify_receipt_signature

_RECEIPT_DOMAIN = b"sis-v3:outcome_receipt:1\0"


def keypair(prefix: str) -> tuple[bytes, bytes, str]:
    seed, public = signatures.generate_keypair()
    return seed, public, prefix + "-" + hashlib.sha256(public).hexdigest()[:16]


def signed_receipt(seed: bytes, key_id: str, *, task_id: str = "t1",
                   repo_digest: str = "0" * 64, outcome: str = "pass",
                   criterion_version: str = "v1",
                   suite_commitment: str = "0" * 64,
                   evaluator_identity: str = "sis-v3-test-evaluator",
                   ) -> OutcomeReceiptV1:
    unsigned = {
        "schema_version": 1,
        "receipt_id": "rcpt-" + hashlib.sha256(
            seed + task_id.encode() + repo_digest.encode()).hexdigest()[:12],
        "evaluator_identity": evaluator_identity,
        "task_id": task_id,
        "evaluated_repo_digest": repo_digest,
        "test_suite_commitment": suite_commitment,
        "criterion_version": criterion_version,
        "outcome": outcome,
        "regression_evidence": [],
        "signer_key_id": key_id,
    }
    signature = signatures.sign(
        seed, _RECEIPT_DOMAIN + canonical_json(unsigned)).hex()
    return OutcomeReceiptV1.from_dict({**unsigned, "signature": signature})


class CandidateStack:
    """A candidate registry wired to test-custody signed authorities."""

    def __init__(self, path: str | Path, *, protocol: str = "e" * 64,
                 expected_protocol: bool = True,
                 qualification_policy=None,
                 qualification_validator=None,
                 certificate_resolver=None,
                 delivery_resolver=None,
                 evidence_custody=None,
                 require_evidence_custody: bool = False,
                 offline_evidence_policy=None,
                 production_serving: bool = False) -> None:
        self.eval_seed, eval_public, self.eval_key = keypair("eval")
        self.op_seed, op_public, self.op_key = keypair("op")
        self.protocol = protocol
        self.receipts: dict[str, OutcomeReceiptV1] = {}
        self.evidence_authority = CandidateEvidenceAuthority(
            trusted_evaluator_keys={self.eval_key: eval_public.hex()})
        self.decision_authority = CandidateDecisionAuthority(
            trusted_operator_keys={self.op_key: op_public.hex()})
        self.registry = CandidateRegistry(
            path,
            receipt_authority=self.resolve_receipt,
            evidence_authority=self.evidence_authority,
            decision_authority=self.decision_authority,
            expected_evaluation_protocol_digest=protocol if expected_protocol else None,
            qualification_policy=qualification_policy,
            qualification_validator=qualification_validator,
            certificate_resolver=certificate_resolver,
            delivery_resolver=delivery_resolver,
            evidence_custody=evidence_custody,
            require_evidence_custody=require_evidence_custody,
            offline_evidence_policy=offline_evidence_policy,
            production_serving=production_serving)

    def close(self) -> None:
        self.registry.close()

    # ---- minting ------------------------------------------------------ #
    def resolve_receipt(self, digest: str) -> OutcomeReceiptV1:
        receipt = self.receipts.get(digest)
        if receipt is None or not verify_receipt_signature(
                receipt, self.eval_public_hex):
            raise ValueError("receipt_signature_invalid")
        return receipt

    @property
    def eval_public_hex(self) -> str:
        return signatures.public_key(self.eval_seed).hex()

    def receipt(self, **kwargs) -> OutcomeReceiptV1:
        receipt = signed_receipt(self.eval_seed, self.eval_key, **kwargs)
        self.receipts[receipt.digest] = receipt
        return receipt

    def evidence(self, candidate, receipts, *, partition: str = "holdout",
                 protocol: str | None = None, outcome: str = "pass"):
        return self.evidence_authority.issue(
            seed=self.eval_seed, candidate=candidate,
            receipt_refs=[r.digest for r in receipts],
            evaluation_protocol_digest=protocol or self.protocol,
            partition=partition, outcome=outcome, signer_key_id=self.eval_key)

    def decision(self, candidate, from_state: str, to_state: str, *,
                 receipt_refs=(), evidence_refs=(),
                 actor_identity: str = "test-operator"):
        return self.decision_authority.issue(
            seed=self.op_seed, candidate=candidate,
            from_state=from_state, to_state=to_state,
            receipt_refs=receipt_refs, evidence_refs=evidence_refs,
            actor_identity=actor_identity, signer_key_id=self.op_key)

    # ---- lifecycle helpers -------------------------------------------- #
    def prepare(self, candidate) -> None:
        """Submit and move to EVALUATING (the state before qualification)."""
        self.registry.submit(candidate, actor_role="learner")
        self.registry.transition(candidate.candidate_id, "validated",
                                 actor_role="learner")
        self.registry.transition(candidate.candidate_id, "evaluating",
                                 actor_role="evaluator")

    def qualify(self, candidate, *, receipt=None, partition: str = "holdout",
                actor_identity: str = "test-operator", protocol: str | None = None,
                certificate_ref: str | None = None):
        """Issue real evidence + a decision and qualify ``candidate``."""
        receipt = receipt or self.receipt(task_id="task-" + candidate.candidate_id,
                                          outcome="pass")
        evidence = self.evidence(candidate, [receipt], partition=partition,
                                 protocol=protocol)
        decision = self.decision(
            candidate, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), actor_identity=actor_identity)
        self.registry.qualify(
            candidate.candidate_id, actor_role="operator",
            actor_identity=actor_identity, receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), decision_ref=decision.digest,
            certificate_ref=certificate_ref)
        return receipt, evidence, decision

    def revoke(self, candidate, *, actor_identity: str = "test-operator"):
        decision = self.decision(candidate, "qualified", "revoked",
                                 actor_identity=actor_identity)
        self.registry.revoke(candidate.candidate_id, actor_role="operator",
                             actor_identity=actor_identity,
                             decision_ref=decision.digest)
        return decision


def make_stack(path: str | Path, **kwargs) -> CandidateStack:
    return CandidateStack(path, **kwargs)
