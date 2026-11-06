"""CandidateRegistry: typed candidates, signed decisions, audit."""
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sis.v3.candidates import (CandidateConflict, CandidateError,
                               CandidateRegistry, content_digest)
from sis.v3.contracts import (CandidateDecisionV1, CandidateEvidenceV1,
                              CandidateV1, ContractError)
from sis.v3.policy import AuthorizationDenied
from tests.v3.candidate_testkit import CandidateStack

NOW = "2026-10-24T12:00:00Z"


class _Receipt:
    def __init__(self, outcome="pass"):
        self.outcome = outcome


def make_candidate(cid="cand-1", ctype="skill_instruction",
                   payload=None, scope=None, episodes=("ep-1",)):
    payload = payload if payload is not None else {
        "title": "t", "steps": ["do the thing"]}
    return CandidateV1(
        schema_version=1,
        candidate_id=cid,
        candidate_type=ctype,
        content_digest=content_digest(ctype, payload),
        parent_candidate_ids=(),
        source_episode_ids=episodes,
        generator_identity="test-generator",
        target_agent="any",
        target_task_family="fam",
        repository_scope=scope or {"kind": "family_id", "value": "fam-a"},
        applicability_predicate=({"kind": "language_is", "value": "python"},),
        known_counterexamples=(),
        payload=payload,
        created_at=NOW)


class RegistryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stack = CandidateStack(self.root / "c.db")
        self.addCleanup(self.stack.close)
        self.reg = self.stack.registry


class CandidateContractTests(unittest.TestCase):
    def test_all_types_accepted(self):
        for i, t in enumerate(("symbolic_procedure", "diagnostic_strategy",
                               "experience_memory", "skill_instruction",
                               "skill_bundle", "prompt_variant")):
            payload = {"steps": ["s"], "lesson": "l"}
            make_candidate(cid=f"c-{i}", ctype=t, payload=payload)
        with self.assertRaises(ContractError):
            make_candidate(ctype="bogus_type")

    def test_content_digest_must_bind_payload(self):
        cand = make_candidate()
        forged = dict(cand.to_dict())
        forged["payload"] = {"steps": ["evil"]}
        with self.assertRaisesRegex(ContractError, "content_digest"):
            CandidateV1.from_dict(forged)

    def test_scope_shape_enforced(self):
        with self.assertRaises(ContractError):
            make_candidate(scope={"kind": "everywhere", "value": "x"})
        with self.assertRaises(ContractError):
            make_candidate(scope={"kind": "global", "value": "x"})
        make_candidate(scope={"kind": "global", "value": ""})

    def test_signed_artifacts_roundtrip_and_validate(self):
        stack = CandidateStack(Path(tempfile.mkdtemp()) / "c.db")
        self.addCleanup(stack.close)
        cand = make_candidate(cid="roundtrip")
        stack.prepare(cand)
        _, evidence, decision = stack.qualify(cand)
        self.assertEqual(
            CandidateEvidenceV1.from_dict(evidence.to_dict()).digest,
            evidence.digest)
        self.assertEqual(
            CandidateDecisionV1.from_dict(decision.to_dict()).digest,
            decision.digest)
        forged = evidence.to_dict()
        forged["partition"] = "everywhere"
        with self.assertRaises(ContractError):
            CandidateEvidenceV1.from_dict(forged)
        forged = decision.to_dict()
        forged["from_state"] = "qualified"
        forged["to_state"] = "qualified"
        with self.assertRaises(ContractError):
            CandidateDecisionV1.from_dict(forged)


class RegistryLifecycleTests(RegistryFixture):
    def test_full_lifecycle_with_audit(self):
        cand = make_candidate()
        self.stack.prepare(cand)
        receipt, evidence, decision = self.stack.qualify(
            cand, actor_identity="op-1")
        self.assertEqual(self.reg.state_of(cand.candidate_id), "qualified")
        revoke = self.stack.revoke(cand, actor_identity="op-1")
        self.assertEqual(self.reg.state_of(cand.candidate_id), "revoked")
        states = [(e["from_state"], e["to_state"])
                  for e in self.reg.audit(cand.candidate_id)]
        self.assertEqual(
            states, [("", "proposed"), ("proposed", "validated"),
                     ("validated", "evaluating"),
                     ("evaluating", "qualified"),
                     ("qualified", "revoked")])
        audit = self.reg.audit(cand.candidate_id)
        self.assertEqual(audit[3]["decision_digest"], decision.digest)
        self.assertEqual(audit[3]["evidence_refs"], [evidence.digest])
        self.assertEqual(audit[3]["receipt_refs"], [receipt.digest])
        self.assertEqual(audit[3]["actor_identity"], "op-1")
        self.assertEqual(audit[4]["decision_digest"], revoke.digest)

    def test_submit_is_idempotent_and_conflicts(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.assertEqual(self.reg.submit(cand, actor_role="learner"),
                         cand.digest)
        other = make_candidate(payload={"steps": ["different"]})
        with self.assertRaises(CandidateConflict):
            self.reg.submit(other, actor_role="learner")

    def test_unauthorized_roles_denied(self):
        cand = make_candidate()
        for role in ("agent", "evaluator", "operator", "forged"):
            with self.assertRaises(AuthorizationDenied):
                self.reg.submit(cand, actor_role=role)
        self.reg.submit(cand, actor_role="learner")
        # proposed->validated is intake (candidate:write): learner only
        for role in ("agent", "runner", "evaluator", "operator"):
            with self.assertRaisesRegex(CandidateConflict, "role_denied"):
                self.reg.transition(cand.candidate_id, "validated",
                                    actor_role=role)
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        # validated->evaluating is evaluator-only: learner cannot self-escalate
        for role in ("agent", "runner", "learner", "operator"):
            with self.assertRaisesRegex(CandidateConflict, "role_denied"):
                self.reg.transition(cand.candidate_id, "evaluating",
                                    actor_role=role)

    def test_qualify_requires_operator_receipts_evidence_and_decision(self):
        cand = make_candidate()
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-" + cand.candidate_id)
        evidence = self.stack.evidence(cand, [receipt])
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), actor_identity="op-1")
        # learner cannot qualify itself — generation never confers authority
        with self.assertRaisesRegex(CandidateConflict, "role_denied"):
            self.reg.qualify(
                cand.candidate_id, actor_role="learner",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        # no receipts — no qualification
        with self.assertRaisesRegex(CandidateConflict, "receipts"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(),
                evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        # no evidence binding — no qualification
        with self.assertRaisesRegex(CandidateConflict, "evidence_binding"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(), decision_ref=decision.digest)
        # no operator decision — no qualification
        with self.assertRaisesRegex(CandidateConflict, "requires_decision"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,), decision_ref=None)
        # malformed receipt ref
        with self.assertRaises(ContractError):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=("nothex",),
                evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        self.reg.qualify(
            cand.candidate_id, actor_role="operator", actor_identity="op-1",
            receipt_refs=(receipt.digest,), evidence_refs=(evidence.digest,),
            decision_ref=decision.digest)
        audit = self.reg.audit(cand.candidate_id)
        self.assertEqual(audit[-1]["receipt_refs"], [receipt.digest])
        self.assertEqual(audit[-1]["evidence_refs"], [evidence.digest])

    def test_qualification_requires_authenticated_pass_receipts(self):
        def evaluating(reg, cid):
            cand = make_candidate(cid=cid)
            reg.submit(cand, actor_role="learner")
            reg.transition(cand.candidate_id, "validated",
                           actor_role="learner")
            reg.transition(cand.candidate_id, "evaluating",
                           actor_role="evaluator")
            return cand

        def artifacts(cand):
            receipt = self.stack.receipt(task_id="task-" + cand.candidate_id)
            evidence = self.stack.evidence(cand, [receipt])
            decision = self.stack.decision(
                cand, "evaluating", "qualified",
                receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,))
            return receipt, evidence, decision

        # No receipt authority: a cited digest is not evidence.
        reg = CandidateRegistry(
            self.root / "no-authority.db",
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(reg.close)
        cand = evaluating(reg, "no-auth")
        receipt, evidence, decision = artifacts(cand)
        with self.assertRaisesRegex(CandidateConflict, "receipt_authority"):
            reg.qualify(cand.candidate_id, actor_role="operator",
                        actor_identity="op-1", receipt_refs=(receipt.digest,),
                        evidence_refs=(evidence.digest,),
                        decision_ref=decision.digest)

        def reject(digest):
            raise ValueError("signature invalid")

        reg = CandidateRegistry(
            self.root / "rejecting.db", receipt_authority=reject,
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(reg.close)
        cand = evaluating(reg, "rejected")
        receipt, evidence, decision = artifacts(cand)
        with self.assertRaisesRegex(CandidateConflict, "receipt_rejected"):
            reg.qualify(cand.candidate_id, actor_role="operator",
                        actor_identity="op-1", receipt_refs=(receipt.digest,),
                        evidence_refs=(evidence.digest,),
                        decision_ref=decision.digest)

        reg = CandidateRegistry(
            self.root / "failing.db",
            receipt_authority=lambda d: _Receipt("fail"),
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(reg.close)
        cand = evaluating(reg, "failing")
        receipt, evidence, decision = artifacts(cand)
        with self.assertRaisesRegex(CandidateConflict, "pass_receipt"):
            reg.qualify(cand.candidate_id, actor_role="operator",
                        actor_identity="op-1", receipt_refs=(receipt.digest,),
                        evidence_refs=(evidence.digest,),
                        decision_ref=decision.digest)

    def test_qualification_rejects_unrelated_receipts(self):
        good = make_candidate(cid="good")
        other = make_candidate(cid="other")
        self.stack.prepare(good)
        self.stack.prepare(other)
        other_receipt = self.stack.receipt(task_id="task-other")
        other_evidence = self.stack.evidence(other, [other_receipt])
        decision = self.stack.decision(
            good, "evaluating", "qualified",
            receipt_refs=(other_receipt.digest,),
            evidence_refs=(other_evidence.digest,), actor_identity="op-1")
        # The receipt and binding are authentic but name another candidate.
        with self.assertRaisesRegex(
                CandidateConflict, "evidence_candidate_digest_mismatch"):
            self.reg.qualify(
                good.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(other_receipt.digest,),
                evidence_refs=(other_evidence.digest,),
                decision_ref=decision.digest)

        # Authentic binding for this candidate, but a different pass
        # receipt than the one the binding attests.
        bound = self.stack.receipt(task_id="task-good")
        unbound = self.stack.receipt(task_id="task-unrelated")
        evidence = self.stack.evidence(good, [bound])
        decision = self.stack.decision(
            good, "evaluating", "qualified",
            receipt_refs=(unbound.digest,),
            evidence_refs=(evidence.digest,), actor_identity="op-1")
        with self.assertRaisesRegex(
                CandidateConflict, "evidence_receipt_not_bound"):
            self.reg.qualify(
                good.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(unbound.digest,),
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest)

    def test_qualification_rejects_wrong_partition_or_protocol(self):
        cand = make_candidate(cid="partition")
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-partition")
        dev = self.stack.evidence(cand, [receipt], partition="development")
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,), evidence_refs=(dev.digest,))
        with self.assertRaisesRegex(
                CandidateConflict, "evidence_partition_not_holdout"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(dev.digest,), decision_ref=decision.digest)

        wrong = self.stack.evidence(cand, [receipt], protocol="f" * 64)
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,), evidence_refs=(wrong.digest,))
        with self.assertRaisesRegex(CandidateConflict, "protocol_mismatch"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(wrong.digest,), decision_ref=decision.digest)

        failed = self.stack.evidence(cand, [receipt], outcome="fail")
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,), evidence_refs=(failed.digest,))
        with self.assertRaisesRegex(
                CandidateConflict, "evidence_outcome_not_pass"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(failed.digest,), decision_ref=decision.digest)

    def test_forged_evidence_and_decision_are_rejected(self):
        cand = make_candidate(cid="forged")
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-forged")
        evidence = self.stack.evidence(cand, [receipt])
        forged = evidence.to_dict()
        forged["evaluator_identity"] = "mallory"
        forged_record = type(evidence).from_dict(forged)
        # White-box: plant the forged record where the resolver looks, so
        # the failure is the signature, not a missing lookup.
        self.stack.evidence_authority._journal[forged_record.digest] = \
            forged_record
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(forged_record.digest,))
        with self.assertRaisesRegex(
                CandidateConflict, "evidence_signature_invalid"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="op-1", receipt_refs=(receipt.digest,),
                evidence_refs=(forged_record.digest,),
                decision_ref=decision.digest)

        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,))
        forged = decision.to_dict()
        forged["actor_identity"] = "mallory"
        forged_decision = type(decision).from_dict(forged)
        self.stack.decision_authority._journal[forged_decision.digest] = \
            forged_decision
        with self.assertRaisesRegex(
                CandidateConflict, "decision_signature_invalid"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="mallory", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,),
                decision_ref=forged_decision.digest)

    def test_decision_for_another_candidate_cannot_authorize(self):
        cand = make_candidate(cid="victim")
        other = make_candidate(cid="attacker")
        self.stack.prepare(cand)
        self.stack.prepare(other)
        receipt = self.stack.receipt(task_id="task-victim")
        evidence = self.stack.evidence(cand, [receipt])
        foreign = self.stack.decision(
            other, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,))
        with self.assertRaisesRegex(
                CandidateConflict, "decision_candidate_digest_mismatch"):
            self.reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="test-operator", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,), decision_ref=foreign.digest)

    def test_revocation_requires_signed_decision(self):
        cand = make_candidate(cid="revoke-me")
        self.stack.prepare(cand)
        self.stack.qualify(cand)
        with self.assertRaisesRegex(CandidateConflict,
                                    "revocation_requires_decision"):
            self.reg.transition(cand.candidate_id, "revoked",
                                actor_role="operator",
                                actor_identity="op-1")
        # A decision for the wrong edge is not a revocation.
        wrong = self.stack.decision(
            cand, "evaluating", "qualified",
            actor_identity="op-1")
        with self.assertRaisesRegex(CandidateConflict,
                                    "decision_edge_mismatch"):
            self.reg.revoke(cand.candidate_id, actor_role="operator",
                            actor_identity="op-1",
                            decision_ref=wrong.digest)
        self.stack.revoke(cand, actor_identity="op-1")
        self.assertEqual(self.reg.state_of(cand.candidate_id), "revoked")

    def test_lookup_distinguishes_missing_from_tampered(self):
        cand = make_candidate(cid="lookup")
        self.reg.submit(cand, actor_role="learner")
        record, state = self.reg.lookup(cand.candidate_id)
        self.assertEqual(record.digest, cand.digest)
        self.assertEqual(state, "proposed")
        self.assertIsNone(self.reg.lookup("absent-candidate"))
        self.reg._conn().execute(
            "UPDATE candidate SET state='qualified' WHERE candidate_id=?",
            (cand.candidate_id,))
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "state_projection_drift"):
            self.reg.lookup(cand.candidate_id)

    def test_direct_state_flip_fails_closed(self):
        cand = make_candidate(cid="flipped")
        self.reg.submit(cand, actor_role="learner")
        self.reg._conn().execute(
            "UPDATE candidate SET state='qualified' WHERE candidate_id=?",
            (cand.candidate_id,))
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "state_projection_drift"):
            self.reg.qualified()
        with self.assertRaisesRegex(CandidateError,
                                    "state_projection_drift"):
            self.reg.state_of(cand.candidate_id)
        report = self.reg.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("state_projection_drift" in p
                            for p in report["problems"]))

    def test_tampered_decision_and_evidence_rows_fail_closed(self):
        cand = make_candidate(cid="tamper")
        self.stack.prepare(cand)
        _, evidence, decision = self.stack.qualify(cand)
        con = self.reg._conn()
        con.execute(
            "UPDATE candidate_decision SET decision_json=?"
            " WHERE decision_digest=?",
            ('{"schema_version":1}', decision.digest))
        con.commit()
        with self.assertRaisesRegex(CandidateError, "decision_tampered"):
            self.reg.qualified()
        con.execute(
            "UPDATE candidate_decision SET decision_json=?"
            " WHERE decision_digest=?",
            (decision.canonical_bytes().decode("utf-8"), decision.digest))
        con.execute(
            "UPDATE candidate_evidence SET evidence_json=?"
            " WHERE evidence_digest=?",
            ('{"schema_version":1}', evidence.digest))
        con.commit()
        with self.assertRaisesRegex(CandidateError, "evidence_tampered"):
            self.reg.qualified()

    def test_serving_basis_exposes_signed_handles(self):
        cand = make_candidate(cid="basis")
        self.stack.prepare(cand)
        receipt, evidence, decision = self.stack.qualify(cand)
        basis = self.reg.serving_basis(cand.candidate_id)
        self.assertEqual(basis["decision_digest"], decision.digest)
        self.assertEqual(basis["evidence_refs"], (evidence.digest,))
        self.assertEqual(basis["receipt_refs"], (receipt.digest,))
        self.stack.revoke(cand)
        with self.assertRaisesRegex(CandidateError,
                                    "candidate_not_qualified"):
            self.reg.serving_basis(cand.candidate_id)

    def test_revoked_signer_stops_serving(self):
        cand = make_candidate(cid="revoked-signer")
        self.stack.prepare(cand)
        self.stack.qualify(cand)
        self.assertEqual(len(self.reg.qualified()), 1)
        self.stack.decision_authority.revoke_signer(self.stack.op_key)
        with self.assertRaisesRegex(
                CandidateError, "decision_signer_revoked"):
            self.reg.qualified()
        self.stack.decision_authority._revoked.discard(self.stack.op_key)
        self.stack.evidence_authority.revoke_signer(self.stack.eval_key)
        with self.assertRaisesRegex(
                CandidateError, "evidence_signer_revoked"):
            self.reg.qualified()

    def test_expired_evidence_stops_serving(self):
        cand = make_candidate(cid="expired")
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-expired")
        self.stack.evidence_authority._fixed_now = "2020-01-01T00:00:00Z"
        evidence = self.stack.evidence_authority.issue(
            seed=self.stack.eval_seed, candidate=cand,
            receipt_refs=[receipt.digest],
            evaluation_protocol_digest=self.stack.protocol,
            partition="holdout", signer_key_id=self.stack.eval_key,
            expires_at="2020-01-02T00:00:00Z")
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,))
        self.reg.qualify(
            cand.candidate_id, actor_role="operator",
            actor_identity="test-operator", receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        self.stack.evidence_authority._fixed_now = "2020-01-03T00:00:00Z"
        with self.assertRaisesRegex(CandidateError, "evidence_expired"):
            self.reg.qualified()

    def test_expected_protocol_is_rechecked_at_serve_time(self):
        cand = make_candidate(cid="protocol")
        self.stack.prepare(cand)
        self.stack.qualify(cand)
        other = CandidateRegistry(
            self.root / "c.db",
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority,
            expected_evaluation_protocol_digest="f" * 64)
        self.addCleanup(other.close)
        with self.assertRaisesRegex(CandidateError, "protocol_mismatch"):
            other.qualified()

    def test_forged_decision_row_cannot_mint_serving_state(self):
        from sis.v3.candidate_authority import (CandidateDecisionAuthority,
                                                CandidateEvidenceAuthority)
        from tests.v3.candidate_testkit import keypair
        cand = make_candidate(cid="forged-state")
        self.stack.prepare(cand)
        # A rogue evaluator/operator pair whose keys the registry does not
        # trust issues structurally valid artifacts.
        rogue_eval_seed, rogue_eval_pub, rogue_eval_key = keypair("rogue-eval")
        rogue_op_seed, rogue_op_pub, rogue_op_key = keypair("rogue-op")
        rogue_evidence_authority = CandidateEvidenceAuthority(
            trusted_evaluator_keys={rogue_eval_key: rogue_eval_pub.hex()})
        rogue_decision_authority = CandidateDecisionAuthority(
            trusted_operator_keys={rogue_op_key: rogue_op_pub.hex()})
        receipt = self.stack.receipt(task_id="task-forged-state")
        evidence = rogue_evidence_authority.issue(
            seed=rogue_eval_seed, candidate=cand,
            receipt_refs=[receipt.digest],
            evaluation_protocol_digest=self.stack.protocol,
            partition="holdout", signer_key_id=rogue_eval_key)
        decision = rogue_decision_authority.issue(
            seed=rogue_op_seed, candidate=cand,
            from_state="evaluating", to_state="qualified",
            actor_identity="mallory", receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,), signer_key_id=rogue_op_key)
        # Forge the audit row and state column exactly as a database
        # writer would; the chain is unkeyed and recomputable.
        with self.reg._lock:
            con = self.reg._conn()
            con.execute("BEGIN IMMEDIATE")
            con.execute(
                "INSERT INTO candidate_decision"
                " (decision_digest, decision_json, signer_key_id,"
                "  decision_nonce, consumed_at) VALUES (?, ?, ?, ?, ?)",
                (decision.digest, decision.canonical_bytes().decode("utf-8"),
                 decision.signer_key_id, decision.decision_nonce, NOW))
            con.execute(
                "INSERT INTO candidate_evidence"
                " (evidence_digest, evidence_json, candidate_id,"
                "  signer_key_id, stored_at) VALUES (?, ?, ?, ?, ?)",
                (evidence.digest, evidence.canonical_bytes().decode("utf-8"),
                 cand.candidate_id, evidence.signer_key_id, NOW))
            self.reg._audit(
                con, cand.candidate_id, "evaluating", "qualified",
                "mallory", (receipt.digest,), (evidence.digest,),
                decision.digest, "forged")
            con.execute(
                "UPDATE candidate SET state='qualified' WHERE candidate_id=?",
                (cand.candidate_id,))
            con.execute("COMMIT")
        with self.assertRaisesRegex(CandidateError,
                                    "decision_signer_untrusted"):
            self.reg.qualified()
        self.assertFalse(self.reg.verify()["ok"])

    def test_illegal_transitions_rejected(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        for target in ("evaluating", "qualified", "revoked"):
            with self.assertRaisesRegex(CandidateConflict,
                                        "illegal_transition"):
                self.reg.transition(cand.candidate_id, target,
                                    actor_role="operator",
                                    actor_identity="op-1",
                                    receipt_refs=("a" * 64,))
        self.reg.transition(cand.candidate_id, "rejected",
                            actor_role="evaluator")
        with self.assertRaisesRegex(CandidateConflict,
                                    "illegal_transition"):
            self.reg.transition(cand.candidate_id, "validated",
                                actor_role="learner")

    def test_tampered_row_fails_closed(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        # corrupt the stored JSON without touching the digest column
        self.reg._conn().execute(
            "UPDATE candidate SET candidate_json=? WHERE candidate_id=?",
            ('{"schema_version":1,"candidate_id":"cand-1"}',
             cand.candidate_id))
        self.reg._conn().commit()
        with self.assertRaises((CandidateError, ContractError)):
            self.reg.get(cand.candidate_id)

    def test_persistence_across_restart(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.close()
        reg2 = CandidateRegistry(self.root / "c.db")
        self.assertEqual(reg2.state_of(cand.candidate_id), "proposed")
        reg2.close()

    def test_qualified_state_survives_restart_with_signed_artifacts(self):
        cand = make_candidate(cid="restart-qualified")
        self.stack.prepare(cand)
        self.stack.qualify(cand)
        self.reg.close()
        reg2 = CandidateRegistry(
            self.root / "c.db",
            receipt_authority=self.stack.resolve_receipt,
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority,
            expected_evaluation_protocol_digest=self.stack.protocol)
        self.addCleanup(reg2.close)
        self.assertEqual(len(reg2.qualified()), 1)
        self.assertTrue(reg2.verify()["ok"])

    def test_audit_chain_detects_row_tamper(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        audit = self.reg.audit()
        self.assertEqual(len(audit), 2)
        self.assertTrue(all(len(e["entry_digest"]) == 64
                            for e in audit))
        # rewrite history: change the recorded actor of a transition
        self.reg._conn().execute(
            "UPDATE candidate_transition SET actor_identity='mallory'"
            " WHERE seq=2")
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit()
        # filtered reads must not bypass verification either
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit(cand.candidate_id)

    def test_audit_chain_detects_deleted_row(self):
        cand = make_candidate()
        self.reg.submit(cand, actor_role="learner")
        self.reg.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        self.reg._conn().execute(
            "DELETE FROM candidate_transition WHERE seq=1")
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError,
                                    "audit_chain_tampered"):
            self.reg.audit()

    def test_legacy_audit_rows_backfilled_on_open(self):
        # A pre-chain database is sealed in place at open: entries gain
        # digests, and reads then verify the chain normally.
        path = self.root / "legacy.db"
        con = sqlite3.connect(str(path))
        con.executescript("""
            CREATE TABLE candidate (
                candidate_id TEXT PRIMARY KEY,
                candidate_digest TEXT NOT NULL UNIQUE,
                candidate_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE candidate_transition (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor_identity TEXT NOT NULL,
                receipt_refs_json TEXT NOT NULL,
                note TEXT NOT NULL,
                committed_at TEXT NOT NULL);""")
        con.execute(
            "INSERT INTO candidate_transition"
            " (candidate_id, from_state, to_state, actor_identity,"
            "  receipt_refs_json, note, committed_at)"
            " VALUES ('c-1', '', 'proposed', 'learner', '[]',"
            "         'submitted', '2026-10-24T00:00:00Z')")
        con.commit()
        con.close()
        reg = CandidateRegistry(path)
        self.addCleanup(reg.close)
        audit = reg.audit()  # verifies the backfilled chain
        self.assertEqual(len(audit), 1)
        self.assertEqual(len(audit[0]["entry_digest"]), 64)
        self.assertEqual(audit[0]["decision_digest"], "")

    def test_legacy_qualified_state_is_unbacked_but_revocable(self):
        cand = make_candidate(cid="legacy-qualified")
        path = self.root / "legacy-qualified.db"
        con = sqlite3.connect(str(path))
        con.executescript("""
            CREATE TABLE candidate (
                candidate_id TEXT PRIMARY KEY,
                candidate_digest TEXT NOT NULL UNIQUE,
                candidate_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE candidate_transition (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor_identity TEXT NOT NULL,
                receipt_refs_json TEXT NOT NULL,
                note TEXT NOT NULL,
                committed_at TEXT NOT NULL);""")
        con.execute(
            "INSERT INTO candidate VALUES (?, ?, ?, 'qualified', ?)",
            (cand.candidate_id, cand.digest,
             cand.canonical_bytes().decode("utf-8"), NOW))
        for frm, to in (("", "proposed"), ("proposed", "validated"),
                        ("validated", "evaluating"),
                        ("evaluating", "qualified")):
            con.execute(
                "INSERT INTO candidate_transition"
                " (candidate_id, from_state, to_state, actor_identity,"
                "  receipt_refs_json, note, committed_at)"
                " VALUES (?, ?, ?, 'legacy', '[]', '', ?)",
                (cand.candidate_id, frm, to, NOW))
        con.commit()
        con.close()
        reg = CandidateRegistry(
            path, evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(reg.close)
        report = reg.verify()
        self.assertFalse(report["ok"])
        self.assertTrue(any("state_not_decision_backed" in p
                            for p in report["problems"]))
        with self.assertRaisesRegex(CandidateError,
                                    "state_not_decision_backed"):
            reg.qualified()
        decision = self.stack.decision_authority.issue(
            seed=self.stack.op_seed, candidate=cand,
            from_state="qualified", to_state="revoked",
            actor_identity="op-1", signer_key_id=self.stack.op_key)
        reg.revoke(cand.candidate_id, actor_role="operator",
                   actor_identity="op-1", decision_ref=decision.digest)
        self.assertEqual(reg.state_of(cand.candidate_id), "revoked")
        self.assertTrue(reg.verify()["ok"])

    def test_missing_evidence_row_is_unbacked_not_frozen(self):
        cand = make_candidate(cid="missing-row")
        self.stack.prepare(cand)
        _, evidence, _ = self.stack.qualify(cand)
        self.reg._conn().execute(
            "DELETE FROM candidate_evidence WHERE evidence_digest=?",
            (evidence.digest,))
        self.reg._conn().commit()
        report = self.reg.verify()
        self.assertFalse(report["ok"])
        self.assertIn("evidence_missing:missing-row", report["problems"])
        with self.assertRaisesRegex(CandidateError, "evidence_missing"):
            self.reg.qualified()
        # The catalog stays writable: intake and takedown both work.
        self.reg.submit(make_candidate(cid="after-corruption"),
                        actor_role="learner")
        decision = self.stack.decision(
            cand, "qualified", "revoked", actor_identity="op-1")
        self.reg.revoke(cand.candidate_id, actor_role="operator",
                        actor_identity="op-1", decision_ref=decision.digest)
        self.assertEqual(self.reg.state_of(cand.candidate_id), "revoked")
        self.assertTrue(self.reg.verify()["ok"])

    def test_missing_decision_row_is_unbacked_not_frozen(self):
        cand = make_candidate(cid="missing-decision")
        self.stack.prepare(cand)
        _, _, decision = self.stack.qualify(cand)
        self.reg._conn().execute(
            "DELETE FROM candidate_decision WHERE decision_digest=?",
            (decision.digest,))
        self.reg._conn().commit()
        self.assertIn("decision_missing:missing-decision",
                      self.reg.verify()["problems"])
        with self.assertRaisesRegex(CandidateError, "decision_missing"):
            self.reg.qualified()
        self.reg.submit(make_candidate(cid="intake-after-decision-loss"),
                        actor_role="learner")

    def test_qualification_requires_pinned_protocol(self):
        cand = make_candidate(cid="unpinned")
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-unpinned")
        evidence = self.stack.evidence(cand, [receipt])
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,))
        unpinned = CandidateRegistry(
            self.root / "unpinned.db",
            receipt_authority=self.stack.resolve_receipt,
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(unpinned.close)
        unpinned.submit(cand, actor_role="learner")
        unpinned.transition(cand.candidate_id, "validated",
                            actor_role="learner")
        unpinned.transition(cand.candidate_id, "evaluating",
                            actor_role="evaluator")
        with self.assertRaisesRegex(
                CandidateConflict, "qualification_requires_expected_protocol"):
            unpinned.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="test-operator", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,), decision_ref=decision.digest)
        # A serving replica that cannot state the expected protocol cannot
        # verify the evidence it is about to serve.
        self.stack.qualify(cand)
        replica = CandidateRegistry(
            self.root / "c.db",
            receipt_authority=self.stack.resolve_receipt,
            evidence_authority=self.stack.evidence_authority,
            decision_authority=self.stack.decision_authority)
        self.addCleanup(replica.close)
        with self.assertRaisesRegex(CandidateError,
                                    "serving_protocol_unpinned"):
            replica.qualified()

    def _pre_migration_chained_db(self, path, cand, *, tamper=False):
        from sis.v3.candidates import _GENESIS, _legacy_entry_digest
        con = sqlite3.connect(str(path))
        con.executescript("""
            CREATE TABLE candidate (
                candidate_id TEXT PRIMARY KEY,
                candidate_digest TEXT NOT NULL UNIQUE,
                candidate_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL);
            CREATE TABLE candidate_transition (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                candidate_id TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                actor_identity TEXT NOT NULL,
                receipt_refs_json TEXT NOT NULL,
                note TEXT NOT NULL,
                committed_at TEXT NOT NULL,
                prev_digest TEXT NOT NULL DEFAULT '',
                entry_digest TEXT NOT NULL DEFAULT '');""")
        con.execute(
            "INSERT INTO candidate VALUES (?, ?, ?, 'qualified', ?)",
            (cand.candidate_id, cand.digest,
             cand.canonical_bytes().decode("utf-8"), NOW))
        prev = _GENESIS
        for seq, (frm, to) in enumerate(
                (("", "proposed"), ("proposed", "validated"),
                 ("validated", "evaluating"), ("evaluating", "qualified")), 1):
            digest = _legacy_entry_digest(
                seq, cand.candidate_id, frm, to, "legacy", "[]", "", NOW, prev)
            con.execute(
                "INSERT INTO candidate_transition"
                " (seq, candidate_id, from_state, to_state, actor_identity,"
                "  receipt_refs_json, note, committed_at, prev_digest,"
                "  entry_digest) VALUES (?, ?, ?, ?, 'legacy', '[]', '', ?, ?, ?)",
                (seq, cand.candidate_id, frm, to, NOW, prev, digest))
            prev = digest
        if tamper:
            con.execute("UPDATE candidate_transition SET note='altered'"
                        " WHERE seq=2")
        con.commit()
        con.close()

    def test_pre_migration_chain_is_verified_before_reseal(self):
        cand = make_candidate(cid="chained-v33")
        path = self.root / "chained-v33.db"
        self._pre_migration_chained_db(path, cand)
        con = sqlite3.connect(str(path))
        before = [row[0] for row in con.execute(
            "SELECT entry_digest FROM candidate_transition ORDER BY seq")]
        con.close()
        reg = CandidateRegistry(path)
        self.addCleanup(reg.close)
        report = reg.verify()
        self.assertEqual(
            [(m["migration"], m["detail"], m["entries"])
             for m in report["migrations"]],
            [("chain-reseal-v1", "resealed_pre_migration_chain", 4)])
        after = [e["entry_digest"] for e in reg.audit()]
        self.assertNotEqual(before, after)
        # The reseal is recorded, and the legacy qualification is unbacked.
        self.assertFalse(report["ok"])
        self.assertIn("state_not_decision_backed:chained-v33",
                      report["problems"])

    def test_tampered_pre_migration_chain_refuses_to_open(self):
        cand = make_candidate(cid="tampered-v33")
        path = self.root / "tampered-v33.db"
        self._pre_migration_chained_db(path, cand, tamper=True)
        with self.assertRaisesRegex(
                CandidateError, "audit_chain_tampered:pre_migration_row_at_2"):
            CandidateRegistry(path)

    def test_missing_authorities_fail_closed(self):
        cand = make_candidate(cid="missing-authority")
        self.stack.prepare(cand)
        receipt = self.stack.receipt(task_id="task-missing-authority")
        evidence = self.stack.evidence(cand, [receipt])
        decision = self.stack.decision(
            cand, "evaluating", "qualified",
            receipt_refs=(receipt.digest,),
            evidence_refs=(evidence.digest,))
        # No decision authority: qualification is refused.
        reg = CandidateRegistry(
            self.root / "no-decision.db",
            receipt_authority=self.stack.resolve_receipt,
            evidence_authority=self.stack.evidence_authority,
            expected_evaluation_protocol_digest=self.stack.protocol)
        self.addCleanup(reg.close)
        reg.submit(cand, actor_role="learner")
        reg.transition(cand.candidate_id, "validated", actor_role="learner")
        reg.transition(cand.candidate_id, "evaluating",
                       actor_role="evaluator")
        with self.assertRaisesRegex(CandidateConflict,
                                    "decision_authority_required"):
            reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="test-operator", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest)
        # No evidence authority: qualification is refused.
        reg = CandidateRegistry(
            self.root / "no-evidence.db",
            receipt_authority=self.stack.resolve_receipt,
            decision_authority=self.stack.decision_authority,
            expected_evaluation_protocol_digest=self.stack.protocol)
        self.addCleanup(reg.close)
        reg.submit(cand, actor_role="learner")
        reg.transition(cand.candidate_id, "validated", actor_role="learner")
        reg.transition(cand.candidate_id, "evaluating",
                       actor_role="evaluator")
        with self.assertRaisesRegex(
                CandidateConflict, "qualification_requires_evidence_authority"):
            reg.qualify(
                cand.candidate_id, actor_role="operator",
                actor_identity="test-operator", receipt_refs=(receipt.digest,),
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest)
        # Serving a backed catalog without the authorities is refused.
        self.stack.qualify(cand)
        reg = CandidateRegistry(
            self.root / "c.db", receipt_authority=self.stack.resolve_receipt)
        self.addCleanup(reg.close)
        with self.assertRaisesRegex(CandidateError,
                                    "serving_integrity_unavailable"):
            reg.qualified()

    def test_illegal_audit_edge_fails_projection(self):
        cand = make_candidate(cid="illegal-edge")
        self.reg.submit(cand, actor_role="learner")
        with self.reg._lock:
            con = self.reg._conn()
            con.execute("BEGIN IMMEDIATE")
            self.reg._audit(con, cand.candidate_id, "proposed", "qualified",
                            "mallory", (), (), "", "forged")
            con.execute(
                "UPDATE candidate SET state='qualified' WHERE candidate_id=?",
                (cand.candidate_id,))
            con.execute("COMMIT")
        with self.assertRaisesRegex(CandidateError,
                                    "state_projection_invalid:edge"):
            self.reg.qualified()
        self.assertFalse(self.reg.verify()["ok"])

    def test_malformed_audit_refs_fail_closed(self):
        cand = make_candidate(cid="malformed-refs")
        self.reg.submit(cand, actor_role="learner")
        self.reg._conn().execute(
            "UPDATE candidate_transition SET evidence_refs_json='not json'"
            " WHERE seq=1")
        self.reg._conn().commit()
        with self.assertRaisesRegex(CandidateError, "audit_row_malformed"):
            self.reg.audit()
        with self.assertRaisesRegex(CandidateError, "audit_row_malformed"):
            self.reg.state_of(cand.candidate_id)

    def test_decision_nonce_cannot_be_consumed_twice(self):
        cand = make_candidate(cid="nonce")
        self.stack.prepare(cand)
        _, _, decision = self.stack.qualify(cand)
        with self.assertRaisesRegex(CandidateConflict, "decision_replayed"):
            with self.reg._lock:
                con = self.reg._conn()
                con.execute("BEGIN IMMEDIATE")
                try:
                    self.reg._store_decision(con, decision)
                finally:
                    con.execute("ROLLBACK")


if __name__ == "__main__":
    unittest.main()
