"""PR-02: candidate-specific certificates and fail-closed qualification.

A candidate may only become production-qualified when a signed
certificate binds its actual delivery, a preregistered protocol, a
conforming sample size, per-task receipts and statistical acceptance.
Passing one task, or asserting ``conforms=true`` without the evidence,
is never enough.
"""
from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.candidates import CandidateConflict, CandidateError
from sis.v3.contracts import canonical_digest
from sis.v3.evaluation_certificate import (
    CertificateError,
    DeliveryAttestationAuthority,
    EvaluationCertificateAuthority,
    ProtocolRegistry,
    QualificationPolicy,
    QualificationValidator,
    aggregate_delivery_digest,
    delivery_digest,
    sign_certificate,
)
from sis.v3.governed_eval import preregister
from sis.v3.control_plane import SqliteControlPlane
from sis.v3.serving import GovernedServingGateway
from tests.v3.candidate_testkit import CandidateStack
from tests.v3.test_candidates import make_candidate

REPO = "a" * 64
TASKS = tuple(f"task-{i:02d}" for i in range(29))
PROTOCOL = preregister(
    primary_metric="paired solved_delta E vs A",
    method="mcnemar_exact", alpha=0.05, min_effect=1.0,
    sample_size=29,
    budget={"wall_seconds": 120, "token_budget": 100_000,
            "tool_budget": 1000})
PROTOCOL_DIGEST = PROTOCOL["protocol_digest"]


def _keypair(prefix):
    seed, public = signatures.generate_keypair()
    return seed, public, prefix + "-" + hashlib.sha256(public).hexdigest()[:16]


class CertificateFixture:
    def __init__(self, root: Path, *, tasks=TASKS, sample_count=None,
                 evidence_class="confirmatory", protocol=PROTOCOL,
                 ci=None, negative=None, conformance=None,
                 authorized_tasks=None, repo_digests=(REPO,)):
        self.root = root
        self.tasks = tuple(tasks)
        self.sample_count = len(self.tasks) if sample_count is None \
            else sample_count
        self.protocol = protocol
        self.protocol_digest = protocol["protocol_digest"]
        self.repo_digests = tuple(repo_digests)
        self.cert_seed, cert_public, self.cert_key = _keypair("cert")
        self.harness_seed, harness_public, self.harness_key = _keypair(
            "harness")
        self.cert_authority = EvaluationCertificateAuthority(
            trusted_evaluator_keys={self.cert_key: cert_public.hex()})
        self.delivery_authority = DeliveryAttestationAuthority(
            trusted_harness_keys={self.harness_key: harness_public.hex()})
        self.protocols = ProtocolRegistry()
        self.protocols.register(protocol)
        self.deliveries = {}
        self.attestations = {}
        self.certificates = {}
        self.policy = QualificationPolicy(
            policy_version="sis-v3.3.1-qualification-1",
            primary_metric=protocol["primary_metric"],
            min_sample_size=29,
            required_protocol_digest=self.protocol_digest,
            required_preregistration_digest=self.protocol_digest,
            confidence_milli=950, min_effect_milli=100,
            require_positive_interval=True,
            max_negative_transfer_rate_milli=0,
            max_regressions=0,
            authorized_repository_digests=self.repo_digests,
            authorized_task_ids=tuple(authorized_tasks or self.tasks),
        )
        self.validator = QualificationValidator(
            self.policy,
            certificate_authority=self.cert_authority,
            delivery_authority=self.delivery_authority,
            protocol_registry=self.protocols,
            receipt_resolver=lambda digest: self.stack.resolve_receipt(digest),
            delivery_resolver=self.deliveries.__getitem__,
        )
        self.stack = CandidateStack(
            root / "candidates.db", protocol=self.protocol_digest,
            qualification_policy=self.policy,
            qualification_validator=self.validator,
            certificate_resolver=self.certificates.__getitem__)
        self.candidate = make_candidate(cid="cert-cand")
        self.stack.prepare(self.candidate)
        self.receipts = []
        self.entries = []
        for task_id in self.tasks:
            receipt = self.stack.receipt(task_id=task_id, repo_digest=REPO)
            self.receipts.append(receipt)
            guidance = hashlib.sha256(("guidance-" + task_id).encode()).hexdigest()
            delivered = delivery_digest(
                candidate_digest=self.candidate.digest,
                content_digest=self.candidate.content_digest,
                task_id=task_id, guidance_digest=guidance)
            attestation = self.delivery_authority.issue(
                self.harness_seed, signer_key_id=self.harness_key,
                attestation_id="att-" + hashlib.sha256(
                    task_id.encode()).hexdigest()[:12],
                candidate_id=self.candidate.candidate_id,
                candidate_digest=self.candidate.digest,
                content_digest=self.candidate.content_digest,
                delivery_digest=delivered, task_id=task_id,
                receipt_digest=receipt.digest,
                harness_identity="harness-1",
                session_nonce="nonce-" + task_id,
                issued_at="2026-10-26T00:00:00Z")
            self.deliveries[delivered] = attestation
            self.attestations[attestation.digest] = attestation
            self.entries.append({
                "task_id": task_id,
                "receipt_digest": receipt.digest,
                "delivery_digest": delivered,
                "attestation_digest": attestation.digest,
                "outcome": "pass",
            })
        self.ci = ci or {
            "method": "wilson", "confidence_milli": 950,
            "lower_milli": 50, "upper_milli": 350,
            "point_estimate_milli": 200}
        self.negative = negative or {
            "evaluated": len(self.tasks), "regressions": 0,
            "negative_transfer_count": 0, "rate_milli": 0}
        self.conformance = conformance or {
            "conforms": True, "executed_task_count": len(self.tasks),
            "declared_sample_size": protocol["sample_size"],
            "mismatches": ()}

    def certificate(self, *, candidate=None, **overrides):
        candidate = candidate or self.candidate
        fields = {
            "schema_version": 1,
            "certificate_id": "cert-" + hashlib.sha256(
                candidate.candidate_id.encode()).hexdigest()[:12],
            "certificate_version": "1",
            "evidence_class": "confirmatory",
            "candidate_id": candidate.candidate_id,
            "candidate_digest": candidate.digest,
            "candidate_content_digest": candidate.content_digest,
            "candidate_delivery_digest": aggregate_delivery_digest(self.entries),
            "baseline_model_digest": "b" * 64,
            "agent_configuration_digest": "c" * 64,
            "evaluation_protocol_digest": self.protocol_digest,
            "preregistration_digest": self.protocol_digest,
            "evaluation_taskset_digest": canonical_digest(
                "eval_taskset", 1, {"tasks": list(self.tasks)}),
            "repository_snapshot_digests": self.repo_digests,
            "individual_task_receipts": tuple(self.entries),
            "grader_identity": "grader-1",
            "evaluator_identity": "evaluator-1",
            "sample_count": self.sample_count,
            "primary_metric": self.protocol["primary_metric"],
            "confidence_interval": self.ci,
            "negative_transfer_results": self.negative,
            "protocol_conformance": self.conformance,
            "qualification_policy_digest": self.policy.digest,
            "partition": "holdout",
            "issued_at": "2026-10-26T00:00:00Z",
            "expires_at": None,
        }
        fields.update(overrides)
        certificate = self.cert_authority.issue(
            self.cert_seed, signer_key_id=self.cert_key, **fields)
        self.certificates[certificate.digest] = certificate
        return certificate

    def qualify(self, certificate):
        evidence = self.stack.evidence(
            self.candidate, self.receipts, protocol=self.protocol_digest)
        decision = self.stack.decision(
            self.candidate, "evaluating", "qualified",
            receipt_refs=tuple(r.digest for r in self.receipts),
            evidence_refs=(evidence.digest,))
        self.stack.registry.qualify(
            self.candidate.candidate_id, actor_role="operator",
            actor_identity="test-operator",
            receipt_refs=tuple(r.digest for r in self.receipts),
            evidence_refs=(evidence.digest,),
            decision_ref=decision.digest,
            certificate_ref=certificate.digest)
        return evidence, decision


class QualificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_conforming_certificate_qualifies(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertTrue(validation.ok, validation.failures)
        fixture.qualify(certificate)
        self.assertEqual(
            fixture.stack.registry.state_of(fixture.candidate.candidate_id),
            "qualified")
        stored = fixture.stack.registry.certificate_for(
            fixture.candidate.candidate_id)
        self.assertEqual(stored.digest, certificate.digest)
        self.assertTrue(fixture.stack.registry.verify()["ok"])
        self.assertEqual(fixture.stack.registry.qualification_mode,
                         "production")

    def test_two_task_experiment_cannot_satisfy_29(self):
        fixture = CertificateFixture(
            self.root, tasks=TASKS[:2], sample_count=2,
            authorized_tasks=TASKS,
            conformance={
                "conforms": True, "executed_task_count": 2,
                "declared_sample_size": 29, "mismatches": ()})
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("sample_count_meets_protocol", validation.failures)
        self.assertIn("sample_count_meets_policy", validation.failures)
        with self.assertRaisesRegex(CandidateConflict,
                                    "certificate_rejected"):
            fixture.qualify(certificate)
        self.assertNotEqual(
            fixture.stack.registry.state_of(fixture.candidate.candidate_id),
            "qualified")

    def test_sample_count_must_match_receipts(self):
        fixture = CertificateFixture(self.root, sample_count=29)
        self.addCleanup(fixture.stack.close)
        # Only two receipts, but the certificate claims 29 samples.
        fixture.tasks = TASKS[:2]
        fixture.entries = fixture.entries[:2]
        fixture.receipts = fixture.receipts[:2]
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("receipt_count_matches_sample", validation.failures)

    def test_unrelated_task_receipt_is_rejected(self):
        fixture = CertificateFixture(
            self.root, authorized_tasks=TASKS[:-1])
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("authorized_task_scope", validation.failures)

    def test_candidate_digest_must_match(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        other = make_candidate(cid="other-cand")
        certificate = fixture.certificate(candidate=other)
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("candidate_id", validation.failures)
        self.assertIn("candidate_digest", validation.failures)

    def test_missing_delivery_attestation_blocks_qualification(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        missing = fixture.entries[0]["delivery_digest"]
        del fixture.deliveries[missing]
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("delivery_attestation", validation.failures)

    def test_forged_conformance_flag_cannot_override_evidence(self):
        fixture = CertificateFixture(
            self.root, tasks=TASKS[:2], sample_count=2,
            conformance={
                "conforms": True, "executed_task_count": 2,
                "declared_sample_size": 29, "mismatches": ()})
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("sample_count_meets_protocol", validation.failures)
        self.assertIn("sample_count_meets_policy", validation.failures)

    def test_protocol_conformance_must_be_declared(self):
        fixture = CertificateFixture(
            self.root,
            conformance={
                "conforms": False, "executed_task_count": 29,
                "declared_sample_size": 29,
                "mismatches": ("sample_size",)})
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("protocol_conformance_declared", validation.failures)
        self.assertIn("protocol_conformance_no_mismatches",
                      validation.failures)

    def test_exploratory_evidence_is_retained_but_not_production(self):
        fixture = CertificateFixture(self.root, evidence_class="exploratory")
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate(evidence_class="exploratory")
        self.assertTrue(fixture.cert_authority.verify(certificate))
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("evidence_class_confirmatory", validation.failures)
        with self.assertRaisesRegex(CandidateConflict,
                                    "certificate_rejected"):
            fixture.qualify(certificate)

    def test_unknown_protocol_is_rejected(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate(
            evaluation_protocol_digest="f" * 64,
            preregistration_digest="f" * 64)
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("protocol_known", validation.failures)

    def test_policy_digest_mismatch_is_rejected(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate(
            qualification_policy_digest="d" * 64)
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("policy_digest", validation.failures)

    def test_negative_transfer_blocks_qualification(self):
        fixture = CertificateFixture(
            self.root,
            negative={"evaluated": 29, "regressions": 2,
                      "negative_transfer_count": 2, "rate_milli": 69})
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("negative_transfer_rate", validation.failures)
        self.assertIn("regressions", validation.failures)

    def test_nonpositive_interval_blocks_qualification(self):
        fixture = CertificateFixture(
            self.root,
            ci={"method": "wilson", "confidence_milli": 950,
                "lower_milli": -20, "upper_milli": 200,
                "point_estimate_milli": 90})
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("positive_interval", validation.failures)
        self.assertIn("effect_size", validation.failures)

    def test_expired_certificate_blocks_qualification(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate(
            issued_at="2020-01-01T00:00:00Z",
            expires_at="2020-01-02T00:00:00Z")
        validation = fixture.validator.validate(
            certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("certificate_not_expired", validation.failures)

    def test_revoked_certificate_blocks_serving(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        fixture.qualify(certificate)
        revoked = QualificationValidator(
            fixture.policy,
            certificate_authority=fixture.cert_authority,
            delivery_authority=fixture.delivery_authority,
            protocol_registry=fixture.protocols,
            receipt_resolver=fixture.stack.resolve_receipt,
            delivery_resolver=fixture.deliveries.__getitem__,
            revoked_certificates={certificate.digest})
        validation = revoked.validate(certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("certificate_not_revoked", validation.failures)

    def test_qualification_requires_certificate(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        evidence = fixture.stack.evidence(
            fixture.candidate, fixture.receipts,
            protocol=fixture.protocol_digest)
        decision = fixture.stack.decision(
            fixture.candidate, "evaluating", "qualified",
            receipt_refs=tuple(r.digest for r in fixture.receipts),
            evidence_refs=(evidence.digest,))
        with self.assertRaisesRegex(
                CandidateConflict,
                "qualification_requires_evaluation_certificate"):
            fixture.stack.registry.qualify(
                fixture.candidate.candidate_id, actor_role="operator",
                actor_identity="test-operator",
                receipt_refs=tuple(r.digest for r in fixture.receipts),
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest)

    def test_certificate_receipt_set_must_match_qualification(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        short = fixture.receipts[:-1]
        evidence = fixture.stack.evidence(
            fixture.candidate, short, protocol=fixture.protocol_digest)
        decision = fixture.stack.decision(
            fixture.candidate, "evaluating", "qualified",
            receipt_refs=tuple(r.digest for r in short),
            evidence_refs=(evidence.digest,))
        with self.assertRaisesRegex(CandidateConflict,
                                    "certificate_receipt_mismatch"):
            fixture.stack.registry.qualify(
                fixture.candidate.candidate_id, actor_role="operator",
                actor_identity="test-operator",
                receipt_refs=tuple(r.digest for r in short),
                evidence_refs=(evidence.digest,),
                decision_ref=decision.digest,
                certificate_ref=certificate.digest)

    def test_certificate_signature_must_authenticate(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        wrong_seed, _, _ = _keypair("wrong")
        forged = sign_certificate(
            wrong_seed,
            **{k: v for k, v in certificate.to_dict().items()
               if k not in {"schema_version", "signature"}})
        validation = fixture.validator.validate(
            forged, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("certificate_signature", validation.failures)

    def test_receipt_from_other_repository_is_rejected(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()

        class _OtherRepositoryReceipt:
            def __init__(self, task_id):
                self.task_id = task_id
                self.outcome = "pass"
                self.evaluated_repo_digest = "b" * 64

        target = fixture.entries[0]["receipt_digest"]
        validator = QualificationValidator(
            fixture.policy,
            certificate_authority=fixture.cert_authority,
            delivery_authority=fixture.delivery_authority,
            protocol_registry=fixture.protocols,
            receipt_resolver=lambda digest: (
                _OtherRepositoryReceipt(fixture.entries[0]["task_id"])
                if digest == target
                else fixture.stack.resolve_receipt(digest)),
            delivery_resolver=fixture.deliveries.__getitem__,
        )
        validation = validator.validate(certificate, fixture.candidate)
        self.assertFalse(validation.ok)
        self.assertIn("receipt_repository_scope", validation.failures)

    def test_high_risk_skill_security_blocks_production_certificate(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        risky = make_candidate(
            cid="risky-skill",
            payload={"title": "t", "steps": ["do it"],
                     "security": {"auto_qualification_allowed": False,
                                  "highest_severity": "high"}})
        certificate = fixture.certificate(candidate=risky)
        validation = fixture.validator.validate(certificate, risky)
        self.assertFalse(validation.ok)
        self.assertIn("candidate_security_auto_qualification_allowed",
                      validation.failures)

    def test_production_gateway_requires_checkpointed_registry(self):
        fixture = CertificateFixture(self.root)
        self.addCleanup(fixture.stack.close)
        certificate = fixture.certificate()
        fixture.qualify(certificate)
        control = SqliteControlPlane(self.root / "control-a.db")
        self.addCleanup(control.close)
        gateway = GovernedServingGateway(
            fixture.stack.registry, repository_registry=None,
            production=True, control_plane=control)
        from tests.v3.test_authority_checkpoints import _request
        guidance = gateway.serve(_request(), repository_id="repo-1")
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")

    def test_production_gateway_excludes_demonstration_registry(self):
        stack = CandidateStack(self.root / "demo.db")
        self.addCleanup(stack.close)
        candidate = make_candidate(cid="demo-cand")
        stack.prepare(candidate)
        stack.qualify(candidate)
        self.assertEqual(stack.registry.qualification_mode,
                         "demonstration")
        control = SqliteControlPlane(self.root / "control-b.db")
        self.addCleanup(control.close)
        gateway = GovernedServingGateway(
            stack.registry, repository_registry=None, production=True,
            control_plane=control)
        from tests.v3.test_authority_checkpoints import _request
        guidance = gateway.serve(_request(), repository_id="repo-1")
        self.assertEqual(guidance.decision, "abstain")
        self.assertEqual(guidance.reason_code, "catalog_unavailable")


if __name__ == "__main__":
    unittest.main()
