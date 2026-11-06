"""CandidateAuthority: signer selection, lifetime and binding checks."""
import tempfile
import unittest

from sis.v3.candidate_authority import (CandidateAuthorityError,
                                        CandidateDecisionAuthority,
                                        CandidateEvidenceAuthority)
from sis.v3.contracts import ContractError
from tests.v3.candidate_testkit import keypair
from tests.v3.test_candidates import make_candidate

PROTOCOL = "e" * 64


class _AuthorityFixture(unittest.TestCase):
    NOW = "2026-10-25T04:00:00Z"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.seed, self.public, self.key = keypair("eval")
        self.other_seed, self.other_public, self.other_key = keypair("other")
        self.cand = make_candidate(cid="authority-" + self.id().split(".")[-1])
        self.receipt = "a" * 64


class EvidenceAuthorityTests(_AuthorityFixture):
    def setUp(self):
        super().setUp()
        self.authority = CandidateEvidenceAuthority(
            trusted_evaluator_keys={self.key: self.public.hex()},
            now=self.NOW)

    def issue(self, **kwargs):
        return self.authority.issue(
            seed=self.seed, candidate=self.cand,
            receipt_refs=[self.receipt],
            evaluation_protocol_digest=PROTOCOL,
            signer_key_id=self.key, **kwargs)

    def test_expiry_compares_instants_not_strings(self):
        # 10:00+05:00 is 05:00Z: already expired at 08:00Z, but it sorts
        # after "…T08:00:00Z" as text.
        expired = self.issue(expires_at="2026-10-25T10:00:00+05:00")
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "evidence_expired"):
            self.authority.authenticate(expired, now="2026-10-25T08:00:00Z")
        # A fractional second past expiry is expired, not accepted.
        plain = self.issue(expires_at="2026-10-25T08:00:00Z")
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "evidence_expired"):
            self.authority.authenticate(
                plain, now="2026-10-25T08:00:00.500Z")
        self.authority.authenticate(plain, now="2026-10-25T07:59:59.999Z")

    def test_lifetime_must_be_positive(self):
        for expires_at in ("2026-10-25T04:00:00Z", "2026-10-25T03:59:59Z"):
            with self.assertRaisesRegex(ContractError,
                                        "later than issued_at"):
                self.issue(expires_at=expires_at)
        with self.assertRaisesRegex(ContractError, "ISO-8601"):
            self.issue(expires_at="tomorrow")

    def test_ambiguous_trust_set_requires_explicit_signer(self):
        authority = CandidateEvidenceAuthority(
            trusted_evaluator_keys={
                self.key: self.public.hex(),
                self.other_key: self.other_public.hex()})
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "signer_key_id_required"):
            authority.issue(seed=self.seed, candidate=self.cand,
                            receipt_refs=[self.receipt],
                            evaluation_protocol_digest=PROTOCOL)
        issued = authority.issue(
            seed=self.seed, candidate=self.cand,
            receipt_refs=[self.receipt],
            evaluation_protocol_digest=PROTOCOL, signer_key_id=self.key)
        self.assertEqual(issued.signer_key_id, self.key)
        empty = CandidateEvidenceAuthority(trusted_evaluator_keys={})
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "no_trusted_evaluator_key"):
            empty.issue(seed=self.seed, candidate=self.cand,
                        receipt_refs=[self.receipt],
                        evaluation_protocol_digest=PROTOCOL)

    def test_partition_is_mandatory(self):
        evidence = self.issue()
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "evidence_partition_not_None"):
            self.authority.check(evidence, candidate=self.cand,
                                 receipt_refs=[self.receipt], partition=None)


class DecisionAuthorityTests(_AuthorityFixture):
    def setUp(self):
        super().setUp()
        self.authority = CandidateDecisionAuthority(
            trusted_operator_keys={self.key: self.public.hex()},
            now=self.NOW)

    def issue(self, **kwargs):
        return self.authority.issue(
            seed=self.seed, candidate=self.cand, from_state="evaluating",
            to_state="qualified", actor_identity="op-1",
            signer_key_id=self.key, **kwargs)

    def test_expiry_compares_instants_not_strings(self):
        expired = self.issue(expires_at="2026-10-25T10:00:00+05:00")
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "decision_expired"):
            self.authority.authenticate(expired, now="2026-10-25T08:00:00Z")
        plain = self.issue(expires_at="2026-10-25T08:00:00Z")
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "decision_expired"):
            self.authority.authenticate(
                plain, now="2026-10-25T08:00:00.500Z")

    def test_lifetime_must_be_positive(self):
        with self.assertRaisesRegex(ContractError, "later than issued_at"):
            self.issue(expires_at="2026-10-25T04:00:00Z")

    def test_ambiguous_trust_set_requires_explicit_signer(self):
        authority = CandidateDecisionAuthority(
            trusted_operator_keys={
                self.key: self.public.hex(),
                self.other_key: self.other_public.hex()})
        with self.assertRaisesRegex(CandidateAuthorityError,
                                    "signer_key_id_required"):
            authority.issue(seed=self.seed, candidate=self.cand,
                            from_state="evaluating", to_state="qualified",
                            actor_identity="op-1")


if __name__ == "__main__":
    unittest.main()
