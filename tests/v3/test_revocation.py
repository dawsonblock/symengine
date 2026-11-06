"""PR-04 adversarial coverage: signed revocations + evidence cascade.

Committed ``RevocationV1`` rows take effect at the serving boundary on the
very next request — no restart, no rebuild. Revoked evidence cascades:
dependent qualified records are suspended through signed decisions and
grants citing the receipt stop permitting. Forged, unsigned, untrusted or
tampered revocations all fail closed.
"""
import hashlib
import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_db import AuthorityConflict, AuthorityDB, AuthorityError
from sis.v3.catalog import Catalog
from sis.v3.promotion import (
    PromotionController, PromotionRejected, operator_token_digest,
)
from sis.v3.repository_registry import RepositoryRegistry
from sis.v3.revocation import (
    RevocationAuthority, sign_revocation, unsigned_revocation,
)
from sis.v3.scope_grants import ScopeGrantAuthority
from sis.v3.secure_guidance import StrictGuidanceGateway

from tests.v3.authority_testkit import (
    drive, evaluator_keypair, issue_and_commit_grant, make_grant_authority,
    make_registry, register_repo, seed as seed_record, signed_receipt,
)
from tests.v3.test_retrieval import _proc, _request

TOKEN = "operator-token-0123456789"


def _tree(repo: str) -> str:
    return hashlib.sha256(("tree:" + repo).encode()).hexdigest()


class RevocationFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = AuthorityDB(self.root / "authority.db")
        self.addCleanup(self.db.close)

        self.registry, self.registry_seed = make_registry()
        self.grants, self.grant_seed, self.grant_key = make_grant_authority(
            self.registry)
        for repo, fam in (("repo-a", "fam-a"), ("repo-b", "fam-b")):
            register_repo(self.registry, self.registry_seed,
                          registry_id=repo, family_id=fam,
                          base_tree_digest=_tree(repo))

        self.eval_seed, eval_pub, self.eval_key = evaluator_keypair()
        self.controller = PromotionController(
            self.db, operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.eval_key: eval_pub.hex()})

        rev_seed, rev_pub = signatures.generate_keypair()
        self.rev_authority = RevocationAuthority(
            trusted_signers={"rev-key-1": rev_pub.hex()})
        self.rev_seed = rev_seed
        self.rev_key = "rev-key-1"

        # p1 cites the qualification receipt so revoking it must cascade.
        self.qual_receipt = signed_receipt(
            self.eval_seed, self.eval_key, task_id="t-qual",
            repo_digest=_tree("repo-a"))
        self.controller._resolve_receipt = \
            {self.qual_receipt.digest: self.qual_receipt}.__getitem__
        seed_record(self.db, replace(
            _proc(pid="p1"), evidence_refs=(self.qual_receipt.digest,)))
        drive(self.db, self.controller, "p1", "qualified",
              token=TOKEN, seed=self.eval_seed, key_id=self.eval_key,
              receipts=[self.qual_receipt])
        # p2 is independent of the revocable receipt.
        other = signed_receipt(self.eval_seed, self.eval_key,
                               task_id="t-other", repo_digest=_tree("repo-a"))
        self.controller._resolve_receipt = lambda d: {
            self.qual_receipt.digest: self.qual_receipt,
            other.digest: other}[d]
        seed_record(self.db, _proc(pid="p2"))
        drive(self.db, self.controller, "p2", "qualified",
              token=TOKEN, seed=self.eval_seed, key_id=self.eval_key, receipts=[other])

        self.catalog = Catalog(self.db)
        self.gateway = StrictGuidanceGateway(
            self.db, self.controller, catalog=self.catalog,
            procedure_owners={"p1": "repo-a", "p2": "repo-a"},
            grant_authority=self.grants)

    def issue_revocation(self, *, kind, target_digest=None, target_id=None,
                         seed=None, key_id=None, rid="rev-1",
                         actor_role="operator"):
        return self.rev_authority.issue(
            actor_role=actor_role,
            seed=seed if seed is not None else self.rev_seed,
            revocation_id=rid, kind=kind,
            target_digest=target_digest, target_id=target_id,
            reason="test revocation", actor_identity="op-1",
            signer_key_id=key_id or self.rev_key)

    def commit_revocation(self, revocation):
        return self.controller.revoke(
            revocation, actor_role="operator", actor_identity="op-1",
            operator_token=TOKEN, verifier=self.rev_authority.verify)

    def transfer_receipts(self, *repos):
        return [signed_receipt(self.eval_seed, self.eval_key,
                               task_id=f"tr-{repo}",
                               repo_digest=_tree(repo))
                for repo in repos]

    def commit_grant(self, *, target_repo, receipts=None):
        return issue_and_commit_grant(
            self.db, self.controller, self.grants,
            record=self.db.get("p2"), source_registry_id="repo-a",
            target_registry_id=target_repo,
            seed=self.grant_seed, key_id=self.grant_key,
            evidence_receipts=receipts or self.transfer_receipts(
                "repo-a", "repo-b"))

    def recommend(self, repository_id="repo-a", **kw):
        return self.gateway.recommend(_request(), repository_id=repository_id,
                                      **kw)


class SignedRevocationTests(RevocationFixture):
    def test_unsigned_or_forged_revocation_rejected(self):
        unsigned = unsigned_revocation(
            revocation_id="rev-forged", kind="record",
            target_digest=self.db.get("p1").digest,
            reason="forged", actor_identity="op-1",
            issued_at="2026-10-24T00:00:00Z", signer_key_id=self.rev_key)
        body = {k: v for k, v in unsigned.items() if k != "signature"}
        real = sign_revocation(self.rev_seed, body)
        forged = type(real).from_dict(
            {**real.to_dict(), "signature": "0" * 128})
        with self.assertRaises(AuthorityConflict):
            self.db.commit_revocation(
                revocation=forged, authority=self.controller,
                verifier=self.rev_authority.verify)

    def test_untrusted_revocation_signer_rejected(self):
        evil_seed, _, evil_key = evaluator_keypair()
        # Attacker mints a well-formed revocation under their own key; the
        # key is simply not in the trusted set — commit must reject it.
        rev = sign_revocation(evil_seed, unsigned_revocation(
            revocation_id="rev-evil", kind="record",
            target_digest=self.db.get("p1").digest,
            reason="forged", actor_identity="op-1",
            issued_at="2026-10-24T00:00:00Z", signer_key_id=evil_key))
        with self.assertRaises(AuthorityConflict):
            self.db.commit_revocation(
                revocation=rev, authority=self.controller,
                verifier=self.rev_authority.verify)

    def test_unbound_authority_cannot_revoke(self):
        other_db = AuthorityDB(self.root / "other.db")
        self.addCleanup(other_db.close)
        intruder = PromotionController(
            other_db, operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.eval_key:
                                    signatures.public_key(self.eval_seed).hex()})
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        with self.assertRaises(AuthorityError):
            self.db.commit_revocation(
                revocation=rev, authority=intruder,
                verifier=self.rev_authority.verify)

    def test_verifier_required(self):
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        with self.assertRaises(AuthorityError):
            self.db.commit_revocation(
                revocation=rev, authority=self.controller)

    def test_duplicate_revocation_conflicts(self):
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        self.commit_revocation(rev)
        with self.assertRaises(AuthorityConflict):
            self.db.commit_revocation(
                revocation=rev, authority=self.controller,
                verifier=self.rev_authority.verify)

    def test_tampered_revocation_row_fails_closed(self):
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        self.commit_revocation(rev)
        con = sqlite3.connect(str(self.db.path))
        try:
            con.execute("PRAGMA foreign_keys=OFF")
            con.execute("UPDATE revocation SET revocation_json='corrupt'")
            con.commit()
        finally:
            con.close()
        self.assertFalse(self.db.verify()["ok"])
        self.assertIn("undecodable_revocation",
                      " ".join(self.db.verify()["problems"]))
        self.assertEqual(self.recommend().decision, "abstain")
        self.assertEqual(self.recommend().reason_code, "catalog_unavailable")


class RevocationEnforcementTests(RevocationFixture):
    def test_record_revocation_denies_immediately(self):
        self.assertEqual(self.recommend().decision, "recommend")
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        self.commit_revocation(rev)
        out = self.recommend()
        self.assertNotIn("p1", out.procedure_ids)

    def test_record_revocation_survives_restart(self):
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p1").digest)
        self.commit_revocation(rev)
        db2 = AuthorityDB(self.db.path)
        self.addCleanup(db2.close)
        controller2 = PromotionController(
            db2, operator_token_digest=operator_token_digest(TOKEN),
            trusted_evaluator_keys={self.eval_key:
                                    signatures.public_key(self.eval_seed).hex()})
        gateway2 = StrictGuidanceGateway(
            db2, controller2, catalog=Catalog(db2),
            procedure_owners={"p1": "repo-a", "p2": "repo-a"},
            grant_authority=self.grants)
        out = gateway2.recommend(_request(), repository_id="repo-a")
        self.assertNotIn("p1", out.procedure_ids)
        self.assertIn("p2", out.procedure_ids)

    def test_evidence_revocation_cascades_signed_suspensions(self):
        rev = self.issue_revocation(
            kind="receipt", target_digest=self.qual_receipt.digest)
        suspended = self.commit_revocation(rev)
        self.assertEqual(len(suspended), 1)
        self.assertEqual(self.db.get("p1").status, "suspended")
        self.assertEqual(self.db.get("p2").status, "qualified")
        out = self.recommend()
        self.assertNotIn("p1", out.procedure_ids)
        self.assertIn("p2", out.procedure_ids)
        # The cascade produced a real signed suspension decision.
        self.assertTrue(self.controller.verify()["ok"])
        self.assertTrue(
            any(d.new_status == "suspended" for d in self.db.decisions()))

    def test_evidence_revocation_denies_citing_record_pre_cascade(self):
        # Even before/without cascade, the citing record is denied at serve.
        rev = self.issue_revocation(
            kind="receipt", target_digest=self.qual_receipt.digest)
        self.db.commit_revocation(
            revocation=rev, authority=self.controller,
            verifier=self.rev_authority.verify)
        out = self.recommend()
        self.assertNotIn("p1", out.procedure_ids)
        self.assertIn("p2", out.procedure_ids)
        self.assertEqual(self.db.get("p1").status, "qualified")  # status unchanged

    def test_grant_revocation_stops_cross_repo_serving(self):
        grant = self.commit_grant(target_repo="repo-b")
        self.assertEqual(
            self.recommend("repo-b").decision, "recommend")
        rev = self.issue_revocation(kind="grant", target_digest=grant.digest)
        self.commit_revocation(rev)
        self.assertEqual(self.recommend("repo-b").decision, "abstain")
        # Owner-local serving is unaffected by grant revocation.
        self.assertIn("p2", self.recommend("repo-a").procedure_ids)

    def test_receipt_revocation_invalidates_grants_citing_it(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        grant = self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        rev = self.issue_revocation(
            kind="receipt", target_digest=receipts[0].digest)
        self.commit_revocation(rev)
        # Grant evidence is revoked → grant stops permitting (grant itself
        # was not revoked).
        self.assertEqual(self.recommend("repo-b").decision, "abstain")

    def test_signer_revocation_stops_its_grants(self):
        self.commit_grant(target_repo="repo-b")
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        rev = self.issue_revocation(kind="signer", target_id=self.grant_key)
        self.commit_revocation(rev)
        self.assertEqual(self.recommend("repo-b").decision, "abstain")

    def test_evaluator_signer_revocation_blocks_new_decisions(self):
        r3 = signed_receipt(self.eval_seed, self.eval_key, task_id="t3",
                            repo_digest=_tree("repo-a"))
        r3b = signed_receipt(self.eval_seed, self.eval_key, task_id="t3b",
                             repo_digest=_tree("repo-a"))
        self.controller._resolve_receipt = {
            self.qual_receipt.digest: self.qual_receipt,
            r3.digest: r3, r3b.digest: r3b}.__getitem__
        seed_record(self.db, _proc(pid="p3"))
        drive(self.db, self.controller, "p3", "evaluated",
              token=TOKEN, seed=self.eval_seed, key_id=self.eval_key,
              receipts=[r3])
        rev = self.issue_revocation(kind="signer", target_id=self.eval_key)
        self.commit_revocation(rev)
        with self.assertRaises(PromotionRejected):
            drive(self.db, self.controller, "p3", "qualified",
                  token=TOKEN, seed=self.eval_seed, key_id=self.eval_key,
                  receipts=[r3b])

    def test_audit_trail_records_revocation(self):
        rev = self.issue_revocation(
            kind="record", target_digest=self.db.get("p2").digest)
        self.commit_revocation(rev)
        events = [e["event_type"] for e in self.db.audit_trail()]
        self.assertIn("revocation_committed", events)
        committed = self.db.revocations()
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0].revocation_id, rev.revocation_id)
