"""PR-03 adversarial coverage: signed scope grants + trusted repository registry.

Every adversarial path must fail closed: forged signatures, untrusted
signers, registry alias collisions, same-family leakage, expired grants,
identity mismatch, nonce replay, post-commit tampering and stale grants
against a superseded revision. Only a fully verified, committed grant may
move guidance beyond repository-local.
"""
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sis.v3 import signatures
from sis.v3.authority_db import AuthorityConflict, AuthorityDB, AuthorityError
from sis.v3.catalog import Catalog
from sis.v3.contracts import ContractError, canonical_json
from sis.v3.promotion import PromotionController, operator_token_digest
from sis.v3.repository_registry import (
    RegistryError, RepositoryRegistry, sign_identity, unsigned_identity,
)
from sis.v3.scope_grants import (
    ScopeGrantAuthority, ScopeGrantError, sign_grant, unsigned_grant,
)
from sis.v3.secure_guidance import StrictGuidanceGateway

from tests.v3.authority_testkit import (
    GRANT_SIGNER_KEY_ID, TEST_TOKEN, drive, evaluator_keypair,
    issue_and_commit_grant, make_grant_authority, make_registry,
    register_repo, seed as seed_record, signed_receipt,
)
from tests.v3.test_retrieval import _proc, _request

FUTURE = "2999-01-01T00:00:00Z"
PAST = "2001-01-01T00:00:00Z"


def _tree(repo: str) -> str:
    return hashlib.sha256(("tree:" + repo).encode()).hexdigest()


class ScopeGrantFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = AuthorityDB(self.root / "authority.db")
        self.addCleanup(self.db.close)

        self.registry, self.registry_seed = make_registry()
        self.grants, self.grant_seed, self.grant_key = make_grant_authority(
            self.registry)
        for repo, fam in (("repo-a", "fam-a"), ("repo-b", "fam-b"),
                          ("repo-c", "fam-a")):
            register_repo(self.registry, self.registry_seed,
                          registry_id=repo, family_id=fam,
                          base_tree_digest=_tree(repo))

        self.eval_seed, eval_pub, self.eval_key = evaluator_keypair()
        self.controller = PromotionController(
            self.db, operator_token_digest=operator_token_digest(TEST_TOKEN),
            trusted_evaluator_keys={self.eval_key: eval_pub.hex()})
        seed_record(self.db, _proc(pid="p1"))
        self.qual_receipt = signed_receipt(
            self.eval_seed, self.eval_key, repo_digest=_tree("repo-a"))
        self.controller._resolve_receipt = \
            {self.qual_receipt.digest: self.qual_receipt}.__getitem__
        drive(self.db, self.controller, "p1", "qualified", seed=self.eval_seed,
              key_id=self.eval_key, receipts=[self.qual_receipt])
        self.catalog = Catalog(self.db)
        self.gateway = StrictGuidanceGateway(
            self.db, self.controller, catalog=self.catalog,
            procedure_owners={"p1": "repo-a"},
            grant_authority=self.grants)

    def transfer_receipts(self, *repos):
        return [signed_receipt(self.eval_seed, self.eval_key,
                               task_id=f"transfer-{repo}-{i}",
                               repo_digest=_tree(repo))
                for i, repo in enumerate(repos)]

    def commit_grant(self, *, source="repo-a", target_repo=None,
                     target_family=None, receipts=None, seed=None,
                     key_id=None, nonce=None, expires_at=None):
        return issue_and_commit_grant(
            self.db, self.controller, self.grants,
            record=self.db.get("p1"), source_registry_id=source,
            target_registry_id=target_repo, target_family_id=target_family,
            seed=seed or self.grant_seed,
            key_id=key_id or self.grant_key,
            evidence_receipts=receipts or self.transfer_receipts(
                "repo-a", "repo-b"),
            expires_at=expires_at, grant_nonce=nonce)

    def recommend(self, repository_id, **kw):
        return self.gateway.recommend(_request(), repository_id=repository_id, **kw)


class LegitimateGrantTests(ScopeGrantFixture):
    def test_repo_local_serves_without_grant(self):
        self.assertEqual(self.recommend("repo-a").decision, "recommend")

    def test_cross_repository_grant_enables_in_scope_access(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        # And the owner still works locally.
        self.assertEqual(self.recommend("repo-a").decision, "recommend")

    def test_family_grant_covers_same_family_member(self):
        receipts = self.transfer_receipts("repo-a", "repo-c")
        self.commit_grant(target_family="fam-a", receipts=receipts)
        # repo-c is a fam-a member: the family grant permits it.
        self.assertEqual(self.recommend("repo-c").decision, "recommend")


class ForgedAndUnsignedGrantTests(ScopeGrantFixture):
    def test_forged_signature_never_serves(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        unsigned = unsigned_grant(
            grant_id="g-1", procedure_revision_digest=self.db.get("p1").digest,
            source_registry_id="repo-a", source_family_id="fam-a",
            target_registry_id="repo-b",
            evaluator_protocol_digest="e" * 64,
            evidence_receipt_refs=tuple(r.digest for r in receipts),
            expires_at=None, grant_nonce="n-1",
            signer_key_id=self.grant_key)
        body = {k: v for k, v in unsigned.items() if k != "signature"}
        real = sign_grant(self.grant_seed, body)
        forged = type(real).from_dict(
            {**real.to_dict(), "signature": "0" * 128})
        self.assertTrue(self.grants.verify(forged, receipts=receipts))
        with self.assertRaises(AuthorityConflict):
            self.db.commit_scope_grant(
                grant=forged, receipts=receipts, authority=self.controller,
                verifier=lambda g: self.grants.verify(g, receipts=receipts))

    def test_untrusted_signer_rejected_at_issue_and_commit(self):
        evil_seed, _evil_pub, evil_key = evaluator_keypair()
        receipts = self.transfer_receipts("repo-a", "repo-b")
        unsigned = unsigned_grant(
            grant_id="g-evil",
            procedure_revision_digest=self.db.get("p1").digest,
            source_registry_id="repo-a", source_family_id="fam-a",
            target_registry_id="repo-b",
            evaluator_protocol_digest="e" * 64,
            evidence_receipt_refs=tuple(r.digest for r in receipts),
            expires_at=None, grant_nonce="n-evil",
            signer_key_id=evil_key)
        forged = sign_grant(evil_seed, unsigned)
        self.assertIn("grant_signature_invalid",
                      self.grants.verify(forged, receipts=receipts))
        with self.assertRaises(AuthorityConflict):
            self.db.commit_scope_grant(
                grant=forged, receipts=receipts, authority=self.controller,
                verifier=lambda g: self.grants.verify(g, receipts=receipts))

    def test_unbound_authority_cannot_commit_grants(self):
        other_db = AuthorityDB(self.root / "other.db")
        self.addCleanup(other_db.close)
        intruder = PromotionController(
            other_db, operator_token_digest=operator_token_digest(TEST_TOKEN),
            trusted_evaluator_keys={self.eval_key:
                                    signatures.public_key(self.eval_seed).hex()})
        receipts = self.transfer_receipts("repo-a", "repo-b")
        grant = self.grants.issue(
            actor_role="operator", seed=self.grant_seed,
            record=self.db.get("p1"), source_registry_id="repo-a",
            target_registry_id="repo-b", evaluator_protocol_digest="e" * 64,
            evidence_receipts=receipts, expires_at=None,
            grant_nonce="n-unbound", signer_key_id=self.grant_key)
        with self.assertRaises(AuthorityError):
            self.db.commit_scope_grant(
                grant=grant, receipts=receipts, authority=intruder,
                verifier=lambda g: self.grants.verify(g, receipts=receipts))

    def test_tampered_committed_grant_fails_closed(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        # Attacker rewrites the stored grant body to target themselves.
        con = sqlite3.connect(str(self.db.path))
        try:
            row = con.execute(
                "SELECT grant_json FROM scope_grant").fetchone()
            parsed = dict(__import__("json").loads(row[0]))
            parsed["target_registry_id"] = "repo-eve"
            import json as _json
            con.execute("PRAGMA foreign_keys=OFF")
            con.execute("UPDATE scope_grant SET grant_json=?",
                        (_json.dumps(parsed),))
            con.commit()
        finally:
            con.close()
        # Tampered body no longer matches grant_digest → undecodable at read.
        self.assertEqual(self.recommend("repo-b").decision, "abstain")
        self.assertFalse(self.db.verify()["ok"])

    def test_nonce_replay_rejected_atomically(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts,
                          nonce="nonce-replay")
        with self.assertRaises(AuthorityConflict):
            self.commit_grant(target_repo="repo-b", receipts=receipts,
                              nonce="nonce-replay")

    def test_verifier_missing_rejects_commit(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        grant = self.grants.issue(
            actor_role="operator", seed=self.grant_seed,
            record=self.db.get("p1"), source_registry_id="repo-a",
            target_registry_id="repo-b", evaluator_protocol_digest="e" * 64,
            evidence_receipts=receipts, expires_at=None,
            grant_nonce="n-noverify", signer_key_id=self.grant_key)
        with self.assertRaises(AuthorityError):
            self.db.commit_scope_grant(
                grant=grant, receipts=receipts, authority=self.controller)


class RegistryLineageTests(ScopeGrantFixture):
    def test_duplicate_registry_id_alias_rejected(self):
        other = sign_identity(self.registry_seed, unsigned_identity(
            registry_id="repo-a", family_id="fam-b",
            base_tree_digest=_tree("different"),
            base_commit=None, trust_domain_id="test-domain",
            attestation_digest="a" * 64, signer_key_id="registry-key-1"))
        with self.assertRaises(RegistryError):
            self.registry.register(other)

    def test_duplicate_tree_alias_rejected(self):
        other = sign_identity(self.registry_seed, unsigned_identity(
            registry_id="repo-eve", family_id="fam-b",
            base_tree_digest=_tree("repo-a"),  # alias another repo's tree
            base_commit=None, trust_domain_id="test-domain",
            attestation_digest="b" * 64, signer_key_id="registry-key-1"))
        with self.assertRaises(RegistryError):
            self.registry.register(other)

    def test_registry_rejects_unsigned_or_wrong_key_identity(self):
        wrong_seed = signatures.generate_keypair()[0]
        fake = sign_identity(wrong_seed, unsigned_identity(
            registry_id="repo-x", family_id="fam-x",
            base_tree_digest=_tree("repo-x"), base_commit=None,
            trust_domain_id="test-domain", attestation_digest="c" * 64,
            signer_key_id="registry-key-1"))
        with self.assertRaises(RegistryError):
            self.registry.register(fake)

    def test_registry_load_fails_closed_on_tamper(self):
        path = self.root / "registry.jsonl"
        self.registry.dump(path)
        lines = path.read_text().splitlines()
        parsed = __import__("json").loads(lines[0])
        parsed["family_id"] = "attacker-fam"
        lines[0] = __import__("json").dumps(parsed)
        path.write_text("\n".join(lines) + "\n")
        with self.assertRaises(RegistryError):
            RepositoryRegistry.load(path,
                                    registry_public_hex=self.registry._public)

    def test_unresolvable_requester_abstains(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        # "repo-b"-adjacent claims that are not registered identities abstain.
        self.assertEqual(self.recommend("repo-bb").decision, "abstain")
        self.assertEqual(self.recommend("").decision, "abstain")

    def test_same_family_membership_alone_grants_nothing(self):
        # repo-c shares fam-a with owner repo-a, but no grant exists → abstain.
        self.assertEqual(self.recommend("repo-c").decision, "abstain")

    def test_family_grant_does_not_leak_across_families(self):
        receipts = self.transfer_receipts("repo-a", "repo-c")
        self.commit_grant(target_family="fam-a", receipts=receipts)
        # repo-b is fam-b: a fam-a grant must not leak to it.
        self.assertEqual(self.recommend("repo-b").decision, "abstain")
        self.assertEqual(self.recommend("repo-c").decision, "recommend")

    def test_grant_for_source_mismatch_does_not_serve(self):
        # A repo-b→repo-c grant does not authorize p1, which is owned by repo-a.
        grant = self.grants.issue(
            actor_role="operator", seed=self.grant_seed,
            record=self.db.get("p1"), source_registry_id="repo-b",
            target_registry_id="repo-c",
            evaluator_protocol_digest="e" * 64,
            evidence_receipts=self.transfer_receipts("repo-b", "repo-c"),
            expires_at=None, grant_nonce="n-src2",
            signer_key_id=self.grant_key)
        self.db.commit_scope_grant(
            grant=grant,
            receipts=self.transfer_receipts("repo-b", "repo-c"),
            authority=self.controller,
            verifier=lambda g: self.grants.verify(
                g, receipts=self.transfer_receipts("repo-b", "repo-c")))
        self.assertEqual(self.recommend("repo-c").decision, "abstain")


class GrantLifecycleTests(ScopeGrantFixture):
    def test_expired_grant_abstains_at_serve_time(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts,
                          expires_at="2027-06-01T00:00:00Z")
        # Before expiry: serves. After: abstains — verified per request.
        self.assertEqual(
            self.recommend("repo-b", now="2027-05-01T00:00:00Z").decision,
            "recommend")
        self.assertEqual(
            self.recommend("repo-b", now="2027-07-01T00:00:00Z").decision,
            "abstain")

    def test_issue_rejects_expired_grant(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        with self.assertRaises(ScopeGrantError):
            self.commit_grant(target_repo="repo-b", receipts=receipts,
                              expires_at=PAST)

    def test_grant_binds_exact_revision_not_lineage(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        # Re-qualify p1 to a NEW revision: the old grant binds the old digest.
        r2 = signed_receipt(self.eval_seed, self.eval_key, task_id="t-requal",
                            repo_digest=_tree("repo-a"))
        self.controller._resolve_receipt = lambda d: {
            self.qual_receipt.digest: self.qual_receipt, r2.digest: r2}[d]
        self.controller.transition(
            "p1", "suspended", actor_role="operator",
            actor_identity="op", operator_token=TEST_TOKEN)
        drive(self.db, self.controller, "p1", "qualified",
              seed=self.eval_seed, key_id=self.eval_key, receipts=[r2])
        self.assertNotEqual(self.db.get("p1").digest,
                            self.db.scope_grants()[0].procedure_revision_digest)
        self.assertEqual(self.recommend("repo-b").decision, "abstain")
        # Repo-local still works for the new revision.
        self.assertEqual(self.recommend("repo-a").decision, "recommend")

    def test_insufficient_transfer_evidence_rejected(self):
        # Only one repo's receipts → below min_transfer_receipts.
        receipts = self.transfer_receipts("repo-a")
        with self.assertRaises(ScopeGrantError):
            self.commit_grant(target_repo="repo-b", receipts=receipts)

    def test_evidence_on_unregistered_trees_rejected(self):
        receipts = [signed_receipt(self.eval_seed, self.eval_key,
                                   task_id="ghost", repo_digest="9" * 64),
                    *self.transfer_receipts("repo-a")]
        with self.assertRaises(ScopeGrantError):
            self.commit_grant(target_repo="repo-b", receipts=receipts)

    def test_revoked_grant_stops_serving(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        grant = self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        self.grants.revoke_grant(grant.grant_id)
        self.assertEqual(self.recommend("repo-b").decision, "abstain")

    def test_revoked_signer_stops_all_grants(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        self.assertEqual(self.recommend("repo-b").decision, "recommend")
        self.grants.revoke_signer(self.grant_key)
        self.assertEqual(self.recommend("repo-b").decision, "abstain")

    def test_committed_grant_row_deletion_fails_closed(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        self.commit_grant(target_repo="repo-b", receipts=receipts)
        con = sqlite3.connect(str(self.db.path))
        try:
            con.execute("PRAGMA foreign_keys=OFF")
            con.execute("DELETE FROM scope_grant")
            con.commit()
        finally:
            con.close()
        self.assertEqual(self.recommend("repo-b").decision, "abstain")
        self.assertTrue(self.db.verify()["ok"])  # deletion is not corruption

    def test_audit_trail_records_grant_commit(self):
        receipts = self.transfer_receipts("repo-a", "repo-b")
        grant = self.commit_grant(target_repo="repo-b", receipts=receipts)
        events = [e["event_type"] for e in self.db.audit_trail()]
        self.assertIn("scope_grant_committed", events)
        bound = self.db.receipts_for_grant(grant.grant_id)
        self.assertEqual({r.digest for r in bound},
                         set(grant.evidence_receipt_refs))
