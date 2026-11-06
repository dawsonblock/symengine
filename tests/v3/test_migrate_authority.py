"""PR-02: legacy JSONL -> AuthorityDB migration tests.

Covers dry-run reconciliation, quarantine of orphan/ambiguous records,
signed report emission, execute, and reversible cutover.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from sis.v3 import signatures
from sis.v3.contracts import canonical_json, loads_json
from sis.v3.procedures import ProcedureStore

import tools.migrate_authority as mig
from tests.v3.test_retrieval import _proc


def _legacy_tree(root: Path) -> tuple[Path, Path]:
    """Build a V2-style catalog log + journal directory for tests."""
    store = ProcedureStore(root / "catalog")
    return store.root / "procedures.jsonl", root / "decisions" / "decisions.jsonl"


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def _write_catalog(self, records):
        """Write a syntactically valid legacy catalog log."""
        log = self.root / "catalog" / "procedures.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        prior = None
        with open(log, "wb") as handle:
            for rec in records:
                line = canonical_json({
                    "record": rec.to_dict(),
                    "record_digest": rec.digest,
                    "prior_record_digest": prior})
                handle.write(line + b"\n")
                prior = hashlib.sha256(line).hexdigest()
        return log

    def test_dry_run_quarantines_decision_managed_seed(self):
        """A rev-1 qualified record (the old fixture bypass) is quarantined."""
        catalog = self._write_catalog([
            _proc(pid="ok-draft", status="draft"),
            _proc(pid="rogue", status="qualified"),
        ])
        journal = self.root / "decisions" / "decisions.jsonl"  # absent = empty
        code = mig.main([
            "--catalog", str(catalog), "--decisions", str(journal)])
        self.assertEqual(code, 1)  # blocked — quarantine requires operator review
        # The quarantine is also visible in reconciliation directly.
        entries, problems = mig._load_catalog(catalog)
        self.assertFalse(problems)
        _seeds, _imports, quarantined, issues = mig.reconcile(entries, [])
        self.assertEqual([r.procedure_id for r, _ in quarantined], ["rogue"])
        self.assertEqual(quarantined[0][1], "seed_with_decision_managed_status")

    def test_orphaned_successor_revision_quarantined(self):
        """A rev-2 with no backing decision is never grandfathered in."""
        base = _proc(pid="p1", status="draft")
        orphan = replace(base, revision=2, status="qualified")
        catalog = self._write_catalog([base, orphan])
        entries, _ = mig._load_catalog(catalog)
        _seeds, _imports, quarantined, _issues = mig.reconcile(entries, [])
        self.assertEqual(
            [(r.revision, reason) for r, reason in quarantined],
            [(2, "revision_without_verified_decision")])

    def test_corrupt_catalog_line_fails_closed(self):
        log = self._write_catalog([_proc(pid="p1", status="draft")])
        with open(log, "ab") as handle:
            handle.write(b"{not json}\n")
        entries, problems = mig._load_catalog(log)
        self.assertEqual(problems, ["undecodable_catalog_entry:1"])
        code = mig.main(["--catalog", str(log),
                         "--decisions", str(self.root / "missing.jsonl")])
        self.assertEqual(code, 1)


class ExecuteAndCutoverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seed, self.public = signatures.generate_keypair()
        self.keyfile = self.root / "key"
        self.keyfile.write_text(self.seed.hex())

    def _write_catalog(self, records):
        log = self.root / "catalog" / "procedures.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        prior = None
        with open(log, "wb") as handle:
            for rec in records:
                line = canonical_json({
                    "record": rec.to_dict(),
                    "record_digest": rec.digest,
                    "prior_record_digest": prior})
                handle.write(line + b"\n")
                prior = hashlib.sha256(line).hexdigest()
        return log

    def test_execute_requires_signing_key(self):
        catalog = self._write_catalog([_proc(pid="p1", status="draft")])
        code = mig.main([
            "--catalog", str(catalog),
            "--decisions", str(self.root / "none.jsonl"),
            "--target", str(self.root / "authority.db"),
            "--execute"])
        self.assertEqual(code, 2)  # blocked: no signing key

    def test_execute_imports_and_signs_report(self):
        from sis.v3.contracts import PromotionDecisionV1
        catalog = self._write_catalog([
            _proc(pid="p1", status="draft"),
            _proc(pid="rogue", status="qualified"),
        ])
        journal = self.root / "decisions" / "decisions.jsonl"
        journal.parent.mkdir(parents=True, exist_ok=True)
        d1 = PromotionDecisionV1.from_dict({
            "schema_version": 1, "decision_id": "dec-legacy",
            "candidate_digest": "0" * 64, "evaluation_protocol_digest": "0" * 64,
            "receipt_refs": ["0" * 64], "actor_identity": "op", "approved": True,
            "policy_version": "v1", "prior_status": "candidate",
            "new_status": "evaluated", "old_qualified_head": "0" * 64,
            "new_qualified_head": None, "rollback_ref": None,
            "evaluator_signature": "not-required",
            "operator_authorization": "operator_token_sha256:" + "0" * 64})
        journal.write_bytes(canonical_json({
            "decision": d1.to_dict(), "decision_digest": d1.digest,
            "prior_decision_digest": None}) + b"\n")
        report_path = self.root / "report.json"
        code = mig.main([
            "--catalog", str(catalog), "--decisions", str(journal),
            "--target", str(self.root / "authority.db"),
            "--execute", "--signing-key", str(self.keyfile),
            "--key-id", "op-migration",
            "--operator-token-digest", "0" * 64,
            "--report", str(report_path)])
        self.assertEqual(code, 0)
        report = json.loads(report_path.read_text())
        self.assertEqual(report["status"], "complete")
        self.assertTrue(report["signed"])
        self.assertEqual(report["signature"]["key_id"], "op-migration")
        # Verify the signature over the unsigned body.
        body = canonical_json({k: v for k, v in report.items()
                               if k not in {"signature", "signed"}})
        self.assertTrue(signatures.verify(
            bytes.fromhex(report["signature"]["digest"]),
            b"sis-v3:migration_report:1\0" + body,
            signatures.public_key(self.seed)))
        # Quarantine row present in the migrated store.
        from sis.v3.authority_db import AuthorityDB
        db = AuthorityDB(self.root / "authority.db")
        self.assertEqual(db.quarantined()[0]["source"], "catalog-jsonl")
        self.assertIn("seed_with_decision_managed_status",
                      db.quarantined()[0]["reason"])
        db.close()

    def test_cutover_renames_and_is_reversible(self):
        catalog = self._write_catalog([_proc(pid="p1", status="draft")])
        journal = self.root / "decisions" / "decisions.jsonl"
        journal.parent.mkdir(parents=True, exist_ok=True)
        journal.write_bytes(b"")
        code = mig.main([
            "--catalog", str(catalog), "--decisions", str(journal),
            "--target", str(self.root / "authority.db"),
            "--execute", "--cutover",
            "--backup-dir", str(self.root / "backup"),
            "--signing-key", str(self.keyfile),
            "--operator-token-digest", "0" * 64])
        self.assertEqual(code, 0)
        self.assertFalse(catalog.exists())
        self.assertTrue((self.root / "catalog" / "procedures.jsonl.migrated").exists())
        backup = self.root / "backup" / "procedures.jsonl"
        self.assertTrue(backup.exists())
        # Rollback: rename back, remove the migrated marker + new store.
        (self.root / "catalog" / "procedures.jsonl.migrated").rename(catalog)
        self.assertEqual(
            hashlib.sha256(catalog.read_bytes()).hexdigest(),
            hashlib.sha256(backup.read_bytes()).hexdigest())


if __name__ == "__main__":
    unittest.main()
