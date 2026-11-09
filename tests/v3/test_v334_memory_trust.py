"""SIS v3.3.4 Phase 3 memory-trust regressions (gate G3).

Covers the three gaps the v3.3.3 audit left open:

- G3.1: development and production trust configurations are explicit;
  production refuses to construct without signed records, a custodian
  chain key, an external witness, and an evaluator verifier.
- G3.2: a separately stored, signed witness detects a rollback to an
  older database snapshot and refuses to re-anchor it.
- G3.3: production memory use requires the full
  experience → outcome → execution → registered-task lineage.
- G3.4: retrieval separates trust from applicability and usefulness, and
  a trust failure can never be rescued by a high score.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from sis.v3 import signatures
from sis.v3.contracts import (
    ContractError,
    ExperienceRecordV1,
    TaskEnvelopeV1,
)
from sis.v3.memory import (
    MemoryError,
    MemoryStore,
    MemoryTrustProfile,
    induce_candidate,
    issue_experience_record,
    retrieve_memories,
    verify_experience_evidence,
)
from sis.v3.memory_witness import MemoryWitness, WitnessError
from sis.v3.retrieval import RetrievalContext
from sis.v3.runner import LocalSubprocessExecutor
from sis.v3.verifier import OutcomeVerifier

PY = sys.executable
ACCEPTANCE = b"import calc\nassert calc.scale(3, 4) == 12\nprint('ok')\n"
NOW = "2026-11-09T12:00:00Z"


def _task(task_id="task-scale") -> TaskEnvelopeV1:
    return TaskEnvelopeV1(
        schema_version=1, task_id=task_id,
        repo_snapshot_digest="0" * 64, base_commit=None,
        task_statement_digest="1" * 64,
        permitted_commands=("run-tests",), isolation_profile="unverified_local",
        time_budget_seconds=300, token_budget=10_000, tool_budget=50,
        actor_id="agent-1", evaluator_task_ref=task_id,
    )


def _v1_record(experience_id="exp-v1", episode_id="ep-v1"):
    return ExperienceRecordV1(
        schema_version=1,
        experience_id=experience_id,
        episode_id=episode_id,
        repository_registry_id="repo-a",
        task_fingerprint=hashlib.sha256(
            ("fp:" + episode_id).encode()).hexdigest(),
        task_category="convention-fix",
        agent_config_digest="a" * 64,
        trace_digest="b" * 64,
        outcome_receipt_digest="c" * 64,
        outcome="fail",
        failure_category="convention_unknown",
        lesson="Use ROUND_HALF_UP for money",
        facts=("baseline failed without guidance",),
        hypotheses=("guidance prevents this class",),
        applicability=({"kind": "language_is", "value": "python"},),
        counterexamples=(),
        provenance={"generator": "test", "method": "unit"},
        captured_at=NOW,
    )


class MemoryFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        submission = self.root / "submission"
        submission.mkdir()
        (submission / "calc.py").write_text(
            "def scale(a, b):\n    return a * b\n", encoding="utf-8")
        self.verifier = OutcomeVerifier(
            executor=LocalSubprocessExecutor(
                self.root / "eval-exec", use_seatbelt=False),
            key_dir=self.root / "keys",
            registry_dir=self.root / "registry")
        self.verifier.register_task(
            actor_role="evaluator", task_id="task-scale",
            criterion_version="acceptance-v1",
            argv=(PY, "acceptance.py"),
            files={"acceptance.py": ACCEPTANCE})
        self.receipt = self.verifier.evaluate(
            actor_role="evaluator", task=_task(),
            submission_dir=submission, evaluation_nonce="nonce-1")
        self.execution = self.verifier.execution_digest_for(
            self.receipt.digest)

        self.record_seed, self.record_public = signatures.generate_keypair()
        self.chain_seed, self.chain_public = signatures.generate_keypair()
        self.witness_seed, self.witness_public = signatures.generate_keypair()

    def record(self, experience_id="exp-1", episode_id="ep-1", **over):
        fields = dict(
            experience_id=experience_id,
            episode_id=episode_id,
            repository_registry_id="repo-a",
            task_id=self.receipt.task_id,
            attempt_id="att-1",
            repo_snapshot_digest=self.receipt.evaluated_repo_digest,
            task_fingerprint=hashlib.sha256(
                ("fp:" + episode_id).encode()).hexdigest(),
            task_category="convention-fix",
            agent_config_digest="a" * 64,
            execution_receipt_digest=self.execution,
            trace_digest="b" * 64,
            outcome_receipt_digest=self.receipt.digest,
            outcome=self.receipt.outcome,
            failure_category=None,
            lesson="Use ROUND_HALF_UP for money",
            facts=("baseline failed without guidance",),
            hypotheses=("guidance prevents this class",),
            applicability=({"kind": "language_is", "value": "python"},),
            counterexamples=(),
            provenance={"generator": "test", "method": "unit"},
            captured_at=NOW,
        )
        fields.update(over)
        return issue_experience_record(self.record_seed, "exp-key-1", **fields)

    def witness(self, path="witness/w.jsonl", seed=None, key_id="witness-key-1"):
        return MemoryWitness(
            self.root / path, seed=seed or self.witness_seed, key_id=key_id)

    def store(self, *, db="db/memory.db", profile=None, witness=None,
              verifier=None, keys=None, chain=None):
        return MemoryStore(
            self.root / db,
            trusted_signer_keys=(
                keys if keys is not None
                else {"exp-key-1": self.record_public.hex()}),
            chain_key=chain if chain is not None
            else (self.chain_seed, "chain-key-1"),
            profile=profile or MemoryTrustProfile.production(),
            witness=witness if witness is not None else self.witness(),
            verifier=verifier if verifier is not None else self.verifier)


class ProductionProfileTests(MemoryFixture):
    """G3.1: production refuses to construct without every trust root."""

    def test_production_requires_signed_records(self):
        with self.assertRaisesRegex(
                ContractError, "production_requires_trusted_signer_keys"):
            self.store(keys={})

    def test_production_requires_chain_key(self):
        with self.assertRaisesRegex(
                ContractError, "production_requires_chain_key"):
            MemoryStore(
                self.root / "db" / "memory.db",
                trusted_signer_keys={"exp-key-1": self.record_public.hex()},
                profile=MemoryTrustProfile.production(),
                witness=self.witness(), verifier=self.verifier)

    def test_production_requires_witness(self):
        with self.assertRaisesRegex(
                ContractError, "production_requires_witness"):
            MemoryStore(
                self.root / "db" / "memory.db",
                trusted_signer_keys={"exp-key-1": self.record_public.hex()},
                chain_key=(self.chain_seed, "chain-key-1"),
                profile=MemoryTrustProfile.production(),
                verifier=self.verifier)

    def test_production_requires_verifier(self):
        with self.assertRaisesRegex(
                ContractError, "production_requires_verifier"):
            MemoryStore(
                self.root / "db" / "memory.db",
                trusted_signer_keys={"exp-key-1": self.record_public.hex()},
                chain_key=(self.chain_seed, "chain-key-1"),
                profile=MemoryTrustProfile.production(),
                witness=self.witness())

    def test_witness_must_live_outside_store_directory(self):
        co_located = self.witness(path="db/w.jsonl")
        with self.assertRaisesRegex(
                ContractError, "witness_must_live_outside_store_directory"):
            self.store(witness=co_located)

    def test_development_profile_reports_untrusted(self):
        store = self.store(profile=MemoryTrustProfile.development())
        record = self.record()
        store.ingest(record, evidence_check=lambda r: True)
        self.assertEqual(
            store.trust_status(record), "untrusted:development_profile")
        self.assertFalse(store.is_trusted(record))

    def test_production_reports_trusted(self):
        store = self.store()
        record = self.record()
        store.ingest(record)
        self.assertEqual(store.trust_status(record), "trusted")
        self.assertTrue(store.is_trusted(record))

    def test_production_rejects_legacy_v1_record(self):
        store = self.store()
        with self.assertRaisesRegex(
                MemoryError, "legacy_v1_record"):
            store.ingest(_v1_record())

    def test_production_rejects_forged_record_signature(self):
        store = self.store()
        other_seed, _public = signatures.generate_keypair()
        forged = issue_experience_record(
            other_seed, "exp-key-1", **self.record().to_dict())
        with self.assertRaisesRegex(MemoryError, "experience_tampered"):
            store.ingest(forged)


class ProductionLineageTests(MemoryFixture):
    """G3.3: production memory needs the full registered-task lineage."""

    def test_unregistered_task_rejected(self):
        class _NoRegistration:
            def __init__(self, inner):
                self._inner = inner

            def load_receipt(self, digest):
                return self._inner.load_receipt(digest)

            def verify_receipt(self, artifact):
                return self._inner.verify_receipt(artifact)

            def execution_digest_for(self, digest):
                return self._inner.execution_digest_for(digest)

            def registered_task(self, task_id):
                return None

        with self.assertRaisesRegex(
                MemoryError, "experience_task_unregistered"):
            verify_experience_evidence(
                self.record(), _NoRegistration(self.verifier),
                require_registered_task=True)

    def test_protocol_mismatch_rejected(self):
        class _WrongProtocol:
            def __init__(self, inner):
                self._inner = inner

            def load_receipt(self, digest):
                return self._inner.load_receipt(digest)

            def verify_receipt(self, artifact):
                return self._inner.verify_receipt(artifact)

            def execution_digest_for(self, digest):
                return self._inner.execution_digest_for(digest)

            def registered_task(self, task_id):
                return SimpleNamespace(suite_commitment="f" * 64)

        with self.assertRaisesRegex(
                MemoryError, "experience_protocol_mismatch"):
            verify_experience_evidence(
                self.record(), _WrongProtocol(self.verifier),
                require_registered_task=True)

    def test_missing_registration_support_is_unverifiable(self):
        class _NoLookup:
            def __init__(self, inner):
                self._inner = inner

            def load_receipt(self, digest):
                return self._inner.load_receipt(digest)

            def verify_receipt(self, artifact):
                return self._inner.verify_receipt(artifact)

            def execution_digest_for(self, digest):
                return self._inner.execution_digest_for(digest)

        with self.assertRaisesRegex(
                MemoryError, "experience_task_registration_unverifiable"):
            verify_experience_evidence(
                self.record(), _NoLookup(self.verifier),
                require_registered_task=True)

    def test_production_store_rejects_unregistered_lineage(self):
        class _NoRegistration:
            def __init__(self, inner):
                self._inner = inner

            def load_receipt(self, digest):
                return self._inner.load_receipt(digest)

            def verify_receipt(self, artifact):
                return self._inner.verify_receipt(artifact)

            def execution_digest_for(self, digest):
                return self._inner.execution_digest_for(digest)

            def registered_task(self, task_id):
                return None

        store = self.store(verifier=_NoRegistration(self.verifier))
        with self.assertRaisesRegex(
                MemoryError, "experience_task_unregistered"):
            store.ingest(self.record())

    def test_development_store_skips_lineage_by_default(self):
        store = self.store(profile=MemoryTrustProfile.development())
        self.assertEqual(
            store.ingest(self.record(), evidence_check=lambda r: True),
            self.record().digest)


class WitnessRollbackTests(MemoryFixture):
    """G3.2: an external witness detects rewinds and cannot be re-anchored."""

    def test_ingest_advances_witness(self):
        store = self.store()
        store.ingest(self.record())
        latest = self.witness().latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.sequence, 1)
        self.assertEqual(latest.memory_head_digest, store.head_digest())

    def test_rollback_to_older_snapshot_detected(self):
        store = self.store()
        store.ingest(self.record())
        store.close()
        snapshot = self.root / "snapshot.db"
        shutil.copy2(self.root / "db" / "memory.db", snapshot)

        store = self.store()
        store.ingest(self.record(experience_id="exp-2", episode_id="ep-2"))
        store.close()

        shutil.copy2(snapshot, self.root / "db" / "memory.db")
        restored = self.store()
        self.assertFalse(restored.verify_chain())
        self.assertEqual(
            restored.last_chain_failure,
            "witness:memory_rollback_detected")
        with self.assertRaisesRegex(
                MemoryError, "memory_rollback_detected"):
            restored.get("exp-1")

    def test_reconcile_cannot_reanchor_rollback(self):
        store = self.store()
        store.ingest(self.record())
        store.close()
        snapshot = self.root / "snapshot.db"
        shutil.copy2(self.root / "db" / "memory.db", snapshot)
        store = self.store()
        store.ingest(self.record(experience_id="exp-2", episode_id="ep-2"))
        store.close()
        shutil.copy2(snapshot, self.root / "db" / "memory.db")

        restored = self.store()
        with self.assertRaisesRegex(
                MemoryError, "witness_sequence_not_advancing"):
            restored.reconcile_witness()

    def test_stale_witness_requires_reconcile(self):
        store = self.store()
        store.ingest(self.record())
        store.close()

        # Simulate the crash window: the database advanced without the
        # witness append.
        writer = MemoryStore(
            self.root / "db" / "memory.db",
            trusted_signer_keys={"exp-key-1": self.record_public.hex()},
            chain_key=(self.chain_seed, "chain-key-1"))
        writer.ingest(self.record(experience_id="exp-2", episode_id="ep-2"))
        writer.close()

        store = self.store()
        with self.assertRaisesRegex(MemoryError, "memory_witness_stale"):
            store.get("exp-1")
        self.assertEqual(store.reconcile_witness(), 2)
        self.assertEqual(store.get("exp-1").experience_id, "exp-1")
        self.assertTrue(store.verify_chain())

    def test_missing_witness_with_entries_fails_closed(self):
        store = self.store()
        store.ingest(self.record())
        store.close()
        (self.root / "witness" / "w.jsonl").unlink()
        reopened = self.store()
        with self.assertRaisesRegex(MemoryError, "witness_missing"):
            reopened.get("exp-1")

    def test_tampered_witness_rejected(self):
        store = self.store()
        store.ingest(self.record())
        store.close()
        path = self.root / "witness" / "w.jsonl"
        record = json.loads(path.read_bytes())
        record["memory_head_digest"] = "0" * 64
        path.write_bytes(json.dumps(record).encode() + b"\n")
        reopened = self.store()
        with self.assertRaisesRegex(
                MemoryError, "witness_signature_invalid"):
            reopened.get("exp-1")

    def test_witness_chain_break_detected(self):
        store = self.store()
        store.ingest(self.record())
        store.ingest(self.record(experience_id="exp-2", episode_id="ep-2"))
        store.close()
        path = self.root / "witness" / "w.jsonl"
        lines = path.read_bytes().splitlines()
        self.assertEqual(len(lines), 2)
        path.write_bytes(lines[1] + b"\n")
        reopened = self.store()
        with self.assertRaisesRegex(MemoryError, "witness_chain_broken"):
            reopened.get("exp-1")

    def test_witness_untrusted_signer_rejected(self):
        store = self.store()
        store.ingest(self.record())
        store.close()
        wrong_key_id = MemoryWitness(
            self.root / "witness" / "w.jsonl",
            seed=self.witness_seed, key_id="witness-key-2")
        reopened = self.store(witness=wrong_key_id)
        with self.assertRaisesRegex(
                MemoryError, "witness_untrusted_signer"):
            reopened.get("exp-1")

    def test_witness_cache_invalidates_on_external_edit(self):
        witness = self.witness()
        store = self.store(witness=witness)
        store.ingest(self.record())
        self.assertIsNotNone(witness.latest())
        path = self.root / "witness" / "w.jsonl"
        document = json.loads(path.read_bytes())
        document["memory_head_digest"] = "0" * 64
        path.write_bytes(json.dumps(document).encode() + b"\n")
        with self.assertRaisesRegex(
                WitnessError, "witness_signature_invalid"):
            witness.latest()

    def test_witness_rejects_sequence_regression(self):
        witness = self.witness()
        witness.advance(sequence=2, memory_head_digest="a" * 64)
        with self.assertRaisesRegex(
                WitnessError, "witness_sequence_not_advancing"):
            witness.advance(sequence=2, memory_head_digest="b" * 64)

    def test_rebuild_over_existing_witness_refused(self):
        store = self.store()
        store.ingest(self.record())
        with self.assertRaisesRegex(
                MemoryError, "memory_witness_rebuild_requires_new_epoch"):
            store.repair_chain(rebuild=True)

    def test_production_repair_refuses_legacy_rows(self):
        legacy_path = self.root / "legacy" / "memory.db"
        legacy = MemoryStore(
            legacy_path, chain_key=(self.chain_seed, "chain-key-1"))
        legacy.ingest(_v1_record())
        legacy.close()
        production = MemoryStore(
            legacy_path,
            trusted_signer_keys={"exp-key-1": self.record_public.hex()},
            chain_key=(self.chain_seed, "chain-key-1"),
            profile=MemoryTrustProfile.production(),
            witness=self.witness(), verifier=self.verifier)
        with self.assertRaisesRegex(
                MemoryError, "legacy_v1_record"):
            production.repair_chain()


class DatabaseTamperTests(MemoryFixture):
    """G3: a rewritten row cannot be served as trusted production memory."""

    def test_rewritten_record_body_detected(self):
        store = self.store()
        record = self.record()
        store.ingest(record)
        row = store._conn().execute(
            "SELECT record_json FROM experience WHERE experience_id=?",
            ("exp-1",)).fetchone()
        document = json.loads(row[0])
        document["lesson"] = "rewritten lesson"
        store._conn().execute(
            "UPDATE experience SET record_json=? WHERE experience_id=?",
            (json.dumps(document), "exp-1"))
        store._conn().commit()
        with self.assertRaisesRegex(MemoryError, "experience_tampered"):
            store.get("exp-1")

    def test_deleted_row_breaks_chain(self):
        store = self.store()
        store.ingest(self.record())
        store.ingest(self.record(experience_id="exp-2", episode_id="ep-2"))
        store._conn().execute(
            "DELETE FROM experience WHERE experience_id=?", ("exp-1",))
        store._conn().commit()
        with self.assertRaisesRegex(
                MemoryError, "memory_chain_invalid"):
            store.get("exp-2")


class RetrievalTrustTests(MemoryFixture):
    """G3.4: trust, applicability, and usefulness stay separate."""

    def _candidate(self, experience_id="exp-r", episode_id="ep-r", **over):
        return induce_candidate(self.record(
            experience_id=experience_id, episode_id=episode_id, **over))

    def ctx(self, **kw):
        defaults = dict(language="python")
        defaults.update(kw)
        return RetrievalContext(**defaults)

    def test_trust_failure_beats_higher_score(self):
        trusted = self._candidate("exp-trusted", "ep-trusted")
        untrusted = self._candidate(
            "exp-untrusted", "ep-untrusted",
            lesson="Use ROUND_HALF_EVEN for money",
            applicability=(
                {"kind": "language_is", "value": "python"},
                {"kind": "toolchain_is", "value": "python"},
            ))
        rejected = []
        picked = retrieve_memories(
            [trusted, untrusted], self.ctx(toolchain="python"),
            trust_check=lambda c: c.digest == trusted.digest,
            on_reject=lambda c, stage, detail: rejected.append(
                (c.digest, stage)))
        self.assertEqual(
            [m.candidate.digest for m in picked], [trusted.digest])
        self.assertIn((untrusted.digest, "untrusted"), rejected)

    def test_inapplicable_rejected_even_with_high_score(self):
        rust = self._candidate(
            "exp-rust", "ep-rust",
            applicability=(
                {"kind": "language_is", "value": "rust"},
                {"kind": "toolchain_is", "value": "rust"},
            ))
        rejected = []
        picked = retrieve_memories(
            [rust], self.ctx(), on_reject=lambda c, s, d: rejected.append(s))
        self.assertEqual(picked, ())
        self.assertEqual(rejected, ["inapplicable"])

    def test_suppressed_candidate_rejected(self):
        candidate = self._candidate(
            "exp-cx", "ep-cx", counterexamples=("legacy-sig",))
        rejected = []
        picked = retrieve_memories(
            [candidate],
            self.ctx(failure_signatures=frozenset({"legacy-sig"})),
            on_reject=lambda c, s, d: rejected.append((s, d)))
        self.assertEqual(picked, ())
        self.assertEqual(rejected, [("suppressed", "legacy-sig")])

    def test_low_score_rejected(self):
        candidate = self._candidate()
        rejected = []
        picked = retrieve_memories(
            [candidate], self.ctx(), min_score=100,
            on_reject=lambda c, s, d: rejected.append(s))
        self.assertEqual(picked, ())
        self.assertEqual(rejected, ["low_score"])

    def test_hooks_must_be_callable(self):
        with self.assertRaisesRegex(ContractError, "trust_check"):
            retrieve_memories([], self.ctx(), trust_check="yes")
        with self.assertRaisesRegex(ContractError, "on_reject"):
            retrieve_memories([], self.ctx(), on_reject="yes")

    def test_untrusted_pool_abstains_with_trust_check(self):
        candidates = [self._candidate()]
        self.assertEqual(
            retrieve_memories(
                candidates, self.ctx(), trust_check=lambda c: False),
            ())


if __name__ == "__main__":
    unittest.main()
